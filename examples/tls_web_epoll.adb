--  TLS Static File Server using epoll (async I/O)
--
--  A real, working HTTPS server built on SPARKTLS that serves static
--  files from a directory.  Uses Linux epoll with non-blocking sockets
--  for async I/O -- the same pattern used by nginx, Caddy, etc.
--
--  Usage:
--    ./tls_web_epoll <cert.pem> <key.pem> [docroot]
--
--  Then: curl -k https://localhost:8443/index.html
--  Or with cert verification if you trust the CA.
--
--  This demonstrates:
--    - Non-blocking sockets with epoll
--    - SPARKTLS Feed_Ciphertext/Drain_Ciphertext/Advance pattern
--    - System root loading, identity loading from PEM
--    - Per-connection Session state
--    - Static file serving over HTTPS
--    - Worker tasks, one event loop each, sharing nothing mutable; one
--      listening socket, which a worker watches (EPOLLEXCLUSIVE) only
--      while it has room for another connection and handshake
--    - A connection table and a SPARKTLS.Handshake_Pool allocated on the
--      heap at start-up, sized from the environment
--
--  Settings (environment, read once at start-up):
--    SPARKTLS_PORT               listen port (8443)
--    SPARKTLS_WORKERS            worker tasks (1)
--    SPARKTLS_MAX_CONNECTIONS    open connections per worker (256)
--    SPARKTLS_HANDSHAKE_SLOTS    handshakes in flight per worker (64)
--    SPARKTLS_HANDSHAKE_TIMEOUT  seconds from accept to Handshake_Done (10)
--    SPARKTLS_IDLE_TIMEOUT       seconds between requests (60)

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Streams;           use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Unchecked_Deallocation;
with Ada.Calendar;
with Ada.Environment_Variables;
with GNAT.OS_Lib;
with Ada.Real_Time;
with Ada.Calendar.Formatting;
with Interfaces;            use Interfaces;
with Interfaces.C;          use Interfaces.C;
with System;

with SPARKNaCl;             use SPARKNaCl;
with X509;
with SPARKTLS;              use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;
with POSIX_Thin;            use POSIX_Thin;
with SPARKTLS.Ticket_Keys;

procedure TLS_Web_Epoll is

   --  One line to stdout in a single write(2), so lines from different
   --  workers never interleave. Ada.Text_IO makes no such promise when
   --  several tasks write to the same file.
   procedure Log (Line : String) is
      Text  : aliased constant String := Line & ASCII.LF;
      Dummy : long;
   begin
      Dummy := C_Write (1, Text'Address, Text'Length);
   end Log;

   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      Hr  : Ada.Calendar.Formatting.Hour_Number;
      Mn  : Ada.Calendar.Formatting.Minute_Number;
      Sc  : Ada.Calendar.Formatting.Second_Number;
      SS  : Ada.Calendar.Formatting.Second_Duration;
   begin
      --  Ada.Calendar.Split works in package Calendar's implementation-
      --  defined (local) time zone, RM 9.6. X.509 notBefore/notAfter are
      --  UTC, so a local split shifts every validity comparison by the
      --  host's UTC offset. Formatting.Split with Time_Zone => 0 is the
      --  UTC one.
      Ada.Calendar.Formatting.Split
        (Now, Y, Mo, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Hr, Minute => Mn, Second => Sc);
   end Current_Time;

   --  To_C_Buf / From_C_Buf removed 2026-04-30. SPARKNaCl.Byte is just
   --  `subtype Byte is Unsigned_8`, so Byte_Seq has identical memory
   --  layout to a C `unsigned char *`. Pass `Buf'Address` straight to
   --  read(2) / write(2) — no per-byte copy needed. Cuts ~16 KB of
   --  byte-shuffling per record on the bulk-throughput path.

   --  A response body read from disk. Its own access type over an
   --  UNCONSTRAINED Byte_Seq: an example must not share a type with the
   --  library's internals.
   type Cached_Body_Access is access all Byte_Seq;
   procedure Free_Cached_Body is new
     Ada.Unchecked_Deallocation (Byte_Seq, Cached_Body_Access);

   --  Only the request path's characters an HTTP path may carry, no
   --  ".." segment, an absolute path. Anything else is answered 404 and
   --  never touches the file system: "GET /../../etc/passwd" served any
   --  file the process could read before 2026-09-14.
   function Safe_Path (Path : String) return Boolean is
   begin
      if Path'Length = 0 or else Path (Path'First) /= '/' then
         return False;
      end if;
      for I in Path'Range loop
         if Character'Pos (Path (I)) < 32 or else Character'Pos (Path (I)) > 126
           or else Path (I) = '\'
         then
            return False;
         end if;
      end loop;
      for I in Path'First .. Path'Last - 1 loop
         if Path (I) = '.' and then Path (I + 1) = '.' then
            return False;
         end if;
      end loop;
      return True;
   end Safe_Path;

   --  Peer-controlled text for the log: control characters become '?', so
   --  a request line cannot forge log entries or drive the terminal.
   function Printable (S : String) return String is
      R : String := S;
   begin
      for I in R'Range loop
         if Character'Pos (R (I)) < 32 or else Character'Pos (R (I)) > 126 then
            R (I) := '?';
         end if;
      end loop;
      return R;
   end Printable;

   --  Read a regular file into a heap buffer (for serving static content).
   --  Symbolic links are followed, as a web server's docroot normally
   --  expects; Safe_Path keeps the request inside the docroot. Read in
   --  chunks: the old version put the whole file on the task stack, and a
   --  request for anything over a few MB was a stack overflow.
   Max_File_Size : constant := 268435456;   --  256 MB (bench payloads)

   function Read_File (Path : String) return Cached_Body_Access is
      package SIO renames Ada.Streams.Stream_IO;
      use type Ada.Directories.File_Kind;
      use type SIO.Count;
      F    : SIO.File_Type;
      Size : SIO.Count;
      Res  : Cached_Body_Access;
   begin
      if not Ada.Directories.Exists (Path)
        or else Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File
      then
         return null;
      end if;
      SIO.Open (F, SIO.In_File, Path);
      Size := SIO.Size (F);
      if Size = 0 or else Size > Max_File_Size then
         SIO.Close (F);
         return null;
      end if;
      Res := new Byte_Seq (0 .. N32 (Size) - 1);
      declare
         Chunk : Stream_Element_Array (1 .. 65536);
         Last  : Stream_Element_Offset;
         Pos   : N32 := 0;
      begin
         while Pos < N32 (Size) loop
            SIO.Read (F, Chunk, Last);
            exit when Last < Chunk'First;
            for I in Chunk'First .. Last loop
               exit when Pos > Res'Last;
               Res (Pos) := SPARKNaCl.Byte (Chunk (I));
               Pos := Pos + 1;
            end loop;
         end loop;
         SIO.Close (F);
         if Pos /= N32 (Size) then
            Free_Cached_Body (Res);
            return null;
         end if;
      end;
      return Res;
   exception
      when others =>
         if Res /= null then
            Free_Cached_Body (Res);
         end if;
         return null;
   end Read_File;

   --  Build HTTP response
   function HTTP_Response (Status : String; Content_Type : String;
                           Payload : Byte_Seq) return Byte_Seq
   is
      Header : constant String :=
         "HTTP/1.1 " & Status & ASCII.CR & ASCII.LF &
         "Content-Type: " & Content_Type & ASCII.CR & ASCII.LF &
         "Content-Length:" & Payload'Length'Image & ASCII.CR & ASCII.LF &
         "Connection: close" & ASCII.CR & ASCII.LF &
         ASCII.CR & ASCII.LF;
      Result : Byte_Seq (0 .. N32 (Header'Length) + N32 (Payload'Length) - 1);
   begin
      for I in Header'Range loop
         Result (N32 (I - Header'First)) :=
            SPARKNaCl.Byte (Character'Pos (Header (I)));
      end loop;
      Result (N32 (Header'Length) .. Result'Last) := Payload;
      return Result;
   end HTTP_Response;

   function HTTP_404 return Byte_Seq is
      Payload : constant String := "404 Not Found";
      Resp : Byte_Seq (0 .. N32 (Payload'Length) - 1);
   begin
      for I in Payload'Range loop
         Resp (N32 (I - Payload'First)) :=
            SPARKNaCl.Byte (Character'Pos (Payload (I)));
      end loop;
      return HTTP_Response ("404 Not Found", "text/plain", Resp);
   end HTTP_404;

   --  Put the next part of Data, from offset From, into the session.
   --  Write_Plaintext takes its plaintext indexed from 0 (its precondition
   --  says so) and at most one TLS record of it per call, so this hands it
   --  up to one record's worth, shifted to start at 0. Passing a slice at
   --  its own offset instead broke every response over one record before
   --  2026-09-24.
   Record_Plaintext : constant := 16_384;

   procedure Write_Next
     (S : in out SPARKTLS.Session; Data : Byte_Seq; From : N32; Written : out N32)
   is
      N : constant N32 := N32'Min (Record_Plaintext, N32 (Data'Length) - From);
      subtype Chunk is Byte_Seq (0 .. N - 1);
   begin
      SPARKTLS.Write_Plaintext
        (S, Chunk (Data (Data'First + From .. Data'First + From + N - 1)), Written);
   end Write_Next;

   --  Configuration, all fixed before the first worker starts and only
   --  read afterwards.
   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Docroot : String (1 .. 256) := (others => ' ');
   Doc_Len : Natural := 0;

   function Env_Natural (Name : String; Default, First, Last : Natural) return Natural is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         declare
            V : constant Natural := Natural'Value (Ada.Environment_Variables.Value (Name));
         begin
            if V in First .. Last then
               return V;
            end if;
            Log (Name & " must be in" & First'Image & " .." & Last'Image & "; using" & Default'Image);
         end;
      end if;
      return Default;
   exception
      when Constraint_Error =>
         Log (Name & " is not a number; using" & Default'Image);
         return Default;
   end Env_Natural;

   --  SPARKTLS_PORT overrides the default, as in tls_blocking_server, so
   --  the integration runner can rotate ports.
   Port            : constant Natural := Env_Natural ("SPARKTLS_PORT", 8443, 1, 65_535);
   Workers         : constant Positive := Env_Natural ("SPARKTLS_WORKERS", 1, 1, 256);
   Max_Connections : constant Positive := Env_Natural ("SPARKTLS_MAX_CONNECTIONS", 256, 1, 65_536);
   Handshake_Slots : constant Slot_Index :=
     Slot_Index (Env_Natural ("SPARKTLS_HANDSHAKE_SLOTS", 64, 1, Max_Handshake_Slots));

   --  The listening socket, non-blocking, opened before the workers start
   --  and shared by all of them.
   Listen_FD : int := -1;

   --  Deadlines. The library is sans-I/O: it learns nothing about a
   --  connection until bytes arrive, so a peer that connects and goes
   --  silent (or stalls part-way through its ClientHello) holds a
   --  connection slot and a Handshake_Pool slot until the APPLICATION
   --  gives up on it. Handshake_Timeout bounds the time from accept to
   --  Handshake_Done; Idle_Timeout bounds the gap between requests on a
   --  connection that is up. Both come from the environment for tests
   --  (SPARKTLS_HANDSHAKE_TIMEOUT / SPARKTLS_IDLE_TIMEOUT, seconds).
   function Env_Seconds (Name : String; Default : Duration) return Duration is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Duration'Value (Ada.Environment_Variables.Value (Name));
      end if;
      return Default;
   end Env_Seconds;

   use type Ada.Real_Time.Time;
   use type Ada.Real_Time.Time_Span;
   Handshake_Timeout : constant Ada.Real_Time.Time_Span :=
     Ada.Real_Time.To_Time_Span (Env_Seconds ("SPARKTLS_HANDSHAKE_TIMEOUT", 10.0));
   Idle_Timeout      : constant Ada.Real_Time.Time_Span :=
     Ada.Real_Time.To_Time_Span (Env_Seconds ("SPARKTLS_IDLE_TIMEOUT", 60.0));
   --  How long epoll_wait may sleep before the deadline sweep runs.
   Sweep_Interval_Ms : constant := 1000;

   EAGAIN : constant := 11;

   --  Per-connection state. A connection holds its Session for its whole
   --  life; the Session holds a slot of its worker's Handshake_Pool only
   --  while the handshake is in flight.
   type Conn_State is (Handshaking, Ready, Sending, Closing, Closed);

   type Connection is record
      S       : SPARKTLS.Server_Session;
      FD      : int := -1;
      State   : Conn_State := Closed;
      Req_Buf : Byte_Seq (0 .. 4095) := (others => 0);
      Req_Len : N32 := 0;
      --  Monotonic clock stamps for the deadlines: when the socket was
      --  accepted, and when bytes last arrived on it.
      Opened_At     : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Last_Activity : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      --  Response in flight: the body by reference and how much of it has
      --  been handed to the session; ciphertext the socket has not accepted
      --  yet; whether close_notify has been queued; and whether EPOLLOUT is
      --  armed. Non-blocking write(2) may take part of a buffer, so the
      --  remainder waits here for the socket to drain.
      Body_Ref     : Cached_Body_Access := null;
      Body_Off     : N32 := 0;
      Out_Buf      : Byte_Seq (0 .. 16639) := (others => 0);
      Out_Len      : N32 := 0;
      Out_Sent     : N32 := 0;
      Close_Queued : Boolean := False;
      Want_Out     : Boolean := False;
   end record;

   type Conn_Index is range 0 .. 65_535;
   type Conn_Array is array (Conn_Index range <>) of Connection;
   type Conn_Array_Access is access Conn_Array;
   type Pool_Access is access SPARKTLS.Handshake_Pool;

   --  One event loop. Each worker has its own epoll instance, connection
   --  table, handshake pool and file cache, and watches the shared
   --  listening socket with EPOLLEXCLUSIVE, so a new connection wakes one
   --  waiting worker rather than all of them. A worker watches it only
   --  while it has both a free connection entry and a free handshake slot:
   --  a busy worker is not waiting in epoll_wait and a full one has taken
   --  the socket out of its set, so connections go to the workers with
   --  room, and none is accepted only to be refused. Nothing mutable is
   --  shared: SPARKTLS keeps all
   --  connection state in the Session, and its only process-wide state is
   --  SPARKTLS.RBG and SPARKTLS.Ticket_Keys, both protected objects. So
   --  the loop takes no locks.
   --
   --  The connection table and the pool are allocated here, once, at
   --  start-up, and initialised in full then: nothing is allocated while
   --  serving. A Handshake_Pool is not safe to share between tasks, which
   --  is why each worker has its own.
   task type Worker (Num : Positive)
     with Storage_Size => 4 * 1024 * 1024;
   type Worker_Access is access Worker;

   task body Worker is
      Conns : constant Conn_Array_Access :=
        new Conn_Array (0 .. Conn_Index (Max_Connections - 1));
      Pool  : constant Pool_Access :=
        new SPARKTLS.Handshake_Pool (Size => Handshake_Slots);

      --  Single-slot file cache: avoids re-reading the same file from
      --  disk (and re-allocating its Byte_Seq) on every request. The
      --  bench drives one path repeatedly, so this turns N reads into 1.
      Cache_Path     : String (1 .. 256) := (others => ' ');
      Cache_Path_Len : Natural := 0;
      Cache_Body     : Cached_Body_Access := null;

      function Get_Cached (Full : String) return Cached_Body_Access is
      begin
         if Cache_Body /= null
            and then Full'Length <= Cache_Path'Length
            and then Cache_Path_Len = Full'Length
            and then Cache_Path (1 .. Cache_Path_Len) = Full
         then
            return Cache_Body;
         end if;
         declare
            Loaded : constant Cached_Body_Access := Read_File (Full);
         begin
            if Loaded = null then
               return null;
            end if;
            --  Free the old body unless a connection is still sending it
            --  (freeing it regardless was a use-after-free before
            --  2026-09-24). One still in use is left to leak, which on a
            --  cache miss mid-response is the rare case.
            if Cache_Body /= null
              and then (for all C of Conns.all => C.Body_Ref /= Cache_Body)
            then
               Free_Cached_Body (Cache_Body);
            end if;
            Cache_Body := Loaded;
            if Full'Length <= Cache_Path'Length then
               Cache_Path (1 .. Full'Length) := Full;
               Cache_Path_Len := Full'Length;
            else
               Cache_Path_Len := 0;
            end if;
            return Cache_Body;
         end;
      end Get_Cached;

      --  Network buffer -- passed directly to read(2) via Buf'Address.
      Raw_Buf : aliased Byte_Seq (0 .. 16383) := (others => 0);

      --  epoll state
      Epfd     : int := -1;
      Events   : aliased Epoll_Event_Array (0 .. 63) := (others => <>);

      --  The epoll tag of a connection: its index + 1. The listening
      --  socket has tag 0.
      function Tag_Of (Idx : Conn_Index) return int is (int (Idx) + 1);

      --  Free connection entries, as a stack: accepting is O(1) however
      --  large the table. An entry is pushed when Close_Conn closes its
      --  socket and popped when a new connection takes it.
      type Index_Array is array (Conn_Index range <>) of Conn_Index;
      Free_List : Index_Array (Conns'Range);
      Free_Top  : Natural := 0;   --  entries on the stack
      Open      : Natural := 0;   --  connections holding a socket

      procedure Init_Free_List is
      begin
         for I in reverse Conns'Range loop
            Free_List (Conn_Index (Free_Top)) := I;
            Free_Top := Free_Top + 1;
         end loop;
      end Init_Free_List;

      --  Whether the listening socket is in this worker's epoll set.
      Accepting : Boolean := False;

      --  Tear a connection down: out of epoll, socket closed, and the
      --  session Dropped so its handshake slot goes back to the pool.
      procedure Close_Conn (Idx : Conn_Index; Why : String := "") is
         Conn : Connection renames Conns (Idx);
         Dummy : int;
      begin
         if Conn.FD >= 0 then
            Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_DEL, Conn.FD, null);
            Dummy := C_Close (Conn.FD);
            Conn.FD := -1;
            Free_List (Conn_Index (Free_Top)) := Idx;
            Free_Top := Free_Top + 1;
            Open := Open - 1;
         end if;
         Conn.State := Closed;
         Conn.Body_Ref := null;
         Conn.Out_Len := 0;
         Conn.Out_Sent := 0;
         Conn.Close_Queued := False;
         Conn.Want_Out := False;
         SPARKTLS.Drop (Conn.S, Pool.all);
         if Why /= "" then
            Log ("  closed: " & Why);
         end if;
      end Close_Conn;

      --  Close every connection that is past its deadline.
      procedure Sweep_Deadlines is
         Now : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
      begin
         for I in Conns'Range loop
            if Conns (I).State = Handshaking
              and then Now - Conns (I).Opened_At > Handshake_Timeout
            then
               Close_Conn (I, "handshake timeout");
            elsif Conns (I).State in Ready | Closing
              and then Now - Conns (I).Last_Activity > Idle_Timeout
            then
               Close_Conn (I, "idle timeout");
            end if;
         end loop;
      end Sweep_Deadlines;

      --  Arm or disarm EPOLLOUT for a connection. EPOLL_CTL_MOD replaces
      --  the event data too, so the tag goes back in with the fd.
      procedure Arm_Output (Idx : Conn_Index; On : Boolean) is
         Conn  : Connection renames Conns (Idx);
         Ev    : aliased Epoll_Event;
         Dummy : int;
      begin
         if Conn.Want_Out = On or else Conn.FD < 0 then
            return;
         end if;
         Ev.Events := unsigned (EPOLLIN) or (if On then unsigned (EPOLLOUT) else 0);
         Ev.Data   := (FD => Conn.FD, Tag => Tag_Of (Idx));
         Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_MOD, Conn.FD, Ev'Access);
         Conn.Want_Out := On;
      end Arm_Output;

      --  Move output towards the socket: pending ciphertext first, then more
      --  from the session, then more plaintext from the response body, then
      --  close_notify. Stops when the socket will not take more (EPOLLOUT is
      --  armed and the rest waits) or when the response is complete (the
      --  connection becomes Closed for the event loop to reap). write(2) on
      --  a non-blocking socket may take part of a buffer; ignoring that
      --  return value corrupted every response larger than the socket buffer
      --  before 2026-09-14.
      procedure Pump_Send (Idx : Conn_Index) is
         Conn    : Connection renames Conns (Idx);
         Written : N32;
      begin
         loop
            if Conn.Out_Sent < Conn.Out_Len then
               declare
                  Wr : constant long :=
                    C_Write (Conn.FD, Conn.Out_Buf (Conn.Out_Sent)'Address,
                             size_t (Conn.Out_Len - Conn.Out_Sent));
               begin
                  if Wr > 0 then
                     Conn.Out_Sent := Conn.Out_Sent + N32 (Wr);
                     Conn.Last_Activity := Ada.Real_Time.Clock;
                  elsif Wr < 0 and then GNAT.OS_Lib.Errno = EAGAIN then
                     Arm_Output (Idx, True);
                     return;
                  else
                     Conn.State := Closed;   --  EPIPE, reset, ...
                     return;
                  end if;
                  if Conn.Out_Sent < Conn.Out_Len then
                     Arm_Output (Idx, True);
                     return;
                  end if;
               end;
            end if;
            Conn.Out_Len := 0;
            Conn.Out_Sent := 0;

            SPARKTLS.Drain_Ciphertext (Conn.S, Conn.Out_Buf, Conn.Out_Len);
            if Conn.Out_Len = 0 then
               if Conn.State = Sending and then Conn.Body_Ref /= null
                 and then Conn.Body_Off < N32 (Conn.Body_Ref'Length)
               then
                  Write_Next (Conn.S, Conn.Body_Ref.all, Conn.Body_Off, Written);
                  if Written = 0 then
                     Conn.State := Closed;
                     return;
                  end if;
                  Conn.Body_Off := Conn.Body_Off + Written;
               elsif Conn.State = Sending and then not Conn.Close_Queued then
                  --  Connection: close -- our close_notify ends the response.
                  SPARKTLS.Server.Close_Notify (Conn.S);
                  Conn.Close_Queued := True;
               else
                  Arm_Output (Idx, False);
                  if Conn.State = Sending then
                     Conn.State := Closed;
                  end if;
                  return;
               end if;
            end if;
         end loop;
      end Pump_Send;

      procedure Handle_Readable (Idx : Conn_Index) is
         Conn : Connection renames Conns (Idx);
         Rd : long;
         Fed : N32;
         Res : SPARKTLS.Action;
      begin
         Conn.Last_Activity := Ada.Real_Time.Clock;
         --  Read directly into Raw_Buf — Byte_Seq is array of Unsigned_8,
         --  byte-identical to a C buffer.
         Rd := C_Read (Conn.FD, Raw_Buf'Address, Raw_Buf'Length);
         if Rd <= 0 then
            Conn.State := Closed;
            return;
         end if;

         SPARKTLS.Feed_Ciphertext (Conn.S, Raw_Buf (0 .. N32 (Rd) - 1), Fed);

         --  Process TLS state machine
         loop
            SPARKTLS.Server.Advance (Conn.S, Pool.all, Res);

            case Res is
               when SPARKTLS.Has_Output =>
                  Pump_Send (Idx);
                  exit when Conn.State = Closed or else Conn.Want_Out;

               when SPARKTLS.Need_Input =>
                  exit;  --  wait for more data from epoll

               when SPARKTLS.Handshake_Done =>
                  Conn.State := Ready;

               when SPARKTLS.Plaintext_Ready =>
                  --  Read decrypted request data
                  declare
                     App : Byte_Seq (0 .. 4095);
                     App_N : N32;
                  begin
                     SPARKTLS.Read_Plaintext (Conn.S, App, App_N);
                     --  Accumulate
                     if Conn.Req_Len + App_N <= Conn.Req_Buf'Last + 1 then
                        Conn.Req_Buf (Conn.Req_Len ..
                                      Conn.Req_Len + App_N - 1) :=
                           App (0 .. App_N - 1);
                        Conn.Req_Len := Conn.Req_Len + App_N;
                     else
                        --  Request larger than we accept: close rather than
                        --  hold a slot for a peer we will never answer.
                        Conn.State := Closed;
                        exit;
                     end if;

                     --  Check if we have a complete HTTP request
                     --  (look for CRLFCRLF)
                     if Conn.Req_Len >= 4 then
                        for I in N32 range 0 .. Conn.Req_Len - 4 loop
                           if Conn.Req_Buf (I) = 16#0D#
                              and Conn.Req_Buf (I + 1) = 16#0A#
                              and Conn.Req_Buf (I + 2) = 16#0D#
                              and Conn.Req_Buf (I + 3) = 16#0A#
                           then
                              --  Parse GET /path
                              declare
                                 Path_Start : N32 := 0;
                                 Path_End   : N32 := 0;
                                 Found      : Boolean := False;
                              begin
                                 --  Find "GET "
                                 if Conn.Req_Len > 4
                                    and then Conn.Req_Buf (0) = 16#47#  -- G
                                    and then Conn.Req_Buf (1) = 16#45#  -- E
                                    and then Conn.Req_Buf (2) = 16#54#  -- T
                                    and then Conn.Req_Buf (3) = 16#20#  -- SP
                                 then
                                    Path_Start := 4;
                                    Path_End := Path_Start;
                                    while Path_End < Conn.Req_Len
                                       and then Conn.Req_Buf (Path_End) /= 16#20#
                                    loop
                                       Path_End := Path_End + 1;
                                    end loop;
                                    Found := True;
                                 end if;

                                 if Found then
                                    declare
                                       P_Len : constant N32 :=
                                          Path_End - Path_Start;
                                       Path : String (1 .. Natural (P_Len));
                                    begin
                                       for J in 0 .. P_Len - 1 loop
                                          Path (Natural (J) + 1) :=
                                             Character'Val (
                                                Conn.Req_Buf (Path_Start + J));
                                       end loop;
                                       Log ("  GET " & Printable (Path));

                                       --  Serve file
                                       declare
                                          function Content_Type
                                            (P : String) return String
                                          is
                                             Dot : Natural := 0;
                                          begin
                                             for I in reverse P'Range loop
                                                if P (I) = '.' then
                                                   Dot := I; exit;
                                                end if;
                                             end loop;
                                             if Dot = 0 then
                                                return "application/octet-stream";
                                             end if;
                                             declare
                                                Ext : constant String :=
                                                   P (Dot .. P'Last);
                                             begin
                                                if Ext = ".html" or Ext = ".htm" then
                                                   return "text/html; charset=utf-8";
                                                elsif Ext = ".css" then
                                                   return "text/css";
                                                elsif Ext = ".js" then
                                                   return "application/javascript";
                                                elsif Ext = ".json" then
                                                   return "application/json";
                                                elsif Ext = ".png" then
                                                   return "image/png";
                                                elsif Ext = ".jpg"
                                                   or Ext = ".jpeg"
                                                then
                                                   return "image/jpeg";
                                                elsif Ext = ".gif" then
                                                   return "image/gif";
                                                elsif Ext = ".svg" then
                                                   return "image/svg+xml";
                                                elsif Ext = ".ico" then
                                                   return "image/x-icon";
                                                elsif Ext = ".txt" then
                                                   return "text/plain";
                                                else
                                                   return "application/octet-stream";
                                                end if;
                                             end;
                                          end Content_Type;

                                          Full : constant String :=
                                             Docroot (1 .. Doc_Len) & Path;
                                          Body_Ref : constant Cached_Body_Access :=
                                             (if Safe_Path (Path) then Get_Cached (Full) else null);
                                          --  Header is small; build inline (no body copy).
                                          Hdr_Str : constant String :=
                                             (if Body_Ref = null
                                              then "HTTP/1.1 404 Not Found"
                                                   & ASCII.CR & ASCII.LF
                                                   & "Content-Type: text/plain"
                                                   & ASCII.CR & ASCII.LF
                                                   & "Content-Length: 13"
                                                   & ASCII.CR & ASCII.LF
                                                   & "Connection: close"
                                                   & ASCII.CR & ASCII.LF
                                                   & ASCII.CR & ASCII.LF
                                                   & "404 Not Found"
                                              else "HTTP/1.1 200 OK"
                                                   & ASCII.CR & ASCII.LF
                                                   & "Content-Type: "
                                                   & Content_Type (Path)
                                                   & ASCII.CR & ASCII.LF
                                                   & "Content-Length:"
                                                   & Body_Ref'Length'Image
                                                   & ASCII.CR & ASCII.LF
                                                   & "Connection: close"
                                                   & ASCII.CR & ASCII.LF
                                                   & ASCII.CR & ASCII.LF);
                                          Hdr_Bytes : Byte_Seq
                                             (0 .. N32 (Hdr_Str'Length) - 1);
                                          Written : N32;
                                          Wr : long;
                                       begin
                                          for I in Hdr_Str'Range loop
                                             Hdr_Bytes (N32 (I - Hdr_Str'First)) :=
                                                SPARKNaCl.Byte
                                                  (Character'Pos (Hdr_Str (I)));
                                          end loop;

                                          --  Header (and the 404 body) into the session, then
                                          --  the body and close_notify by reference through
                                          --  Pump_Send as the socket takes them.
                                          declare
                                             Total_Sent : N32 := 0;
                                          begin
                                             while Total_Sent < Hdr_Bytes'Length loop
                                                Write_Next (Conn.S, Hdr_Bytes, Total_Sent, Written);
                                                exit when Written = 0;
                                                Total_Sent := Total_Sent + Written;
                                             end loop;
                                          end;
                                          Conn.Body_Ref := Body_Ref;
                                          Conn.Body_Off := 0;
                                          Conn.Close_Queued := False;
                                          Conn.State := Sending;
                                          Pump_Send (Idx);
                                       end;
                                    end;
                                 end if;
                              end;
                              Conn.Req_Len := 0;
                              exit;
                           end if;
                        end loop;
                     end if;
                  end;
                  exit when Conn.State in Sending | Closed;

               when SPARKTLS.Shutdown =>
                  --  Answer the peer's close_notify with ours, then close once
                  --  the socket has taken it.
                  SPARKTLS.Server.Close_Notify (Conn.S);
                  Conn.Body_Ref := null;
                  Conn.Close_Queued := True;
                  Conn.State := Sending;
                  Pump_Send (Idx);
                  exit;

               when SPARKTLS.Error_Alert =>
                  Log ("  TLS error: " &
                     SPARKTLS.Describe (SPARKTLS.Last_Error (Conn.S)));
                  Conn.State := Closed;
                  exit;

               when others =>
                  null;
            end case;
         end loop;
      end Handle_Readable;

      --  Room for one more connection: a free entry and a free handshake
      --  slot (Configure takes a slot).
      function Has_Room return Boolean is
        (Free_Top > 0 and then SPARKTLS.Has_Free_Slot (Pool.all));

      --  Take one new connection from the listening socket into a free
      --  entry. False when there was none to take (another worker got it,
      --  or the backlog is empty) or accept failed.
      function Accept_One return Boolean is
         Client_FD   : int;
         Addr_Len    : aliased int := Sockaddr_In'Size / 8;
         Client_Addr : aliased Sockaddr_In;
         Ev          : aliased Epoll_Event;
         Dummy       : int;
      begin
         Client_FD := C_Accept4 (Listen_FD, Client_Addr'Access, Addr_Len'Access, SOCK_NONBLOCK);
         if Client_FD < 0 then
            return False;
         end if;
         Free_Top := Free_Top - 1;
         Open := Open + 1;
         declare
            Idx  : constant Conn_Index := Free_List (Conn_Index (Free_Top));
            Conn : Connection renames Conns (Idx);
         begin
            Conn.FD := Client_FD;
            Conn.State := Handshaking;
            Conn.Req_Len := 0;
            Conn.Opened_At := Ada.Real_Time.Clock;
            Conn.Last_Activity := Ada.Real_Time.Clock;
            --  A reused entry must not carry the previous connection's
            --  unsent bytes or body reference.
            Conn.Body_Ref := null;
            Conn.Body_Off := 0;
            Conn.Out_Len := 0;
            Conn.Out_Sent := 0;
            Conn.Close_Queued := False;
            Conn.Want_Out := False;
            Conn.S :=
              SPARKTLS.Server.Configure
                ((Local          => Id'Unchecked_Access,
                  Get_Active_TEK => SPARKTLS.Ticket_Keys.Get_Active_TEK'Access,
                  Get_TEK_By_Id  => SPARKTLS.Ticket_Keys.Get_TEK_By_Id'Access,
                  others         => <>),
                 Pool.all);

            Ev.Events := unsigned (EPOLLIN);
            Ev.Data   := (FD => Client_FD, Tag => Tag_Of (Idx));
            Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_ADD, Client_FD, Ev'Access);
         end;
         return True;
      end Accept_One;

      --  Accept while there is room and a connection waiting.
      procedure Accept_Pending is
      begin
         while Has_Room loop
            exit when not Accept_One;
         end loop;
      end Accept_Pending;

      --  Watch the listening socket exactly while there is room. With
      --  EPOLLEXCLUSIVE the registration cannot be modified, only added
      --  and removed.
      procedure Update_Accepting is
         Ev    : aliased Epoll_Event;
         Dummy : int;
         Want  : constant Boolean := Has_Room;
      begin
         if Want = Accepting then
            return;
         end if;
         if Want then
            Ev.Events := unsigned (EPOLLIN) or unsigned (EPOLLEXCLUSIVE);
            Ev.Data   := (FD => Listen_FD, Tag => 0);
            Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_ADD, Listen_FD, Ev'Access);
         else
            Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_DEL, Listen_FD, null);
         end if;
         Accepting := Want;
      end Update_Accepting;

      --  Service one event for the connection its tag names. The fd check
      --  guards against an event for a connection that was closed, and its
      --  entry reused, earlier in the same batch.
      procedure Service (E : Epoll_Event) is
      begin
         if E.Data.Tag not in 1 .. int (Conns'Last) + 1 then
            return;
         end if;
         declare
            Idx : constant Conn_Index := Conn_Index (E.Data.Tag - 1);
            Ev  : constant unsigned := E.Events;
         begin
            if Conns (Idx).State = Closed or else Conns (Idx).FD /= E.Data.FD then
               return;
            end if;
            if (Ev and (unsigned (EPOLLERR) or unsigned (EPOLLHUP))) /= 0
              and then (Ev and unsigned (EPOLLIN)) = 0
            then
               Conns (Idx).State := Closed;
            else
               if (Ev and unsigned (EPOLLOUT)) /= 0 then
                  --  Socket drained: continue the response.
                  Pump_Send (Idx);
               end if;
               if (Ev and unsigned (EPOLLIN)) /= 0
                 and then Conns (Idx).State /= Closed
               then
                  Handle_Readable (Idx);
               end if;
            end if;
            if Conns (Idx).State = Closed then
               Close_Conn (Idx);
            end if;
         end;
      end Service;

      Nfds : int;
   begin
      Init_Free_List;
      Epfd := Epoll_Create1 (0);
      if Epfd < 0 then
         Log ("worker" & Num'Image & ": epoll_create1() failed");
      end if;

      --  Event loop
      while Epfd >= 0 loop
         Update_Accepting;
         Nfds := Epoll_Wait (Epfd, Events (Events'First)'Unrestricted_Access, 64, Sweep_Interval_Ms);
         if Nfds < 0 then
            Log ("worker" & Num'Image & ": epoll_wait error");
            exit;
         end if;

         for I in 0 .. Natural (Nfds) - 1 loop
            if Events (I).Data.Tag = 0 then
               Accept_Pending;
            else
               Service (Events (I));
            end if;
         end loop;

         --  Runs after every wake-up, including the idle ones epoll_wait's
         --  timeout produces, so a silent peer cannot hold a slot for long.
         Sweep_Deadlines;
      end loop;
   exception
      when E : others =>
         Log ("worker" & Num'Image & ": " & Ada.Exceptions.Exception_Information (E));
   end Worker;

   Pool_Bytes : constant Long_Long_Integer :=
     Long_Long_Integer (Handshake_Slots) * Long_Long_Integer (SPARKTLS.HS_Data'Size / 8);
   Conn_Bytes : constant Long_Long_Integer :=
     Long_Long_Integer (Max_Connections) * Long_Long_Integer (Connection'Size / 8);

begin
   Entropy_Random.Init;
   --  Seed the stateless-ticket (RFC 5077) TEK ring so resumption works.
   SPARKTLS.Ticket_Keys.Initialize (Clock => null);

   --  Parse arguments
   if Ada.Command_Line.Argument_Count < 2 then
      Log ("Usage: tls_web_epoll <cert.pem> <key.pem> [docroot]");
      return;
   end if;

   Credentials.Load_Identity
     (Id,
      Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2),
      Id_OK);
   if not Id_OK then
      Log ("Failed to load identity");
      return;
   end if;

   if Ada.Command_Line.Argument_Count >= 3 then
      declare
         D : constant String := Ada.Command_Line.Argument (3);
      begin
         Doc_Len := D'Length;
         Docroot (1 .. Doc_Len) := D;
      end;
   else
      Docroot (1) := '.';
      Doc_Len := 1;
   end if;

   --  A peer that closes before we finish writing must not kill the
   --  process (write(2) raises SIGPIPE; GNAT.Sockets is not used here).
   declare
      Old_Handler : System.Address;
   begin
      Old_Handler := C_Signal (SIGPIPE, SIG_IGN);
   end;

   --  The listening socket, shared by every worker.
   declare
      One   : aliased int := 1;
      Addr  : aliased Sockaddr_In;
      Dummy : int;
   begin
      Listen_FD := C_Socket (AF_INET, SOCK_STREAM + SOCK_NONBLOCK, 0);
      if Listen_FD < 0 then
         Log ("socket() failed");
         return;
      end if;
      Dummy := C_Setsockopt (Listen_FD, SOL_SOCKET, SO_REUSEADDR, One'Access, 4);
      Addr.Sin_Port := Htons (unsigned_short (Port));
      Addr.Sin_Addr := 0;  --  INADDR_ANY
      if C_Bind (Listen_FD, Addr'Access, Sockaddr_In'Size / 8) < 0 then
         Log ("bind() failed");
         return;
      end if;
      if C_Listen (Listen_FD, 1024) < 0 then
         Log ("listen() failed");
         return;
      end if;
   end;

   Log ("=== SPARKTLS Web Server (epoll) ===");
   Log ("Docroot: " & Docroot (1 .. Doc_Len));
   Log ("Listening on 0.0.0.0:" & Port'Image);
   Log ("Workers:" & Workers'Image & ", each with" & Max_Connections'Image
        & " connections (" & Long_Long_Integer'Image (Conn_Bytes / 1_048_576) & " MB) and"
        & Handshake_Slots'Image & " handshake slots (" & Long_Long_Integer'Image (Pool_Bytes / 1_048_576)
        & " MB)");

   --  Start the workers. Their access type is declared in this procedure,
   --  so the procedure is their master and does not return while they run.
   declare
      W : Worker_Access;
   begin
      for N in 1 .. Workers loop
         W := new Worker (N);
      end loop;
   end;
   Log ("Ready. Waiting for connections...");
end TLS_Web_Epoll;
