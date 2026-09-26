--  TLS Static File Server using io_uring (async I/O)
--
--  tls_web_epoll's twin on Linux io_uring: the same server -- workers,
--  connection tables and handshake pools allocated at start-up, admission
--  control, deadlines, static files over HTTPS -- with completion-based I/O
--  in place of readiness. A worker submits its accepts, receives, sends and
--  shutdowns to its own ring and reaps their completions, many per system
--  call. IO_Uring is a pure-Ada binding to the kernel interface (no
--  liburing, no C).
--
--  Usage:
--    ./tls_web_uring <cert.pem> <key.pem> [docroot]
--
--  Then: curl -k https://localhost:8443/index.html
--  Or with cert verification if you trust the CA.
--
--  This demonstrates:
--    - io_uring submission and completion rings, no liburing
--    - SPARKTLS Feed_Ciphertext/Drain_Ciphertext/Advance pattern
--    - System root loading, identity loading from PEM
--    - Per-connection Session state
--    - Static file serving over HTTPS
--    - Worker tasks, one ring each, sharing nothing mutable; one listening
--      socket, on which a worker has an accept outstanding only while it
--      has room for another connection and handshake
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
with Ada.Environment_Variables;
with Ada.Real_Time;
with Interfaces;            use Interfaces;
with Interfaces.C;          use Interfaces.C;
with System;

with SPARKNaCl;             use SPARKNaCl;
with SPARKTLS;              use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;
with POSIX_Thin;            use POSIX_Thin;
with SPARKTLS.Ticket_Keys;
with IO_Uring;              use IO_Uring;

procedure TLS_Web_Uring is

   --  One line to stdout in a single write(2), so lines from different
   --  workers never interleave. Ada.Text_IO makes no such promise when
   --  several tasks write to the same file.
   procedure Log (Line : String) is
      Text  : aliased constant String := Line & ASCII.LF;
      Dummy : long;
   begin
      Dummy := C_Write (1, Text'Address, Text'Length);
   end Log;

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

   --  Per-connection state. A connection holds its Session for its whole
   --  life; the Session holds a slot of its worker's Handshake_Pool only
   --  while the handshake is in flight. Recv_Buf and Out_Buf are handed to
   --  the kernel with a receive or send in flight and not touched until it
   --  completes; at most one of each is in flight per connection.
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
      --  io_uring bookkeeping: the receive buffer, requests in flight, and
      --  the generation that tags this use of the entry in every request's
      --  user data (a completion from an earlier use is ignored).
      Recv_Buf     : Byte_Seq (0 .. 16383) := (others => 0);
      Recv_Pending : Boolean := False;
      Send_Pending : Boolean := False;
      Pending      : Natural := 0;       --  requests in flight
      Shutting     : Boolean := False;   --  shutdown submitted; close when Pending = 0
      Gen          : Unsigned_32 := 0;
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
   --  One ring. Each worker has its own io_uring, connection table,
   --  handshake pool and file cache. It keeps a single accept outstanding on
   --  the shared listening socket while it has both a free connection entry
   --  and a free handshake slot: the kernel gives each new connection to one
   --  waiting accept, so connections go to the workers with room, and a
   --  full worker accepts nothing it would have to refuse (a multishot accept
   --  would keep accepting after it filled up). Nothing mutable is shared:
   --  SPARKTLS keeps all connection state in the Session, and its only
   --  process-wide state is SPARKTLS.RBG and SPARKTLS.Ticket_Keys, both
   --  protected objects. So the loop takes no locks.
   --
   --  The connection table, the pool and the ring are allocated here, once,
   --  at start-up: nothing is allocated while serving.
   task type Worker (Num : Positive)
     with Storage_Size => 4 * 1024 * 1024;
   type Worker_Access is access Worker;

   task body Worker is
      Conns : constant Conn_Array_Access :=
        new Conn_Array (0 .. Conn_Index (Max_Connections - 1));
      Pool  : constant Pool_Access :=
        new SPARKTLS.Handshake_Pool (Size => Handshake_Slots);
      R     : Ring;

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
            --  Free the old body unless a connection is still sending it.
            --  One still in use is left to leak, which on a cache miss
            --  mid-response is the rare case.
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

      ------------------------------------------------------------------------
      --  User data: what a completion is for. Kind in the top byte, the
      --  connection's generation in the next 24 bits, its index in the low
      --  32 (both zero for the accept and the timer).
      ------------------------------------------------------------------------

      type Kind is (None, Accepted, Received, Sent, Shut_Down, Tick);

      function Tag (K : Kind; Idx : Conn_Index := 0) return Unsigned_64 is
        (Shift_Left (Unsigned_64 (Kind'Pos (K)), 56)
         or Shift_Left (Unsigned_64 (Conns (Idx).Gen and 16#FF_FFFF#), 32)
         or Unsigned_64 (Idx));

      function Kind_Of (Data : Unsigned_64) return Kind is
        (if Shift_Right (Data, 56) <= Kind'Pos (Kind'Last)
         then Kind'Val (Shift_Right (Data, 56)) else None);

      --  The connection a completion is for, if it is still the same use of
      --  that entry.
      procedure Target (Data : Unsigned_64; Idx : out Conn_Index; Valid : out Boolean) is
         Index : constant Unsigned_64 := Data and 16#FFFF_FFFF#;
         Gen   : constant Unsigned_32 := Unsigned_32 (Shift_Right (Data, 32) and 16#FF_FFFF#);
      begin
         Valid := Index <= Unsigned_64 (Conns'Last);
         Idx := (if Valid then Conn_Index (Index) else 0);
         Valid := Valid and then (Conns (Idx).Gen and 16#FF_FFFF#) = Gen;
      end Target;

      --  A submission entry, handing the queue to the kernel first if it is
      --  full (a loop iteration rarely fills it).
      function Next_SQE return SQE_Access is
         E      : SQE_Access := Get_SQE (R);
         Result : Integer;
      begin
         if E = null then
            Submit (R, 0, Result);
            E := Get_SQE (R);
         end if;
         return E;
      end Next_SQE;

      ------------------------------------------------------------------------
      --  Free entries, as a stack: accepting is O(1) however large the
      --  table. An entry is pushed when its socket is closed and popped when
      --  a new connection takes it.
      ------------------------------------------------------------------------

      type Index_Array is array (Conn_Index range <>) of Conn_Index;
      Free_List : Index_Array (Conns'Range);
      Free_Top  : Natural := 0;

      procedure Init_Free_List is
      begin
         for I in reverse Conns'Range loop
            Free_List (Conn_Index (Free_Top)) := I;
            Free_Top := Free_Top + 1;
         end loop;
      end Init_Free_List;

      --  An accept outstanding on the listening socket.
      Accept_Pending : Boolean := False;

      --  Room for one more connection: a free entry and a free handshake
      --  slot (Configure takes a slot).
      function Has_Room return Boolean is
        (Free_Top > 0 and then SPARKTLS.Has_Free_Slot (Pool.all));

      ------------------------------------------------------------------------
      --  Requests on a connection
      ------------------------------------------------------------------------

      procedure Submit_Recv (Idx : Conn_Index) is
         Conn : Connection renames Conns (Idx);
      begin
         if Conn.Recv_Pending or else Conn.Shutting or else Conn.FD < 0 then
            return;
         end if;
         Prep_Recv (Next_SQE, Conn.FD, Conn.Recv_Buf'Address, Conn.Recv_Buf'Length,
                    Tag (Received, Idx));
         Conn.Recv_Pending := True;
         Conn.Pending := Conn.Pending + 1;
      end Submit_Recv;

      procedure Submit_Send (Idx : Conn_Index) is
         Conn : Connection renames Conns (Idx);
      begin
         Prep_Send (Next_SQE, Conn.FD, Conn.Out_Buf (Conn.Out_Sent)'Address,
                    Unsigned_32 (Conn.Out_Len - Conn.Out_Sent), Tag (Sent, Idx));
         Conn.Send_Pending := True;
         Conn.Pending := Conn.Pending + 1;
      end Submit_Send;

      --  Start closing: shut the socket down so any receive or send in
      --  flight completes. The entry is freed when the last one has.
      procedure Begin_Close (Idx : Conn_Index; Why : String := "") is
         Conn : Connection renames Conns (Idx);
      begin
         Conn.State := Closed;
         if Conn.Shutting or else Conn.FD < 0 then
            return;
         end if;
         Prep_Shutdown (Next_SQE, Conn.FD, SHUT_RDWR, Tag (Shut_Down, Idx));
         Conn.Shutting := True;
         Conn.Pending := Conn.Pending + 1;
         if Why /= "" then
            Log ("  closed: " & Why);
         end if;
      end Begin_Close;

      --  Nothing in flight any more: close the socket, Drop the session so
      --  its handshake slot goes back to the pool, and free the entry.
      procedure Finish_Close (Idx : Conn_Index) is
         Conn  : Connection renames Conns (Idx);
         Dummy : int;
      begin
         Dummy := C_Close (Conn.FD);
         Conn.FD := -1;
         Conn.Shutting := False;
         Conn.Body_Ref := null;
         Conn.Out_Len := 0;
         Conn.Out_Sent := 0;
         Conn.Close_Queued := False;
         SPARKTLS.Drop (Conn.S, Pool.all);
         Free_List (Conn_Index (Free_Top)) := Idx;
         Free_Top := Free_Top + 1;
      end Finish_Close;

      --  Close every connection that is past its deadline.
      procedure Sweep_Deadlines is
         Now : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
      begin
         for I in Conns'Range loop
            if Conns (I).FD >= 0 and then not Conns (I).Shutting then
               if Conns (I).State = Handshaking
                 and then Now - Conns (I).Opened_At > Handshake_Timeout
               then
                  Begin_Close (I, "handshake timeout");
               elsif Conns (I).State in Ready | Closing
                 and then Now - Conns (I).Last_Activity > Idle_Timeout
               then
                  Begin_Close (I, "idle timeout");
               end if;
            end if;
         end loop;
      end Sweep_Deadlines;

      --  Move output towards the socket: pending ciphertext first, then more
      --  from the session, then more plaintext from the response body, then
      --  close_notify. Returns with a send in flight (the rest continues when
      --  it completes) or with nothing left, in which case a finished
      --  response leaves the connection Closed for the caller to close.
      procedure Pump (Idx : Conn_Index) is
         Conn    : Connection renames Conns (Idx);
         Written : N32;
      begin
         if Conn.Send_Pending or else Conn.Shutting then
            return;
         end if;
         loop
            if Conn.Out_Sent < Conn.Out_Len then
               Submit_Send (Idx);
               return;
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
                  if Conn.State = Sending then
                     Conn.State := Closed;
                  end if;
                  return;
               end if;
            end if;
         end loop;
      end Pump;

      --  Run the session over the ciphertext it has been fed, as far as it
      --  will go without a send in flight.
      procedure Process (Idx : Conn_Index) is
         Conn : Connection renames Conns (Idx);
         Res  : SPARKTLS.Action;
      begin
         loop
            exit when Conn.State = Closed or else Conn.Send_Pending;
            SPARKTLS.Server.Advance (Conn.S, Pool.all, Res);

            case Res is
               when SPARKTLS.Has_Output =>
                  Pump (Idx);

               when SPARKTLS.Need_Input =>
                  exit;  --  wait for the next receive

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
                                          begin
                                             for I in Hdr_Str'Range loop
                                                Hdr_Bytes (N32 (I - Hdr_Str'First)) :=
                                                   SPARKNaCl.Byte
                                                     (Character'Pos (Hdr_Str (I)));
                                             end loop;

                                             --  Header (and the 404 body) into the session, then
                                             --  the body and close_notify by reference through
                                             --  Pump as the socket takes them.
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
                                             Pump (Idx);
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
                  --  it has been sent.
                  SPARKTLS.Server.Close_Notify (Conn.S);
                  Conn.Body_Ref := null;
                  Conn.Close_Queued := True;
                  Conn.State := Sending;
                  Pump (Idx);
                  exit;

               when SPARKTLS.Error_Alert =>
                  --  The library has queued the fatal alert: send it, then
                  --  close.
                  Log ("  TLS error: " &
                     SPARKTLS.Describe (SPARKTLS.Last_Error (Conn.S)));
                  Conn.Body_Ref := null;
                  Conn.Close_Queued := True;
                  Conn.State := Sending;
                  Pump (Idx);
                  exit;

               when others =>
                  null;
            end case;
         end loop;
      end Process;

      ------------------------------------------------------------------------
      --  Completions
      ------------------------------------------------------------------------

      procedure On_Accept (Res : Integer_32) is
         Dummy : int;
      begin
         Accept_Pending := False;
         if Res < 0 then
            return;
         end if;
         if not Has_Room then
            --  Cannot happen with one accept outstanding and no other taker
            --  of entries or slots, but never serve beyond capacity.
            Dummy := C_Close (int (Res));
            return;
         end if;
         Free_Top := Free_Top - 1;
         declare
            Idx  : constant Conn_Index := Free_List (Conn_Index (Free_Top));
            Conn : Connection renames Conns (Idx);
         begin
            Conn.Gen := Conn.Gen + 1;
            Conn.FD := int (Res);
            Conn.State := Handshaking;
            Conn.Req_Len := 0;
            Conn.Opened_At := Ada.Real_Time.Clock;
            Conn.Last_Activity := Ada.Real_Time.Clock;
            Conn.Body_Ref := null;
            Conn.Body_Off := 0;
            Conn.Out_Len := 0;
            Conn.Out_Sent := 0;
            Conn.Close_Queued := False;
            Conn.Recv_Pending := False;
            Conn.Send_Pending := False;
            Conn.Pending := 0;
            Conn.Shutting := False;
            Conn.S :=
              SPARKTLS.Server.Configure
                ((Local          => Id'Unchecked_Access,
                  Get_Active_TEK => SPARKTLS.Ticket_Keys.Get_Active_TEK'Access,
                  Get_TEK_By_Id  => SPARKTLS.Ticket_Keys.Get_TEK_By_Id'Access,
                  others         => <>),
                 Pool.all);
            Submit_Recv (Idx);
         end;
      end On_Accept;

      procedure On_Recv (Idx : Conn_Index; Res : Integer_32) is
         Conn : Connection renames Conns (Idx);
         Fed  : N32;
      begin
         Conn.Recv_Pending := False;
         if Conn.Shutting then
            return;
         end if;
         if Res <= 0 then
            Begin_Close (Idx);   --  peer closed, or an error
            return;
         end if;
         Conn.Last_Activity := Ada.Real_Time.Clock;
         SPARKTLS.Feed_Ciphertext (Conn.S, Conn.Recv_Buf (0 .. N32 (Res) - 1), Fed);
         Process (Idx);
         if Conn.State = Closed then
            if not Conn.Send_Pending then
               Begin_Close (Idx);
            end if;
         else
            Submit_Recv (Idx);
         end if;
      end On_Recv;

      procedure On_Send (Idx : Conn_Index; Res : Integer_32) is
         Conn : Connection renames Conns (Idx);
      begin
         Conn.Send_Pending := False;
         if Conn.Shutting then
            return;
         end if;
         if Res <= 0 then
            Begin_Close (Idx);   --  reset, EPIPE, ...
            return;
         end if;
         Conn.Out_Sent := Conn.Out_Sent + N32 (Res);
         Conn.Last_Activity := Ada.Real_Time.Clock;
         Pump (Idx);
         if not Conn.Send_Pending then
            --  Output drained: the session may have more input to work on.
            Process (Idx);
         end if;
         if Conn.State = Closed and then not Conn.Send_Pending then
            Begin_Close (Idx);
         end if;
      end On_Send;

      procedure On_Completion (C : CQE) is
         Idx   : Conn_Index;
         Valid : Boolean;
      begin
         case Kind_Of (C.User_Data) is
            when Accepted =>
               On_Accept (C.Res);
            when Tick =>
               Sweep_Deadlines;
            when Received | Sent | Shut_Down =>
               Target (C.User_Data, Idx, Valid);
               if not Valid then
                  return;
               end if;
               Conns (Idx).Pending := Conns (Idx).Pending - 1;
               case Kind_Of (C.User_Data) is
                  when Received => On_Recv (Idx, C.Res);
                  when Sent     => On_Send (Idx, C.Res);
                  when others   => null;
               end case;
               if Conns (Idx).Shutting and then Conns (Idx).Pending = 0 then
                  Finish_Close (Idx);
               end if;
            when None =>
               null;
         end case;
      end On_Completion;

      Ring_Entries : constant := 1024;
      Tick_Every   : aliased constant Kernel_Timespec :=
        (Sec => Integer_64 (Sweep_Interval_Ms / 1000), Nsec => 0);
      EINTR        : constant := 4;
      OK           : Boolean;
      Result       : Integer;
      C            : CQE;
      Found        : Boolean;
   begin
      Init_Free_List;
      Setup (R, Ring_Entries, IORING_SETUP_SINGLE_ISSUER or IORING_SETUP_COOP_TASKRUN, OK);
      if not OK then
         Log ("worker" & Num'Image & ": io_uring_setup failed (kernel without io_uring, or disabled)");
      else
         Prep_Periodic_Timeout (Next_SQE, Tick_Every'Access, Tag (Tick));
      end if;

      while Is_Set_Up (R) loop
         if not Accept_Pending and then Has_Room then
            Prep_Accept (Next_SQE, Listen_FD, Tag (Accepted));
            Accept_Pending := True;
         end if;
         --  Hand the kernel everything prepared and wait for a completion;
         --  -EINTR (a signal) is harmless, anything else ends the worker.
         Submit (R, 1, Result);
         if Result < 0 and then Result /= -EINTR then
            Log ("worker" & Num'Image & ": io_uring_enter failed," & Result'Image);
            exit;
         end if;
         loop
            Next_CQE (R, C, Found);
            exit when not Found;
            On_Completion (C);
         end loop;
      end loop;
      Close (R);
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
      Log ("Usage: tls_web_uring <cert.pem> <key.pem> [docroot]");
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
      Old_Handler : constant System.Address := C_Signal (SIGPIPE, SIG_IGN);
      pragma Unreferenced (Old_Handler);
   begin
      null;
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

   Log ("=== SPARKTLS Web Server (io_uring) ===");
   Log ("Docroot: " & Docroot (1 .. Doc_Len));
   Log ("Listening on 0.0.0.0:" & Port'Image);
   Log ("Workers:" & Workers'Image & ", each with" & Max_Connections'Image
        & " connections (" & Long_Long_Integer'Image (Conn_Bytes / 1_048_576) & " MB) and"
        & Handshake_Slots'Image & " handshake slots (" & Long_Long_Integer'Image (Pool_Bytes / 1_048_576)
        & " MB)");

   --  Start the workers. Their access type is declared in this procedure,
   --  so the procedure is their master and does not return while they run.
   for N in 1 .. Workers loop
      declare
         W : constant Worker_Access := new Worker (N);
         pragma Unreferenced (W);
      begin
         null;
      end;
   end loop;
   Log ("Ready. Waiting for connections...");
end TLS_Web_Uring;
