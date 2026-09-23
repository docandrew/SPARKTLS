--  TLS Static File Server using epoll (async I/O)
--
--  A real, working HTTPS server built on SPARKTLS that serves static
--  files from a directory.  Uses Linux epoll with non-blocking sockets
--  for async I/O — the same pattern used by nginx, Caddy, etc.
--
--  Usage:
--    ./tls_static_server <cert.pem> <key.pem> [docroot]
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

with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
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
with TLS_Echo_Pool;         use TLS_Echo_Pool;
with SPARKTLS.Ticket_Keys;

procedure TLS_Web_Epoll is

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

   subtype Cached_Body_Access is TLS_Echo_Pool.Body_Access;
   procedure Free_Cached_Body is new
     Ada.Unchecked_Deallocation (Byte_Seq, TLS_Echo_Pool.Body_Access);

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

   --  Configuration
   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Docroot : String (1 .. 256) := (others => ' ');
   Doc_Len : Natural := 0;
   --  SPARKTLS_PORT overrides the default, as in tls_blocking_server, so
   --  the integration runner can rotate ports.
   function Get_Port return Natural is
   begin
      if Ada.Environment_Variables.Exists ("SPARKTLS_PORT") then
         return Natural'Value (Ada.Environment_Variables.Value ("SPARKTLS_PORT"));
      end if;
      return 8443;
   end Get_Port;
   Port    : constant Natural := Get_Port;

   --  Single-slot file cache: avoids re-reading the same file from
   --  disk (and re-allocating its Byte_Seq) on every request. The
   --  bench drives one path repeatedly, so this turns N reads into 1.
   --  Its OWN access type over an UNCONSTRAINED Byte_Seq. This used to
   --  borrow SPARKTLS.Byte_Seq_Access "already visible via the use clause";
   --  that type became `access Reasm_Buffer` (fixed 0 .. Max_HS_Msg - 1)
   --  when the reassembly buffer was constrained, which left this code
   --  compiling but allocating a constrained subtype from an unconstrained
   --  value -- a latent Constraint_Error for any body not exactly 128 KB.
   --  An example must not share a type with the library's internals.

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
         if Cache_Body /= null then
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

   --  Session ticket cache (shared across connections)

   --  Per-connection state, Conns array, etc. live at library level
   --  in TLS_Echo_Pool (BSS, not main stack).

   --  Find the connection slot matching FD, or -1 if none.
   function Find_By_FD (FD : int) return Integer is
   begin
      for I in Conn_Index loop
         if Conns (I).State /= Closed and then Conns (I).FD = FD then
            return Integer (I);
         end if;
      end loop;
      return -1;
   end Find_By_FD;

   --  Find a free slot, or -1 if full.
   function Find_Free return Integer is
   begin
      for I in Conn_Index loop
         if Conns (I).State = Closed then
            return Integer (I);
         end if;
      end loop;
      return -1;
   end Find_Free;

   --  Network buffers — passed directly to read(2) / write(2) via
   --  Buf'Address. No intermediate `aliased String C_Buf` layer
   --  any more (was costing two ~16 KB byte-shuffles per record).
   Raw_Buf : aliased Byte_Seq (0 .. 16383) := (others => 0);
   Snd_Buf : aliased Byte_Seq (0 .. 16383) := (others => 0);

   --  epoll state
   Epfd     : int;
   Sock_FD  : int;
   Ev       : aliased Epoll_Event;
   Events   : aliased Epoll_Event_Array (0 .. 63) := (others => <>);

   --  Deadlines. The library is sans-I/O: it learns nothing about a
   --  connection until bytes arrive, so a peer that connects and goes
   --  silent (or stalls part-way through its ClientHello) holds a
   --  connection slot and a SPARKTLS.HS_Pool slot until the APPLICATION
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
      end if;
      Conn.State := Closed;
      Conn.Body_Ref := null;
      Conn.Out_Len := 0;
      Conn.Out_Sent := 0;
      Conn.Close_Queued := False;
      Conn.Want_Out := False;
      SPARKTLS.Drop (Conn.S);
      if Why /= "" then
         Put_Line ("  closed: " & Why);
      end if;
   end Close_Conn;

   --  Close every connection that is past its deadline.
   procedure Sweep_Deadlines is
      Now : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
   begin
      for I in Conn_Index loop
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

   --  Arm or disarm EPOLLOUT for a connection.
   procedure Arm_Output (Idx : Conn_Index; On : Boolean) is
      Conn  : Connection renames Conns (Idx);
      Ev    : aliased Epoll_Event;
      Dummy : int;
   begin
      if Conn.Want_Out = On or else Conn.FD < 0 then
         return;
      end if;
      Ev.Events  := unsigned (EPOLLIN) or (if On then unsigned (EPOLLOUT) else 0);
      Ev.Data.FD := Conn.FD;
      Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_MOD, Conn.FD, Ev'Access);
      Conn.Want_Out := On;
   end Arm_Output;

   EAGAIN : constant := 11;

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
               SPARKTLS.Write_Plaintext
                 (Conn.S,
                  Conn.Body_Ref (Conn.Body_Ref'First + Conn.Body_Off .. Conn.Body_Ref'Last),
                  Written);
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
         SPARKTLS.Server.Advance (Conn.S, Res);

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
                                    Put_Line ("  GET " & Printable (Path));

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
                                             SPARKTLS.Write_Plaintext
                                               (Conn.S,
                                                Hdr_Bytes (Total_Sent .. Hdr_Bytes'Last),
                                                Written);
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
               Put_Line ("  TLS error: " &
                  SPARKTLS.Describe (SPARKTLS.Last_Error (Conn.S)));
               Conn.State := Closed;
               exit;

            when others =>
               null;
         end case;
      end loop;
   end Handle_Readable;

   One   : aliased int := 1;
   Addr  : aliased Sockaddr_In;
   Nfds  : int;
   Dummy : int;

begin
   Entropy_Random.Init;
   --  Seed the stateless-ticket (RFC 5077) TEK ring so resumption works.
   SPARKTLS.Ticket_Keys.Initialize
     (Clock => null);

   --  Parse arguments
   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_web_epoll <cert.pem> <key.pem> [docroot]");
      return;
   end if;

   Credentials.Load_Identity
     (Id,
      Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2),
      Id_OK);
   if not Id_OK then
      Put_Line ("Failed to load identity");
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

   Put_Line ("=== SPARKTLS Web Server (epoll) ===");
   Put_Line ("Docroot: " & Docroot (1 .. Doc_Len));
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   --  Create listening socket
   Sock_FD := C_Socket (AF_INET, SOCK_STREAM + SOCK_NONBLOCK, 0);
   if Sock_FD < 0 then
      Put_Line ("socket() failed");
      return;
   end if;

   Dummy := C_Setsockopt (Sock_FD, SOL_SOCKET, SO_REUSEADDR,
                           One'Access, 4);

   Addr.Sin_Port := Htons (unsigned_short (Port));
   Addr.Sin_Addr := 0;  --  INADDR_ANY

   if C_Bind (Sock_FD, Addr'Access, Sockaddr_In'Size / 8) < 0 then
      Put_Line ("bind() failed");
      return;
   end if;

   if C_Listen (Sock_FD, 128) < 0 then
      Put_Line ("listen() failed");
      return;
   end if;

   --  Create epoll
   --  A peer that closes before we finish writing must not kill the
   --  process (write(2) raises SIGPIPE; GNAT.Sockets is not used here).
   declare
      Old_Handler : System.Address;
   begin
      Old_Handler := C_Signal (SIGPIPE, SIG_IGN);
   end;
   Epfd := Epoll_Create1 (0);
   if Epfd < 0 then
      Put_Line ("epoll_create1() failed");
      return;
   end if;

   --  Add listener to epoll
   Ev.Events := unsigned (EPOLLIN);
   Ev.Data.FD := Sock_FD;
   Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_ADD, Sock_FD, Ev'Access);

   Put_Line ("Ready. Waiting for connections...");

   --  Event loop
   loop
      Nfds := Epoll_Wait (Epfd, Events (Events'First)'Unrestricted_Access, 64, Sweep_Interval_Ms);
      if Nfds < 0 then
         Put_Line ("epoll_wait error");
         exit;
      end if;

      for I in 0 .. Natural (Nfds) - 1 loop
         if Events (I).Data.FD = Sock_FD then
            --  New connection
            declare
               Client_FD : int;
               Addr_Len  : aliased int := Sockaddr_In'Size / 8;
               Client_Addr : aliased Sockaddr_In;
            begin
               Client_FD := C_Accept4 (Sock_FD, Client_Addr'Access,
                                        Addr_Len'Access, SOCK_NONBLOCK);
               if Client_FD >= 0 then
                  declare
                     Slot : constant Integer := Find_Free;
                  begin
                     if Slot < 0 then
                        Dummy := C_Close (Client_FD);
                     else
                        Conns (Conn_Index (Slot)).FD := Client_FD;
                        Conns (Conn_Index (Slot)).State := Handshaking;
                        Conns (Conn_Index (Slot)).Req_Len := 0;
                        Conns (Conn_Index (Slot)).Opened_At := Ada.Real_Time.Clock;
                        Conns (Conn_Index (Slot)).Last_Activity := Ada.Real_Time.Clock;
                        --  A reused slot must not carry the previous
                        --  connection's unsent bytes or body reference.
                        Conns (Conn_Index (Slot)).Body_Ref := null;
                        Conns (Conn_Index (Slot)).Body_Off := 0;
                        Conns (Conn_Index (Slot)).Out_Len := 0;
                        Conns (Conn_Index (Slot)).Out_Sent := 0;
                        Conns (Conn_Index (Slot)).Close_Queued := False;
                        Conns (Conn_Index (Slot)).Want_Out := False;
                        Conns (Conn_Index (Slot)).S :=
                          SPARKTLS.Server.Configure
                            ((Local   => Id'Unchecked_Access,
                              Get_Active_TEK =>
                                SPARKTLS.Ticket_Keys.Get_Active_TEK'Access,
                              Get_TEK_By_Id  =>
                                SPARKTLS.Ticket_Keys.Get_TEK_By_Id'Access,
                              others  => <>));

                        Ev.Events := unsigned (EPOLLIN);
                        Ev.Data.FD := Client_FD;
                        Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_ADD,
                                             Client_FD, Ev'Access);
                     end if;
                  end;
               end if;
            end;

         else
            declare
               Hit : constant Integer := Find_By_FD (Events (I).Data.FD);
            begin
               if Hit >= 0 then
                  declare
                     Idx : constant Conn_Index := Conn_Index (Hit);
                     Ev  : constant unsigned := Events (I).Events;
                  begin
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
               end if;
            end;
         end if;
      end loop;

      --  Runs after every wake-up, including the idle ones epoll_wait's
      --  timeout produces, so a silent peer cannot hold a slot for long.
      Sweep_Deadlines;
   end loop;

end TLS_Web_Epoll;
