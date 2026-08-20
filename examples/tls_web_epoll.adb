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
with SPARKTLS.Session_Cache;

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

   --  Read a file into a Byte_Seq (for serving static content)
   function Read_File (Path : String) return Byte_Seq is
      package SIO renames Ada.Streams.Stream_IO;
      F    : SIO.File_Type;
      Size : Natural;
   begin
      if not Ada.Directories.Exists (Path) then
         return Byte_Seq'(0 => 0);
      end if;
      SIO.Open (F, SIO.In_File, Path);
      Size := Natural (SIO.Size (F));
      if Size = 0 or Size > 268435456 then  --  256 MB max (bench-friendly)
         SIO.Close (F);
         return Byte_Seq'(0 => 0);
      end if;
      declare
         B   : Stream_Element_Array (1 .. Stream_Element_Offset (Size));
         Last : Stream_Element_Offset;
         Res : Byte_Seq (0 .. N32 (Size) - 1);
      begin
         SIO.Read (F, B, Last);
         SIO.Close (F);
         for I in B'Range loop
            Res (N32 (I - 1)) := SPARKNaCl.Byte (B (I));
         end loop;
         return Res;
      end;
   exception
      when others => return Byte_Seq'(0 => 0);
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
   Port    : constant := 8443;

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
   type Cached_Body_Access is access Byte_Seq;
   procedure Free_Cached_Body is new
     Ada.Unchecked_Deallocation (Byte_Seq, Cached_Body_Access);

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
         Loaded : constant Byte_Seq := Read_File (Full);
      begin
         if Loaded'Length <= 1 then
            return null;
         end if;
         if Cache_Body /= null then
            Free_Cached_Body (Cache_Body);
         end if;
         Cache_Body := new Byte_Seq'(Loaded);
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

   procedure Handle_Readable (Idx : Conn_Index) is
      Conn : Connection renames Conns (Idx);
      Rd : long;
      Fed : N32;
      Res : SPARKTLS.Action;
   begin
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
               declare
                  N : N32;
                  Wr : long;
               begin
                  SPARKTLS.Drain_Ciphertext (Conn.S, Snd_Buf, N);
                  if N > 0 then
                     Wr := C_Write (Conn.FD, Snd_Buf'Address, size_t (N));
                  end if;
               end;

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
                                    Put_Line ("  GET " & Path);

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
                                       Body_Ref : Cached_Body_Access :=
                                          Get_Cached (Full);
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

                                       --  Send header (and 404 inline body if applicable).
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
                                             loop
                                                declare
                                                   Snd_N : N32;
                                                begin
                                                   SPARKTLS.Drain_Ciphertext
                                                     (Conn.S, Snd_Buf, Snd_N);
                                                   exit when Snd_N = 0;
                                                   Wr := C_Write
                                                     (Conn.FD,
                                                      Snd_Buf'Address,
                                                      size_t (Snd_N));
                                                end;
                                             end loop;
                                          end loop;
                                       end;

                                       --  Send body by reference (no per-request copy).
                                       if Body_Ref /= null then
                                          declare
                                             Total_Sent : N32 := 0;
                                             B_Last     : constant N32 := Body_Ref'Last;
                                             B_First    : constant N32 := Body_Ref'First;
                                             B_Len      : constant N32 :=
                                                N32 (Body_Ref'Length);
                                          begin
                                             while Total_Sent < B_Len loop
                                                SPARKTLS.Write_Plaintext
                                                  (Conn.S,
                                                   Body_Ref
                                                     (B_First + Total_Sent .. B_Last),
                                                   Written);
                                                exit when Written = 0;
                                                Total_Sent := Total_Sent + Written;
                                                loop
                                                   declare
                                                      Snd_N : N32;
                                                   begin
                                                      SPARKTLS.Drain_Ciphertext
                                                        (Conn.S, Snd_Buf, Snd_N);
                                                      exit when Snd_N = 0;
                                                      Wr := C_Write
                                                        (Conn.FD,
                                                         Snd_Buf'Address,
                                                         size_t (Snd_N));
                                                   end;
                                                end loop;
                                             end loop;
                                          end;
                                       end if;
                                       --  Send close_notify (Connection: close)
                                       SPARKTLS.Server.Close_Notify (Conn.S);
                                       loop
                                          declare
                                             Snd_N : N32;
                                          begin
                                             SPARKTLS.Drain_Ciphertext
                                               (Conn.S, Snd_Buf, Snd_N);
                                             exit when Snd_N = 0;
                                             Wr := C_Write
                                               (Conn.FD, Snd_Buf'Address,
                                                size_t (Snd_N));
                                          end;
                                       end loop;
                                       Conn.State := Closed;
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

            when SPARKTLS.Shutdown =>
               --  Send our close_notify back
               SPARKTLS.Server.Close_Notify (Conn.S);
               declare
                  Snd_N : N32;
                  Wr    : long;
               begin
                  SPARKTLS.Drain_Ciphertext (Conn.S, Snd_Buf, Snd_N);
                  if Snd_N > 0 then
                     Wr := C_Write (Conn.FD, Snd_Buf'Address, size_t (Snd_N));
                  end if;
               end;
               Conn.State := Closed;
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

   Addr.Sin_Port := Htons (Port);
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
      Nfds := Epoll_Wait (Epfd, Events (Events'First)'Unrestricted_Access, 64, -1);
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
                        SPARKTLS.Server.Configure
                          (S       => Conns (Conn_Index (Slot)).S,
                           Local   => Id'Unchecked_Access,
                           Random  => Entropy_Random.Random'Access,
                           Store_Session  =>
                             SPARKTLS.Session_Cache.Store_Session'Access,
                           Lookup_Session =>
                             SPARKTLS.Session_Cache.Lookup_Session'Access);

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
                  Handle_Readable (Conn_Index (Hit));
                  if Conns (Conn_Index (Hit)).State = Closed then
                     Dummy := Epoll_Ctl
                       (Epfd, EPOLL_CTL_DEL,
                        Conns (Conn_Index (Hit)).FD, null);
                     Dummy := C_Close (Conns (Conn_Index (Hit)).FD);
                     Conns (Conn_Index (Hit)).FD := -1;
                  end if;
               end if;
            end;
         end if;
      end loop;
   end loop;

end TLS_Web_Epoll;
