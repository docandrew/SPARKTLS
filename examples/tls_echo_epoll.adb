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
with Ada.Calendar;
with Ada.Numerics.Discrete_Random;
with Interfaces;            use Interfaces;
with Interfaces.C;          use Interfaces.C;
with System;

with SPARKNaCl;             use SPARKNaCl;
with X509;
with SPARKTLS;              use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with POSIX_Thin;            use POSIX_Thin;
with TLS_Echo_Pool;         use TLS_Echo_Pool;

procedure TLS_Echo_Epoll is

   package Random_Byte is new
      Ada.Numerics.Discrete_Random (SPARKNaCl.Byte);
   Gen : Random_Byte.Generator;

   procedure My_Random (Output : out Byte_Seq) is
   begin
      for I in Output'Range loop
         Output (I) := Random_Byte.Random (Gen);
      end loop;
   end My_Random;

   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      Secs : Day_Duration;
   begin
      Split (Now, Y, Mo, D, Secs);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Natural (Secs) / 3600,
              Minute => (Natural (Secs) mod 3600) / 60,
              Second => Natural (Secs) mod 60);
   end Current_Time;

   --  Convert SPARKNaCl.Byte_Seq to/from C buffer
   procedure To_C_Buf (Src : Byte_Seq; Dst : System.Address; Len : N32) is
      type C_Bytes is array (0 .. Natural (Len) - 1) of Unsigned_8;
      Buf : C_Bytes;
      for Buf'Address use Dst;
   begin
      for I in 0 .. N32 (Len) - 1 loop
         Buf (Natural (I)) := Unsigned_8 (Src (I));
      end loop;
   end To_C_Buf;

   procedure From_C_Buf (Src : System.Address; Dst : out Byte_Seq;
                         Len : Natural) is
      type C_Bytes is array (0 .. Len - 1) of Unsigned_8;
      Buf : C_Bytes;
      for Buf'Address use Src;
   begin
      for I in 0 .. Len - 1 loop
         Dst (N32 (I)) := SPARKNaCl.Byte (Buf (I));
      end loop;
   end From_C_Buf;

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
      if Size = 0 or Size > 1048576 then  --  1MB max
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

   --  Network buffers
   Raw_Buf : aliased Byte_Seq (0 .. 16383) := (others => 0);
   Snd_Buf : Byte_Seq (0 .. 16383);
   C_Buf   : aliased String (1 .. 16384);

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
      Put_Line ("  [Handle_Readable fd=" & Conn.FD'Image & " slot="
                & Idx'Image & "]");
      --  Read from socket
      Rd := C_Read (Conn.FD, C_Buf'Address, C_Buf'Length);
      Put_Line ("    read -> " & Rd'Image);
      if Rd <= 0 then
         Put_Line ("  Connection closed by peer");
         Conn.State := Closed;
         return;
      end if;

      --  Convert and feed to TLS
      From_C_Buf (C_Buf'Address, Raw_Buf, Natural (Rd));
      SPARKTLS.Feed_Ciphertext (Conn.S, Raw_Buf (0 .. N32 (Rd) - 1), Fed);
      Put_Line ("    fed " & Fed'Image & " / " & Rd'Image);

      --  Process TLS state machine
      loop
         SPARKTLS.Server.Advance (Conn.S, Res);
         Put_Line ("    advance -> " & Res'Image);

         case Res is
            when SPARKTLS.Has_Output =>
               declare
                  N : N32;
                  Wr : long;
               begin
                  SPARKTLS.Drain_Ciphertext (Conn.S, Snd_Buf, N);
                  Put_Line ("      drained " & N'Image & " bytes");
                  if N > 0 then
                     To_C_Buf (Snd_Buf, C_Buf'Address, N);
                     Put_Line ("      pre-write Conn.FD=" & Conn.FD'Image);
                     Wr := C_Write (Conn.FD, C_Buf'Address, size_t (N));
                     Put_Line ("      wrote   " & Wr'Image
                               & (if Wr < 0
                                  then "  errno=" & Errno_Location.all'Image
                                  else ""));
                  end if;
               end;

            when SPARKTLS.Need_Input =>
               exit;  --  wait for more data from epoll

            when SPARKTLS.Handshake_Done =>
               Put_Line ("  TLS handshake complete");
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
                                       Content : constant Byte_Seq :=
                                          Read_File (Full);
                                       Resp : Byte_Seq :=
                                          (if Content'Length <= 1
                                           then HTTP_404
                                           else HTTP_Response
                                                  ("200 OK",
                                                   Content_Type (Path),
                                                   Content));
                                       Written : N32;
                                       Wr : long;
                                    begin
                                       SPARKTLS.Server.Write_Plaintext
                                         (Conn.S, Resp, Written);
                                       --  Drain encrypted output
                                       loop
                                          declare
                                             Snd_N : N32;
                                          begin
                                             SPARKTLS.Drain_Ciphertext
                                               (Conn.S, Snd_Buf, Snd_N);
                                             exit when Snd_N = 0;
                                             To_C_Buf
                                               (Snd_Buf, C_Buf'Address, Snd_N);
                                             Wr := C_Write
                                               (Conn.FD, C_Buf'Address,
                                                size_t (Snd_N));
                                          end;
                                       end loop;
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

            when SPARKTLS.Error_Alert =>
               Put_Line ("  TLS error: " &
                  Conn.S.Last_Error'Image);
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
   Random_Byte.Reset (Gen);

   --  Parse arguments
   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_echo_epoll <cert.pem> <key.pem> [docroot]");
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

   Put_Line ("Epoll_Event'Size      =" & Integer'Image (Epoll_Event'Size / 8)
             & " bytes (expect 12)");
   Put_Line ("Array component size  ="
             & Integer'Image (Epoll_Event_Array'Component_Size / 8)
             & " bytes (expect 12)");
   Put_Line ("=== SPARKTLS Static File Server (epoll) ===");
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

      Put_Line ("[epoll_wait: nfds=" & Nfds'Image & "]");
      for I in 0 .. Natural (Nfds) - 1 loop
         Put_Line ("  [event" & I'Image & " fd=" & Events (I).Data.FD'Image
                   & " events=0x" & Events (I).Events'Image & "]");
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
                        Put_Line ("  No free slots — dropping connection");
                        Dummy := C_Close (Client_FD);
                     else
                        Put_Line ("New connection (fd=" & Client_FD'Image
                                  & ", slot=" & Slot'Image & ")");
                        Conns (Conn_Index (Slot)).FD := Client_FD;
                        Conns (Conn_Index (Slot)).State := Handshaking;
                        Conns (Conn_Index (Slot)).Req_Len := 0;
                        SPARKTLS.Server.Configure
                          (S      => Conns (Conn_Index (Slot)).S,
                           Local  => Id'Unchecked_Access,
                           Random => My_Random'Unrestricted_Access);

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
                     Put_Line ("Connection closed (slot=" & Hit'Image & ")");
                     Conns (Conn_Index (Hit)).FD := -1;
                  end if;
               end if;
            end;
         end if;
      end loop;
   end loop;

end TLS_Echo_Epoll;
