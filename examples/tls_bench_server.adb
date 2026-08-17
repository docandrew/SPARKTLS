--  Minimal TLS handshake benchmark server (epoll, no HTTP)
--
--  Matches OpenSSL s_server behavior: accepts connections, completes
--  the TLS handshake, then closes.  No application data, no file I/O.
--
--  Usage: ./tls_bench_server <cert.pem> <key.pem> [port]

with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;            use Interfaces;
with Interfaces.C;          use Interfaces.C;
with System;

with SPARKNaCl;             use SPARKNaCl;
with SPARKTLS;              use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;
with POSIX_Thin;            use POSIX_Thin;
with TLS_Echo_Pool;         use TLS_Echo_Pool;
with SPARKTLS.Session_Cache;

procedure TLS_Bench_Server is

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

   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Port    : Interfaces.C.unsigned_short := 8443;

   Raw_Buf : aliased Byte_Seq (0 .. 16383) := (others => 0);
   Snd_Buf : Byte_Seq (0 .. 16383);
   C_Buf   : aliased String (1 .. 16384);

   Epfd    : int;
   Sock_FD : int;
   Ev      : aliased Epoll_Event;
   Events  : aliased Epoll_Event_Array (0 .. 63) := (others => <>);
   Nfds    : int;
   Dummy   : int;

   function Find_By_FD (FD : int) return Integer is
   begin
      for I in Conn_Index loop
         if Conns (I).State /= Closed and then Conns (I).FD = FD then
            return Integer (I);
         end if;
      end loop;
      return -1;
   end Find_By_FD;

   function Find_Free return Integer is
   begin
      for I in Conn_Index loop
         if Conns (I).State = Closed then
            return Integer (I);
         end if;
      end loop;
      return -1;
   end Find_Free;

   procedure Close_Conn (Idx : Conn_Index) is
   begin
      --  Remove from epoll BEFORE closing FD to avoid stale-FD races
      Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_DEL, Conns (Idx).FD, null);
      Dummy := C_Close (Conns (Idx).FD);
      Conns (Idx).State := Closed;
   end Close_Conn;

   procedure Handle_Readable (Idx : Conn_Index) is
      Conn : Connection renames Conns (Idx);
      Rd   : long;
      Fed  : N32;
      Res  : SPARKTLS.Action;
   begin
      Rd := C_Read (Conn.FD, C_Buf'Address, C_Buf'Length);
      if Rd <= 0 then
         Close_Conn (Idx);
         return;
      end if;

      From_C_Buf (C_Buf'Address, Raw_Buf, Natural (Rd));
      SPARKTLS.Feed_Ciphertext (Conn.S, Raw_Buf (0 .. N32 (Rd) - 1), Fed);

      loop
         SPARKTLS.Server.Advance (Conn.S, Res);

         case Res is
            when SPARKTLS.Has_Output =>
               declare
                  N  : N32;
                  Wr : long;
               begin
                  SPARKTLS.Drain_Ciphertext (Conn.S, Snd_Buf, N);
                  if N > 0 then
                     To_C_Buf (Snd_Buf, C_Buf'Address, N);
                     Wr := C_Write (Conn.FD, C_Buf'Address, size_t (N));
                  end if;
               end;

            when SPARKTLS.Need_Input =>
               exit;

            when SPARKTLS.Handshake_Done =>
               Conn.State := Ready;

            when SPARKTLS.Plaintext_Ready =>
               --  Discard any app data; close on EOF from client
               declare
                  App   : Byte_Seq (0 .. 4095);
                  App_N : N32;
               begin
                  SPARKTLS.Read_Plaintext (Conn.S, App, App_N);
               end;

            when SPARKTLS.Shutdown =>
               Close_Conn (Idx);
               return;

            when SPARKTLS.Error_Alert =>
               Close_Conn (Idx);
               return;

            when others =>
               null;  --  OK: keep looping
         end case;
      end loop;
   end Handle_Readable;

   One  : aliased int := 1;
   Addr : aliased Sockaddr_In;

begin
   Entropy_Random.Init;

   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_bench_server <cert> <key> [port]");
      return;
   end if;

   if Ada.Command_Line.Argument_Count >= 3 then
      Port := Interfaces.C.unsigned_short'Value (Ada.Command_Line.Argument (3));
   end if;

   SPARKTLS.Credentials.Load_Identity
     (Id, Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2), Id_OK);
   if not Id_OK then
      Put_Line ("Failed to load certificate/key");
      return;
   end if;

   --  Seed ticket storage. No clock is wired here, so rotation stays off --
   --  fine for a short-lived benchmark process; a long-running server should
   --  pass Clock so keys rotate.
   SPARKTLS.Session_Cache.Initialize
     (Random => Entropy_Random.Random'Access,
      Clock  => null);

   Put_Line ("=== SPARKTLS Bench Server ===");
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   Sock_FD := C_Socket (AF_INET, SOCK_STREAM + SOCK_NONBLOCK, 0);
   if Sock_FD < 0 then
      Put_Line ("socket() failed");
      return;
   end if;

   Dummy := C_Setsockopt (Sock_FD, SOL_SOCKET, SO_REUSEADDR,
                           One'Access, 4);

   Addr.Sin_Port := Htons (Port);
   Addr.Sin_Addr := 0;

   if C_Bind (Sock_FD, Addr'Access, Sockaddr_In'Size / 8) < 0 then
      Put_Line ("bind() failed");
      return;
   end if;

   if C_Listen (Sock_FD, 128) < 0 then
      Put_Line ("listen() failed");
      return;
   end if;

   Epfd := Epoll_Create1 (0);
   Ev.Events := unsigned (EPOLLIN);
   Ev.Data.FD := Sock_FD;
   Dummy := Epoll_Ctl (Epfd, EPOLL_CTL_ADD, Sock_FD, Ev'Access);

   Put_Line ("Ready.");

   loop
      Nfds := Epoll_Wait (Epfd,
                           Events (Events'First)'Unrestricted_Access,
                           64, -1);
      if Nfds < 0 then exit; end if;

      for I in 0 .. Natural (Nfds) - 1 loop
         if Events (I).Data.FD = Sock_FD then
            declare
               Client_FD   : int;
               Addr_Len    : aliased int := Sockaddr_In'Size / 8;
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
               end if;
            end;
         end if;
      end loop;
   end loop;
end TLS_Bench_Server;
