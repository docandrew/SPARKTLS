--  Simple blocking TLS 1.3 server for protocol compliance testing.
--  Handles one connection at a time, sequentially. No epoll, no async.
--  Perfect for tlsfuzzer and protocol testing tools.
--
--  Usage: tls_blocking_server <cert.pem> <key.pem>

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Blocking_Server is

   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Tickets : aliased SPARKTLS.Ticket_Store;
   Roots   : aliased SPARKTLS.Trust_Store;
   MTLS    : Boolean := False;
   MTLS_Require : Boolean := False;

   Server_Sock : Socket_Type;
   Port        : constant := 8443;

   procedure Handle_Connection (Client_Sock : Socket_Type) is
      S         : SPARKTLS.Session;
      Res       : SPARKTLS.Action;
      Read_Dead : Boolean := False;

      Net_In  : Byte_Seq (0 .. 16383);
      Net_Out : Byte_Seq (0 .. 16383);

      procedure Send_Output is
         N : N32;
         Last : Stream_Element_Offset;
      begin
         loop
            Drain_Ciphertext (S, Net_Out, N);
            exit when N = 0;
            declare
               SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
            begin
               for I in SE'Range loop
                  SE (I) := Stream_Element (Net_Out (N32 (I - 1)));
               end loop;
               GNAT.Sockets.Send_Socket (Client_Sock, SE, Last);
            end;
         end loop;
      end Send_Output;

      procedure Read_Input is
         SE   : Stream_Element_Array (1 .. 16384);
         Last : Stream_Element_Offset;
         Fed  : N32;
      begin
         GNAT.Sockets.Receive_Socket (Client_Sock, SE, Last);
         if Last >= SE'First then
            null;
            for I in SE'First .. Last loop
               Net_In (N32 (I - 1)) := Byte (SE (I));
            end loop;
            Feed_Ciphertext (S, Net_In (0 .. N32 (Last) - 1), Fed);
         else
            Read_Dead := True;
         end if;
      exception
         when others => Read_Dead := True;
      end Read_Input;

   begin
      Set_Socket_Option
        (Client_Sock, Socket_Level,
         (Name => Receive_Timeout, Timeout => 30.0));
      Set_Socket_Option
        (Client_Sock, IP_Protocol_For_TCP_Level,
         (Name => No_Delay, Enabled => True));

      Server.Configure
        (S                   => S,
         Local               => Id'Unchecked_Access,
         Random              => Entropy_Random.Random'Access,
         Trust               => (if MTLS then Roots'Unchecked_Access
                                 else null),
         Request_Client_Cert => MTLS,
         Require_Client_Cert => MTLS_Require,
         Tickets             => Tickets'Unchecked_Access);

      --  Handshake + data loop
      loop
         Server.Advance (S, Res);

         case Res is
            when Has_Output =>
               Send_Output;

            when Need_Input =>
               if Read_Dead then exit; end if;
               Read_Input;
               if Read_Dead then exit; end if;

            when Handshake_Done =>
               null;  --  Handshake complete, continue processing

            when Plaintext_Ready =>
               --  Read decrypted data, echo it back verbatim
               declare
                  App   : Byte_Seq (0 .. 16383);
                  App_N : N32;
               begin
                  Read_Plaintext (S, App, App_N);
                  if App_N > 0 then
                     declare
                        Written : N32;
                     begin
                        Server.Write_Plaintext
                          (S, App (0 .. App_N - 1), Written);
                        Send_Output;
                     end;
                  end if;
               end;

            when Error_Alert =>
               --  Alert already sent (drained via Has_Output).
               --  Graceful TCP shutdown: close write side, then
               --  wait for the peer to read our alert and close.
               begin
                  Shutdown_Socket (Client_Sock, Shut_Write);
               exception
                  when others => null;
               end;
               --  Read until peer closes or timeout
               declare
                  Dummy : Stream_Element_Array (1 .. 1024);
                  Last  : Stream_Element_Offset;
               begin
                  loop
                     Receive_Socket (Client_Sock, Dummy, Last);
                     exit when Last < Dummy'First;
                  end loop;
               exception
                  when others => null;
               end;
               exit;

            when Shutdown =>
               Server.Close_Notify (S);
               Send_Output;
               begin
                  Shutdown_Socket (Client_Sock, Shut_Write);
               exception
                  when others => null;
               end;
               exit;

            when others =>
               null;
         end case;
      end loop;

   exception
      when E : others =>
         Put_Line ("  Connection error: " &
                   Ada.Exceptions.Exception_Message (E));
   end Handle_Connection;

begin
   Entropy_Random.Init;

   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_blocking_server <cert.pem> <key.pem>" &
                " [--mtls <ca.pem>]");
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

   --  Check for --mtls / --mtls-require flag
   if Ada.Command_Line.Argument_Count >= 4
      and then (Ada.Command_Line.Argument (3) = "--mtls"
                or else Ada.Command_Line.Argument (3) = "--mtls-require")
   then
      declare
         Roots_OK : Boolean;
      begin
         Credentials.Load_Trust_Store
           (Roots, Ada.Command_Line.Argument (4), Roots_OK);
         if Roots_OK then
            MTLS := True;
            MTLS_Require :=
              Ada.Command_Line.Argument (3) = "--mtls-require";
            Put_Line ("mTLS enabled (trust: " &
                      Ada.Command_Line.Argument (4)
                      & (if MTLS_Require then ", REQUIRED)" else ")"));
         else
            Put_Line ("Warning: failed to load trust store, mTLS disabled");
         end if;
      end;
   end if;

   Put_Line ("=== SPARKTLS Blocking Server ===");
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   Initialize;
   Create_Socket (Server_Sock);
   Set_Socket_Option (Server_Sock, Socket_Level,
                      (Name => Reuse_Address, Enabled => True));
   Bind_Socket (Server_Sock,
                (Family => Family_Inet,
                 Addr   => Any_Inet_Addr,
                 Port   => Port));
   Listen_Socket (Server_Sock, 5);

   Put_Line ("Ready.");

   --  Accept connections forever
   loop
      declare
         Client_Sock : Socket_Type;
         Client_Addr : Sock_Addr_Type;
      begin
         Accept_Socket (Server_Sock, Client_Sock, Client_Addr);
         Handle_Connection (Client_Sock);
         begin
            Shutdown_Socket (Client_Sock, Shut_Read_Write);
         exception
            when others => null;
         end;
         Close_Socket (Client_Sock);
      exception
         when E : others =>
            Put_Line ("Error: " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
end TLS_Blocking_Server;
