--  Test server using the SPARKTLS library API.
--  Listens on 0.0.0.0:8443 for a single TLS 1.3 client connection,
--  echoes data back, then exits.
--
--  Usage:
--    ./tls_test_server cert.pem key.pem
--
--  Or generate a cert with our CLI:
--    sparktls devcert localhost to key.pem cert.pem

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

procedure TLS_Test_Server is

   --  Identity (loaded from cert + key files)
   Id    : aliased SPARKTLS.Identity;
   Id_OK : Boolean;

   --  Session
   S   : SPARKTLS.Session;
   Res : SPARKTLS.Action;

   --  Network I/O buffers
   Net_Buf : Byte_Seq (0 .. 16383);
   N       : N32;

   --  Socket
   Server_Sock : GNAT.Sockets.Socket_Type;
   Client_Sock : GNAT.Sockets.Socket_Type;
   Client_Addr : GNAT.Sockets.Sock_Addr_Type;
   Channel     : Stream_Access;

begin
   Entropy_Random.Init;

   --  Check command line args
   if Ada.Command_Line.Argument_Count /= 2 then
      Put_Line ("Usage: tls_test_server <cert.pem> <key.pem>");
      return;
   end if;

   --  Load identity from cert + key PEM files
   Credentials.Load_Identity
     (Id,
      Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2),
      Id_OK);
   if not Id_OK then
      Put_Line ("Failed to load identity");
      return;
   end if;
   Put_Line ("Identity: loaded (" & Id.Sign_Algo'Image & ")");

   Put_Line ("=== SPARKTLS Test Server ===");
   Put_Line ("Listening on 0.0.0.0:8443...");

   --  Create listening socket
   GNAT.Sockets.Initialize;
   GNAT.Sockets.Create_Socket (Socket => Server_Sock);
   GNAT.Sockets.Set_Socket_Option
     (Socket => Server_Sock,
      Level  => GNAT.Sockets.Socket_Level,
      Option => (Name    => Reuse_Address,
                 Enabled => True));
   GNAT.Sockets.Bind_Socket
     (Socket  => Server_Sock,
      Address => (Family => GNAT.Sockets.Family_Inet,
                  Addr   => GNAT.Sockets.Any_Inet_Addr,
                  Port   => 8443));
   GNAT.Sockets.Listen_Socket (Socket => Server_Sock, Length => 1);

   --  Accept one connection
   Put_Line ("Waiting for connection...");
   GNAT.Sockets.Accept_Socket
     (Server  => Server_Sock,
      Socket  => Client_Sock,
      Address => Client_Addr);

   GNAT.Sockets.Set_Socket_Option
     (Socket => Client_Sock,
      Level  => GNAT.Sockets.Socket_Level,
      Option => (Name    => GNAT.Sockets.Receive_Timeout,
                 Timeout => 30.0));

   Channel := GNAT.Sockets.Stream (Client_Sock);
   Put_Line ("Client connected from " &
      GNAT.Sockets.Image (Client_Addr));

   --  Initialize TLS server session
   SPARKTLS.Server.Configure
     (S      => S,
      Local  => Id'Unchecked_Access,
      Random => Entropy_Random.Random'Access);

   Put_Line ("Waiting for ClientHello...");

   --  Main handshake loop
   Handshake_Loop : loop
      SPARKTLS.Server.Advance (S, Res);

      case Res is
         when Has_Output =>
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               declare
                  SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
               begin
                  for I in SE'Range loop
                     SE (I) := Stream_Element (Net_Buf (N32 (I - 1)));
                  end loop;
                  Ada.Streams.Write (Channel.all, SE);
               end;
            end if;

         when Need_Input =>
            declare
               SE   : Stream_Element_Array (1 .. 16384);
               Last : Stream_Element_Offset;
            begin
               Ada.Streams.Read (Channel.all, SE, Last);
               if Last >= SE'First then
                  for I in SE'First .. Last loop
                     Net_Buf (N32 (I - 1)) := Byte (SE (I));
                  end loop;
                  SPARKTLS.Feed_Ciphertext
                    (S, Net_Buf (0 .. N32 (Last) - 1), N);
               end if;
            exception
               when others =>
                  Put_Line ("Connection lost during handshake");
                  return;
            end;

         when Handshake_Done =>
            Put_Line ("Handshake complete");
            Put_Line ("  Cipher: 0x" & S.Negotiated_Suite'Image);
            exit Handshake_Loop;

         when Error_Alert =>
            Put_Line ("Handshake error: " & S.Last_Error'Image);
            return;

         when Shutdown =>
            Put_Line ("Connection closed during handshake");
            return;

         when others =>
            null;
      end case;
   end loop Handshake_Loop;

   --  Echo loop: read app data and echo it back
   Put_Line ("Connected. Echoing data...");
   Echo_Loop : loop
      SPARKTLS.Server.Advance (S, Res);

      case Res is
         when Has_Output =>
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               declare
                  SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
               begin
                  for I in SE'Range loop
                     SE (I) := Stream_Element (Net_Buf (N32 (I - 1)));
                  end loop;
                  Ada.Streams.Write (Channel.all, SE);
               end;
            end if;

         when Need_Input =>
            declare
               SE   : Stream_Element_Array (1 .. 16384);
               Last : Stream_Element_Offset;
            begin
               Ada.Streams.Read (Channel.all, SE, Last);
               if Last >= SE'First then
                  for I in SE'First .. Last loop
                     Net_Buf (N32 (I - 1)) := Byte (SE (I));
                  end loop;
                  SPARKTLS.Feed_Ciphertext
                    (S, Net_Buf (0 .. N32 (Last) - 1), N);
               end if;
            exception
               when others =>
                  exit Echo_Loop;
            end;

         when Plaintext_Ready =>
            declare
               App   : Byte_Seq (0 .. 4095);
               App_N : N32;
               Written : N32;
            begin
               SPARKTLS.Read_Plaintext (S, App, App_N);
               if App_N > 0 then
                  declare
                     Msg : String (1 .. Natural (App_N));
                  begin
                     for I in Msg'Range loop
                        Msg (I) := Character'Val (App (N32 (I - 1)));
                     end loop;
                     Put_Line ("Received: " & Msg);
                  end;
                  --  Echo back
                  SPARKTLS.Write_Plaintext
                    (S, App (0 .. App_N - 1), Written);
               end if;
            end;

         when Shutdown =>
            Put_Line ("Client sent close_notify");
            exit Echo_Loop;

         when Error_Alert =>
            Put_Line ("Error: " & S.Last_Error'Image);
            exit Echo_Loop;

         when others =>
            null;
      end case;
   end loop Echo_Loop;

   --  Send close_notify
   SPARKTLS.Server.Close_Notify (S);
   SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
   if N > 0 then
      declare
         SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
      begin
         for I in SE'Range loop
            SE (I) := Stream_Element (Net_Buf (N32 (I - 1)));
         end loop;
         Ada.Streams.Write (Channel.all, SE);
      end;
   end if;

   Put_Line ("Done.");

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
end TLS_Test_Server;
