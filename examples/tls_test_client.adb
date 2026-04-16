--  Test client using the SPARKTLS library API.
--  Connects to openssl s_server on 127.0.0.1:8443.
--
--  To run a compatible server:
--    openssl genpkey -algorithm ED25519 -out key.pem
--    openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
--    openssl s_server -key key.pem -cert cert.pem -accept 8443 -tls1_3
--
--  Supported cipher suites:
--    TLS_AES_128_GCM_SHA256 (0x1301)
--    TLS_CHACHA20_POLY1305_SHA256 (0x1303)

with Ada.Exceptions;
with Ada.Calendar;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;         use SPARKTLS;
with SPARKTLS.Client;
with Entropy_Random;
with X509;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Test_Client is

   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      S   : Day_Duration;
   begin
      Split (Now, Y, Mo, D, S);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Natural (S) / 3600,
              Minute => (Natural (S) mod 3600) / 60,
              Second => Natural (S) mod 60);
   end Current_Time;

   --  Session
   S   : SPARKTLS.Session;
   Res : SPARKTLS.Action;

   --  Network I/O buffers
   Net_Buf : Byte_Seq (0 .. 16383);
   N       : N32;

   --  Socket
   Sock    : GNAT.Sockets.Socket_Type;
   Channel : Stream_Access;

   --  Set hostname for SNI
   Host : constant String := "localhost";

begin
   Entropy_Random.Init;

   Put_Line ("=== SPARKTLS Test Client ===");
   Put_Line ("Connecting to 127.0.0.1:8443...");

   --  Connect socket
   GNAT.Sockets.Initialize;
   GNAT.Sockets.Create_Socket (Socket => Sock);
   GNAT.Sockets.Set_Socket_Option
     (Socket => Sock,
      Level  => GNAT.Sockets.Socket_Level,
      Option => (Name    => Reuse_Address,
                 Enabled => True));
   GNAT.Sockets.Set_Socket_Option
     (Socket => Sock,
      Level  => GNAT.Sockets.Socket_Level,
      Option => (Name    => GNAT.Sockets.Receive_Timeout,
                 Timeout => 5.0));
   GNAT.Sockets.Connect_Socket
     (Socket => Sock,
      Server => (Family => GNAT.Sockets.Family_Inet,
                 Addr   => GNAT.Sockets.Inet_Addr ("127.0.0.1"),
                 Port   => 8443));

   Channel := GNAT.Sockets.Stream (Sock);
   Put_Line ("Connected.");

   --  Initialize TLS client session (skip verification for test)
   SPARKTLS.Client.Configure
     (S        => S,
      Hostname => Host,
      Trust    => null,
      Random   => Entropy_Random.Random'Access,
      Clock    => Current_Time'Unrestricted_Access);
   Put_Line ("ClientHello built, output pending:" &
      SPARKTLS.Output_Pending (S)'Image & " bytes");

   --  Main handshake + data loop
   Handshake_Loop : loop
      SPARKTLS.Client.Advance (S, Res);

      case Res is
         when SPARKTLS.Has_Output =>
            --  Drain output and send over socket
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               Put_Line (">> Sending" & N'Image & " bytes");
               Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
            end if;

         when SPARKTLS.Need_Input =>
            --  Read from socket and feed into TLS
            Put_Line ("<< Waiting for data...");
            begin
               --  Read record header first (5 bytes)
               Byte_Seq'Read (Channel, Net_Buf (0 .. 4));

               declare
                  Rec_Len : constant N32 :=
                     N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
               begin
                  if Rec_Len > 0 and Rec_Len <= 16640 then
                     --  Read the rest of the record
                     Byte_Seq'Read (Channel,
                        Net_Buf (5 .. 4 + Rec_Len));

                     N := 5 + Rec_Len;
                     Put_Line ("<< Received" & N'Image &
                        " bytes (type:" & Net_Buf (0)'Image & ")");

                     SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);
                  end if;
               end;
            exception
               when E : others =>
                  Put_Line ("Socket read error: " &
                     Ada.Exceptions.Exception_Message (E));
                  exit Handshake_Loop;
            end;

         when SPARKTLS.Handshake_Done =>
            Put_Line ("");
            Put_Line ("=== HANDSHAKE COMPLETE ===");
            Put_Line ("State: " & S.State'Image);

            case S.Negotiated_Suite is
               when SPARKTLS.Suite_AES_128_GCM_SHA256 =>
                  Put_Line ("Cipher: TLS_AES_128_GCM_SHA256");
               when SPARKTLS.Suite_CHACHA20_POLY1305_SHA256 =>
                  Put_Line ("Cipher: TLS_CHACHA20_POLY1305_SHA256");
               when SPARKTLS.Suite_AES_256_GCM_SHA384 =>
                  Put_Line ("Cipher: TLS_AES_256_GCM_SHA384");
               when others =>
                  Put_Line ("Cipher: 0x" & S.Negotiated_Suite'Image);
            end case;

            if SPARKTLS.Client.Has_Peer_Certificate (S) then
               Put_Line ("Peer certificate: valid");
            end if;

            exit Handshake_Loop;

         when SPARKTLS.Plaintext_Ready =>
            SPARKTLS.Read_Plaintext (S, Net_Buf, N);
            Put_Line ("App data (" & N'Image & " bytes)");

         when SPARKTLS.Error_Alert =>
            Put_Line ("ERROR: " & S.Last_Error'Image);
            exit Handshake_Loop;

         when SPARKTLS.Shutdown =>
            Put_Line ("Connection closed by peer");
            exit Handshake_Loop;

         when SPARKTLS.OK =>
            null;  --  Progress made, keep going
      end case;
   end loop Handshake_Loop;

   --  If connected, do application data exchange
   if S.State = SPARKTLS.Connected then
      --  Drain any post-handshake messages (NewSessionTicket etc.)
      Post_HS : loop
         begin
            Byte_Seq'Read (Channel, Net_Buf (0 .. 4));

            declare
               Rec_Len : constant N32 :=
                  N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
            begin
               if Rec_Len > 0 and Rec_Len <= 16640 then
                  Byte_Seq'Read (Channel,
                     Net_Buf (5 .. 4 + Rec_Len));
                  N := 5 + Rec_Len;

                  Put_Line ("<< Post-HS record (" & N'Image &
                     " bytes, type:" & Net_Buf (0)'Image & ")");
                  SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);

                  --  Process the record
                  SPARKTLS.Client.Advance (S, Res);
                  if Res = SPARKTLS.Plaintext_Ready then
                     SPARKTLS.Read_Plaintext (S, Net_Buf, N);
                     Put_Line ("App data from server (" & N'Image & " bytes)");
                  end if;
               end if;
            end;
         exception
            when others =>
               Put_Line ("No more post-handshake messages (timeout)");
               exit Post_HS;
         end;
      end loop Post_HS;

      --  Send "Hello from SPARKTLS!" to the server
      declare
         Msg : constant String := "Hello from SPARKTLS!";
         Msg_Bytes : Byte_Seq (0 .. N32 (Msg'Length) - 1);
         Written : N32;
      begin
         for I in Msg'Range loop
            Msg_Bytes (N32 (I - Msg'First)) :=
               Byte (Character'Pos (Msg (I)));
         end loop;

         SPARKTLS.Client.Write_Plaintext (S, Msg_Bytes, Written);
         Put_Line ("Queued" & Written'Image &
            " bytes of app data for sending");

         --  Drain and send
         SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
         if N > 0 then
            Put_Line (">> Sending" & N'Image & " bytes (encrypted app data)");
            Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
         end if;
      end;

      --  Wait for response from server
      begin
         Byte_Seq'Read (Channel, Net_Buf (0 .. 4));

         declare
            Rec_Len : constant N32 :=
               N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
         begin
            if Rec_Len > 0 and Rec_Len <= 16640 then
               Byte_Seq'Read (Channel, Net_Buf (5 .. 4 + Rec_Len));
               N := 5 + Rec_Len;

               SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);
               SPARKTLS.Client.Advance (S, Res);

               if Res = SPARKTLS.Plaintext_Ready then
                  declare
                     App_Buf : Byte_Seq (0 .. 4095);
                     App_N   : N32;
                  begin
                     SPARKTLS.Read_Plaintext (S, App_Buf, App_N);
                     Put_Line ("Server response (" & App_N'Image & " bytes):");
                     declare
                        Resp : String (1 .. Integer (App_N));
                     begin
                        for I in Resp'Range loop
                           Resp (I) := Character'Val (App_Buf (N32 (I - 1)));
                        end loop;
                        Put_Line ("  " & Resp);
                     end;
                  end;
               end if;
            end if;
         end;
      exception
         when others =>
            Put_Line ("No response from server (timeout)");
      end;

      --  Send close_notify
      SPARKTLS.Client.Close_Notify (S);
      SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
      if N > 0 then
         Put_Line (">> Sending close_notify (" & N'Image & " bytes)");
         Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
      end if;
   end if;

   Put_Line ("");
   Put_Line ("Final state: " & S.State'Image);
   Put_Line ("Done.");

   GNAT.Sockets.Close_Socket (Sock);

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
      begin
         GNAT.Sockets.Close_Socket (Sock);
      exception
         when others => null;
      end;
end TLS_Test_Client;
