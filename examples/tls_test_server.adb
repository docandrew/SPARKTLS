--  Test server using the SPARKTLS library API.
--  Listens on 0.0.0.0:8443 for a TLS 1.3 client connection.
--
--  To generate a compatible certificate and key:
--    openssl genpkey -algorithm ED25519 -out key.pem
--    openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
--
--  Then run:
--    ./tls_test_server cert.pem key.pem

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Numerics.Discrete_Random;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;

with X509;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Server;

with PEM;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Test_Server is

   --  Simple PRNG (NOT CSPRNG - demo only)
   package Random_Byte is new
      Ada.Numerics.Discrete_Random (SPARKNaCl.Byte);

   Gen : Random_Byte.Generator;

   procedure My_Random (Output : out Byte_Seq) is
   begin
      for I in Output'Range loop
         Output (I) := Random_Byte.Random (Gen);
      end loop;
   end My_Random;

   --  Read a text file into a String
   function Read_Text_File (Path : String) return String is
      use Ada.Text_IO;
      F      : File_Type;
      Result : String (1 .. 65536) := (others => ' ');
      Len    : Natural := 0;
      Line   : String (1 .. 1024);
      Last   : Natural;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Get_Line (F, Line, Last);
         if Len + Last + 1 <= Result'Last then
            Result (Len + 1 .. Len + Last) := Line (1 .. Last);
            Len := Len + Last;
            Result (Len + 1) := ASCII.LF;
            Len := Len + 1;
         end if;
      end loop;
      Close (F);
      return Result (1 .. Len);
   exception
      when E : others =>
         Put_Line ("Error reading " & Path & ": " &
            Ada.Exceptions.Exception_Message (E));
         return "";
   end Read_Text_File;

   --  Session
   S   : SPARKTLS.Session;
   Res : SPARKTLS.Action;

   --  Network I/O buffers
   Net_Buf : Byte_Seq (0 .. 16383);
   N       : N32;

   --  Certificate and key buffers
   Cert_Buf : Byte_Seq (0 .. Max_Cert_DER_Len - 1) := (others => 0);
   Cert_Len : N32 := 0;
   Key_64   : Bytes_64 := (others => 0);

   --  Identity (loaded from cert + key files)
   Server_Id : aliased SPARKTLS.Identity;

   --  Socket
   Server_Sock : GNAT.Sockets.Socket_Type;
   Client_Sock : GNAT.Sockets.Socket_Type;
   Client_Addr : GNAT.Sockets.Sock_Addr_Type;
   Channel     : Stream_Access;

begin
   Random_Byte.Reset (Gen);

   --  Check command line args
   if Ada.Command_Line.Argument_Count /= 2 then
      Put_Line ("Usage: tls_test_server <cert.pem> <key.pem>");
      return;
   end if;

   --  Read and decode certificate PEM
   declare
      Cert_Text : constant String :=
         Read_Text_File (Ada.Command_Line.Argument (1));
      R : PEM.Decode_Result;
   begin
      if Cert_Text'Length = 0 then
         Put_Line ("Failed to read certificate file");
         return;
      end if;

      PEM.Decode (Cert_Text, R);

      if not R.OK then
         Put_Line ("Failed to decode certificate PEM");
         return;
      end if;

      if R.DER_Len > Natural (Max_Cert_DER_Len) then
         Put_Line ("Certificate too large");
         return;
      end if;

      --  Copy DER bytes (PEM.DER is String, Cert_Buf is Byte_Seq)
      Cert_Len := N32 (R.DER_Len);
      for I in 0 .. Cert_Len - 1 loop
         Cert_Buf (I) := Byte (Character'Pos (R.DER (Natural (I) + 1)));
      end loop;
   end;
   Put_Line ("Certificate:" & Cert_Len'Image & " bytes (DER)");

   --  Read and decode private key PEM
   declare
      Key_Text : constant String :=
         Read_Text_File (Ada.Command_Line.Argument (2));
      R : PEM.Decode_Result;
   begin
      if Key_Text'Length = 0 then
         Put_Line ("Failed to read key file");
         return;
      end if;

      PEM.Decode (Key_Text, R);

      if not R.OK then
         Put_Line ("Failed to decode key PEM");
         return;
      end if;

      --  Extract Ed25519 seed from PKCS#8 DER.
      --  Structure: sequence { int(0), seq{OID}, octet(04 20 <seed>) }
      --  The 32-byte seed starts at offset 16 (after 04 20 wrapper).
      --  We derive the public key using SPARKNaCl.Sign.Keypair.
      if R.DER_Len < 48 then
         Put_Line ("Key DER too short:" & R.DER_Len'Image);
         return;
      end if;

      declare
         Seed_Offset : constant := 16;
         Seed        : Bytes_32;
         SK          : SPARKNaCl.Sign.Signing_SK;
         PK          : SPARKNaCl.Sign.Signing_PK;
      begin
         for I in N32 range 0 .. 31 loop
            Seed (I) := Byte (Character'Pos (
               R.DER (Seed_Offset + Natural (I) + 1)));
         end loop;

         SPARKNaCl.Sign.Keypair (Seed, PK, SK);
         Key_64 := SPARKNaCl.Sign.Serialize (SK);
      end;
   end;
   Put_Line ("Key: loaded");

   --  Load identity from cert + key
   declare
      --  Convert Cert_Buf to X509.Byte_Seq for Set_Identity
      X_Cert : X509.Byte_Seq (0 .. X509.N32 (Cert_Len) - 1);
      Id_OK  : Boolean;
   begin
      for I in X_Cert'Range loop
         X_Cert (I) := X509.Byte (Cert_Buf (N32 (I)));
      end loop;
      SPARKTLS.Cert_Verify.Set_Identity
        (Server_Id, X_Cert, Key_64, Id_OK);
      if not Id_OK then
         Put_Line ("Failed to load identity");
         return;
      end if;
   end;
   Put_Line ("Identity: loaded");

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
      Local  => Server_Id'Unchecked_Access,
      Random => My_Random'Unrestricted_Access);

   Put_Line ("Server initialized, waiting for ClientHello...");

   --  Main handshake loop
   Handshake_Loop : loop
      SPARKTLS.Server.Advance (S, Res);

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
               Byte_Seq'Read (Channel, Net_Buf (0 .. 4));

               declare
                  Rec_Len : constant N32 :=
                     N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
               begin
                  if Rec_Len > 0 and Rec_Len <= 16640 then
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

            exit Handshake_Loop;

         when SPARKTLS.Error_Alert =>
            Put_Line ("ERROR: " & S.Last_Error'Image);
            exit Handshake_Loop;

         when SPARKTLS.Shutdown =>
            Put_Line ("Connection closed by peer");
            exit Handshake_Loop;

         when SPARKTLS.OK =>
            null;

         when SPARKTLS.Plaintext_Ready =>
            null;
      end case;
   end loop Handshake_Loop;

   --  If connected, handle application data
   if S.State = SPARKTLS.Connected then
      --  Wait for client data
      App_Loop : loop
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

                  Put_Line ("<< Received" & N'Image &
                     " bytes (type:" & Net_Buf (0)'Image & ")");
                  SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);

                  SPARKTLS.Server.Advance (S, Res);

                  if Res = SPARKTLS.Plaintext_Ready then
                     declare
                        App_Buf : Byte_Seq (0 .. 4095);
                        App_N   : N32;
                     begin
                        SPARKTLS.Read_Plaintext (S, App_Buf, App_N);
                        Put_Line ("Client data (" & App_N'Image & " bytes):");
                        declare
                           Msg : String (1 .. Integer (App_N));
                        begin
                           for I in Msg'Range loop
                              Msg (I) := Character'Val (App_Buf (N32 (I - 1)));
                           end loop;
                           Put_Line ("  " & Msg);
                        end;

                        --  Echo it back
                        declare
                           Written : N32;
                        begin
                           SPARKTLS.Server.Write_Plaintext
                             (S, App_Buf (0 .. App_N - 1), Written);
                           Put_Line ("Echoing" & Written'Image & " bytes back");

                           SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
                           if N > 0 then
                              Put_Line (">> Sending" & N'Image & " bytes");
                              Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
                           end if;
                        end;
                     end;

                  elsif Res = SPARKTLS.Shutdown then
                     Put_Line ("Client sent close_notify");
                     exit App_Loop;

                  elsif Res = SPARKTLS.Error_Alert then
                     Put_Line ("Error: " & S.Last_Error'Image);
                     exit App_Loop;
                  end if;
               end if;
            end;
         exception
            when others =>
               Put_Line ("No more data (timeout)");
               exit App_Loop;
         end;
      end loop App_Loop;

      --  Send close_notify
      SPARKTLS.Server.Close_Notify (S);
      SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
      if N > 0 then
         begin
            Put_Line (">> Sending close_notify (" & N'Image & " bytes)");
            Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
         exception
            when others =>
               Put_Line ("(peer already closed)");
         end;
      end if;
   end if;

   Put_Line ("");
   Put_Line ("Final state: " & S.State'Image);
   Put_Line ("Done.");

   GNAT.Sockets.Close_Socket (Client_Sock);
   GNAT.Sockets.Close_Socket (Server_Sock);

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
      begin
         GNAT.Sockets.Close_Socket (Client_Sock);
         GNAT.Sockets.Close_Socket (Server_Sock);
      exception
         when others => null;
      end;
end TLS_Test_Server;
