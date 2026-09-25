--  TLS server whose identity key lives in a YubiKey PIV slot.
--
--    tls_yubikey_server <9a|9c|9e> [port] [--pin-stdin]
--
--  The PIN is prompted for without echo (never on the command line, where
--  ps would show it); --pin-stdin reads it from standard input instead,
--  for scripts and tests. Slot 9e (card authentication) signs without a
--  PIN by PIV policy, so no PIN is asked for it. The certificate is read from the token, the identity is loaded
--  public-only, and every handshake signature is produced by the token
--  through PIV_Signer: this process never holds the
--  private key. One connection at a time, echo service, like
--  tls_test_server. Talks to the token directly over /dev/bus/usb (pcscd
--  must NOT be running) and needs a P-256 or P-384 key in the
--  slot (yubico-piv-tool -a generate -s 9c -A ECCP256 ...).
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Cert_Verify;
with Server_Pool;
with X509;
with Entropy_Random;
with GNAT.Sockets;               use GNAT.Sockets;
with PIV;
with PIV.Linux_USB;
with PIV_Signer;
with PIN_Prompt;

procedure TLS_Yubikey_Server is
   Id      : aliased SPARKTLS.Identity;
   S       : SPARKTLS.Server_Session;
   Res     : SPARKTLS.Action;
   Net_Buf : Byte_Seq (0 .. 16383);
   N       : N32;
   Port    : Port_Type := 8443;
   PIN_Buf : String (1 .. 8) := (others => ' ');   --  scrubbed after Init
   PIN_Len : Natural := 0;

   Server_Sock, Client_Sock : Socket_Type;
   Client_Addr : Sock_Addr_Type;
   Channel     : Stream_Access;
   Peer_Closed : Boolean := False;   --  zero-byte receive: peer went away

   procedure Send_Output is
   begin
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
   end Send_Output;

   procedure Read_Input is
      SE   : Stream_Element_Array (1 .. 16384);
      Last : Stream_Element_Offset;
   begin
      Receive_Socket (Client_Sock, SE, Last);
      if Last >= SE'First then
         for I in SE'First .. Last loop
            Net_Buf (N32 (I - 1)) := Byte (SE (I));
         end loop;
         SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N32 (Last) - 1), N);
      else
         --  EOF without close_notify (a client that just hangs up). Leave
         --  the loops instead of asking for input forever.
         Peer_Closed := True;
      end if;
   exception
      when others =>
         Peer_Closed := True;
   end Read_Input;

begin
   Entropy_Random.Init;
   if Ada.Command_Line.Argument_Count < 1 then
      Put_Line ("Usage: tls_yubikey_server <9a|9c|9e> [port] [--pin-stdin]");
      return;
   end if;
   declare
      PIN_From_Stdin : Boolean := False;
   begin
      for I in 2 .. Ada.Command_Line.Argument_Count loop
         if Ada.Command_Line.Argument (I) = "--pin-stdin" then
            PIN_From_Stdin := True;
         else
            Port := Port_Type'Value (Ada.Command_Line.Argument (I));
         end if;
      end loop;
      if Ada.Command_Line.Argument (1) /= "9e" and Ada.Command_Line.Argument (1) /= "9E" then
         declare
            P : constant String :=
              (if PIN_From_Stdin then PIN_Prompt.Read_Stdin
               else PIN_Prompt.Read_Hidden ("YubiKey PIN: "));
         begin
            if P'Length not in 6 .. 8 then
               Put_Line ("PIN must be 6 to 8 characters");
               return;
            end if;
            PIN_Len := P'Length;
            PIN_Buf (1 .. PIN_Len) := P;
         end;
      end if;
   end;

   --  Token: connect, select PIV, verify PIN, read the slot certificate.
   declare
      Slot_Arg : constant String := Ada.Command_Line.Argument (1);
      Slot     : PIV.Slot := PIV.Slot_9C_Signature;
      Reader   : String (1 .. 128);
      Slot_OK  : Boolean := True;
      R_Len    : Natural;
      R_OK     : Boolean;
      Cert     : Byte_Seq (0 .. 4095);
      Cert_Len : N32;
      T_OK     : Boolean;
      Why      : PIV.Status;
   begin
      if Slot_Arg = "9a" or Slot_Arg = "9A" then
         Slot := PIV.Slot_9A_Authentication;
      elsif Slot_Arg = "9c" or Slot_Arg = "9C" then
         Slot := PIV.Slot_9C_Signature;
      elsif Slot_Arg = "9e" or Slot_Arg = "9E" then
         Slot := PIV.Slot_9E_Card_Authentication;
      else
         Slot_OK := False;
      end if;
      if not Slot_OK then
         Put_Line ("Unknown slot '" & Slot_Arg & "': use 9a, 9c or 9e");
         return;
      end if;
      PIV.Linux_USB.Connect (Reader, R_Len, R_OK);
      if not R_OK then
         Put_Line ("No YubiKey CCID interface reachable: inserted? udev rule? pcscd not running?");
         return;
      end if;
      Put_Line ("Token: " & Reader (1 .. R_Len));
      PIV_Signer.Init (Slot, PIN_Buf (1 .. PIN_Len), Cert, Cert_Len, T_OK, Why);
      PIN_Buf := (others => '0');   --  the signer keeps its own copy
      pragma Inspection_Point (PIN_Buf);
      if not T_OK then
         Put_Line ("PIV setup failed: " & Why'Image);
         return;
      end if;
      Put_Line ("Slot " & Slot_Arg & ": certificate read (" & Cert_Len'Image & " bytes)");
      --  Public-only identity from the token's certificate.
      declare
         DER : X509.Byte_Seq (0 .. X509.N32 (Cert_Len) - 1);
         Set_OK : Boolean;
      begin
         for I in DER'Range loop
            DER (I) := X509.Byte (Cert (N32 (I)));
         end loop;
         SPARKTLS.Cert_Verify.Set_Identity_Public (Id, DER, Set_OK);
         if not Set_OK then
            Put_Line ("Certificate from the token was not accepted as an identity");
            return;
         end if;
      end;
      Put_Line ("Identity: " & Id.Sign_Algo'Image & " (public only; the key stays in the YubiKey)");
   end;

   GNAT.Sockets.Initialize;
   Create_Socket (Server_Sock);
   Set_Socket_Option (Server_Sock, Socket_Level, (Reuse_Address, True));
   Bind_Socket (Server_Sock, (Family_Inet, Any_Inet_Addr, Port));
   Listen_Socket (Server_Sock, 1);
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   loop
      Accept_Socket (Server_Sock, Client_Sock, Client_Addr);
      --  One misbehaving client (reset mid-flight, send timeout) must not
      --  take the server down: everything per connection is handled here.
      begin
      Set_Socket_Option (Client_Sock, Socket_Level, (Receive_Timeout, 30.0));
      Set_Socket_Option (Client_Sock, Socket_Level, (Send_Timeout, 10.0));
      Channel := Stream (Client_Sock);
      Put_Line ("Client " & Image (Client_Addr));

      S := SPARKTLS.Server.Configure
        ((Local  => Id'Unchecked_Access,
          Sign   => PIV_Signer.Sign'Access,      --  the YubiKey signs
          others => <>), Server_Pool.Handshakes);

      Peer_Closed := False;
      Handshake : loop
         SPARKTLS.Server.Advance (S, Server_Pool.Handshakes, Res);
         exit Handshake when Peer_Closed;
         case Res is
            when Has_Output     => Send_Output;
            when Need_Input     => Read_Input;
            when Handshake_Done =>
               Put_Line ("  handshake complete, suite " & Negotiated_Suite (S)'Image
                         & " (signed by the token)");
               exit Handshake;
            when Error_Alert =>
               Put_Line ("  handshake error: " & SPARKTLS.Describe (SPARKTLS.Last_Error (S)));
               exit Handshake;
            when Shutdown => exit Handshake;
            when others   => null;
         end case;
      end loop Handshake;

      if Res = Handshake_Done and not Peer_Closed then
         Echo : loop
            SPARKTLS.Server.Advance (S, Server_Pool.Handshakes, Res);
            exit Echo when Peer_Closed;
            case Res is
               when Has_Output      => Send_Output;
               when Need_Input      => Read_Input;
               when Plaintext_Ready =>
                  declare
                     Buf : Byte_Seq (0 .. 4095);
                     L, W : N32;
                  begin
                     SPARKTLS.Read_Plaintext (S, Buf, L);
                     if L > 0 then
                        SPARKTLS.Write_Plaintext (S, Buf (0 .. L - 1), W);
                     end if;
                  end;
               when Shutdown | Error_Alert => exit Echo;
               when others => null;
            end case;
         end loop Echo;
      end if;
      Close_Socket (Client_Sock);
      Put_Line ("  closed");
      exception
         when E : others =>
            Put_Line ("  connection error: " & Ada.Exceptions.Exception_Message (E));
            begin
               Close_Socket (Client_Sock);
            exception
               when others => null;
            end;
      end;
   end loop;
exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
      PIV.Linux_USB.Disconnect;
end TLS_Yubikey_Server;
