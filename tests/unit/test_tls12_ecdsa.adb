with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake.TLS12;
with X509;

procedure Test_TLS12_ECDSA is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   function Hex_Val (C : Character) return Byte is
   begin
      case C is
         when '0' .. '9' => return Byte (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' => return Byte (10 + Character'Pos (C) - Character'Pos ('a'));
         when 'A' .. 'F' => return Byte (10 + Character'Pos (C) - Character'Pos ('A'));
         when others     => return 0;
      end case;
   end Hex_Val;

   function From_Hex (S : String) return Byte_Seq is
      R : Byte_Seq (0 .. N32 (S'Length / 2) - 1);
      P : Positive := S'First;
   begin
      for I in R'Range loop
         R (I) := Hex_Val (S (P)) * 16 + Hex_Val (S (P + 1));
         P := P + 2;
      end loop;
      return R;
   end From_Hex;

   Cert_DER : constant Byte_Seq := From_Hex
     ("308201313081d9a003020102020106300a06082a8648ce3d0403023020311e"
      & "301c060355040313155465737420454344534120502d32353620526f6f74301e"
      & "170d3236303730373130343931365a170d3236303730373132343931365a3000"
      & "3059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2"
      & "bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7"
      & "d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1"
      & "a3243022300f0603551d23040830068004726f6f74300f0603551d11040830"
      & "06820474657374300a06082a8648ce3d0403020347003044022018f1cc4592"
      & "3adf5a9e0bce7576f2d27bf0b7459ab332bb95da7941ba593aa49a022050"
      & "241af2d61861cbe3e74d2db23108a0fc4df1937fdd9f8a8574f4ce1f2d3a"
      & "d6");

   Signed_Data : constant Byte_Seq := From_Hex
     ("9a1f47f05de4bb8452b29beef5dbea9bf2b00af895d4cd25b37c261b6c"
      & "ab9136e171e86163bf4911a96fee81a758a964dcbeffd5532b448df5a92a"
      & "490366fff403001d20c365b84dd207191b2c2d091dd08cd2f3578331125e"
      & "86a278aab2616153e63257");

   Sig : constant Byte_Seq := From_Hex
     ("3046022100a618eebd38842e161337009287a64565175853c680a774d05f"
      & "fabead6b7583df022100fab559a3957d3467fac6f214bc05f28a780be1ab"
      & "ed2e405720f1f15b78059cec");

   SKE_Body : constant Byte_Seq := From_Hex
     ("03001d20c365b84dd207191b2c2d091dd08cd2f3578331125e86a2"
      & "78aab2616153e63257050300483046022100a618eebd38842e161337"
      & "009287a64565175853c680a774d05ffabead6b7583df022100fab559"
      & "a3957d3467fac6f214bc05f28a780be1abed2e405720f1f15b78059c"
      & "ec");

   Client_Random : constant Bytes_32 := Bytes_32 (From_Hex
     ("9a1f47f05de4bb8452b29beef5dbea9bf2b00af895d4cd25b37c261b6c"
      & "ab9136"));
   Server_Random : constant Bytes_32 := Bytes_32 (From_Hex
     ("e171e86163bf4911a96fee81a758a964dcbeffd5532b448df5a92a490366"
      & "fff4"));

   Cert : X509.Certificate;
   OK   : Boolean;
begin
   X509.Parse (X509.Byte_Seq (Cert_DER), Cert, OK);
   Check ("BoGo P-256 cert parses", OK);

   if OK then
      Check
        ("TLS 1.2 accepts P-256 ECDSA key with SHA-384 signature",
         SPARKTLS.Cert_Verify.Verify_Signature_TLS12
           (Data       => Signed_Data,
            Sig        => Sig,
            Cert       => Cert,
            Sig_Scheme => 16#0503#));

      Check
        ("TLS 1.2 allows default ECDSA cert curve policy",
         SPARKTLS.Handshake.TLS12.ECDSA_Cert_Curve_Allowed_TLS12
           (0, X509.Algo_EC_P256));

      Check
        ("TLS 1.2 rejects P-256 ECDSA cert when only P-384 offered",
         not SPARKTLS.Handshake.TLS12.ECDSA_Cert_Curve_Allowed_TLS12
           (SPARKTLS.Handshake.TLS12.Group_Secp384r1, X509.Algo_EC_P256));

      Check
        ("TLS 1.2 accepts P-384 ECDSA cert when P-384 offered",
         SPARKTLS.Handshake.TLS12.ECDSA_Cert_Curve_Allowed_TLS12
           (SPARKTLS.Handshake.TLS12.Group_Secp384r1, X509.Algo_EC_P384));

      Check
        ("TLS 1.2 rejects NIST ECDSA cert when only X25519 offered",
         not SPARKTLS.Handshake.TLS12.ECDSA_Cert_Curve_Allowed_TLS12
           (SPARKTLS.Handshake.TLS12.Group_X25519, X509.Algo_EC_P384));

      Check
        ("TLS 1.2 allows default selected ECDHE group policy",
         SPARKTLS.Handshake.TLS12.Selected_Group_Allowed_TLS12
           (0, SPARKTLS.Handshake.TLS12.Group_Secp256r1));

      Check
        ("TLS 1.2 accepts selected group that was offered",
         SPARKTLS.Handshake.TLS12.Selected_Group_Allowed_TLS12
           (SPARKTLS.Handshake.TLS12.Group_Secp384r1,
            SPARKTLS.Handshake.TLS12.Group_Secp384r1));

      Check
        ("TLS 1.2 rejects selected group that was not offered",
         not SPARKTLS.Handshake.TLS12.Selected_Group_Allowed_TLS12
           (SPARKTLS.Handshake.TLS12.Group_Secp384r1,
            SPARKTLS.Handshake.TLS12.Group_Secp256r1));

      declare
         HC       : Handshake_Context;
         Parse_OK : Boolean;
      begin
         HC.Client_Random := Client_Random;
         HC.Server_Random := Server_Random;
         HC.Peer_Cert := Cert;
         HC.Peer_Cert_Valid := True;

         SPARKTLS.Handshake.TLS12.Parse_Server_Key_Exchange
           (HC, SKE_Body, Parse_OK);
         Check
           ("TLS 1.2 parser accepts BoGo P-256/SHA-384 SKE",
            Parse_OK);
      end;

      declare
         HC       : Handshake_Context;
         Parse_OK : Boolean;
         Bad_SKE  : constant Byte_Seq := From_Hex
           ("0300172103c365b84dd207191b2c2d091dd08cd2f3578331125e"
            & "86a278aab2616153e632570403000100");
      begin
         HC.Client_Random := Client_Random;
         HC.Server_Random := Server_Random;
         HC.Peer_Cert := Cert;
         HC.Peer_Cert_Valid := True;

         SPARKTLS.Handshake.TLS12.Parse_Server_Key_Exchange
           (HC, Bad_SKE, Parse_OK);
         Check
           ("TLS 1.2 SKE compressed EC point is illegal_parameter",
            (not Parse_OK) and HC.Ext_Parse_Err = Illegal_Parameter);
      end;

      declare
         HC       : Handshake_Context;
         Parse_OK : Boolean;
         Bad_CKE  : constant Byte_Seq := From_Hex
           ("2103c365b84dd207191b2c2d091dd08cd2f3578331125e86a"
            & "278aab2616153e63257");
      begin
         HC.Selected_Group := SPARKTLS.Handshake.TLS12.Group_Secp256r1;
         SPARKTLS.Handshake.TLS12.Parse_Client_Key_Exchange
           (HC, Bad_CKE, Parse_OK);
         Check
           ("TLS 1.2 CKE compressed EC point is illegal_parameter",
            (not Parse_OK) and HC.Ext_Parse_Err = Illegal_Parameter);
      end;
   end if;

   Put_Line ("Total checks: " & Natural'Image (Total)
             & " passed" & Natural'Image (Pass)
             & " failed" & Natural'Image (Fail));
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_TLS12_ECDSA;
