--  External signature path: a public-only identity
--  plus a Sign_Fn callback, checked at the TLS 1.3 CertificateVerify
--  builder with a P-256 key (the YubiKey case).
--
--  Usage: test_external_sign <p256.crt> <p256.key>
with Ada.Command_Line;
with Ada.Text_IO;   use Ada.Text_IO;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLS.Cert_Verify;
with SPARKTLS.External_Signing;
with SPARKTLS.Handshake.TLS13;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.RFC6979;

procedure Test_External_Sign is
   Total, Pass, Fail : Natural := 0;
   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1; Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1; Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   Key_Id : aliased Identity;   --  holds the key: the "hardware"
   Pub_Id : aliased Identity;   --  what the TLS side gets
   Id_OK, Pub_OK : Boolean;

   --  Deterministic test randomness (blinding only; RFC 6979 nonce).
   procedure Fixed_Random (Output : out Byte_Seq) is
   begin
      Output := (others => 16#5A#);
   end Fixed_Random;

   Mode : Natural := 0;   --  0 sign correctly, 1 corrupt, 2 refuse

   procedure P256_Sign
     (Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status)
   is
      pragma Unreferenced (Message);
      H, K  : Bytes_32;
      Blind : constant Byte_Seq (0 .. 39) := (others => 16#5A#);
      R, S  : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
      Raw   : Byte_Seq (0 .. 63);
      DER   : Byte_Seq (0 .. External_Signing.Max_ECDSA_DER_Len - 1);
      D_Len : N32;
      K_OK, S_OK, D_OK : Boolean;
   begin
      Sig := (others => 0); Sig_Len := 0; Status := Failed;
      if Mode = 2 or else Scheme /= Sig_ECDSA_P256_SHA256 or else Digest'Length /= 32 then
         return;
      end if;
      H := Bytes_32 (Digest);
      SPARKTLSCrypto.RFC6979.Derive_K_P256 (Key_Id.ECDSA_P256_Key, H, K, K_OK);
      if not K_OK then return; end if;
      SPARKTLSCrypto.P256.ECDSA.Sign
        (Hash => H, D => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (Key_Id.ECDSA_P256_Key),
         K => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K), Blind => Blind,
         R_Out => R, S_Out => S, OK => S_OK);
      if not S_OK then return; end if;
      Raw (0 .. 31) := Byte_Seq (R); Raw (32 .. 63) := Byte_Seq (S);
      External_Signing.ECDSA_Raw_To_DER (Raw, 32, DER, D_Len, D_OK);
      if not D_OK then return; end if;
      Sig (Sig'First .. Sig'First + D_Len - 1) := DER (0 .. D_Len - 1);
      if Mode = 1 then
         Sig (Sig'First + 4) := Sig (Sig'First + 4) xor 16#80#;   --  inside r
      end if;
      Sig_Len := D_Len;
      Status := Signed;
   end P256_Sign;

   TH    : constant Byte_Seq (0 .. 31) := (others => 16#42#);   --  a transcript hash
   Arena : aliased Arena_Bytes := (others => 0);
   CV    : Byte_Seq (0 .. 523);
   CV_Len : N32;
begin
   if Ada.Command_Line.Argument_Count /= 2 then
      Put_Line ("usage: test_external_sign <p256.crt> <p256.key>");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;
   Credentials.Load_Identity
     (Key_Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Id_OK);
   Check ("private identity loads", Id_OK and then Key_Id.Has_Private_Key);
   Credentials.Load_Identity_Public (Pub_Id, Ada.Command_Line.Argument (1), Pub_OK);
   Check ("public-only identity loads", Pub_OK);
   Check ("public-only identity: no private key", not Pub_Id.Has_Private_Key);
   Check ("public-only identity: key kind from the certificate",
          Pub_Id.Sign_Algo = Sign_ECDSA_P256);
   Check ("public-only identity: key fields are zero",
          (for all B of Pub_Id.ECDSA_P256_Key => B = 0));

   --  1. Public-only identity and no callback: must fail closed.
   Handshake.TLS13.Build_Certificate_Verify
     (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
      Role => Role_Server, Random => Fixed_Random'Unrestricted_Access, Sign => null,
      Arena_Storage => Arena, Result => CV, Len => CV_Len);
   Check ("no key and no callback: CertificateVerify refused", CV_Len = 0);

   --  2. External signer, correct: builds, and the signature verifies
   --     under the certificate exactly as a peer would check it.
   Mode := 0;
   Handshake.TLS13.Build_Certificate_Verify
     (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
      Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
      Sign => P256_Sign'Unrestricted_Access,
      Arena_Storage => Arena, Result => CV, Len => CV_Len);
   Check ("external signer: CertificateVerify built", CV_Len > 8);
   if CV_Len > 8 then
      declare
         --  CV = hs header(4) || scheme(2) || len(2) || sig
         Sig_Len : constant N32 := N32 (CV (6)) * 256 + N32 (CV (7));
         Content : Byte_Seq (0 .. 129) := (others => 16#20#);
         Ctx     : constant String := "TLS 1.3, server CertificateVerify";
      begin
         for I in Ctx'Range loop
            Content (64 + N32 (I - Ctx'First)) := Byte (Character'Pos (Ctx (I)));
         end loop;
         Content (97) := 0;
         Content (98 .. 129) := TH;
         Check ("external signer: scheme on the wire is ecdsa_secp256r1_sha256",
                CV (4) = 16#04# and CV (5) = 16#03#);
         if Sig_Len > 0 and then 8 + Sig_Len = CV_Len then
            declare
               --  Verify_Signature wants the signature based at 0.
               Sig0 : constant Byte_Seq (0 .. Sig_Len - 1) := CV (8 .. 8 + Sig_Len - 1);
            begin
               Check ("external signer: signature verifies under the certificate",
                      Cert_Verify.Verify_Signature
                        (Content, Sig0, Pub_Id.Cert, Sig_ECDSA_P256_SHA256));
            end;
         else
            Check ("external signer: signature verifies under the certificate", False);
         end if;
      end;
   end if;

   --  3. Local signing with the private identity gives the SAME bytes
   --     (RFC 6979 nonce, so ECDSA is deterministic): one code path.
   declare
      CV2 : Byte_Seq (0 .. 523);
      L2  : N32;
   begin
      Handshake.TLS13.Build_Certificate_Verify
        (Transcript_Hash => TH, Id => Key_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
         Role => Role_Server, Random => Fixed_Random'Unrestricted_Access, Sign => null,
         Arena_Storage => Arena, Result => CV2, Len => L2);
      Check ("local and external CertificateVerify are byte-identical",
             L2 = CV_Len and then L2 > 0 and then CV2 (0 .. L2 - 1) = CV (0 .. CV_Len - 1));
   end;

   --  4. A signer that returns a wrong signature: verify-before-wire rejects.
   Mode := 1;
   Handshake.TLS13.Build_Certificate_Verify
     (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
      Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
      Sign => P256_Sign'Unrestricted_Access,
      Arena_Storage => Arena, Result => CV, Len => CV_Len);
   Check ("corrupt signature from the signer is rejected before the wire", CV_Len = 0);

   --  5. A signer that fails: fail closed.
   Mode := 2;
   Handshake.TLS13.Build_Certificate_Verify
     (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
      Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
      Sign => P256_Sign'Unrestricted_Access,
      Arena_Storage => Arena, Result => CV, Len => CV_Len);
   Check ("signer failure: CertificateVerify refused", CV_Len = 0);

   --  6. ECDSA_Raw_To_DER rejects a wrong length.
   declare
      Bad  : constant Byte_Seq (0 .. 62) := (others => 1);
      DER  : Byte_Seq (0 .. External_Signing.Max_ECDSA_DER_Len - 1);
      DL   : N32;
      DOK  : Boolean;
   begin
      External_Signing.ECDSA_Raw_To_DER (Bad, 32, DER, DL, DOK);
      Check ("ECDSA_Raw_To_DER rejects 63-byte input", not DOK and DL = 0);
   end;

   Put_Line ("Total:" & Total'Image & "  Pass:" & Pass'Image & "  Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_External_Sign;
