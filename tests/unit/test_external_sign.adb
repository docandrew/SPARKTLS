--  External signature path: a public-only identity
--  plus a Sign_Fn callback, checked at the TLS 1.3 CertificateVerify
--  builder with a P-256 key (the YubiKey case).
--
--  Usage: test_external_sign <p256.crt> <p256.key> [<rsa.crt> <rsa.key>]
with Ada.Command_Line;
with Ada.Text_IO;   use Ada.Text_IO;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLS.Cert_Verify;
with SPARKTLS.External_Signing;
with SPARKTLS.Handshake.TLS13;
with SPARKTLS.Handshake.TLS12;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.RSA;

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

   Mode : Natural := 0;   --  0 sign correctly, 1 corrupt, 2 refuse, 3 report Pending

   procedure P256_Sign
     (Id      : in     Identity;
      Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status)
   is
      pragma Unreferenced (Id, Message);
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
         --  Flip the LAST byte (low bit of s): still valid DER, so the
         --  rejection can only come from verification, not from parsing.
         Sig (Sig'First + D_Len - 1) := Sig (Sig'First + D_Len - 1) xor 16#01#;
      end if;
      Sig_Len := D_Len;
      Status := (if Mode = 3 then Pending else Signed);
   end P256_Sign;

   --  An RSA signer over a second identity (PSS for 1.3, PKCS#1 v1.5 for 1.2).
   RSA_Id : aliased Identity;
   RSA_OK : Boolean := False;
   procedure RSA_Sign
     (Id      : in     Identity;
      Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status)
   is
      pragma Unreferenced (Id, Message);
      H_Len : constant N32 := Digest'Length;
      M_Hash : Byte_Seq (0 .. 63) := (others => 0);
      Salt   : constant Byte_Seq (0 .. 63) := (others => 16#33#);
      Blind  : constant Bytes_16 := (others => 16#5A#);
      Out_S  : Byte_Seq (0 .. 1023) := (others => 0);
      O_Len  : N32;
      OK     : Boolean := False;
   begin
      Sig := (others => 0); Sig_Len := 0; Status := Failed;
      if Mode = 2 or else not RSA_OK or else H_Len not in 32 | 48 | 64 or else Sig'Length < RSA_Id.RSA_Mod_Len then
         return;
      end if;
      M_Hash (0 .. H_Len - 1) := Digest;
      case Scheme is
         when Sig_RSA_PSS_SHA256 =>
            SPARKTLSCrypto.RSA.Sign_PSS
              (M_Hash => M_Hash (0 .. 31), Hash_Len => 32, Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
               Modulus => RSA_Id.RSA_Modulus, Mod_Len => RSA_Id.RSA_Mod_Len, Priv_Exp => RSA_Id.RSA_Priv_Exp,
               Salt => Salt (0 .. 31), Signature => Out_S, Sig_Len => O_Len, OK => OK,
               Blind => Blind, Pub_Exp => RSA_Id.RSA_Pub_Exp, CRT => RSA_Id.RSA_CRT);
         when Sig_RSA_PKCS1_SHA256 =>
            SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
              (M_Hash => M_Hash (0 .. 31), Hash_Len => 32,
               Modulus => RSA_Id.RSA_Modulus, Mod_Len => RSA_Id.RSA_Mod_Len, Priv_Exp => RSA_Id.RSA_Priv_Exp,
               Signature => Out_S, Sig_Len => O_Len, OK => OK,
               Blind => Blind, Pub_Exp => RSA_Id.RSA_Pub_Exp, CRT => RSA_Id.RSA_CRT);
         when others => return;
      end case;
      if not OK then return; end if;
      Sig (Sig'First .. Sig'First + O_Len - 1) := Out_S (0 .. O_Len - 1);
      if Mode = 1 then
         Sig (Sig'First + O_Len - 1) := Sig (Sig'First + O_Len - 1) xor 16#01#;
      end if;
      Sig_Len := O_Len;
      Status := Signed;
   end RSA_Sign;

   TH    : constant Byte_Seq (0 .. 31) := (others => 16#42#);   --  a transcript hash
   Arena : aliased Arena_Bytes := (others => 0);
   CV    : Byte_Seq (0 .. 523);
   CV_Len : N32;
begin
   if Ada.Command_Line.Argument_Count not in 2 | 4 then
      Put_Line ("usage: test_external_sign <p256.crt> <p256.key>");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;
   Credentials.Load_Identity
     (Key_Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
      Fixed_Random'Unrestricted_Access, Id_OK);
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

   --  5b. A signer that reports Pending (reserved): treated as failure.
   Mode := 3;
   Handshake.TLS13.Build_Certificate_Verify
     (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
      Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
      Sign => P256_Sign'Unrestricted_Access,
      Arena_Storage => Arena, Result => CV, Len => CV_Len);
   Check ("signer status Pending: CertificateVerify refused", CV_Len = 0);

   --  5c. TLS 1.2 client CertificateVerify through the callback (pre-hashed
   --  path: the signer gets the digest only). Correct, then corrupt, then
   --  refused; and Ed25519 refused before the signer is ever called.
   declare
      CV12  : Byte_Seq (0 .. Handshake.TLS12.Max_Certificate_Verify_12 - 1);
      L12   : N32;
      L12b  : N32;
      CV12b : Byte_Seq (0 .. Handshake.TLS12.Max_Certificate_Verify_12 - 1);
   begin
      Mode := 0;
      Handshake.TLS12.Build_Certificate_Verify_12
        (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
         Random => Fixed_Random'Unrestricted_Access, Sign => P256_Sign'Unrestricted_Access,
         Result => CV12, Len => L12);
      Check ("1.2 CV external (digest only): built", L12 > 8);
      Handshake.TLS12.Build_Certificate_Verify_12
        (Transcript_Hash => TH, Id => Key_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
         Random => Fixed_Random'Unrestricted_Access, Sign => null,
         Result => CV12b, Len => L12b);
      Check ("1.2 CV local and external byte-identical",
             L12 = L12b and then L12 > 0 and then CV12 (0 .. L12 - 1) = CV12b (0 .. L12b - 1));
      Mode := 1;
      Handshake.TLS12.Build_Certificate_Verify_12
        (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
         Random => Fixed_Random'Unrestricted_Access, Sign => P256_Sign'Unrestricted_Access,
         Result => CV12, Len => L12);
      Check ("1.2 CV external: corrupt signature rejected before the wire", L12 = 0);
      Mode := 2;
      Handshake.TLS12.Build_Certificate_Verify_12
        (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_ECDSA_P256_SHA256,
         Random => Fixed_Random'Unrestricted_Access, Sign => P256_Sign'Unrestricted_Access,
         Result => CV12, Len => L12);
      Check ("1.2 CV external: signer failure refused", L12 = 0);
      Mode := 0;
      Handshake.TLS12.Build_Certificate_Verify_12
        (Transcript_Hash => TH, Id => Pub_Id, Sig_Algo_Wire => Sig_Ed25519,
         Random => Fixed_Random'Unrestricted_Access, Sign => P256_Sign'Unrestricted_Access,
         Result => CV12, Len => L12);
      Check ("1.2 CV external: Ed25519 refused (no message available)", L12 = 0);
   end;

   --  5d. RSA through the callback, if an RSA identity was given: PSS on 1.3
   --  and PKCS#1 v1.5 on 1.2, each verified under the certificate; corrupt
   --  rejected.
   if Ada.Command_Line.Argument_Count >= 4 then
      declare
         RSA_Pub : aliased Identity;
         P_OK    : Boolean;
         CVr     : Byte_Seq (0 .. Handshake.TLS12.Max_Certificate_Verify_12 - 1);
         Lr      : N32;
      begin
         Credentials.Load_Identity (RSA_Id, Ada.Command_Line.Argument (3), Ada.Command_Line.Argument (4),
                                    Fixed_Random'Unrestricted_Access, RSA_OK);
         Credentials.Load_Identity_Public (RSA_Pub, Ada.Command_Line.Argument (3), P_OK);
         Check ("RSA identities load (private + public-only)", RSA_OK and P_OK and RSA_Pub.Sign_Algo = Sign_RSA_PSS);
         Mode := 0;
         Handshake.TLS13.Build_Certificate_Verify
           (Transcript_Hash => TH, Id => RSA_Pub, Sig_Algo_Wire => Sig_RSA_PSS_SHA256,
            Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
            Sign => RSA_Sign'Unrestricted_Access, Arena_Storage => Arena, Result => CVr, Len => Lr);
         Check ("1.3 CV external RSA-PSS: built and verified", Lr = 8 + RSA_Pub.RSA_Mod_Len);
         Mode := 1;
         Handshake.TLS13.Build_Certificate_Verify
           (Transcript_Hash => TH, Id => RSA_Pub, Sig_Algo_Wire => Sig_RSA_PSS_SHA256,
            Role => Role_Server, Random => Fixed_Random'Unrestricted_Access,
            Sign => RSA_Sign'Unrestricted_Access, Arena_Storage => Arena, Result => CVr, Len => Lr);
         Check ("1.3 CV external RSA-PSS: corrupt rejected", Lr = 0);
         Mode := 0;
         Handshake.TLS12.Build_Certificate_Verify_12
           (Transcript_Hash => TH, Id => RSA_Pub, Sig_Algo_Wire => Sig_RSA_PKCS1_SHA256,
            Random => Fixed_Random'Unrestricted_Access, Sign => RSA_Sign'Unrestricted_Access,
            Result => CVr, Len => Lr);
         Check ("1.2 CV external RSA PKCS#1: built and verified", Lr > 8);
         Mode := 1;
         Handshake.TLS12.Build_Certificate_Verify_12
           (Transcript_Hash => TH, Id => RSA_Pub, Sig_Algo_Wire => Sig_RSA_PKCS1_SHA256,
            Random => Fixed_Random'Unrestricted_Access, Sign => RSA_Sign'Unrestricted_Access,
            Result => CVr, Len => Lr);
         Check ("1.2 CV external RSA PKCS#1: corrupt rejected", Lr = 0);
         Mode := 0;
      end;
   end if;

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
