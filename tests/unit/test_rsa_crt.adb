--  RSA CRT signing: the CRT path must produce exactly the plain-d
--  signature (PSS with a fixed salt is deterministic), verify under the
--  public key, and survive corrupted CRT parameters by falling back.
--  Usage: test_rsa_crt <cert.pem> <key.pem>

with Ada.Command_Line;
with Ada.Text_IO;   use Ada.Text_IO;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLSCrypto.RSA;

procedure Test_RSA_CRT is
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

   Id : SPARKTLS.Identity;
   OK : Boolean;
begin
   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("usage: test_rsa_crt <cert.pem> <key.pem>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   SPARKTLS.Credentials.Load_Identity
     (Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), OK);
   Check ("identity loads", OK and then Id.Sign_Algo = Sign_RSA_PSS);
   if not OK then
      Put_Line ("Total:" & Total'Image & " Pass:" & Pass'Image & " Fail:" & Fail'Image);
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;
   Put_Line ("  modulus bytes:" & Id.RSA_Mod_Len'Image
             & "  CRT loaded: " & Id.RSA_CRT.Valid'Image);

   --  A modulus with an odd byte count (e.g. 2056 bits) cannot carry
   --  balanced CRT primes; the loader leaves CRT off and signing runs
   --  the plain path. Its Decode/Encode of a non-word-multiple size is
   --  what this exercises.
   if Id.RSA_Mod_Len mod 2 = 1 then
      Check ("odd-size modulus: CRT left off", not Id.RSA_CRT.Valid);
      declare
         Hash : constant Bytes_32 := (others => 16#5A#);
         Salt : constant Bytes_32 := (others => 16#A5#);
         Sig  : Byte_Seq (0 .. N32 (Id.RSA_Mod_Len) - 1) := (others => 0);
         L    : N32;
         S_OK : Boolean;
      begin
         SPARKTLSCrypto.RSA.Sign_PSS
           (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
            Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
            Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
            Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
            Signature => Sig, Sig_Len => L, OK => S_OK,
            Pub_Exp => Id.RSA_Pub_Exp, CRT => Id.RSA_CRT);
         Check ("odd-size modulus: PSS sign OK", S_OK);
         Check ("odd-size modulus: PSS signature verifies",
                SPARKTLSCrypto.RSA.Verify_PSS_SHA256
                  (Hash => Hash, Modulus => Id.RSA_Modulus,
                   Mod_Len => Id.RSA_Mod_Len, Exponent => Id.RSA_Pub_Exp,
                   Signature => Sig, Sig_Len => L));
         SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
           (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
            Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
            Priv_Exp => Id.RSA_Priv_Exp,
            Signature => Sig, Sig_Len => L, OK => S_OK);
         Check ("odd-size modulus: PKCS1 sign OK", S_OK);
         Check ("odd-size modulus: PKCS1 signature verifies",
                SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
                  (Hash => Hash, Modulus => Id.RSA_Modulus,
                   Mod_Len => Id.RSA_Mod_Len, Exponent => Id.RSA_Pub_Exp,
                   Signature => Sig, Sig_Len => L));
      end;
      Put_Line ("Total:" & Total'Image & " Pass:" & Pass'Image & " Fail:" & Fail'Image);
      if Fail > 0 then
         Ada.Command_Line.Set_Exit_Status (1);
      end if;
      return;
   end if;

   Check ("CRT parameters present", Id.RSA_CRT.Valid);
   Check ("prime length is half the modulus",
          2 * Id.RSA_CRT.Prime_Len = Id.RSA_Mod_Len);
   if not Id.RSA_CRT.Valid then
      Put_Line ("Total:" & Total'Image & " Pass:" & Pass'Image & " Fail:" & Fail'Image);
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   declare
      Hash  : constant Bytes_32 := (others => 16#5A#);
      Salt  : constant Bytes_32 := (others => 16#A5#);
      Plain : Byte_Seq (0 .. N32 (Id.RSA_Mod_Len) - 1) := (others => 0);
      CRT   : Byte_Seq (0 .. N32 (Id.RSA_Mod_Len) - 1) := (others => 0);
      LP, LC : N32;
      OK_P, OK_C : Boolean;
      Bad   : SPARKTLSCrypto.RSA.CRT_Params := Id.RSA_CRT;
   begin
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => Plain, Sig_Len => LP, OK => OK_P);
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => CRT, Sig_Len => LC, OK => OK_C,
         Pub_Exp => Id.RSA_Pub_Exp, CRT => Id.RSA_CRT);
      Check ("plain sign OK", OK_P);
      Check ("CRT sign OK", OK_C);
      Check ("CRT signature = plain signature", LP = LC and then Plain = CRT);
      Check ("CRT signature verifies",
             SPARKTLSCrypto.RSA.Verify_PSS_SHA256
               (Hash => Hash, Modulus => Id.RSA_Modulus,
                Mod_Len => Id.RSA_Mod_Len, Exponent => Id.RSA_Pub_Exp,
                Signature => CRT, Sig_Len => LC));

      --  PKCS#1 v1.5 too (deterministic by construction)
      SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp,
         Signature => Plain, Sig_Len => LP, OK => OK_P);
      SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp,
         Signature => CRT, Sig_Len => LC, OK => OK_C,
         Pub_Exp => Id.RSA_Pub_Exp, CRT => Id.RSA_CRT);
      Check ("PKCS1 plain sign OK", OK_P);
      Check ("PKCS1 CRT sign OK", OK_C);
      Check ("PKCS1 CRT signature = plain", LP = LC and then Plain = CRT);
      Check ("PKCS1 CRT signature verifies",
             SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash => Hash, Modulus => Id.RSA_Modulus,
                Mod_Len => Id.RSA_Mod_Len, Exponent => Id.RSA_Pub_Exp,
                Signature => CRT, Sig_Len => LC));

      --  Corrupted dP: the verify-after-sign check must reject the CRT
      --  result and the fallback must still yield the right signature.
      Bad.DP (Bad.Prime_Len / 2) := Bad.DP (Bad.Prime_Len / 2) xor 16#01#;
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => Plain, Sig_Len => LP, OK => OK_P);
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => CRT, Sig_Len => LC, OK => OK_C,
         Pub_Exp => Id.RSA_Pub_Exp, CRT => Bad);
      Check ("corrupt dP: sign still OK (fallback)", OK_C);
      Check ("corrupt dP: signature = plain", LP = LC and then Plain = CRT);

      --  Corrupted qInv, same expectation.
      Bad := Id.RSA_CRT;
      Bad.QInv (Bad.Prime_Len - 1) := Bad.QInv (Bad.Prime_Len - 1) xor 16#80#;
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => CRT, Sig_Len => LC, OK => OK_C,
         Pub_Exp => Id.RSA_Pub_Exp, CRT => Bad);
      Check ("corrupt qInv: sign still OK (fallback)", OK_C);
      Check ("corrupt qInv: signature = plain", LP = LC and then Plain = CRT);

      --  Odd shapes are refused up front: prime length not half of n.
      Bad := Id.RSA_CRT;
      Bad.Prime_Len := Bad.Prime_Len - 1;
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => Id.RSA_Modulus, Mod_Len => Id.RSA_Mod_Len,
         Priv_Exp => Id.RSA_Priv_Exp, Salt => Byte_Seq (Salt),
         Signature => CRT, Sig_Len => LC, OK => OK_C,
         Pub_Exp => Id.RSA_Pub_Exp, CRT => Bad);
      Check ("short prime: sign still OK (fallback)", OK_C);
      Check ("short prime: signature = plain", LP = LC and then Plain = CRT);
   end;

   Put_Line ("Total:" & Total'Image & " Pass:" & Pass'Image & " Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_RSA_CRT;
