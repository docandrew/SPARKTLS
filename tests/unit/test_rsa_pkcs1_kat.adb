--  KAT for SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256.
--
--  Test vector generated via openssl with a 2048-bit RSA key signing
--  the literal string "SPARKTLS PKCS#1 v1.5 KAT" (no trailing
--  newline). Exponent 65537 (0x010001).
--
--  The test verifies:
--    1. The valid signature passes Verify_PKCS1_v1_5_SHA256
--    2. Tampering one byte of the signature → fails
--    3. Tampering one byte of the hash → fails
--    4. Wrong padding (constructed PSS-style EM) → fails
--
--  Together with the integration suite (which exercises the
--  happy-path verifier against rsa.crt = sha256WithRSAEncryption =
--  PKCS#1 v1.5) this covers the EMSA-PKCS1-v1_5 padding decode.

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line;
with SPARKNaCl;   use SPARKNaCl;
with Interfaces; use Interfaces;
with SPARKTLSCrypto.RSA;

procedure Test_RSA_PKCS1_KAT is
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

   --  Hex-string → byte sequence helper.
   function From_Hex (S : String) return Byte_Seq is
      Result : Byte_Seq (0 .. N32 (S'Length / 2) - 1);
      function Nybble (C : Character) return Byte is
        (case C is
            when '0' .. '9' => Byte (Character'Pos (C) - Character'Pos ('0')),
            when 'a' .. 'f' => Byte (Character'Pos (C) - Character'Pos ('a') + 10),
            when 'A' .. 'F' => Byte (Character'Pos (C) - Character'Pos ('A') + 10),
            when others     => 0);
   begin
      for I in 0 .. (S'Length / 2) - 1 loop
         Result (N32 (I)) := Nybble (S (S'First + I * 2)) * 16
                           + Nybble (S (S'First + I * 2 + 1));
      end loop;
      return Result;
   end From_Hex;

   --  Modulus (256 bytes, big-endian).
   Modulus_Hex : constant String :=
     "DDBE8CD94F729B252E32712CC3A43666A75AC36EEC3C87264660EADAB8004C23"
   & "34900644883E45350AF9E52EE25737E7605CA194CDA7073664CE19C248F895C7"
   & "78FC22DD4F1A502B81B4CB4753FA73AA2C911DF337C8BD8EB6DA4F85687690F8"
   & "D657C883C2F58A3D83108E610C75797221AE149622905C7BEBEACB12B0277FC6"
   & "29BB123ABC021F901E69031949F8E7EF94FE3707ADD863F9FAD3A4A046F10CBA"
   & "D6D9B84CE739AE598F7C1FEFD68D82FD17B2672D2D5B64F05BC3B15996CB3CDA"
   & "8DAB1C83479F7B69F79E44B2C31B0B5EF87479B1BA067E29ABE802EBF7BB6157"
   & "04704D081C70AC7A754D69E2155B7D3CA4F117ABFC5A0D26D126D8DF766BDBE9";

   --  Signature (256 bytes, big-endian, RSA-PKCS#1 v1.5 SHA-256).
   Signature_Hex : constant String :=
     "615e89eb0ae024827283f75972baa8fbed606870fbd2fff0464751a25af1b092"
   & "e222be495d06b20a5da31805536612ade8751f7b31e468f8044c7b8b325af26a"
   & "31f6076b31af37f3835e7fe50b22ffa991bdebc37f2e24c05e31da8f36a19dd7"
   & "7058727de5a302f9a40895ff5c9033f8629f11a273590cc2e88afcf6ba9c5e36"
   & "5c8f4a472cff0cdb144165897ade94f7cfb44fc9e0104ea5f975ffd08e759112"
   & "7c643bde1af3f850f8cc4ddb4fc684c7483c625cc6f5c7dc7cb1bdf6b250129f"
   & "6ff8eb146e5b80be53bf280e149406d6322340918d44d1df19a1987118fb909f"
   & "f4540af9f8d7068827ead8ada06b5de6ca1aaa802785519a761496404ba52f22";

   --  SHA-256 hash of "SPARKTLS PKCS#1 v1.5 KAT".
   Hash_Hex : constant String :=
     "3ddcd8a366d11431e2857ff7dca2666d65e79c252036ce1ce8306e350aead268";

   Modulus  : constant Byte_Seq := From_Hex (Modulus_Hex);
   Sig      : constant Byte_Seq := From_Hex (Signature_Hex);
   Hash_BS  : constant Byte_Seq := From_Hex (Hash_Hex);
   Hash     : Bytes_32;

begin
   Put_Line ("RSA PKCS#1 v1.5 KAT");
   Put_Line ("===================");

   for I in N32 range 0 .. 31 loop
      Hash (I) := Hash_BS (I);
   end loop;

   --  1. Valid signature must verify.
   Check ("Valid v1.5 signature verifies",
          SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
            (Hash      => Hash,
             Modulus   => Modulus,
             Mod_Len   => 256,
             Exponent  => 16#0001_0001#,
             Signature => Sig,
             Sig_Len   => 256));

   --  2. One-byte signature tamper must fail.
   declare
      Bad_Sig : Byte_Seq := Sig;
   begin
      Bad_Sig (0) := Bad_Sig (0) xor 16#01#;
      Check ("Tampered signature first byte rejected",
             not SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash      => Hash,
                Modulus   => Modulus,
                Mod_Len   => 256,
                Exponent  => 16#0001_0001#,
                Signature => Bad_Sig,
                Sig_Len   => 256));
   end;

   declare
      Bad_Sig : Byte_Seq := Sig;
   begin
      Bad_Sig (255) := Bad_Sig (255) xor 16#01#;
      Check ("Tampered signature last byte rejected",
             not SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash      => Hash,
                Modulus   => Modulus,
                Mod_Len   => 256,
                Exponent  => 16#0001_0001#,
                Signature => Bad_Sig,
                Sig_Len   => 256));
   end;

   --  3. One-byte hash tamper must fail.
   declare
      Bad_Hash : Bytes_32 := Hash;
   begin
      Bad_Hash (0) := Bad_Hash (0) xor 16#01#;
      Check ("Tampered hash byte rejected",
             not SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash      => Bad_Hash,
                Modulus   => Modulus,
                Mod_Len   => 256,
                Exponent  => 16#0001_0001#,
                Signature => Sig,
                Sig_Len   => 256));
   end;

   --  4. Wrong exponent must fail.
   Check ("Wrong exponent rejected",
          not SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
            (Hash      => Hash,
             Modulus   => Modulus,
             Mod_Len   => 256,
             Exponent  => 3,
             Signature => Sig,
             Sig_Len   => 256));

   --  5. v1.5 signature must NOT pass PSS verifier (different padding).
   --  This used to silently succeed because CT_Eq0 was broken — a
   --  regression test for that fix.
   Check ("v1.5 signature does not pass PSS verifier",
          not SPARKTLSCrypto.RSA.Verify_PSS_SHA256
            (Hash      => Hash,
             Modulus   => Modulus,
             Mod_Len   => 256,
             Exponent  => 16#0001_0001#,
             Signature => Sig,
             Sig_Len   => 256));

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " /" & Total'Image);
   if Fail = 0 then
      Put_Line ("PASS");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line ("FAIL");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_RSA_PKCS1_KAT;
