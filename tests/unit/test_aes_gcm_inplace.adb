--  Equivalence test: AES_GCM.Encrypt vs Encrypt_InPlace MUST produce
--  byte-identical (ciphertext, tag) for the same (key, IV, AAD,
--  plaintext). Wycheproof exercises only Decrypt; Encrypt and
--  Encrypt_InPlace had ZERO KAT coverage before this test.
--
--  Sizes covered are the ones the TLS 1.3 record layer actually
--  hits — including the small (~9, ~37 byte) plaintexts produced
--  by encrypting a TLS 1.3 client Certificate (8 bytes) or
--  Finished (36 bytes), which is where mTLS bad_record_mac was
--  first observed against OpenSSL.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;

procedure Test_AES_GCM_InPlace is
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

   --  AES-128 round trip: encrypt with both APIs, compare.
   procedure Equiv_128 (Name : String; Plain_Len : N32) is
      Key : constant Bytes_32 :=
        (16#fe#, 16#ff#, 16#e9#, 16#92#, 16#86#, 16#65#, 16#73#, 16#1c#,
         16#6d#, 16#6a#, 16#8f#, 16#94#, 16#67#, 16#30#, 16#83#, 16#08#,
         others => 0);
      AES_K : constant AES.AES128_Key := AES.Construct (Key (0 .. 15));
      IV  : constant Bytes_12 :=
        (16#ca#, 16#fe#, 16#ba#, 16#be#, 16#fa#, 16#ce#,
         16#db#, 16#ad#, 16#de#, 16#ca#, 16#f8#, 16#88#);
      AAD : constant Byte_Seq (0 .. 4) :=
        (16#17#, 16#03#, 16#03#, 16#00#, 16#19#);
      Plain : Byte_Seq (0 .. Plain_Len - N32 (1));
      C_Sep : Byte_Seq (0 .. Plain_Len - N32 (1));
      Tag_Sep : Bytes_16;
      Buf_IP : Byte_Seq (0 .. Plain_Len - N32 (1));
      Tag_IP : Bytes_16;
      Match : Boolean := True;
   begin
      --  Fill Plain with a recognizable pattern.
      for I in Plain'Range loop
         Plain (I) := Byte (I mod 256);
      end loop;
      Buf_IP := Plain;

      SPARKTLSCrypto.AES_GCM.Encrypt
        (C => C_Sep, Tag => Tag_Sep,
         M => Plain, N => IV, K => AES_K, AAD => AAD);

      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Buf_IP, Tag => Tag_IP,
         N => IV, K => AES_K, AAD => AAD);

      --  Compare ciphertexts byte-by-byte.
      for I in C_Sep'Range loop
         if C_Sep (I) /= Buf_IP (I) then
            Match := False;
            exit;
         end if;
      end loop;
      Check (Name & ": ciphertext bytes match", Match);

      --  Compare tags.
      Match := True;
      for I in Tag_Sep'Range loop
         if Tag_Sep (I) /= Tag_IP (I) then
            Match := False;
            exit;
         end if;
      end loop;
      Check (Name & ": tag matches", Match);
   end Equiv_128;

begin
   Put_Line ("=== AES_GCM Encrypt vs Encrypt_InPlace equivalence ===");

   --  Sizes that hit each internal codepath:
   Equiv_128 ("9-byte (TLS empty Cert + inner_type)",  9);
   Equiv_128 ("37-byte (TLS Finished + inner_type)",   37);
   Equiv_128 ("64-byte (1-stripe boundary)",           64);
   Equiv_128 ("128-byte (2-stripe boundary)",          128);
   Equiv_128 ("256-byte (AVX-512 boundary)",           256);
   Equiv_128 ("1024-byte (full AVX-512 path)",         1024);
   Equiv_128 ("1500-byte (typical TLS app record)",    1500);

   New_Line;
   Put_Line ("=== AES_GCM_InPlace: " & Total'Image
             & " tests," & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_AES_GCM_InPlace;
