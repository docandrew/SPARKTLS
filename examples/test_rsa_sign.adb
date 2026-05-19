--  Quick test: load RSA key, sign with PSS, verify signature
with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Numerics.Discrete_Random;
with SPARKNaCl;             use SPARKNaCl;
with SPARKNaCl.Hashing.SHA256;
with SPARKTLS;              use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLS.RSA;

procedure Test_RSA_Sign is

   package Random_Byte is new
      Ada.Numerics.Discrete_Random (SPARKNaCl.Byte);
   Gen : Random_Byte.Generator;

   procedure My_Random (Output : out Byte_Seq) is
   begin
      for I in Output'Range loop
         Output (I) := Random_Byte.Random (Gen);
      end loop;
   end My_Random;

   Id    : aliased SPARKTLS.Identity;
   Id_OK : Boolean;

   Test_Msg : constant Byte_Seq (0 .. 31) := (others => 42);
   H        : SPARKNaCl.Hashing.SHA256.Digest;
   Salt     : Bytes_32;
   Sig      : Byte_Seq (0 .. 511) := (others => 0);
   Sig_Len  : N32;
   Sign_OK  : Boolean;
   Vfy_OK   : Boolean;
begin
   Random_Byte.Reset (Gen);

   Put_Line ("Loading RSA identity...");
   Credentials.Load_Identity
     (Id, "/tmp/rsa_test_cert.pem", "/tmp/rsa_test_key_pkcs8.pem", Id_OK);

   if not Id_OK then
      Put_Line ("FAIL: Load_Identity failed");
      return;
   end if;

   Put_Line ("  Sign_Algo: " & Id.Sign_Algo'Image);
   Put_Line ("  RSA_Mod_Len:" & Id.RSA_Mod_Len'Image);
   Put_Line ("  RSA_Pub_Exp:" & Id.RSA_Pub_Exp'Image);

   if Id.Sign_Algo /= Sign_RSA_PSS then
      Put_Line ("FAIL: expected Sign_RSA_PSS");
      return;
   end if;

   --  Hash the test message
   SPARKNaCl.Hashing.SHA256.Hash (H, Test_Msg);

   --  Generate salt
   My_Random (Byte_Seq (Salt));

   --  Sign
   Put_Line ("Signing with RSA-PSS-SHA256...");
   SPARKTLS.RSA.Sign_PSS
     (M_Hash    => Byte_Seq (H),
      Hash_Len  => 32,
      Hash_Alg  => SPARKTLS.RSA.PSS_SHA256,
      Modulus   => Id.RSA_Modulus,
      Mod_Len   => Id.RSA_Mod_Len,
      Priv_Exp  => Id.RSA_Priv_Exp,
      Salt      => Byte_Seq (Salt),
      Signature => Sig,
      Sig_Len   => Sig_Len,
      OK        => Sign_OK);

   if not Sign_OK then
      Put_Line ("FAIL: Sign_PSS returned False");
      return;
   end if;

   Put_Line ("  Sig_Len:" & Sig_Len'Image);

   --  Verify
   Put_Line ("Verifying...");
   Vfy_OK := SPARKTLS.RSA.Verify_PSS_SHA256
     (Hash      => H,
      Modulus   => Id.RSA_Modulus,
      Mod_Len   => Id.RSA_Mod_Len,
      Exponent  => Id.RSA_Pub_Exp,
      Signature => Sig,
      Sig_Len   => Sig_Len);

   if Vfy_OK then
      Put_Line ("PASS: signature verified");
   else
      Put_Line ("FAIL: signature verification failed");
   end if;
end Test_RSA_Sign;
