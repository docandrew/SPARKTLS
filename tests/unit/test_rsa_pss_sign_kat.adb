with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.RSA;

procedure Test_RSA_PSS_Sign_KAT is
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

   function From_Hex (S : String) return Byte_Seq is
      Result : Byte_Seq (0 .. N32 ((S'Length / 2) - 1));
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

   --  Key material: throwaway RSA-2048 pair generated 2026-09-14 with
   --    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
   --  (regenerated until the private exponent came out 255 bytes long).
   --  Expected_Sig_Hex was computed from Hash_Hex and Salt_Hex with an
   --  independent RFC 8017 9.1.1 EMSA-PSS-ENCODE (SHA-256, sLen 32) plus
   --  pow (EM, d, n), and cross-checked with `openssl pkeyutl -verify
   --  -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32`. The key
   --  exists only in this test source and protects nothing.
   Modulus_Hex : constant String :=
     "b9985cc5febf96119e9fc0d6f69f228c12da4c6754fa678558878b20e086c913"
   & "e6e98539a9c147c15ef2a65be21fe826f5f50a1832c0c7196626caab8ac55032"
   & "49293f45d631ac39a787879d0a8daa35cd6f39462c986b161d90030d8c90ee61"
   & "77229dfa99f97d34d22f6e4fa77847b7ff670d147c101620ffca93e622b401e7"
   & "18f65382fd4bc2315159dcf682cd5c876296263a0d88adfc037bbdcb147e3176"
   & "a5caa6b56d240360dbca535dc928152ff579219f57b0a7ce6ba90a5e43d9689f"
   & "4f33e957ba7f0127a106661edda82c2d92f008dc81b94454f8b40ab5deeef9bd"
   & "fc664cfe5ffa00f99a51b86813ec97f57c157c7989aef62a47de557b3d1acf5d";

   --  255-byte private exponent from the same key. The Identity loader
   --  must left-pad this to the 256-byte modulus size before signing.
   Priv_Exp_Hex : constant String :=
     "d620c20558b3a430daa0bd63b834f04a815969bf07618b00470e8cfdafd5d28c"
   & "4748de73cc8ac84611f79c3f74ba4d1751126d286fd7d089047620a5d86e871f"
   & "7d57aecc3277f243cb7ec47f47d1552576e6ffd11a77f8dc4b311c549ae046d2"
   & "c91a03e3b35ed7c8042a5185f8c770db0aad61b82b4eb955bce583cc4f84c339"
   & "7bd7b9bbe6b75bd8acb8ec5fa84a38f84261779aa2bc74954b276039a649bbe1"
   & "68232f9dfe9fb0f0c89805e5f0a8277a8f93079ba3bf6458e32179072744b2e5"
   & "a11ad12a87875624196ac82b720c1cffc61ebf223116ce97b08fd610fc12f2c9"
   & "2fd0ccc03a7757f0dadbbea6197a72290f2d6d3edb03fdada126d922782731";

   Hash_Hex : constant String :=
     "544e62cee8033709e389e5b2755343d0d0fa8c4850215cfb6331717e80d1aea3";

   Salt_Hex : constant String :=
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

   Expected_Sig_Hex : constant String :=
     "31e3200f98acc425b561349dc316e7879db5456d738325994b56d52df32ee5d0"
   & "09a33983d1c00a42e33f2a9f9f983f4c6135d9ac681cd97f1f8a1e1c444e1eb8"
   & "9a918054a89adbd1f253754862244bea4c926f1346ed6f60b9cf27feed2b1092"
   & "75f0fb88377da55c5761e98f26afdcb278dc11a17a817815014021260ff54fb7"
   & "5b9a74e60bd66b39d863b7a733c79a8170ae2b21d63dd05a41ccb0aff7fc4b99"
   & "e1eca69f84a079117542c11d0a532ce57d6f23c5ff269221edcb79f9099f8f80"
   & "46067adf087e94c04c11c0cedaaf9fe976b46cd9cbf147c7c86426034e779307"
   & "84ec73e18721e6ae359ab2e6c34a918d292aab5cc3d65079fba9668766fee2ff";

   Modulus      : constant Byte_Seq := From_Hex (Modulus_Hex);
   D_Unpadded   : constant Byte_Seq := From_Hex (Priv_Exp_Hex);
   Hash_BS      : constant Byte_Seq := From_Hex (Hash_Hex);
   Salt         : constant Byte_Seq := From_Hex (Salt_Hex);
   Expected_Sig : constant Byte_Seq := From_Hex (Expected_Sig_Hex);

   D      : Byte_Seq (0 .. 255) := (others => 0);
   Hash   : Bytes_32;
   Sig    : Byte_Seq (0 .. 255) := (others => 0);
   Sig_Len : N32;
   OK     : Boolean;
begin
   Put_Line ("RSA-PSS Sign KAT");
   Put_Line ("================");

   D (1 .. 255) := D_Unpadded;
   for I in N32 range 0 .. 31 loop
      Hash (I) := Hash_BS (I);
   end loop;

   SPARKTLSCrypto.RSA.Sign_PSS
     (M_Hash    => Hash_BS,
      Hash_Len  => 32,
      Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
      Modulus   => Modulus,
      Mod_Len   => 256,
      Priv_Exp  => D,
      Salt      => Salt,
      Signature => Sig,
      Sig_Len   => Sig_Len,
      OK        => OK);

   Check ("Sign_PSS succeeds", OK);
   Check ("Signature length is modulus length", Sig_Len = 256);
   Check ("Signature matches RFC 8017 PSS reconstruction",
          Sig = Expected_Sig);
   Check ("Generated signature verifies",
          SPARKTLSCrypto.RSA.Verify_PSS_SHA256
            (Hash      => Hash,
             Modulus   => Modulus,
             Mod_Len   => 256,
             Exponent  => 16#0001_0001#,
             Signature => Sig,
             Sig_Len   => Sig_Len));

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " /" & Total'Image);
   if Fail = 0 then
      Put_Line ("PASS");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line ("FAIL");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_RSA_PSS_Sign_KAT;
