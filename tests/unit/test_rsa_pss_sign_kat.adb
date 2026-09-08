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

   Modulus_Hex : constant String :=
     "bdc2209f486e3aaf30834aa63b7a23f9de761a77cd73afa42cbfda08858e5f7c"
   & "b3e948fe4ca66a087f8052dc85675798694c3e5019429a85e98c53aea1d943ac"
   & "b40c9bd5c0597bbfcb7e451ff34297f7737f5c954c67790260f53edcdf8d6b"
   & "d970644a60f459ce27588119ceeab5e975e24132a969d04fc681701f47ad45"
   & "8f65dcf73548a5dd9bdd6aca650283fe8d875c714894653a74988186f750d"
   & "b2d10d2f73b0110b74d4ade3383ec78c5b2829bf0b13d279f207b35d022"
   & "3aecf9393c1eeb383d268f8eeddbc26a95b2b389862d34e3a341a79b478"
   & "f97436ac84be897f2641ec2958955d1195fdf9bf742a3aa26f5022bb70c"
   & "b3166a8b88eac5bc6559e1";

   --  255-byte private exponent from the same key. The Identity loader
   --  must left-pad this to the 256-byte modulus size before signing.
   Priv_Exp_Hex : constant String :=
     "458d6212554f673324bfa57248affc2a6f3530290ea52de67f2b283fa209b7"
   & "f627fb849b067d4e0acf5bb9ae1a8cf10e6c34b0a255f53e58d717183fbf"
   & "68633b14c38a5af9507de0a435cecb11ded6d4b1ab7d193c12b11d58c1"
   & "e0c8bf27ec3546d226710dc9dcf0e455184b3f6718ab476d9e4ecfa4b"
   & "598e22e0bf3b9b99aaa99d4bb78a23fd3294faa4cd62a95f998112b37"
   & "5263ea9f6cc2ce1980af536ab2de32041eb1fcbc43c31311e89577a85"
   & "bbf3063799495742a1c988eff6f096c3ae8d2df34d0b103972982ff1f"
   & "5fa8737b09a43ab3a9804665f05c66334a8da342372f319a5463c7d040"
   & "71550a8fc8e8d7fb53c1d1c9ba45d34c8869b7363803";

   Hash_Hex : constant String :=
     "544e62cee8033709e389e5b2755343d0d0fa8c4850215cfb6331717e80d1aea3";

   Salt_Hex : constant String :=
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

   Expected_Sig_Hex : constant String :=
     "36de270276d25b9a70c4306ed58ab9126f9b863b2dbbedadf3b86766871c151"
   & "74ec83e3ab2b1e24b543db0c2b249eec349c4cccf051bd61a42ccb74af893"
   & "87b3a3a27697627ed7a5158846060c118dd79f8b2c69422672b0ba258244"
   & "24539bd4c2875dbeb8d502b694bf1c2e22393791b58d60a476a57201493"
   & "504f9ba695bf4e00e2c1bbad50a331b0d26d9f0ebcfdc035905868de22"
   & "17ed0e57b8f926637d709110a0817271647385ca74a186d61ddd5c8d42"
   & "222355465e7f9469693fb2045f6972e8c75b2f765981eb85b603279360"
   & "8211bc743a5ab3c3e1d3a68f7d4b521adfb3e0f13948fe22ffa5de539"
   & "ccbff4361a3a0fc78825fc8e7a6f7d0dd5ee8e";

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
