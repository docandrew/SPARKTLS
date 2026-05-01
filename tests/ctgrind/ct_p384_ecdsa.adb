--  Constant-time check for ECDSA-P-384 signing.
--  Same structure as ct_p256_ecdsa: mark D and K as undefined.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.ECDSA;
with Ctgrind;

procedure Ct_P384_ECDSA is
   Hash : constant Bytes_48 := (others => 16#A5#);

   D : Byte_Seq (0 .. 47) :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#,
      16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
      16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#);

   K : Byte_Seq (0 .. 47) :=
     (16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
      16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#,
      16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#,
      16#48#, 16#49#, 16#4A#, 16#4B#, 16#4C#, 16#4D#, 16#4E#, 16#4F#,
      16#50#, 16#51#, 16#52#, 16#53#, 16#54#, 16#55#, 16#56#, 16#57#,
      16#58#, 16#59#, 16#5A#, 16#5B#, 16#5C#, 16#5D#, 16#5E#, 16#5F#);

   R_Out, S_Out : Byte_Seq (0 .. 47);
   OK : Boolean;
begin
   Ctgrind.Make_Undefined (D'Address, Interfaces.C.size_t (D'Length));
   Ctgrind.Make_Undefined (K'Address, Interfaces.C.size_t (K'Length));

   SPARKTLSCrypto.P384.ECDSA.Sign (Hash, D, K, R_Out, S_Out, OK);

   Ctgrind.Make_Defined
     (R_Out'Address, Interfaces.C.size_t (R_Out'Length));
   Ctgrind.Make_Defined
     (S_Out'Address, Interfaces.C.size_t (S_Out'Length));
   Ctgrind.Use_Output
     (R_Out'Address, Interfaces.C.size_t (R_Out'Length));
   Ctgrind.Use_Output
     (S_Out'Address, Interfaces.C.size_t (S_Out'Length));

   Put_Line ("ct_p384_ecdsa: Sign completed (OK=" & OK'Image & ")");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_P384_ECDSA;
