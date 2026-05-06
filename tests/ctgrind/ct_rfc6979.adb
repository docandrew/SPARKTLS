--  Constant-time check for SPARKTLSCrypto.RFC6979.Derive_K_*.
--
--  This module is what we just wrote to fix the original ECDSA CT
--  bug — would be ironic if it had its own CT bug. The HMAC chain
--  is constant-time by construction; the part to vet is the
--  Reduce_And_Bias mod-N reduction (we wrote it with bitwise mask
--  selection but worth confirming).
--
--  Marks the private key D as undefined and runs both Derive_K_P256
--  and Derive_K_P384.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKTLSCrypto.RFC6979;
with Ctgrind;

procedure Ct_RFC6979 is
   --  Public hash inputs.
   H256 : constant Bytes_32 := (others => 16#A5#);
   H384 : constant Bytes_48 := (others => 16#A5#);

   --  Secret private keys.
   D256 : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
   D384 : Bytes_48 :=
     (16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
      16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#,
      16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
      16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#,
      16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#,
      16#48#, 16#49#, 16#4A#, 16#4B#, 16#4C#, 16#4D#, 16#4E#, 16#4F#);

   K256 : Bytes_32;
   K384 : Bytes_48;
begin
   Ctgrind.Make_Undefined
     (D256'Address, Interfaces.C.size_t (D256'Length));
   SPARKTLSCrypto.RFC6979.Derive_K_P256 (D256, H256, K256);
   --  K is also secret-derived — re-mark defined for the use sink.
   Ctgrind.Make_Defined
     (K256'Address, Interfaces.C.size_t (K256'Length));
   Ctgrind.Use_Output
     (K256'Address, Interfaces.C.size_t (K256'Length));

   Ctgrind.Make_Undefined
     (D384'Address, Interfaces.C.size_t (D384'Length));
   SPARKTLSCrypto.RFC6979.Derive_K_P384 (D384, H384, K384);
   Ctgrind.Make_Defined
     (K384'Address, Interfaces.C.size_t (K384'Length));
   Ctgrind.Use_Output
     (K384'Address, Interfaces.C.size_t (K384'Length));

   Put_Line ("ct_rfc6979: Derive_K_P256 + Derive_K_P384 completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_RFC6979;
