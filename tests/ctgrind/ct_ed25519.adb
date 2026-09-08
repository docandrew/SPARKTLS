--  Constant-time check for Ed25519 signing.
--
--  Marks the secret key (64 bytes = seed || PK) as undefined and
--  signs a fixed message. Any branch / memory access in the signing
--  path whose target depends on the secret key bytes will trigger
--  a memcheck error.
--
--  Particularly relevant: the scalar-multiply during signing uses
--  Edwards-form windowed arithmetic. If the window selection isn't
--  constant-time (e.g. if it indexes a precomputed table by secret
--  scalar bits), valgrind catches it as a secret-dependent load.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.Ed25519;
with Ctgrind;

procedure Ct_Ed25519 is
   M  : Byte_Seq (0 .. 31)  := (others => 16#A5#);  -- 32-byte plaintext
   SM : Byte_Seq (0 .. 95);                         -- 64 sig + 32 msg

   --  Secret key = 32-byte seed || 32-byte derived PK (we just put
   --  arbitrary bytes; valgrind doesn't care if it's a "real" key).
   SK : Bytes_64 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#,
      16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
      16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#,
      16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
      16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#);
begin
   Ctgrind.Make_Undefined (SK'Address, Interfaces.C.size_t (SK'Length));

   SPARKTLSCrypto.Ed25519.Sign (SM, M, SK);

   Ctgrind.Make_Defined (SM'Address, Interfaces.C.size_t (SM'Length));
   Ctgrind.Use_Output (SM'Address, Interfaces.C.size_t (SM'Length));

   Put_Line ("ct_ed25519: Sign completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Ed25519;
