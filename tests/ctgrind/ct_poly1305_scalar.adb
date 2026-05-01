--  Constant-time check for the scalar fast Poly1305 (radix-2²⁶).
--
--  Marks the Poly1305 key as undefined and runs Onetimeauth. The
--  scalar Poly1305 has all the multiplication / carry / final-
--  reduction logic written in pure Ada — easier to inadvertently
--  introduce a secret-dependent branch than in the asm-only AVX-512
--  paths. A separate canary harness for this is worth keeping.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.MAC;
with SPARKTLSCrypto.Poly1305;
with Ctgrind;

procedure Ct_Poly1305_Scalar is
   M : Byte_Seq (0 .. 1023) := (others => 16#5A#);
   K_Bytes : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
   K   : SPARKNaCl.MAC.Poly_1305_Key;
   Tag : Bytes_16;
begin
   Ctgrind.Make_Undefined
     (K_Bytes'Address, Interfaces.C.size_t (K_Bytes'Length));
   SPARKNaCl.MAC.Construct (K, K_Bytes);

   SPARKTLSCrypto.Poly1305.Onetimeauth (Tag, M, K);

   Ctgrind.Make_Defined (Tag'Address, Interfaces.C.size_t (Tag'Length));
   Ctgrind.Use_Output (Tag'Address, Interfaces.C.size_t (Tag'Length));

   Put_Line ("ct_poly1305_scalar: Onetimeauth completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Poly1305_Scalar;
