--  SPARKTLS P-256 Field Arithmetic
--  Ported from BearSSL's ec_p256_m31.c (Thomas Pornin, MIT license)
--
--  Representation: 9 limbs of 30 bits each (little-endian), for values
--  up to 2^270-1. The top limb (index 8) holds only 16 bits for a
--  fully reduced value.
--
--  Field operations produce results less than 2*p (partially reduced).
--  Use Reduce_Final to get a fully reduced canonical value.

with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;

package SPARKTLS.P256 with
   SPARK_Mode => On
is
   --  30-bit limb mask
   Limb_Mask : constant U32 := 16#3FFF_FFFF#;

   --  Index types
   subtype Limb_Index   is I32 range 0 .. 8;
   subtype Wide_Index   is I32 range 0 .. 17;

   --  Field element: 9 x 30-bit limbs (little-endian)
   type P256_Limbs is array (Limb_Index) of U32;

   --  Wide product: 18 x 30-bit limbs
   type P256_Wide is array (Wide_Index) of U32;

   --  Signed wide intermediate for reduction
   type P256_Wide_S is array (Wide_Index) of I64;

   --  The prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
   --  in 30-bit limb representation
   F256 : constant P256_Limbs :=
     (16#3FFF_FFFF#, 16#3FFF_FFFF#, 16#3FFF_FFFF#, 16#0000_003F#,
      16#0000_0000#, 16#0000_0000#, 16#0000_1000#, 16#3FFF_C000#,
      16#0000_FFFF#);

   --  Curve coefficient b for y^2 = x^3 - 3x + b
   P256_B : constant P256_Limbs :=
     (16#27D2_604B#, 16#2F38_F0F8#, 16#053B_0F63#, 16#0741_AC33#,
      16#1886_BC65#, 16#2EF5_55DA#, 16#293E_7B3E#, 16#0D76_2A8E#,
      16#0000_5AC6#);

   --  Zero field element
   FE_Zero : constant P256_Limbs := (others => 0);

   --  One field element
   FE_One : constant P256_Limbs := (0 => 1, others => 0);

   ---------------------------------------------------------------
   --  Constant-time helpers
   ---------------------------------------------------------------

   --  Returns 1 if A /= B, else 0 (constant-time)
   function CT_NEQ (A, B : U32) return U32 with Inline;

   --  Returns 1 if A = B, else 0 (constant-time)
   function CT_EQ (A, B : U32) return U32 with Inline;

   --  Constant-time conditional copy: if Ctl = 1, copy Src to Dst
   procedure CT_Copy
     (Ctl : in     U32;
      Dst : in out P256_Limbs;
      Src : in     P256_Limbs) with Inline;

   ---------------------------------------------------------------
   --  Schoolbook multiply / square (produces 18-limb wide result)
   ---------------------------------------------------------------

   procedure Mul9
     (D :    out P256_Wide;
      A : in     P256_Limbs;
      B : in     P256_Limbs);

   procedure Square9
     (D :    out P256_Wide;
      A : in     P256_Limbs);

   ---------------------------------------------------------------
   --  Field arithmetic mod p
   ---------------------------------------------------------------

   --  D := A + B mod (partially reduced, < 2p)
   procedure Add_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs);

   --  D := A - B mod (adds 2p to ensure positive, < 2p)
   procedure Sub_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs);

   --  D := A * B mod p (partially reduced, < 2p)
   procedure Mul_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs);

   --  D := A^2 mod p (partially reduced, < 2p)
   procedure Square_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs);

   --  Final reduction: if D >= p, subtract p.
   --  Did_Reduce is 1 if subtraction was performed, 0 otherwise.
   procedure Reduce_Final_F256
     (D          : in out P256_Limbs;
      Did_Reduce :    out U32);

   ---------------------------------------------------------------
   --  Byte conversion
   ---------------------------------------------------------------

   --  Big-endian 32 bytes -> 9 x 30-bit limbs (little-endian)
   procedure BE8_To_LE30
     (Dst : out P256_Limbs;
      Src : in  Byte_Seq)
   with Pre => Src'Length = 32;

   --  9 x 30-bit limbs (little-endian) -> big-endian 32 bytes
   procedure LE30_To_BE8
     (Dst : out Byte_Seq;
      Src : in  P256_Limbs)
   with Pre => Dst'Length = 32;

end SPARKTLS.P256;
