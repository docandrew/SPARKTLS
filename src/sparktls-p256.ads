--  SPARKTLS P-256 Field Arithmetic
--
--  Field elements use Fiat Crypto's 4×64-bit Montgomery representation
--  (Coq-verified, ported from fiat-crypto p256_64.c).
--
--  Legacy 9×30-bit representation retained for ECDSA scalar arithmetic.

with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with SPARKTLS.Fiat_P256;

package SPARKTLS.P256 with
   SPARK_Mode => On
is
   ---------------------------------------------------------------
   --  Field element type (4×64-bit Montgomery, from Fiat Crypto)
   ---------------------------------------------------------------
   subtype P256_FE is SPARKTLS.Fiat_P256.FE;

   --  Zero and one in Montgomery domain
   FE_Zero : constant P256_FE := SPARKTLS.Fiat_P256.FE_Zero;
   FE_One  : constant P256_FE := SPARKTLS.Fiat_P256.FE_One;

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
      Dst : in out P256_FE;
      Src : in     P256_FE) with Inline;

   ---------------------------------------------------------------
   --  Field arithmetic mod p (delegated to Fiat Crypto)
   ---------------------------------------------------------------

   procedure Add_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE) with Inline;

   procedure Sub_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE) with Inline;

   procedure Mul_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE) with Inline;

   procedure Square_F256
     (D :    out P256_FE;
      A : in     P256_FE) with Inline;

   ---------------------------------------------------------------
   --  Byte conversion (big-endian 32 bytes <-> Montgomery FE)
   ---------------------------------------------------------------

   --  Big-endian 32 bytes -> Montgomery field element
   procedure Bytes_To_FE
     (Dst : out P256_FE;
      Src : in  Byte_Seq)
   with Pre => Src'Length = 32;

   --  Montgomery field element -> big-endian 32 bytes
   procedure FE_To_Bytes
     (Dst : out Byte_Seq;
      Src : in  P256_FE)
   with Pre => Dst'Length = 32;

   --  Check if FE is zero
   function FE_Is_Zero (A : P256_FE) return Boolean;

   ---------------------------------------------------------------
   --  Legacy 30-bit representation (for ECDSA scalar arithmetic)
   ---------------------------------------------------------------

   Limb_Mask : constant U32 := 16#3FFF_FFFF#;
   subtype Limb_Index is I32 range 0 .. 8;
   subtype Wide_Index  is I32 range 0 .. 17;

   type P256_Limbs is array (Limb_Index) of U32;
   type P256_Wide  is array (Wide_Index)  of U32;

   procedure Mul9
     (D :    out P256_Wide;
      A : in     P256_Limbs;
      B : in     P256_Limbs);

   procedure Square9
     (D :    out P256_Wide;
      A : in     P256_Limbs);

   --  Big-endian 32 bytes -> 9×30-bit limbs (for scalar arithmetic)
   procedure BE8_To_LE30
     (Dst : out P256_Limbs;
      Src : in  Byte_Seq)
   with Pre => Src'Length = 32;

   --  9×30-bit limbs -> big-endian 32 bytes
   procedure LE30_To_BE8
     (Dst : out Byte_Seq;
      Src : in  P256_Limbs)
   with Pre => Dst'Length = 32;

   --  N order in 30-bit representation (used by ECDSA)
   N_Order : constant P256_Limbs :=
     (16#2551_FC63#, 16#0215_D28A#, 16#2F1B_E659#, 16#3EBC_E6FA#,
      16#3FFF_FFFF#, 16#3FFF_FFFF#, 16#0000_003F#, 16#3FFF_C000#,
      16#0000_FFFF#);

end SPARKTLS.P256;
