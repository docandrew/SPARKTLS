--  SPARKTLS Fiat Curve25519 — GF(2^255-19) field arithmetic
--
--  Faithful SPARK Ada port of fiat-crypto's curve25519_64.c
--  (MIT PLV, Coq-proven, unsaturated Solinas, 5×51-bit limbs)
--
--  Shared by X25519 (ECDHE) and Ed25519 (signatures).

with Interfaces; use Interfaces;

package SPARKTLS.Fiat_25519 with
   SPARK_Mode => On
is
   --  Field element: 5 × 51-bit limbs (unsaturated radix-2^51)
   type FE is array (0 .. 4) of Unsigned_64;

   Mask51 : constant Unsigned_64 := 16#7_FFFF_FFFF_FFFF#;

   FE_Zero : constant FE := (others => 0);
   FE_One  : constant FE := (1, 0, 0, 0, 0);

   --  carry_mul: multiply two field elements, produce tight result
   --  Fiat bounds: tight = [0, 2^51], loose = [0, 3*2^51]
   --  carry_mul/carry_square: loose in → tight out (with carry)
   --  add/sub: tight in → loose out
   function Is_Loose (F : FE) return Boolean is
     (for all I in 0 .. 4 => F (I) <= 16#18_0000_0000_0000#)
   with Ghost;

   function Is_Carried (F : FE) return Boolean is
     (for all I in 0 .. 4 => F (I) <= Mask51)
   with Ghost;

   function Mul (A, B : FE) return FE
   with Inline,
        Pre  => Is_Loose (A) and Is_Loose (B),
        Post => Is_Carried (Mul'Result);

   function Sqr (A : FE) return FE
   with Inline,
        Pre  => Is_Loose (A),
        Post => Is_Carried (Sqr'Result);

   --  add: carried in → loose out
   function Add (A, B : FE) return FE
   with Inline,
        Pre  => Is_Carried (A) and Is_Carried (B),
        Post => Is_Loose (Add'Result);

   --  sub: carried in → loose out
   function Sub (A, B : FE) return FE
   with Inline,
        Pre  => Is_Carried (A) and Is_Carried (B),
        Post => Is_Loose (Sub'Result);

   --  carry: reduce loose field element to tight
   procedure Carry (F : in out FE)
   with Inline,
        Post => Is_Carried (F);

   --  carry_scmul: multiply by small scalar with carry
   function Scmul (A : FE; S : Unsigned_64) return FE
   with Inline,
        Pre  => Is_Loose (A) and S <= 131071,
        Post => Is_Carried (Scmul'Result);

   --  constant-time conditional swap
   procedure CSwap (A, B : in out FE; Swap : Unsigned_64)
   with Inline,
        Pre  => Swap <= 1 and Is_Carried (A) and Is_Carried (B),
        Post => Is_Carried (A) and Is_Carried (B);

   --  field inversion: a^(p-2) mod p via addition chain
   function Inv (Z : FE) return FE
   with Pre  => Is_Carried (Z),
        Post => Is_Carried (Inv'Result);

end SPARKTLS.Fiat_25519;
