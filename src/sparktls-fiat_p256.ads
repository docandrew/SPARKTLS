--  SPARKTLS Fiat P-256 — Formally verified field arithmetic
--
--  Faithful SPARK Ada port of fiat-crypto's p256_64.c
--  (MIT PLV, Coq-proven, word-by-word Montgomery, 4×64-bit limbs)

with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;

package SPARKTLS.Fiat_P256 with
   SPARK_Mode => On
is
   type FE is array (0 .. 3) of Unsigned_64;

   FE_One : constant FE :=
     (16#0000_0000_0000_0001#,
      16#FFFF_FFFF_0000_0000#,
      16#FFFF_FFFF_FFFF_FFFF#,
      16#0000_0000_FFFF_FFFE#);

   FE_Zero : constant FE := (others => 0);

   P256_Prime : constant FE :=
     (16#FFFF_FFFF_FFFF_FFFF#,
      16#0000_0000_FFFF_FFFF#,
      16#0000_0000_0000_0000#,
      16#FFFF_FFFF_0000_0001#);

   ----------------------------------------------------------------
   --  Field arithmetic (all in Montgomery domain)
   --  Functions to avoid SPARK aliasing issues.
   ----------------------------------------------------------------

   function Mul (Arg1, Arg2 : FE) return FE with Inline;
   function Sqr (Arg1 : FE) return FE with Inline;
   function Add (Arg1, Arg2 : FE) return FE with Inline;
   function Sub (Arg1, Arg2 : FE) return FE with Inline;
   function Opp (Arg1 : FE) return FE with Inline;
   function From_Montgomery (Arg1 : FE) return FE with Inline;
   function To_Montgomery (Arg1 : FE) return FE with Inline;
   function Selectznz (Cond : Unsigned_64; Arg2, Arg3 : FE) return FE
   with Inline;
   function From_Bytes (Arg1 : Byte_Seq) return FE
   with Pre => Arg1'Length = 32;

   --  To_Bytes must stay a procedure (output is Byte_Seq with caller bounds)
   procedure To_Bytes (Out1 : out Byte_Seq; Arg1 : FE)
   with Pre => Out1'Length = 32;

   --  Returns 1 if arg1 is nonzero, 0 otherwise
   procedure Nonzero (Out1 : out Unsigned_64; Arg1 : FE);

end SPARKTLS.Fiat_P256;
