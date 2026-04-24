--  SPARKTLS X25519 — Curve25519 Diffie-Hellman (RFC 7748)
--
--  5×51-bit limb representation for ~10x speedup over SPARKNaCl's
--  16×16-bit limbs. Uses Unsigned_128 for partial products.
--
--  API matches SPARKNaCl.Scalar.Mult for drop-in replacement.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.X25519 with
   SPARK_Mode => On
is
   --  Compute Q = clamp(N) * P on Curve25519.
   --  N: 32-byte scalar (secret key / nonce)
   --  P: 32-byte x-coordinate (public key / basepoint)
   --  Q: 32-byte x-coordinate (shared secret)
   --  Variable-base: Q = clamp(N) * P (Montgomery ladder)
   procedure Scalar_Mult
     (Q : out Bytes_32;
      N : in  Bytes_32;
      P : in  Bytes_32);

   --  Fixed-base: Q = clamp(N) * basepoint(9)
   --  Uses windowed Edwards internally for ~2x speedup over Scalar_Mult.
   procedure Scalar_Mult_Base
     (Q : out Bytes_32;
      N : in  Bytes_32);

   --  Test helper: encode(decode(input)) round-trip
   --  Test helper: FE multiply two encoded values
   procedure Test_FE_Mul
     (A, B   : in  Bytes_32;
      Result : out Bytes_32);

   procedure Test_Encode_Decode
     (Input  : in  Bytes_32;
      Output : out Bytes_32);

end SPARKTLS.X25519;
