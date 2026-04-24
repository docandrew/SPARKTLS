--  SPARKTLS Ed25519 — EdDSA signatures over Curve25519
--
--  Drop-in replacement for SPARKNaCl.Sign using Fiat Crypto
--  field arithmetic (5×51-bit limbs) for ~10x speedup.
--
--  Implements RFC 8032 Ed25519.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Ed25519 with
   SPARK_Mode => On
is
   --  Sign a message. SM receives the 64-byte signature followed by M.
   procedure Sign
     (SM : out Byte_Seq;
      M  : in  Byte_Seq;
      SK : in  Bytes_64)
   with Pre => SM'First = 0
               and SM'Length = M'Length + 64
               and M'First = 0;

   --  Verify a signed message. If valid, M(0..Msg_Len-1) holds the message.
   procedure Open
     (M       :    out Byte_Seq;
      Valid   :    out Boolean;
      Msg_Len :    out I32;
      SM      : in     Byte_Seq;
      PK      : in     Bytes_32)
   with Pre => SM'First = 0
               and SM'Length >= 64
               and M'First = 0
               and M'Length = SM'Length;

   --  Derive keypair from 32-byte seed.
   --  PK = public key (32 bytes), SK = secret key (64 bytes = seed || PK)
   procedure Keypair
     (Seed : in     Bytes_32;
      PK   :    out Bytes_32;
      SK   :    out Bytes_64);

   --  Compute clamp(N) * basepoint in Edwards, output as Montgomery u-coord.
   --  Used by X25519 keypair generation for fixed-base speedup.
   procedure Scalar_Mult_Base_To_Montgomery
     (U : out Bytes_32;
      N : in  Bytes_32);

end SPARKTLS.Ed25519;
