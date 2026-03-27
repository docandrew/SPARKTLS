--  SPARKTLS ECDSA P-384 Signature Verification
--  Uses RSA Big_Int infrastructure for field/group arithmetic.
--
--  Verification only - no signing, no key generation.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P384.ECDSA with
   SPARK_Mode => On
is
   --  Verify an ECDSA-P384-SHA384 signature.
   --
   --  Hash : the SHA-384 hash of the signed message (48 bytes)
   --  Qx   : public key X coordinate (48 bytes, big-endian)
   --  Qy   : public key Y coordinate (48 bytes, big-endian)
   --  R    : signature r value (48 bytes, big-endian)
   --  S    : signature s value (48 bytes, big-endian)
   --
   --  Returns True if the signature is valid.
   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   with Pre => Qx'First = 0 and Qx'Length = 48
               and Qy'First = 0 and Qy'Length = 48
               and R'First = 0 and R'Length = 48
               and S'First = 0 and S'Length = 48;

end SPARKTLS.P384.ECDSA;
