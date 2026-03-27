--  SPARKTLS ECDSA P-256 Signature Verification
--  Ported from BearSSL (Thomas Pornin, MIT license)
--
--  Verification only - no signing, no key generation.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P256.ECDSA with
   SPARK_Mode => On
is
   --  ECDSA signature (r, s) - each 32 bytes, big-endian
   subtype ECDSA_Sig_Half is Byte_Seq (0 .. 31);

   --  Verify an ECDSA-P256-SHA256 signature.
   --
   --  Hash : the SHA-256 hash of the signed message (32 bytes)
   --  Qx   : public key X coordinate (32 bytes, big-endian)
   --  Qy   : public key Y coordinate (32 bytes, big-endian)
   --  R    : signature r value (32 bytes, big-endian)
   --  S    : signature s value (32 bytes, big-endian)
   --
   --  Returns True if the signature is valid.
   function Verify
     (Hash : in Bytes_32;
      Qx   : in ECDSA_Sig_Half;
      Qy   : in ECDSA_Sig_Half;
      R    : in ECDSA_Sig_Half;
      S    : in ECDSA_Sig_Half) return Boolean;

end SPARKTLS.P256.ECDSA;
