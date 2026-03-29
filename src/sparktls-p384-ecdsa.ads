--  SPARKTLS ECDSA P-384 Signature Verification
--  Uses SPARK-proven BigNat for group order arithmetic.
--
--  Verification only - no signing, no key generation.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P384.ECDSA with
   SPARK_Mode => On
is
   --  Verify an ECDSA-P384-SHA384 signature.
   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   with SPARK_Mode => Off;

end SPARKTLS.P384.ECDSA;
