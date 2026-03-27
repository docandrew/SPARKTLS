with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA384;

--  HMAC-SHA-384 (RFC 2104)
--
--  Built on SPARKNaCl.Hashing.SHA384.
--  SHA-384 block size = 128 bytes, digest = 48 bytes.
package SPARKTLS.HMAC384 with
   SPARK_Mode => On
is
   subtype Digest_384 is SPARKNaCl.Hashing.SHA384.Digest;

   procedure HMAC_SHA_384
     (Output :    out Digest_384;
      M      : in     Byte_Seq;
      K      : in     Byte_Seq)
   with Pre => M'First = 0 and
               M'Last <= N32'Last - 128 and
               (if K'Length > 0 then K'First = 0);

end SPARKTLS.HMAC384;
