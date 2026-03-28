with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA384;

--  HKDF with SHA-384 (RFC 5869)
--
--  Mirror of SPARKNaCl.HKDF but using SHA-384 (48-byte digest).
--  Needed for TLS_AES_256_GCM_SHA384 cipher suite.
package SPARKTLS.HKDF384 with
   SPARK_Mode => On
is
   Hash_Len : constant := 48;

   subtype Digest_384 is SPARKNaCl.Hashing.SHA384.Digest;

   subtype OKM384_Index is N32 range 0 .. Hash_Len * 255 - 1;
   type OKM384_Seq is array (OKM384_Index range <>) of Byte;

   procedure Extract
     (PRK  :    out Digest_384;
      IKM  : in     Byte_Seq;
      Salt : in     Byte_Seq)
   with Pre => IKM'First = 0 and
               IKM'Length > 0 and
               IKM'Last <= N32'Last - 128 and
               (if Salt'Length > 0 then Salt'First = 0);

   procedure Expand
     (OKM  :    out OKM384_Seq;
      PRK  : in     Digest_384;
      Info : in     Byte_Seq)
   with Pre => OKM'First = 0 and
               OKM'Length > 0 and
               OKM'Length <= 255 * Hash_Len and
               (if Info'Length > 0 then Info'First = 0) and
               Info'Last < N32'Last - 256;

end SPARKTLS.HKDF384;
