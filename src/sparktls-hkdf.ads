--  SPARKTLS HKDF — HKDF-SHA-256 (RFC 5869)
--
--  Derived from SPARKNaCl.HKDF (R. Chapman, MIT license).
--  Uses SPARKTLS.MAC.HMAC_SHA_256 (SHA-NI accelerated) internally.

with SPARKTLS.Hashing.SHA256;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.HKDF with
   SPARK_Mode => On
is
   Hash_Len : constant := 32;

   subtype OKM_Index is N32 range 0 .. Hash_Len * 255 - 1;
   type OKM_Seq is array (OKM_Index range <>) of Byte;

   procedure Extract (PRK  :    out Hashing.SHA256.Digest;
                      IKM  : in     Byte_Seq;
                      Salt : in     Byte_Seq)
   with Global => null,
        Pre    => PRK'First = 0 and
                  IKM'First = 0 and
                  IKM'Length > 0 and
                  IKM'Length < U32 (N32'Last - 64) and
                  (if Salt'Length > 0 then Salt'First = 0);

   procedure Expand (OKM  :    out OKM_Seq;
                     PRK  : in     Hashing.SHA256.Digest;
                     Info : in     Byte_Seq)
   with Global => null,
        Relaxed_Initialization => OKM,
        Pre    => OKM'First = 0 and
                  OKM'Length > 0 and
                  OKM'Length <= 255 * Hash_Len and
                  PRK'First = 0 and
                  (if Info'Length > 0 then Info'First = 0) and
                  Info'Length < U32 (N32'Last) - 97,
        Post   => OKM'Initialized;

end SPARKTLS.HKDF;
