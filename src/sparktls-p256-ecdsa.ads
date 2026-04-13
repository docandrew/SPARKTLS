--  SPARKTLS ECDSA P-256 Signature Verification and Signing
--  Ported from BearSSL (Thomas Pornin, MIT license)

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P256.ECDSA with
   SPARK_Mode => On
is
   subtype ECDSA_Sig_Half is Byte_Seq (0 .. 31);

   function Verify
     (Hash : in Bytes_32;
      Qx   : in ECDSA_Sig_Half;
      Qy   : in ECDSA_Sig_Half;
      R    : in ECDSA_Sig_Half;
      S    : in ECDSA_Sig_Half) return Boolean;

   procedure Sign
     (Hash  : in     Bytes_32;
      D     : in     ECDSA_Sig_Half;
      K     : in     ECDSA_Sig_Half;
      R_Out :    out ECDSA_Sig_Half;
      S_Out :    out ECDSA_Sig_Half;
      OK    :    out Boolean);

end SPARKTLS.P256.ECDSA;
