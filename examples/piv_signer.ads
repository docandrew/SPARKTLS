--  PIV_Signer: a SPARKTLS.Sign_Fn whose private key lives in a PIV token
--  (a YubiKey). ECDSA P-256 and P-384 (the token signs the digest SPARKTLS
--  supplies and returns the DER signature TLS wants) and Ed25519 (firmware
--  5.7+, the token signs the message). RSA slots are Failed for now: the
--  card does the raw exponentiation and the PKCS#1 encoding is not here yet.
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS;  use SPARKTLS;
with PIV;

package PIV_Signer is

   --  Select the applet, verify the PIN and remember the slot. Cert
   --  receives the slot's certificate (DER) for Set_Identity_Public.
   procedure Init
     (S        : PIV.Slot;
      PIN      : String;
      Cert     : out Byte_Seq;
      Cert_Len : out N32;
      OK       : out Boolean;
      Why      : out PIV.Status);

   procedure Sign
     (Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status);

end PIV_Signer;
