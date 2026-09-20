--  Software_Signer: a SPARKTLS.Sign_Fn backed by a private key held in
--  this process. It is the "signer" half of the external-signature path
--  for tests and examples: the TLS side runs with a
--  public-only identity and never touches the key; every signature goes
--  through Sign below, exactly as it would to a YubiKey, TPM or HSM.
--
--  Moving this package into a separate process behind a Unix socket gives
--  the privilege-separated signer; replacing its body with PIV APDUs gives
--  the YubiKey signer. The TLS side is unchanged in every case.
--
--  Example code: not SPARK, uses the example entropy source.
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS;  use SPARKTLS;

package Software_Signer is

   --  Load the private identity this signer will use. Cert_Path is needed
   --  only so Set_Identity can check the key against the certificate.
   procedure Init (Cert_Path, Key_Path : String; OK : out Boolean);

   --  The SPARKTLS.Sign_Fn. Signs Message or Digest as the scheme needs
   --  and returns the signature as TLS carries it.
   procedure Sign
     (Id      : in     Identity;
      Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status);

   --  Test hook: when True, Sign returns a wrong (bit-flipped) signature so
   --  a test can check that SPARKTLS's verify-before-wire rejects it.
   Corrupt_Output : Boolean := False;

   --  Test hook: when True, Sign reports Failed without signing.
   Refuse : Boolean := False;

end Software_Signer;
