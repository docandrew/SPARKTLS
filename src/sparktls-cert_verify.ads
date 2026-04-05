with SPARKNaCl; use SPARKNaCl;
with X509;

--  Certificate Signature & Chain Verification
--
--  Verifies certificate signatures and validates certificate chains.
--  Uses SPARKTLS crypto (RSA-PSS, ECDSA P-256/P-384, Ed25519).
package SPARKTLS.Cert_Verify with
   SPARK_Mode => On
is
   --  Verify a certificate's signature against its issuer's public key.
   function Verify_Cert_Signature
     (Cert_DER : Byte_Seq;
      Cert     : X509.Certificate;
      Issuer   : X509.Certificate) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last;

   --  Validation result
   type Validation_Result is
     (Valid,
      Err_Parse_Failed,
      Err_Expired,
      Err_Unknown_Critical,
      Err_Unknown_Algorithm,
      Err_Signature_Invalid,
      Err_Not_CA,
      Err_Path_Length_Exceeded,
      Err_Hostname_Mismatch,
      Err_No_Trust_Anchor);

   --  Validate a trust anchor (root CA).
   --  Checks: structural validity, CA flag, known algorithms, date validity.
   --  Does NOT verify the root's self-signature (trust anchors are trusted
   --  by definition, and self-signature verification is not required by
   --  RFC 5280 §6.1).
   function Validate_Root
     (Root : X509.Certificate;
      Now  : X509.Date_Time) return Validation_Result
   with Post =>
     (if Validate_Root'Result = Valid then
        --  RFC 5280 §6.1.1(d): trust anchor must parse
        X509.Is_Valid (Root)
        --  RFC 5280 §4.2: no unrecognized critical extensions
        and not X509.Has_Unknown_Critical_Extension (Root)
        --  RFC 5280 §4.1.2.5: must be within validity period
        and X509.Is_Date_Valid (Root, Now)
        --  RFC 5280 §4.2.1.9: trust anchor must be CA
        and X509.Is_CA (Root)
        --  Full structural validity (encoding, extensions, etc.)
        and X509.Is_Structurally_Valid (Root, Now));

   --  Maximum chain depth (end-entity + intermediates)
   Max_Chain_Depth : constant := 10;

   --  Validate a single certificate against its issuer.
   --  Checks: structural validity, signature, CA constraint, path length.
   --  Chain_Depth = number of certs below this one in the chain
   --  (0 for end-entity, 1+ for intermediates).
   function Validate_Cert
     (Cert_DER    : Byte_Seq;
      Cert        : X509.Certificate;
      Issuer      : X509.Certificate;
      Now         : X509.Date_Time;
      Must_Be_CA  : Boolean;
      Chain_Depth : Natural := 0) return Validation_Result
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last;

end SPARKTLS.Cert_Verify;
