--  SPARKTLS.Credentials.Parsing — SPARK-verified credential parsing
--
--  Pure parsing of PKCS#8 keys and PEM-encoded identities.
--  No file I/O — operates on in-memory byte/string buffers.
--  SPARK_Mode On: formally verified for memory safety.

with X509;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS.PEM;

package SPARKTLS.Credentials.Parsing with
   SPARK_Mode => On
is
   --  Extract raw key bytes from a PKCS#8 DER-encoded private key.
   --  Supports Ed25519, P-256, P-384, and RSA.
   --  Output format depends on algorithm:
   --    Ed25519: 64 bytes (seed expanded to signing key)
   --    P-256:   32 bytes (scalar)
   --    P-384:   48 bytes (scalar)
   --    RSA:     n_len(2) || n || d_len(2) || d || e(4)
   procedure Extract_Key
     (DER     : X509.Byte_Seq;
      DER_Len : X509.N32;
      Key_Out : out Byte_Seq;
      Key_Len : out N32;
      OK      : out Boolean)
   with Pre  => DER'First = 0
                and DER'Last < X509.N32'Last
                and DER_Len <= DER'Last + 1
                and Key_Out'First = 0
                and Key_Out'Last < N32'Last,
        Post => (if OK then Key_Len in 1 .. Key_Out'Last + 1);

   --  Load identity from PEM strings (no file I/O).
   --  Cert_PEM: leaf cert + optional intermediate chain.
   --  Key_PEM: PKCS#8 private key.
   procedure Load_Identity_PEM
     (Id       : out Identity;
      Cert_PEM : String;
      Key_PEM  : String;
      OK       : out Boolean)
   with Pre  => Cert_PEM'Last <= PEM.Max_PEM_Input
                and Key_PEM'Last <= PEM.Max_PEM_Input;

end SPARKTLS.Credentials.Parsing;
