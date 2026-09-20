--  Load certificate + private key from PEM files into an Identity.
--
--  SPARK_Mode Off: performs file I/O.
--
--  Usage:
--    Id : aliased SPARKTLS.Identity;
--    OK : Boolean;
--    SPARKTLS.Credentials.Load_Identity (Id, "server.crt", "server.key", OK);

package SPARKTLS.Credentials
  with SPARK_Mode => Off
is
   --  Load identity from PEM files.
   --
   --  Cert_Path: PEM file with leaf cert, optionally followed by
   --    intermediate certs (sent to peer in the Certificate message).
   --  Key_Path: PEM file with PRIVATE KEY (Ed25519, P-256, or P-384).
   --
   --  The signing algorithm is inferred from the leaf certificate.
   procedure Load_Identity
     (Id : out Identity; Cert_Path : String; Key_Path : String; OK : out Boolean);

   --  Load identity from PEM strings (for embedded certs, testing).
   procedure Load_Identity_PEM
     (Id : out Identity; Cert_PEM : String; Key_PEM : String; OK : out Boolean);

   --  Public-only identity: the certificate chain, no private key. Every
   --  handshake signature then comes from Config.Sign;
   --  the TLS process never holds the key.
   procedure Load_Identity_Public
     (Id : out Identity; Cert_Path : String; OK : out Boolean);
   procedure Load_Identity_Public_PEM
     (Id : out Identity; Cert_PEM : String; OK : out Boolean);

   --  Load trust store from a PEM file containing one or more
   --  CA certificates (for server-side client cert validation,
   --  or client-side server cert validation).
   procedure Load_Trust_Store (Store : out Trust_Store; Path : String; OK : out Boolean);

   --  Load a DER-encoded OCSPResponse (what `openssl ocsp -respout`
   --  writes) and attach it to Id as the response it staples for clients
   --  that ask (Set_OCSP_Staple). OK = False if the file cannot be read,
   --  is empty, or exceeds Max_OCSP_Response; the staple is then cleared.
   procedure Load_Staple (Id : in out Identity; Path : String; OK : out Boolean);

end SPARKTLS.Credentials;
