--  X.509v3 Certificate Construction
--
--  Builds DER-encoded X.509 certificates from components.
--  Handles TBS construction, signing, and outer wrapping.

with X509; use type X509.N32;
with SPARKNaCl; use SPARKNaCl;
with Key_Util;
with DER_Builder;

package Cert_Builder is

   Max_Cert_DER : constant := DER_Builder.Max_DER;
   subtype Cert_DER_Buf is X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1);

   --  Subject/Issuer distinguished name fields
   type DN is record
      CN      : String (1 .. 128) := (others => ASCII.NUL);
      CN_Len  : Natural := 0;
      Org     : String (1 .. 128) := (others => ASCII.NUL);
      Org_Len : Natural := 0;
   end record;

   --  Subject Alternative Names (up to 16)
   Max_SANs : constant := 16;
   type SAN_Entry is record
      Name    : String (1 .. 256) := (others => ASCII.NUL);
      Name_Len : Natural := 0;
      Is_IP    : Boolean := False;  --  True = IP address, False = DNS name
   end record;
   type SAN_Array is array (1 .. Max_SANs) of SAN_Entry;

   --  Certificate parameters
   type Cert_Params is record
      Subject     : DN;
      Issuer      : DN;             --  = Subject for self-signed
      Key         : Key_Util.Private_Key;  --  signing key
      SPKI        : X509.Byte_Seq (0 .. 255) := (others => 0);  --  subject's SPKI
      SPKI_Len    : X509.N32 := 0;
      Is_CA       : Boolean := False;
      Has_EKU_Server_Auth : Boolean := False;
      Valid_Days  : Natural := 365;
      SANs        : SAN_Array := (others => <>);
      SAN_Count   : Natural := 0;
      --  Authority Key Identifier for a CA-signed certificate: the issuer's
      --  Subject Key Identifier. Len = 0 means self-signed, and the
      --  certificate's own key identifier is used (RFC 5280 4.2.1.1).
      Issuer_Key_ID     : X509.Byte_Seq (0 .. 31) := (others => 0);
      Issuer_Key_ID_Len : X509.N32 := 0;
   end record;

   --  Build a complete DER-encoded X.509v3 certificate.
   --  Fill Params.Issuer_Key_ID from the CA certificate: its Subject Key
   --  Identifier extension when present, otherwise the RFC 5280 4.2.1.2
   --  method (1) value, SHA-1 of its subjectPublicKey BIT STRING. A leaf
   --  whose AKID does not match the CA's SKID cannot be chained by OpenSSL
   --  ("unable to get local issuer certificate"), which is how the CLI lane
   --  caught the old builder using the LEAF's key hash (2026-09-14).
   --  Locate the subjectPublicKey BIT STRING content inside a DER
   --  SubjectPublicKeyInfo (the key bytes, unused-bits byte excluded).
   --  The CLI handles standalone SPKIs (key files, CSRs), which X509.Parse
   --  does not take, so the walk lives here.
   procedure Public_Key_Bits
     (SPKI : X509.Byte_Seq; First : out X509.N32; Length : out X509.N32; OK : out Boolean);

   procedure Set_Issuer_Key_ID
     (Params : in out Cert_Params; CA_DER : X509.Byte_Seq; CA : X509.Certificate);

   procedure Build_Certificate
     (Params   : Cert_Params;
      Cert_DER : out Cert_DER_Buf;
      Cert_Len : out X509.N32;
      OK       : out Boolean);

end Cert_Builder;
