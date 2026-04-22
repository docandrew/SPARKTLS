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
   end record;

   --  Build a complete DER-encoded X.509v3 certificate.
   procedure Build_Certificate
     (Params   : Cert_Params;
      Cert_DER : out Cert_DER_Buf;
      Cert_Len : out X509.N32;
      OK       : out Boolean);

end Cert_Builder;
