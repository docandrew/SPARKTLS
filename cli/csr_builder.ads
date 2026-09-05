--  PKCS#10 Certificate Signing Request Construction and Parsing

with X509; use type X509.N32;
with SPARKNaCl; use SPARKNaCl;
with Key_Util;
with Cert_Builder;
with DER_Builder;

package CSR_Builder is

   Max_CSR_DER : constant := DER_Builder.Max_DER;
   subtype CSR_DER_Buf is X509.Byte_Seq (0 .. X509.N32 (Max_CSR_DER) - 1);

   --  Build a PKCS#10 CSR.
   procedure Build_CSR
     (Key      : Key_Util.Private_Key;
      Subject  : Cert_Builder.DN;
      SANs     : Cert_Builder.SAN_Array;
      SAN_Count : Natural;
      CSR_DER  : out CSR_DER_Buf;
      CSR_Len  : out X509.N32;
      OK       : out Boolean);

   --  Parse a CSR and extract the subject DN and SPKI.
   --  Used by "sign-csr" to build a cert from a CSR.
   procedure Parse_CSR
     (DER      : X509.Byte_Seq;
      Subject  : out Cert_Builder.DN;
      SPKI     : out X509.Byte_Seq;
      SPKI_Len : out X509.N32;
      OK       : out Boolean)
   with Pre => DER'First = 0 and SPKI'First = 0 and SPKI'Length >= 256;

end CSR_Builder;
