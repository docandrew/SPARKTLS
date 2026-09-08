--  PEM Encoding — wraps DER bytes in PEM format.

with X509;

package PEM_Util is

   --  Encode DER bytes as PEM with the given label.
   --  Example: Encode_PEM(der_bytes, "CERTIFICATE") produces
   --    -----BEGIN CERTIFICATE-----
   --    <base64 lines>
   --    -----END CERTIFICATE-----
   function Encode_PEM
     (DER   : X509.Byte_Seq;
      Label : String) return String;

   --  Write PEM to a file. Returns False on I/O error.
   procedure Write_PEM_File
     (Path  : String;
      DER   : X509.Byte_Seq;
      Label : String;
      OK    : out Boolean);

end PEM_Util;
