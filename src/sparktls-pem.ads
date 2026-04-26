--  PEM Decoding (RFC 7468)
--
--  Decodes PEM-encoded data to raw DER bytes as X509.Byte_Seq.
--  Outputs into Cert_DER_Buf (8192 bytes, 0-indexed) so results
--  plug directly into Add_Root, Set_Identity, etc.

with X509;

package SPARKTLS.PEM with
   SPARK_Mode => On
is
   Max_Label_Length : constant := 64;
   subtype Label_String is String (1 .. Max_Label_Length);

   type PEM_Label is
     (Label_Certificate,
      Label_Private_Key,
      Label_Public_Key,
      Label_Unknown);

   type Decode_Result is record
      OK        : Boolean   := False;
      Oversize  : Boolean   := False;  --  DER exceeded Max_Cert_DER
      Label     : PEM_Label := Label_Unknown;
      Label_Raw : Label_String := (others => ' ');
      Label_Len : Natural := 0;
      DER       : Cert_DER_Buf := (others => 0);
      DER_Len   : X509.N32 := 0;
   end record;

   Max_PEM_Input : constant := 1_048_576;  --  1 MB cap (real PEMs are ~12 KB)

   --  Decode first PEM block from Input.
   procedure Decode (Input : String; Result : out Decode_Result)
   with Pre  => Input'Last <= Max_PEM_Input,
        Post => (if Result.OK then Result.DER_Len in 1 .. Max_Cert_DER);

end SPARKTLS.PEM;
