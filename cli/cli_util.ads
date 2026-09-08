with X509;
with Ada.Unchecked_Deallocation;

package CLI_Util is

   type Byte_Seq_Access is access X509.Byte_Seq;

   procedure Free is new Ada.Unchecked_Deallocation
     (X509.Byte_Seq, Byte_Seq_Access);

   --  Read a DER file into a heap-allocated Byte_Seq (0-based).
   procedure Read_DER_File
     (Path : String;
      Data : out Byte_Seq_Access;
      OK   : out Boolean);

   --  Read a certificate file as PEM or raw DER into a heap-allocated
   --  DER Byte_Seq (0-based).
   procedure Read_Cert_File
     (Path : String;
      Data : out Byte_Seq_Access;
      OK   : out Boolean);

   --  Convert a Span to a String by reading bytes from DER.
   function Span_To_String
     (DER : X509.Byte_Seq;
      S   : X509.Span) return String;

   --  Format bytes as colon-separated hex: "AB:CD:EF"
   function To_Hex (Data : X509.Byte_Seq) return String;

   --  Hex with truncation: first Max bytes then "... (N bytes)"
   function To_Hex_Trunc
     (Data : X509.Byte_Seq;
      Max  : Natural := 20) return String;

   --  Algorithm_ID -> human-readable name
   function Algo_Name (A : X509.Algorithm_ID) return String;

   --  Public key algorithm + bit size description
   function PK_Description
     (Algo : X509.Algorithm_ID;
      Len  : X509.N32) return String;

   --  Date_Time -> "2025-03-15 14:30:00 UTC"
   function Format_Date (D : X509.Date_Time) return String;

   --  Current time as X509.Date_Time
   function Now return X509.Date_Time;

   --  Print "  Label:  Value" with aligned columns
   procedure Put_Field (Label : String; Value : String);

   --  Print a check result line: "  [N] Description .... OK/FAIL"
   procedure Put_Check
     (Index : Natural;
      Label : String;
      OK    : Boolean;
      Detail : String := "");

end CLI_Util;
