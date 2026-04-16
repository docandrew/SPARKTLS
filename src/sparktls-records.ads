with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Secretbox;
with SPARKNaCl.Core;  use SPARKNaCl.Core;

--  TLS 1.3 Record Layer
package SPARKTLS.Records with
   SPARK_Mode => On
is
   Record_Header_Size : constant := 5;
   Max_Fragment : constant := 16384;
   Tag_Size : constant := 16;

   type Record_Content is
     (Content_Handshake,
      Content_Alert,
      Content_Application_Data,
      Content_Change_Cipher_Spec,
      Content_Unknown);

   type Parse_Result is record
      OK           : Boolean := False;
      Content      : Record_Content := Content_Unknown;
      Fragment_Pos : N32 := 0;
      Fragment_Len : N32 := 0;
      Record_Len   : N32 := 0;
   end record;

   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   with Pre => Data'First = 0
               and Data'Last < N32'Last - 1
               and Avail > 0
               and Avail - 1 <= Data'Last;

   procedure Build_Handshake_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre => Fragment'First = 0
               and Fragment'Length > 0
               and Fragment'Length <= Max_Fragment;

   procedure Build_Encrypted_Record
     (Plaintext    : in     Byte_Seq;
      Inner_Type   : in     Byte;
      Keys         : in out Traffic_Keys;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   with Pre => Plaintext'First = 0
               and Plaintext'Last < Max_Fragment;

   procedure Decrypt_Record
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in out Traffic_Keys;
      Plaintext   :    out Byte_Seq;
      Plain_Len   :    out N32;
      Inner_Type  :    out Byte;
      Valid       :    out Boolean)
   with Pre => Encrypted'First = 0
               and Encrypted'Last < Max_Fragment + 256
               and Encrypted'Last >= Tag_Size + 1
               and Record_Hdr'First = 0
               and Record_Hdr'Length = Record_Header_Size
               and Plaintext'First = 0
               and Plaintext'Last < Max_Fragment + 256;

   procedure Build_CCS_Record
     (Output    : in out IO_Buffer;
      Bytes_Out :    out N32);

   procedure Build_Alert_Record
     (Level      : in     Byte;
      Desc       : in     Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32);

   --  Build a plaintext alert record (no encryption).
   --  Uses RFLX-generated alert serializer for the payload.
   --  Used during handshake before keys are established.
   procedure Build_Plaintext_Alert
     (Level     : in     Byte;   --  1=warning, 2=fatal
      Desc      : in     Byte;   --  TLS alert description
      Output    : in out IO_Buffer;
      Bytes_Out :    out N32);

end SPARKTLS.Records;
