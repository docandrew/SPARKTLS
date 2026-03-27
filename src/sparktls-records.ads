with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Secretbox;
with SPARKNaCl.Core;  use SPARKNaCl.Core;

--  TLS 1.3 Record Layer
--
--  Uses RecordFlux-generated parsers for incoming records and
--  constructs outgoing records. Handles encryption/decryption
--  of application data and post-handshake records.
package SPARKTLS.Records with
   SPARK_Mode => On
is
   --  5-byte TLS record header size
   Record_Header_Size : constant := 5;

   --  Maximum plaintext fragment size (RFC 8446)
   Max_Fragment : constant := 16384;

   --  AEAD tag size (Poly1305)
   Tag_Size : constant := 16;

   --================================================================
   --  Record parsing result
   --================================================================

   type Record_Content is
     (Content_Handshake,
      Content_Alert,
      Content_Application_Data,
      Content_Change_Cipher_Spec,
      Content_Unknown);

   type Parse_Result is record
      OK           : Boolean := False;
      Content      : Record_Content := Content_Unknown;
      Fragment_Pos : N32 := 0;    --  Start of fragment in input buffer
      Fragment_Len : N32 := 0;    --  Length of fragment
      Record_Len   : N32 := 0;    --  Total record length (header + fragment)
   end record;

   --  Parse a TLS record header from the input buffer.
   --  Returns the content type and fragment boundaries without
   --  consuming the data. Returns OK = False if insufficient data.
   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   with Pre => Avail <= N32 (Data'Length);

   --================================================================
   --  Record construction
   --================================================================

   --  Build a plaintext handshake record.
   --  Writes: record header (5 bytes) + fragment into Output buffer.
   --  Returns the number of bytes written.
   procedure Build_Handshake_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre => Fragment'First = 0
               and Fragment'Length > 0
               and N32 (Fragment'Length) <= Max_Fragment;

   --  Build an encrypted application data record.
   --  Encrypts plaintext with the given key/IV/nonce, writes the
   --  TLS record wrapping (type 0x17 = application_data) with
   --  ciphertext + AEAD tag.
   --
   --  The plaintext has the actual content type appended as the last byte
   --  before encryption (inner content type per RFC 8446 Section 5.2).
   procedure Build_Encrypted_Record
     (Plaintext    : in     Byte_Seq;
      Inner_Type   : in     Byte;
      Keys         : in out Traffic_Keys;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   with Pre => Plaintext'First = 0
               and N32 (Plaintext'Length) + 1 + Tag_Size <=
                   Max_Fragment + 256;

   --  Decrypt an encrypted TLS record.
   --  The input is the encrypted fragment (after the 5-byte header).
   --  Returns the decrypted plaintext (minus AEAD tag and inner content type).
   --  Inner_Type is set to the actual content type byte.
   --  Valid is False if AEAD authentication fails.
   procedure Decrypt_Record
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in out Traffic_Keys;
      Plaintext   :    out Byte_Seq;
      Plain_Len   :    out N32;
      Inner_Type  :    out Byte;
      Valid       :    out Boolean)
   with Pre => Encrypted'First = 0
               and N32 (Encrypted'Length) > Tag_Size
               and Record_Hdr'First = 0
               and Record_Hdr'Length = Record_Header_Size
               and Plaintext'First = 0
               and N32 (Plaintext'Length) >=
                   N32 (Encrypted'Length) - Tag_Size - 1;

   --  Build a Change Cipher Spec record (middlebox compatibility)
   procedure Build_CCS_Record
     (Output    : in out IO_Buffer;
      Bytes_Out :    out N32);

   --  Build an encrypted alert record
   procedure Build_Alert_Record
     (Level      : in     Byte;
      Desc       : in     Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32);

end SPARKTLS.Records;
