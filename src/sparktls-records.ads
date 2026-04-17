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

   --  RFC 8446 §5.1: Parsed TLS record header.
   type Parse_Result is record
      OK           : Boolean := False;
      Overflow     : Boolean := False;  --  fragment exceeds RFC limit
      Content      : Record_Content := Content_Unknown;
      Fragment_Pos : N32 := 0;  --  offset of fragment in Data
      Fragment_Len : N32 := 0;  --  fragment byte count
      Record_Len   : N32 := 0;  --  total record length (header + fragment)
   end record
     with Predicate =>
       (if Parse_Result.OK then
          Parse_Result.Content /= Content_Unknown
          and Parse_Result.Fragment_Pos = Record_Header_Size
          and not Parse_Result.Overflow);

   --  RFC 8446 §5.1: Parse a TLS record header (5 bytes).
   --  Validates content type and fragment length bounds.
   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   with Pre  => Data'First = 0
                and Data'Last < N32'Last - 1
                and Avail > 0
                and Avail - 1 <= Data'Last,
        Post => (if Result.OK then
                   Result.Content /= Content_Unknown       --  known type
                   and Result.Fragment_Len <= Max_Fragment + Max_Record_Overhead
                                                            --  RFC 8446 §5.1
                   and Result.Record_Len <= Avail           --  fits in buffer
                   and Result.Fragment_Pos = Record_Header_Size
                   and not Result.Overflow)                  --  type predicate
               and (if Result.Overflow then not Result.OK);  --  overflow → !OK

   --  RFC 8446 §5.1: Build a plaintext handshake record.
   --  Used for ClientHello and ServerHello (before encryption).
   procedure Build_Handshake_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre => Fragment'First = 0
               and Fragment'Length > 0
               and Fragment'Length <= Max_Fragment;  --  RFC 8446 §5.1

   --  RFC 8446 §5.2: Build an encrypted TLS record.
   --  Inner_Type: 0x15 (alert), 0x16 (handshake), 0x17 (application_data).
   --  The nonce counter is incremented for each record.
   --  RFC 8446 §5.2: Build an encrypted TLS record.
   --  Nonce counter increments by 1 for each record (§5.3).
   procedure Build_Encrypted_Record
     (Plaintext    : in     Byte_Seq;
      Inner_Type   : in     Byte;
      Keys         : in out Traffic_Keys;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   with Pre  => Plaintext'First = 0
                and Plaintext'Last < Max_Fragment
                and Inner_Type in 16#15# | 16#16# | 16#17#,  --  RFC 8446 §5.4
        Post => Keys.Counter = Keys.Counter'Old + 1;          --  RFC 8446 §5.3

   --  Decrypt a TLS 1.3 encrypted record.
   --  RFC 8446 Section 5.4: After decryption, the inner plaintext
   --  MUST be non-empty (at least the content type byte), and
   --  Inner_Type MUST NOT be zero (content type of zero is invalid).
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
               and Plaintext'Last >= Encrypted'Last,  --  plaintext buffer >= encrypted
        Post => Keys.Counter = Keys.Counter'Old + 1              --  RFC 8446 §5.3
                and (if Valid then
                   (Plain_Len = 0
                    or else Plain_Len - 1 <= Plaintext'Last));     --  bounds

   --  RFC 8446 §5: Build a Change Cipher Spec record.
   --  Always exactly 6 bytes: header(5) + payload(1 byte = 0x01).
   procedure Build_CCS_Record
     (Output    : in out IO_Buffer;
      Bytes_Out :    out N32)
   with Post => Bytes_Out in 0 | 6;  --  RFC 8446 §5: CCS is exactly 6 bytes

   --  RFC 8446 §6: Build an encrypted alert record.
   --  Level: 1 = warning (only for close_notify), 2 = fatal.
   procedure Build_Alert_Record
     (Level      : in     Byte;
      Desc       : in     Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre => Level in 1 .. 2;

   --  Build a plaintext alert record (no encryption).
   --  Uses RFLX-generated alert serializer for the payload.
   --  Used during handshake before keys are established.
   procedure Build_Plaintext_Alert
     (Level     : in     Byte;   --  1=warning, 2=fatal
      Desc      : in     Byte;   --  TLS alert description
      Output    : in out IO_Buffer;
      Bytes_Out :    out N32);

end SPARKTLS.Records;
