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
      Bad_Version  : Boolean := False;  --  record version not in {3,1}..{3,4}
      Content      : Record_Content := Content_Unknown;
      Fragment_Pos : N32 := 0;  --  offset of fragment in Data
      Fragment_Len : N32 := 0;  --  fragment byte count
      Record_Len   : N32 := 0;  --  total record length (header + fragment)
   end record
     with Predicate =>
       (if Parse_Result.OK then
          Parse_Result.Content /= Content_Unknown
          and Parse_Result.Fragment_Pos = Record_Header_Size
          and not Parse_Result.Overflow
          and not Parse_Result.Bad_Version);

   --  RFC 8446 §5.1: Parse a TLS record header (5 bytes).
   --  Validates content type and fragment length bounds.
   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   --  Body indexes via Data'First + offset, so no First = 0 needed.
   --  Data'Last bounded by IO_Buffer_Capacity so all callers (slices
   --  into S.Input.Data, which is itself bounded) satisfy the Pre.
   with Pre  => Data'Length > 0
                and then Data'Last < N32 (IO_Buffer_Capacity)
                and then Avail > 0
                and then Avail <= N32 (IO_Buffer_Capacity)
                and then Data'First + Avail - 1 <= Data'Last,
        Post => (if Result.OK then
                   Result.Content /= Content_Unknown       --  known type
                   and Result.Fragment_Len >= 1             --  never zero
                   and Result.Fragment_Len <= Max_Fragment + Max_Record_Overhead
                                                            --  RFC 8446 §5.1
                   and Result.Record_Len <= Avail           --  fits in buffer
                   and Result.Fragment_Pos = Record_Header_Size
                   --  Body sets Record_Len := Header_Size + Fragment_Len,
                   --  so callers can derive Fragment_Pos + Fragment_Len.
                   and Result.Record_Len =
                         Result.Fragment_Pos + Result.Fragment_Len
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

   --  RFC 8446 §5.1: Build the initial ClientHello record with the
   --  legacy_record_version = TLS 1.0 (0x0301). The RFC permits both
   --  0x0301 and 0x0303 for the initial ClientHello, but middleboxes
   --  and version-strict peers (e.g. BoGo's VersionNegotiation tests)
   --  expect 0x0301 for maximum compatibility. All subsequent
   --  client-side plaintext handshake records use 0x0303 via
   --  Build_Handshake_Record above.
   procedure Build_Initial_ClientHello_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre => Fragment'First = 0
               and Fragment'Length > 0
               and Fragment'Length <= Max_Fragment;

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
   --  Relaxed 2026-04-29: the body uses Ada slide-assignment to copy
   --  Plaintext into a 0-based local Inner buffer, so any First works.
   --  Length-based bound replaces the prior absolute-Last bound so a
   --  fragmenting caller can pass slices `Plaintext (Pos .. ...)` of
   --  a larger buffer without re-basing each chunk.
   --
   --  Plaintext'Length is compared without the N32 conversion that
   --  SPARK can't prove safe (Plaintext'Last could in principle be
   --  N32'Last, making Length one past N32'Last).
   --
   --  Post is conditional: when Output is full, the body bails early
   --  with Bytes_Out = 0 and does not advance Keys.Counter. Callers
   --  must check Bytes_Out and only treat the call as completed when
   --  it is non-zero.
   with Pre  => Plaintext'Length <= Max_Fragment
                --  RFC 8446 §5.4: only alert/handshake/application_data
                --  may be emitted as inner content type. CCS (0x14)
                --  only appears in unencrypted records.
                and SPARKTLS.Inner_Type_Valid_RFC_8446_5_4 (Inner_Type)
                and Nonce_Space_Available (Keys),             --  RFC 8446 §5.5
        Post => (if Bytes_Out > 0
                 then Keys.Counter = Keys.Counter'Old + 1   --  RFC 8446 §5.3
                 else Keys.Counter = Keys.Counter'Old);

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
               and Encrypted'Last >= Tag_Size
               and Record_Hdr'First = 0
               and Record_Hdr'Length = Record_Header_Size
               and Plaintext'First = 0
               and Plaintext'Last >= Encrypted'Last  --  plaintext buffer >= encrypted
               and Nonce_Space_Available (Keys),     --  RFC 8446 §5.5
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
   --  RFC 8446 §6.1 / §6.2 binding: warning level only for close_notify
   --  / user_canceled; everything else is fatal.
   procedure Build_Alert_Record
     (Level      : in     Byte;
      Desc       : in     Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   with Pre =>
     SPARKTLS.Alert_Level_Description_Valid_RFC_8446_6_1 (Level, Desc)
     and Nonce_Space_Available (Keys);

   --  Build a plaintext alert record (no encryption).
   --  Uses RFLX-generated alert serializer for the payload.
   --  Used during handshake before keys are established.
   --
   --  RFC 8446 §6 (and the RFLX schema):
   --    Warning level (1) is ONLY valid with close_notify (0) or
   --    user_canceled (90).
   --    Fatal level (2) is for all OTHER alerts (close_notify and
   --    user_canceled are warning-only).
   procedure Build_Plaintext_Alert
     (Level     : in     Byte;   --  1=warning, 2=fatal
      Desc      : in     Byte;   --  TLS alert description
      Output    : in out IO_Buffer;
      Bytes_Out :    out N32)
   with Pre =>
     SPARKTLS.Alert_Level_Description_Valid_RFC_8446_6_1 (Level, Desc);

end SPARKTLS.Records;
