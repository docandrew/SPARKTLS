--  ASN.1 DER Construction Primitives
--
--  Builds DER-encoded structures into a flat byte buffer.
--  All operations take a buffer and cursor (Pos), advancing Pos
--  past the written bytes.
--
--  For variable-length structures (SEQUENCE, SET, context tags),
--  use the Start_*/End_* pairs: Start writes a placeholder length,
--  End patches it with the actual content length.

with X509; use X509;

package DER_Builder is
   use type N32;

   --  Maximum buffer size for cert construction
   Max_DER : constant := 8192;
   subtype DER_Index is N32 range 0 .. Max_DER - 1;
   subtype DER_Buffer is Byte_Seq (DER_Index);

   --  ASN.1 tag constants
   TAG_INTEGER          : constant Byte := 16#02#;
   TAG_BIT_STRING       : constant Byte := 16#03#;
   TAG_OCTET_STRING     : constant Byte := 16#04#;
   TAG_NULL             : constant Byte := 16#05#;
   TAG_OID              : constant Byte := 16#06#;
   TAG_UTF8_STRING      : constant Byte := 16#0C#;
   TAG_PRINTABLE_STRING : constant Byte := 16#13#;
   TAG_UTC_TIME         : constant Byte := 16#17#;
   TAG_GENERALIZED_TIME : constant Byte := 16#18#;
   TAG_SEQUENCE         : constant Byte := 16#30#;
   TAG_SET              : constant Byte := 16#31#;

   --  Common OIDs (DER-encoded value bytes, without tag+length)
   OID_RSA_Encryption   : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#);
   OID_EC_Public_Key    : constant Byte_Seq (0 .. 6) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#);
   OID_Secp256r1        : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
   OID_Secp384r1        : constant Byte_Seq (0 .. 4) :=
     (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
   OID_Ed25519          : constant Byte_Seq (0 .. 2) :=
     (16#2B#, 16#65#, 16#70#);

   --  Signature algorithm OIDs
   OID_SHA256_With_ECDSA : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#);
   OID_SHA384_With_ECDSA : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#03#);
   OID_Ed25519_Sig       : constant Byte_Seq (0 .. 2) :=
     (16#2B#, 16#65#, 16#70#);

   --  Extension OIDs
   OID_Basic_Constraints : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#1D#, 16#13#);
   OID_Key_Usage         : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#1D#, 16#0F#);
   OID_Subject_Alt_Name  : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#1D#, 16#11#);

   --  X.520 attribute type OIDs
   OID_Common_Name       : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#04#, 16#03#);
   OID_Organization      : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#04#, 16#0A#);
   OID_Country           : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#04#, 16#06#);

   --  Write a raw byte
   procedure Put_Byte
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Val : Byte);

   --  Write raw bytes
   procedure Put_Bytes
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Data : Byte_Seq);

   --  Encode a DER length (short or long form)
   procedure Put_Length
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Len : N32);

   --  Write TAG_NULL (05 00)
   procedure Put_Null
     (Buf : in out DER_Buffer;
      Pos : in out N32);

   --  Write an INTEGER (tag + length + value with sign padding)
   procedure Put_Integer
     (Buf   : in out DER_Buffer;
      Pos   : in out N32;
      Value : Byte_Seq);

   --  Write a small non-negative INTEGER from a Natural value
   procedure Put_Small_Integer
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Val : Natural);

   --  Write an OID (tag + length + encoded OID bytes)
   procedure Put_OID
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      OID : Byte_Seq);

   --  Write an OCTET STRING (tag + length + data)
   procedure Put_Octet_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Data : Byte_Seq);

   --  Write a BIT STRING (tag + length + unused_bits + data)
   procedure Put_Bit_String
     (Buf         : in out DER_Buffer;
      Pos         : in out N32;
      Data        : Byte_Seq;
      Unused_Bits : Byte := 0);

   --  Write a UTF8String (tag + length + text bytes)
   procedure Put_UTF8_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Text : String);

   --  Write a PrintableString (tag + length + text bytes)
   procedure Put_Printable_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Text : String);

   --  Write a UTCTime (YYMMDDHHMMSSZ)
   procedure Put_UTC_Time
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      DT  : Date_Time);

   --  Write a GeneralizedTime (YYYYMMDDHHMMSSZ)
   procedure Put_Generalized_Time
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      DT  : Date_Time);

   --  Start a SEQUENCE — writes tag + placeholder length.
   --  Returns the position to patch later.
   procedure Start_Sequence
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos :    out N32);

   --  End a SEQUENCE — patches the length at Saved_Pos.
   procedure End_Sequence
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32);

   --  Start/End a SET (same mechanism, different tag)
   procedure Start_Set
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos :    out N32);

   procedure End_Set
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32);

   --  Start/End an explicit context tag ([0], [3], etc.)
   procedure Start_Context
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Tag_Num   : Byte;
      Saved_Pos :    out N32);

   procedure End_Context
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32);

   --  Build a complete RDN (SET { SEQUENCE { OID, value } })
   --  for a distinguished name attribute like CN, O, or C.
   procedure Put_RDN
     (Buf   : in out DER_Buffer;
      Pos   : in out N32;
      OID   : Byte_Seq;
      Value : String);

end DER_Builder;
