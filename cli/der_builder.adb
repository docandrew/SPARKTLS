package body DER_Builder is
   use type Byte;

   procedure Put_Byte
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Val : Byte)
   is
   begin
      if Pos <= Buf'Last then
         Buf (Pos) := Val;
         Pos := Pos + 1;
      end if;
   end Put_Byte;

   procedure Put_Bytes
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Data : Byte_Seq)
   is
   begin
      for I in Data'Range loop
         Put_Byte (Buf, Pos, Data (I));
      end loop;
   end Put_Bytes;

   procedure Put_Length
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Len : N32)
   is
   begin
      if Len < 128 then
         Put_Byte (Buf, Pos, Byte (Len));
      elsif Len < 256 then
         Put_Byte (Buf, Pos, 16#81#);
         Put_Byte (Buf, Pos, Byte (Len));
      else
         Put_Byte (Buf, Pos, 16#82#);
         Put_Byte (Buf, Pos, Byte (Len / 256));
         Put_Byte (Buf, Pos, Byte (Len mod 256));
      end if;
   end Put_Length;

   procedure Put_Null
     (Buf : in out DER_Buffer;
      Pos : in out N32)
   is
   begin
      Put_Byte (Buf, Pos, TAG_NULL);
      Put_Byte (Buf, Pos, 0);
   end Put_Null;

   procedure Put_Integer
     (Buf   : in out DER_Buffer;
      Pos   : in out N32;
      Value : Byte_Seq)
   is
      Skip    : N32 := 0;
      Pad     : Boolean;
      Val_Len : N32;
   begin
      --  Skip leading zeros (but keep at least one byte)
      while Skip < N32 (Value'Length) - 1
         and then Value (Value'First + Skip) = 0
      loop
         Skip := Skip + 1;
      end loop;

      --  Need sign padding if high bit set
      Pad := Value (Value'First + Skip) >= 128;
      Val_Len := N32 (Value'Length) - Skip + (if Pad then 1 else 0);

      Put_Byte (Buf, Pos, TAG_INTEGER);
      Put_Length (Buf, Pos, Val_Len);
      if Pad then
         Put_Byte (Buf, Pos, 0);
      end if;
      Put_Bytes (Buf, Pos,
                 Value (Value'First + Skip .. Value'Last));
   end Put_Integer;

   procedure Put_Small_Integer
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      Val : Natural)
   is
   begin
      if Val < 128 then
         Put_Byte (Buf, Pos, TAG_INTEGER);
         Put_Length (Buf, Pos, 1);
         Put_Byte (Buf, Pos, Byte (Val));
      elsif Val < 256 then
         Put_Byte (Buf, Pos, TAG_INTEGER);
         Put_Length (Buf, Pos, 2);
         Put_Byte (Buf, Pos, 0);  --  sign pad
         Put_Byte (Buf, Pos, Byte (Val));
      else
         Put_Byte (Buf, Pos, TAG_INTEGER);
         Put_Length (Buf, Pos, 3);
         Put_Byte (Buf, Pos, 0);  --  sign pad
         Put_Byte (Buf, Pos, Byte (Val / 256));
         Put_Byte (Buf, Pos, Byte (Val mod 256));
      end if;
   end Put_Small_Integer;

   procedure Put_OID
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      OID : Byte_Seq)
   is
   begin
      Put_Byte (Buf, Pos, TAG_OID);
      Put_Length (Buf, Pos, N32 (OID'Length));
      Put_Bytes (Buf, Pos, OID);
   end Put_OID;

   procedure Put_Octet_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Data : Byte_Seq)
   is
   begin
      Put_Byte (Buf, Pos, TAG_OCTET_STRING);
      Put_Length (Buf, Pos, N32 (Data'Length));
      Put_Bytes (Buf, Pos, Data);
   end Put_Octet_String;

   procedure Put_Bit_String
     (Buf         : in out DER_Buffer;
      Pos         : in out N32;
      Data        : Byte_Seq;
      Unused_Bits : Byte := 0)
   is
   begin
      Put_Byte (Buf, Pos, TAG_BIT_STRING);
      Put_Length (Buf, Pos, N32 (Data'Length) + 1);
      Put_Byte (Buf, Pos, Unused_Bits);
      Put_Bytes (Buf, Pos, Data);
   end Put_Bit_String;

   procedure Put_UTF8_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Text : String)
   is
   begin
      Put_Byte (Buf, Pos, TAG_UTF8_STRING);
      Put_Length (Buf, Pos, N32 (Text'Length));
      for I in Text'Range loop
         Put_Byte (Buf, Pos, Byte (Character'Pos (Text (I))));
      end loop;
   end Put_UTF8_String;

   procedure Put_Printable_String
     (Buf  : in out DER_Buffer;
      Pos  : in out N32;
      Text : String)
   is
   begin
      Put_Byte (Buf, Pos, TAG_PRINTABLE_STRING);
      Put_Length (Buf, Pos, N32 (Text'Length));
      for I in Text'Range loop
         Put_Byte (Buf, Pos, Byte (Character'Pos (Text (I))));
      end loop;
   end Put_Printable_String;

   --  Format: YYMMDDHHMMSSZ (13 bytes)
   procedure Put_UTC_Time
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      DT  : Date_Time)
   is
      procedure Put_Two_Digits (V : Natural) is
      begin
         Put_Byte (Buf, Pos, Byte (Character'Pos ('0') + V / 10));
         Put_Byte (Buf, Pos, Byte (Character'Pos ('0') + V mod 10));
      end Put_Two_Digits;
   begin
      Put_Byte (Buf, Pos, TAG_UTC_TIME);
      Put_Length (Buf, Pos, 13);
      Put_Two_Digits (DT.Year mod 100);
      Put_Two_Digits (DT.Month);
      Put_Two_Digits (DT.Day);
      Put_Two_Digits (DT.Hour);
      Put_Two_Digits (DT.Minute);
      Put_Two_Digits (DT.Second);
      Put_Byte (Buf, Pos, Byte (Character'Pos ('Z')));
   end Put_UTC_Time;

   --  Format: YYYYMMDDHHMMSSZ (15 bytes)
   procedure Put_Generalized_Time
     (Buf : in out DER_Buffer;
      Pos : in out N32;
      DT  : Date_Time)
   is
      procedure Put_Two_Digits (V : Natural) is
      begin
         Put_Byte (Buf, Pos, Byte (Character'Pos ('0') + V / 10));
         Put_Byte (Buf, Pos, Byte (Character'Pos ('0') + V mod 10));
      end Put_Two_Digits;
   begin
      Put_Byte (Buf, Pos, TAG_GENERALIZED_TIME);
      Put_Length (Buf, Pos, 15);
      Put_Two_Digits (DT.Year / 100);
      Put_Two_Digits (DT.Year mod 100);
      Put_Two_Digits (DT.Month);
      Put_Two_Digits (DT.Day);
      Put_Two_Digits (DT.Hour);
      Put_Two_Digits (DT.Minute);
      Put_Two_Digits (DT.Second);
      Put_Byte (Buf, Pos, Byte (Character'Pos ('Z')));
   end Put_Generalized_Time;

   --  Start_Sequence/End_Sequence and friends use a two-pass approach:
   --  Start writes tag + a 3-byte length placeholder (82 XX XX),
   --  End patches the actual length. This limits content to 65535 bytes
   --  which is more than enough for certificates.

   procedure Start_Compound
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Tag       : Byte;
      Saved_Pos :    out N32)
   is
   begin
      Put_Byte (Buf, Pos, Tag);
      Saved_Pos := Pos;
      --  Reserve 3 bytes for length (82 XX XX)
      Put_Byte (Buf, Pos, 16#82#);
      Put_Byte (Buf, Pos, 0);
      Put_Byte (Buf, Pos, 0);
   end Start_Compound;

   procedure End_Compound
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32)
   is
      Content_Start : constant N32 := Saved_Pos + 3;
      Content_Len   : constant N32 := Pos - Content_Start;
   begin
      if Content_Len < 128 then
         --  Short form: shift content left by 2, write 1-byte length
         Buf (Saved_Pos) := Byte (Content_Len);
         Buf (Saved_Pos + 1 .. Saved_Pos + Content_Len) :=
            Buf (Content_Start .. Content_Start + Content_Len - 1);
         Pos := Saved_Pos + 1 + Content_Len;
      elsif Content_Len < 256 then
         --  Long form 1 byte: shift content left by 1
         Buf (Saved_Pos) := 16#81#;
         Buf (Saved_Pos + 1) := Byte (Content_Len);
         Buf (Saved_Pos + 2 .. Saved_Pos + 1 + Content_Len) :=
            Buf (Content_Start .. Content_Start + Content_Len - 1);
         Pos := Saved_Pos + 2 + Content_Len;
      else
         --  Long form 2 bytes: no shift needed (we reserved exactly 3)
         Buf (Saved_Pos) := 16#82#;
         Buf (Saved_Pos + 1) := Byte (Content_Len / 256);
         Buf (Saved_Pos + 2) := Byte (Content_Len mod 256);
      end if;
   end End_Compound;

   procedure Start_Sequence
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos :    out N32)
   is
   begin
      Start_Compound (Buf, Pos, TAG_SEQUENCE, Saved_Pos);
   end Start_Sequence;

   procedure End_Sequence
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32)
   is
   begin
      End_Compound (Buf, Pos, Saved_Pos);
   end End_Sequence;

   procedure Start_Set
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos :    out N32)
   is
   begin
      Start_Compound (Buf, Pos, TAG_SET, Saved_Pos);
   end Start_Set;

   procedure End_Set
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32)
   is
   begin
      End_Compound (Buf, Pos, Saved_Pos);
   end End_Set;

   procedure Start_Context
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Tag_Num   : Byte;
      Saved_Pos :    out N32)
   is
   begin
      Start_Compound (Buf, Pos, 16#A0# or Tag_Num, Saved_Pos);
   end Start_Context;

   procedure End_Context
     (Buf       : in out DER_Buffer;
      Pos       : in out N32;
      Saved_Pos : N32)
   is
   begin
      End_Compound (Buf, Pos, Saved_Pos);
   end End_Context;

   procedure Put_RDN
     (Buf   : in out DER_Buffer;
      Pos   : in out N32;
      OID   : Byte_Seq;
      Value : String)
   is
      Set_Pos, Seq_Pos : N32;
   begin
      Start_Set (Buf, Pos, Set_Pos);
      Start_Sequence (Buf, Pos, Seq_Pos);
      Put_OID (Buf, Pos, OID);
      Put_UTF8_String (Buf, Pos, Value);
      End_Sequence (Buf, Pos, Seq_Pos);
      End_Set (Buf, Pos, Set_Pos);
   end Put_RDN;

end DER_Builder;
