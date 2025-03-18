package body SPARKTLS with SPARK_Mode => On is

   MAX_PLAINTEXT_SIZE      : constant := 16384;
   RECORD_HEADER_SIZE      : constant := 5;
   CONTENT_TYPE_SIZE       : constant := 1;
   AUTHENTICATION_TAG_SIZE : constant := 16;
   PADDING_SIZE            : constant := 256;

   --  Per RFC 8446, the maximum size of a TLS 1.3 record is 2^14 + 256
   MAX_CIPHERTEXT_SIZE     : constant := MAX_PLAINTEXT_SIZE + 
                                         PADDING_SIZE;

   LEGACY_TLS_VERSION      : constant Bytes_2 := (3, 1);

   HANDSHAKE_MESSAGE       : constant Bytes_2 := (0, 16#CA#);

   --------------------------------------------------------
   --  Conversion of TLS 1.3 2-byte size fields
   --
   --  There are faster ways to do this with unchecked
   --  conversions, but this is more portable and safer.
   --------------------------------------------------------
   function To_Byte_Seq (U : U16) return Bytes_2
   is
      X : Bytes_2;
   begin
      X (0) := Byte (U / 256);
      X (1) := Byte (U mod 256);
      return X;
   end To_Byte_Seq;

   function To_Byte_Seq_3 (U : U24) return Bytes_3
   is
      X : Bytes_3;
   begin
      X (0) := Byte (U / 65536);
      X (1) := Byte ((U mod 65536) / 256);
      X (2) := Byte (U mod 256);
      return X;
   end To_Byte_Seq_3;

   function To_U16 (I : Bytes_2) return U16
   is
   begin
      return U16 (I (0)) * 256 + U16 (I (1));
   end To_U16;

   --------------------------------------------------------
   --  Conversion of 3-byte size fields
   --------------------------------------------------------
   function To_U32 (I : Bytes_3) return U32
   is
   begin
      return U32 (I (0)) * 65536 + U32 (I (1)) * 256 + U32 (I (2));
   end To_U32;

   --------------------------------------------------------
   --  TLV
   --------------------------------------------------------
   function TLV (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq is
   begin
      return Byte (Tag) &
             To_Byte_Seq (U16 (Msg'Length)) &
             Msg;
   end TLV;

   --------------------------------------------------------
   --  TLV (2-byte tag)
   --------------------------------------------------------
   function TLV (
      Tag : Tag_16;
      Msg : Byte_Seq) return Byte_Seq is
   begin
      return To_Byte_Seq (U16 (Tag)) &
             To_Byte_Seq (U16 (Msg'Length)) &
             Msg;
   end TLV;

   --------------------------------------------------------
   --  TLV (1-byte tag w/ String)
   --------------------------------------------------------
   function TLV (
      Tag : Tag_8;
      Msg : String) return Byte_Seq is
   begin
      return Byte (Tag) & 
             To_Byte_Seq (U16 (Msg'Length)) &
             To_Byte_Seq (Msg);
   end TLV;

   --------------------------------------------------------
   --  TLV_Handshake
   --  Note handshake messages use 3-byte length fields
   --------------------------------------------------------
   function TLV_Handshake (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq is
   begin
      return Byte (Tag) &
             To_Byte_Seq_3 (U24 (Msg'Length)) &
             Msg;
   end TLV_Handshake;
   
   --------------------------------------------------------
   --  TLV_Record
   --  Note inclusion of the legacy protocol version.
   --------------------------------------------------------
   function TLV_Record (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq is
   begin
      return Byte (Tag) &
             To_Byte_Seq (U16 (Msg'Length)) &
             Msg;
   end TLV_Record;

   --------------------------------------------------------
   --  LV
   --------------------------------------------------------
   function LV (Msg : Byte_Seq) return Byte_Seq is
   begin
      return To_Byte_Seq (U16 (Msg'Length)) & Msg;
   end LV;

end SPARKTLS;
