package body SPARKTLS.Extensions is

   --------------------------------------------------------
   --  Private constants
   --------------------------------------------------------
   DNS_Hostname     : constant Tag_8 := 16#00#;
   Supported_Groups : constant Tag_16 := 16#00_0A#;

   --------------------------------------------------------
   --  Serialize Extension_Type in TLV format
   --------------------------------------------------------
   function TLVE (E : Extension_Type; Msg : Byte_Seq)
      return Byte_Seq is
   begin
      return To_Byte_Seq (U16 (E'Enum_Rep)) &
             To_Byte_Seq (U16 (Msg'Length)) &
             Msg;
   end TLVE;

   function To_Tag_16 (G : Named_Group) return Tag_16 is
   begin
      return Tag_16 (G'Enum_Rep);
   end To_Tag_16;

   --------------------------------------------------------
   --  Generate extension header w/ type and size
   --------------------------------------------------------

   --------------------------------------------------------
   --  Server Name Extension
   --------------------------------------------------------
   function Server_Name_Extension (Host : String)
      return Byte_Seq
   is
      Ext_Data : Byte_Seq := TLV (DNS_Hostname, Host);
   begin
      return TLVE (Server_Name, Ext_Data);
   end Server_Name_Extension;

   --------------------------------------------------------
   --  Supported Groups Extension
   --------------------------------------------------------
   function Supported_Groups_Extension (
      Groups : Supported_Group_List) return Byte_Seq
   is
      Ext_Data : Byte_Seq := To_Byte_Seq (Supported_Groups);
   begin
      return TLVE (Supported_Groups, Ext_Data);
   end Supported_Groups_Extension;

   --------------------------------------------------------
   --  Signature Algorithms Extension
   --------------------------------------------------------
   function Signature_Algorithms_Extension (
      Sigs : Supported_Signature_List) return Byte_Seq
   is
      --  Note this only supports a single key share. We send
      --  the length of all the following key share data, each
      --  key is prepended with its type and length.
      Ext_Data : Byte_Seq :=
         LV (TLV (To_Tag_16 (Signature_Algorithms), Sigs));
   begin
      return TLVE (Signature_Algorithms, Ext_Data);
   end Signature_Algorithms_Extension;

   --------------------------------------------------------
   --  Key Share Extension
   --------------------------------------------------------
   function Key_Share_Extension (
      Key_Type : Named_Group;
      PK : Byte_Seq)
      return Extension_Bytes
   is
      --  Note this only supports a single key share. We send
      --  the length of all the following key share data, each
      --  key is prepended with its type and length.
      Ext_Data : Byte_Seq :=
         LV (TLV (To_Tag_16 (Key_Type), PK));
   begin
      return TLVE (Key_Share, Ext_Data);
   end Key_Share_Extension;

end SPARKTLS.Extensions;
