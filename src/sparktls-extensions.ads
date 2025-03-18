package SPARKTLS.Extensions is

   --------------------------------------------------------
   --  Extensions
   --------------------------------------------------------
   type Extension_Type is (
      Server_Name,
      Max_Fragment_Length,
      Status_Request,
      Supported_Groups,
      Signature_Algorithms,
      Use_SRTP,
      Heartbeat,
      Application_Layer_Protocol_Negotiation,
      Signed_Certificate_Timestamp,
      Client_Certificate_Type,
      Server_Certificate_Type,
      Padding,
      Pre_Shared_Key,
      Early_Data,
      Supported_Versions,
      Cookie,
      PSK_Key_Exchange_Modes,
      Certificate_Authorities,
      OID_Filters,
      Post_Handshake_Auth,
      Signature_Algorithms_Cert,
      Key_Share
   ) with Size => 16;

   for Extension_Type use (
      Server_Name                            => 0,
      Max_Fragment_Length                    => 1,
      Status_Request                         => 5,
      Supported_Groups                       => 10,
      Signature_Algorithms                   => 13,
      Use_SRTP                               => 14,
      Heartbeat                              => 15,
      Application_Layer_Protocol_Negotiation => 16,
      Signed_Certificate_Timestamp           => 18,
      Client_Certificate_Type                => 19,
      Server_Certificate_Type                => 20,
      Padding                                => 21,
      Pre_Shared_Key                         => 41,
      Early_Data                             => 42,
      Supported_Versions                     => 43,
      Cookie                                 => 44,
      PSK_Key_Exchange_Modes                 => 45,
      Certificate_Authorities                => 47,
      OID_Filters                            => 48,
      Post_Handshake_Auth                    => 49,
      Signature_Algorithms_Cert              => 50,
      Key_Share                              => 51
   );

   --------------------------------------------------------
   --  For supported groups and key share extensions
   --------------------------------------------------------
   type Named_Group is new U16 with
      Static_Predicate => Named_Group in
      16#0017# .. 16#001E# | 16#0100# .. 16#0104#;

   --  Elliptic curves
   SECP256R1  : constant Named_Group := 16#0017#;
   SECP384R1  : constant Named_Group := 16#0018#;
   SECP521R1  : constant Named_Group := 16#0019#;
   X25519     : constant Named_Group := 16#001D#;
   X448       : constant Named_Group := 16#001E#;

   --  Finite Field Groups (DHE)
   FFDHE_2048 : constant Named_Group := 16#0100#;
   FFDHE_3072 : constant Named_Group := 16#0101#;
   FFDHE_4096 : constant Named_Group := 16#0102#;
   FFDHE_6144 : constant Named_Group := 16#0103#;
   FFDHE_8192 : constant Named_Group := 16#0104#;

   type Supported_Group_List is array (Natural range <>)
      of Named_Group;

   --------------------------------------------------------
   --  Extension Generation Functions
   --------------------------------------------------------
   function Server_Name_Extension (Host : String)
      return Byte_Seq;

   function Key_Share_Extension (
      Key_Type : Named_Group;
      PK       : Byte_Seq) return Byte_Seq;

   function Supported_Groups_Extension (
      Groups : Supported_Group_List) return Byte_Seq;

end SPARKTLS.Extensions;
