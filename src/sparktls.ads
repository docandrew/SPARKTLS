with Interfaces; use Interfaces;

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS with SPARK_Mode => On is

   --------------------------------------------------------
   --  Basic Types. We use the types from SPARKNaCl
   --  wherever possible for consistency.
   --------------------------------------------------------

   subtype U24     is Unsigned_24;

   subtype Bytes_2 is Byte_Seq (0 .. 1);
   subtype Bytes_3 is Byte_Seq (0 .. 2);

   type TLS_Mode   is (Client, Server);

   type Tag_8      is new Byte;
   type Tag_16     is new U16;

   --------------------------------------------------------
   --  State Machine
   --------------------------------------------------------
   type Client_State is (
      Sending_Client_Hello,
      Waiting_Server_Hello,
      Waiting_Encrypted_Extensions,
      Waiting_Certificate_Request,
      Waiting_Certificate,
      Waiting_Certificate_Verify,
      Waiting_Finished,
      Established
   );

   type Server_State is (
      Waiting_Client_Hello,
      Received_Client_Hello,
      Negotiated,
      Wait_End_Of_Early_Data,
      Sending_Certificate,
      Sending_Certificate_Verify,
      Sending_Finished,
      Established
   );

   --------------------------------------------------------
   --  Record Layer
   --------------------------------------------------------
   type Content_Type is (
      Invalid,
      Change_Cipher_Spec,
      Alert,
      Handshake,
      Application_Data,
      Heartbeat
   ) with Size => 8;

   for Content_Type use (
      Invalid             => 0,
      Change_Cipher_Spec  => 20,
      Alert               => 21,
      Handshake           => 22,
      Application_Data    => 23,
      Heartbeat           => 24
   );

   --------------------------------------------------------
   --  Handshake Protocol
   --------------------------------------------------------
   type Handshake_Type is (
      Client_Hello,
      Server_Hello,
      New_Session_Ticket,
      End_Of_Early_Data,
      Encrypted_Extensions,
      Certificate,
      Certificate_Request,
      Certificate_Verify,
      Finished,
      Key_Update,
      Message_Hash
   ) with Size => 8;

   for Handshake_Type use (
      Client_Hello          => 1,
      Server_Hello          => 2,
      New_Session_Ticket    => 4,
      End_Of_Early_Data     => 5,
      Encrypted_Extensions  => 8,
      Certificate           => 11,
      Certificate_Request   => 13,
      Certificate_Verify    => 15,
      Finished              => 20,
      Key_Update            => 24,
      Message_Hash          => 254
   );

   type Protocol_Version is record
      Major : Byte;
      Minor : Byte;
   end record with Size => 16;

   for Protocol_Version use record
      Major at 0 range 0 .. 7;
      Minor at 0 range 8 .. 15;
   end record;

   --  TLSPlaintext
   type TLS_Plaintext_Header is record
      CType : Content_Type;
      Legacy_Record_Version : Protocol_Version;
      Length : U16;
   end record;

   for TLS_Plaintext_Header use record
      CType at 0 range 0 .. 7;
      Legacy_Record_Version at 1 range 0 .. 15;
      Length at 3 range 0 .. 15;
   end record;

   --  TLSCiphertext
   type TLS_Ciphertext_Header is record
      CType : Content_Type := Application_Data;
      Legacy_Record_Version : Protocol_Version := (Major => 3, Minor => 3);
      Length : U16;
   end record;

   for TLS_Ciphertext_Header use record
      CType at 0 range 0 .. 7;
      Legacy_Record_Version at 1 range 0 .. 15;
      Length at 3 range 0 .. 15;
   end record;

   --------------------------------------------------------
   --  Basic Conversions
   --------------------------------------------------------
   function To_Byte_Seq   (U : U16) return Bytes_2;
   function To_Byte_Seq_3 (U : U24) return Bytes_3;
   function To_U16 (I : Bytes_2) return U16;
   function To_U32 (I : Bytes_3) return U32;

   --------------------------------------------------------
   --  TLV (Type-Length-Value) Encoding
   --
   --  Given a message type and a message, return the
   --  message with the type and length prepended.
   --------------------------------------------------------
   function TLV (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq with
      Pre => Msg'Length <= 65535;
   
   function TLV (
      Tag : Tag_16;
      Msg : Byte_Seq) return Byte_Seq with
      Pre => Msg'Length <= 65535;

   function TLV (
      Tag : Tag_8;
      Msg : String) return Byte_Seq with
      Pre => Msg'Length <= 65535;
   
   --------------------------------------------------------
   --  TLV with 3 bytes of length
   --------------------------------------------------------
   function TLV_Handshake (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq with
      Pre => Msg'Length <= 16777215;
   
   --------------------------------------------------------
   --  TLV with legacy version for record layer
   --------------------------------------------------------
   function TLV_Record (
      Tag : Tag_8;
      Msg : Byte_Seq) return Byte_Seq with
      Pre => Msg'Length <= 65535;
   
   --------------------------------------------------------
   --  LV (Length-Value) Encoding. Some fields in the
   --  TLS protocol are encoded as a length followed by
   --  the value. This function returns the length and
   --  value as a sequence.
   --------------------------------------------------------
   function LV (Msg : Byte_Seq) return Byte_Seq with
      Pre => Msg'Length <= 65535;

end SPARKTLS;
