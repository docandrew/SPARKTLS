with SPARKNaCl;          use SPARKNaCl;
with SPARKNaCl.Cryptobox;

--  TLS 1.3 Handshake Message Construction and Parsing
--
--  Builds and parses handshake messages (ClientHello, ServerHello,
--  Certificate, CertificateVerify, Finished) as byte sequences.
--  These are then wrapped in TLS record layer by SPARKTLS.Records.
package SPARKTLS.Handshake with
   SPARK_Mode => On
is
   --  Handshake message type codes (RFC 8446 Section 4)
   HT_Client_Hello        : constant Byte := 16#01#;
   HT_Server_Hello        : constant Byte := 16#02#;
   HT_Encrypted_Extensions : constant Byte := 16#08#;
   HT_Certificate         : constant Byte := 16#0B#;
   HT_Certificate_Request : constant Byte := 16#0D#;
   HT_Certificate_Verify  : constant Byte := 16#0F#;
   HT_Finished            : constant Byte := 16#14#;

   --  Extension type codes
   Ext_Server_Name         : constant := 16#00_00#;
   Ext_Supported_Groups    : constant := 16#00_0A#;
   Ext_Signature_Algorithms : constant := 16#00_0D#;
   Ext_Key_Share           : constant := 16#00_33#;
   Ext_PSK_Key_Exchange    : constant := 16#00_2D#;
   Ext_Supported_Versions  : constant := 16#00_2B#;

   --  Maximum ClientHello size
   Max_Client_Hello : constant := 816;

   --  Build a TLS 1.3 ClientHello handshake message.
   --  Returns the complete handshake message (type + length + body)
   --  ready to be wrapped in a TLS record.
   --
   --  Cipher suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
   --  Key share: X25519
   --  Signature algorithm: Ed25519
   procedure Build_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and N32 (Result'Length) >= Max_Client_Hello
                and HC.Cfg.Random /= null;

   --  Parse a ServerHello from raw handshake message bytes
   --  (after stripping the record header).
   --  Extracts: server random, cipher suite, key share (server public key).
   procedure Parse_Server_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre => Data'Length > 0;

   --  Parse an encrypted handshake message.
   --  msg_type is set to the handshake type (0x08, 0x0B, 0x0F, 0x14, etc.)
   --  payload starts at offset 4 (after type + 3-byte length).
   procedure Parse_Handshake_Header
     (Data     : in     Byte_Seq;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      OK       :    out Boolean);

   --  Build a Finished handshake message.
   --  verify_data is a 32-byte HMAC.
   procedure Build_Finished
     (Verify_Data : in     Bytes_32;
      Result      :    out Byte_Seq;
      Len         :    out N32)
   with Pre => Result'First = 0 and N32 (Result'Length) >= 36;

   --================================================================
   --  Server-side handshake procedures
   --================================================================

   --  Maximum ServerHello size
   Max_Server_Hello : constant := 256;

   --  Parse a ClientHello from raw handshake message bytes.
   --  Extracts: client_random, legacy_session_id, cipher suites offered,
   --  key share (client public key).
   --  Selects the best cipher suite we support.
   procedure Parse_Client_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre => Data'Length > 0;

   --  Build a ServerHello handshake message.
   --  Includes key_share and supported_versions extensions.
   --  Returns the complete handshake message ready for record wrapping.
   procedure Build_Server_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and N32 (Result'Length) >= Max_Server_Hello
                and HC.Cfg.Random /= null;

   --  Build a minimal EncryptedExtensions message (empty extension list).
   procedure Build_Encrypted_Extensions
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0 and N32 (Result'Length) >= 6;

   --  Build a Certificate handshake message wrapping a DER certificate.
   procedure Build_Certificate
     (Cert_DER : in     Byte_Seq;
      Cert_Len : in     N32;
      Result   :    out Byte_Seq;
      Len      :    out N32)
   with Pre => Result'First = 0
               and N32 (Result'Length) >= Cert_Len + 16
               and Cert_DER'First = 0
               and Cert_Len > 0;

   --  Build a Certificate message with leaf + intermediates from an Identity.
   procedure Build_Certificate_Chain
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0 and N32 (Result'Length) >= 16;

   procedure Build_Certificate_Verify
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Role            : in     TLS_Role;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   with Pre => Result'First = 0
               and N32 (Result'Length) >= 524
               and Transcript_Hash'First = 0
               and (Transcript_Hash'Length = 32
                    or Transcript_Hash'Length = 48);

   --================================================================
   --  mTLS support
   --================================================================

   --  Build a CertificateRequest handshake message (server → client).
   --  Minimal: empty certificate_request_context, signature_algorithms
   --  extension listing Ed25519, ECDSA-P256-SHA256, ECDSA-P384-SHA384.
   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0 and N32 (Result'Length) >= 32;

end SPARKTLS.Handshake;
