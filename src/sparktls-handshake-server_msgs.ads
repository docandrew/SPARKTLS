with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;

--  TLS 1.3 Server Handshake Messages
--
--  Parse ClientHello, build ServerHello, EncryptedExtensions,
--  and CertificateRequest.
package SPARKTLS.Handshake.Server_Msgs with
   SPARK_Mode => On
is
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

   --  RFC 8446 Section 4.3.1: Build EncryptedExtensions.
   --  Sent immediately after ServerHello (encrypted with HS keys).
   --  May include ALPN extension if client offered and server matches.
   procedure Build_Encrypted_Extensions
     (HC     : in     Handshake_Context;
      S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0 and Result'Last >= 270;
   --  Header(4) + ext_list_len(2) + ALPN ext(7 + Max_Hostname_Len=255) = 268

   --  Build a CertificateRequest handshake message (server -> client).
   --  Minimal: empty certificate_request_context, signature_algorithms
   --  extension listing Ed25519, ECDSA-P256-SHA256, ECDSA-P384-SHA384.
   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0
               and Result'Last in 31 .. 16#FFFF#;

end SPARKTLS.Handshake.Server_Msgs;
