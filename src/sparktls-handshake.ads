with SPARKNaCl;          use SPARKNaCl;

--  TLS 1.3 Handshake -- Shared Utilities
--
--  Constants, header parsing, Finished message, and ECDSA DER encoding.
--  Protocol-specific messages are in child packages:
--    SPARKTLS.Handshake.Client_Msgs  -- Build_Client_Hello, Parse_Server_Hello
--    SPARKTLS.Handshake.Server_Msgs  -- Parse_Client_Hello, Build_Server_Hello,
--                                       Build_Encrypted_Extensions,
--                                       Build_Certificate_Request
--    SPARKTLS.Handshake.Certs        -- Build_Certificate, Build_Certificate_Chain,
--                                       Build_Certificate_Verify
--    SPARKTLS.Handshake.TLS12        -- TLS 1.2 handshake messages
package SPARKTLS.Handshake with
   SPARK_Mode => On
is
   --  Handshake message type codes (RFC 8446 Section 4)
   HT_Client_Hello        : constant Byte := 16#01#;
   HT_Server_Hello        : constant Byte := 16#02#;
   HT_New_Session_Ticket   : constant Byte := 16#04#;
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

   --  RFC 8446 Section 4: Parse handshake message header.
   --  Every handshake message starts with type(1) + length(3).
   --  Returns the type and body length.
   procedure Parse_Handshake_Header
     (Data     : in     Byte_Seq;
      Msg_Type :    out HS_Msg_Type;
      Msg_Len  :    out N32;
      OK       :    out Boolean)
   --  Body uses Data'Length and To_RFLX, both First-agnostic.
   with Pre  => Data'Length > 0 and Data'Last < N32 (Natural'Last),
        Post => (if OK then
                   Msg_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                              16#0B# | 16#0C# | 16#0D# | 16#0E# |
                              16#0F# | 16#10# | 16#14#
                   and Msg_Len <= Max_HS_Msg);

   --  RFC 8446 Section 4.4.4: Build a Finished handshake message.
   --  Contains HMAC verify_data (32 bytes for SHA-256).
   --  Result is type(1) + length(3) + verify_data(32) = 36 bytes.
   procedure Build_Finished
     (Verify_Data : in     Bytes_32;
      Result      :    out Byte_Seq;
      Len         :    out N32)
   with Pre  => Result'First = 0
                and Result'Last < N32'Last
                and Result'Last >= 35,
        Post => Len = 36;

   --  Encode ECDSA (r, s) values as DER SEQUENCE of two INTEGERs.
   --  Used by both TLS 1.3 CertificateVerify and TLS 1.2 ServerKeyExchange.
   Max_ECDSA_DER_Len : constant := 140;

   procedure ECDSA_To_DER
     (R_Raw, S_Raw : in     Byte_Seq;
      Half_Len     : in     N32;
      DER_Out      :    out Byte_Seq;
      DER_Len      :    out N32)
   with Pre => R_Raw'First = 0
               and R_Raw'Last >= Half_Len - 1
               and S_Raw'First = 0
               and S_Raw'Last >= Half_Len - 1
               and Half_Len in 32 | 48
               and DER_Out'First = 0
               and DER_Out'Last >= Max_ECDSA_DER_Len - 1,
        Post => DER_Len <= Max_ECDSA_DER_Len;

   --  Pick a TLS sig-algo wire code that is (a) acceptable to the
   --  server (appears in Sig_Algs as a 2-byte big-endian list) and
   --  (b) compatible with our cert key type. Walks the server's list
   --  in order and returns the first match. Returns 0 if no match —
   --  caller should treat that as a CertificateVerify-impossible
   --  situation and either send an empty Cert or fail the handshake.
   --
   --  Sig_Algs layout: a flat byte buffer of (count*2) bytes where
   --  each pair is a 2-byte big-endian sig algo code (RFC 8446
   --  §4.2.3 / RFC 5246 §7.4.1.4.1).
   --
   --  Used by TLS 1.3 client (CertReq's signature_algorithms
   --  extension body) and TLS 1.2 client (CertReq's
   --  supported_signature_algorithms field).
   --  Allow_PKCS1_v1_5: True only for TLS 1.2 callers. RFC 8446
   --  §4.2.3 forbids RSA-PKCS1-v1_5 codes from being selected for
   --  TLS 1.3 CertificateVerify even though servers may list them
   --  in `signature_algorithms` for back-compat.
   function Pick_Sig_Algo
     (Sig_Algs           : Byte_Seq;
      Cert               : Signing_Algorithm;
      Allow_PKCS1_v1_5   : Boolean := False) return Unsigned_16
   with Pre => Sig_Algs'First >= 0
               and then Sig_Algs'Last < N32'Last;

end SPARKTLS.Handshake;
