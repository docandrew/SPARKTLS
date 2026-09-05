with SPARKNaCl;
use SPARKNaCl;

--  TLS 1.3 Handshake -- Shared Utilities
--
--  Constants, header parsing, and ECDSA DER encoding.
--  Protocol-specific messages are in child packages:
--    SPARKTLS.Handshake.Client_Msgs  -- Build_Client_Hello, Parse_Server_Hello
--    SPARKTLS.Handshake.Server_Msgs  -- Parse_Client_Hello, shared ALPN selection
--    SPARKTLS.Handshake.Certs        -- Shared X.509 helpers and TLS 1.2 parser
--    SPARKTLS.Handshake.TLS12        -- TLS 1.2 handshake messages
--    SPARKTLS.Handshake.TLS13        -- TLS 1.3 handshake messages

package SPARKTLS.Handshake
  with SPARK_Mode => On
is
   --  Handshake message type codes (RFC 8446 Section 4)
   --  HandshakeType names are the Maybe_HS_Msg enum literals in SPARKTLS;
   --  wire bytes come from HS_Msg_Wire.

   --  Extension type codes
   Ext_Server_Name          : constant := 16#00_00#;
   Ext_Supported_Groups     : constant := 16#00_0A#;
   Ext_Signature_Algorithms : constant := 16#00_0D#;
   Ext_Key_Share            : constant := 16#00_33#;
   Ext_PSK_Key_Exchange     : constant := 16#00_2D#;
   Ext_Supported_Versions   : constant := 16#00_2B#;

   --  RFC 8446 Section 4: Parse handshake message header.
   --  Every handshake message starts with type(1) + length(3).
   --  Returns the type and body length.
   procedure Parse_Handshake_Header
     (Data     : in Byte_Seq;
      Msg_Type : out HS_Msg_Type;
      Msg_Len  : out N32;
      OK       : out Boolean)
      --  Body uses Data'Length and To_RFLX, both First-agnostic.
   with
     Pre => Data'Length > 0 and Data'Last < N32 (Natural'Last),
     Post =>
       (if OK
        then
          Msg_Type /= HT_Unknown
          and Msg_Len <= Max_HS_Msg
          and Msg_Len <= N32 (Data'Length) - 4);

   --  Encode ECDSA (r, s) values as DER SEQUENCE of two INTEGERs.
   --  Used by both TLS 1.3 CertificateVerify and TLS 1.2 ServerKeyExchange.
   Max_ECDSA_DER_Len : constant := 140;

   procedure ECDSA_To_DER
     (R_Raw, S_Raw : in Byte_Seq; Half_Len : in N32; DER_Out : out Byte_Seq; DER_Len : out N32)
   with
     Pre =>
       R_Raw'First = 0
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
   --  in order and returns the first match. Returns 0 if no match
   --  caller should treat that as a CertificateVerify-impossible
   --  situation and either send an empty Cert or fail the handshake.
   --
   --  Sig_Algs layout: a flat byte buffer of (count*2) bytes where
   --  each pair is a 2-byte big-endian sig algo code (RFC 8446
   --  4.2.3 / RFC 5246 7.4.1.4.1).
   --
   --  Used by TLS 1.3 client (CertReq's signature_algorithms
   --  extension body) and TLS 1.2 client (CertReq's
   --  supported_signature_algorithms field).
   --  Allow_PKCS1_v1_5: True only for TLS 1.2 callers. RFC 8446
   --  4.2.3 forbids RSA-PKCS1-v1_5 codes from being selected for
   --  TLS 1.3 CertificateVerify even though servers may list them
   --  in `signature_algorithms` for back-compat.
   function Sig_Algo_Compatible_With_Cert
     (Scheme : Maybe_Sig_Scheme; Cert : Signing_Algorithm; Allow_PKCS1_v1_5 : Boolean := False)
      return Boolean
   is (Scheme = Scheme_None
       or else (case Cert is
                  when Sign_Ed25519 => Scheme = Sig_Ed25519,
                  when Sign_ECDSA_P256 => Scheme = Sig_ECDSA_P256_SHA256,
                  when Sign_ECDSA_P384 => Scheme = Sig_ECDSA_P384_SHA384,
                  when Sign_RSA_PSS =>
                    Scheme in Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512
                    or else (Allow_PKCS1_v1_5
                             and then Scheme in
                                        Sig_RSA_PKCS1_SHA256
                                        | Sig_RSA_PKCS1_SHA384
                                        | Sig_RSA_PKCS1_SHA512),
                  when Sign_None => False));

   function Pick_Sig_Algo
     (Sig_Algs : Byte_Seq; Cert : Signing_Algorithm; Allow_PKCS1_v1_5 : Boolean := False)
      return Maybe_Sig_Scheme
   with
     Pre => Sig_Algs'Last < N32'Last,
     Post => Sig_Algo_Compatible_With_Cert (Pick_Sig_Algo'Result, Cert, Allow_PKCS1_v1_5);

   function Pick_Sig_Algo_With_Prefs
     (Sig_Algs         : Byte_Seq;
      Cert             : Signing_Algorithm;
      Prefs            : Sig_Algo_List;
      Count            : Natural;
      Allow_PKCS1_v1_5 : Boolean := False) return Maybe_Sig_Scheme
   with
     Pre => Sig_Algs'Last < N32'Last and then Count <= Max_Sig_Algos,
     Post =>
       Sig_Algo_Compatible_With_Cert (Pick_Sig_Algo_With_Prefs'Result, Cert, Allow_PKCS1_v1_5);

end SPARKTLS.Handshake;
