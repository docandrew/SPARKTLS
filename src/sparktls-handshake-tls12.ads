with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Handshake.Client_Msgs;

--  TLS 1.2 Handshake Messages (RFC 5246 §7.4, RFC 8422)
--
--  TLS 1.2 ECDHE handshake flow (server-authenticated):
--
--    Client                           Server
--    ------                           ------
--    ClientHello        -------->
--                                     ServerHello
--                                     Certificate
--                                     ServerKeyExchange
--                       <--------     ServerHelloDone
--    ClientKeyExchange
--    [ChangeCipherSpec]
--    Finished           -------->
--                                     [ChangeCipherSpec]
--                       <--------     Finished
--
--  This package handles TLS-1.2-specific messages.
--  Shared messages (Certificate, Parse_Handshake_Header) stay in
--  SPARKTLS.Handshake.
package SPARKTLS.Handshake.TLS12 with
   SPARK_Mode => On
is
   --================================================================
   --  Constants from RFC 5246 and RFC 8422
   --================================================================

   --  Handshake type codes
   HT_Server_Key_Exchange : constant Byte := 16#0C#;
   HT_Server_Hello_Done   : constant Byte := 16#0E#;
   HT_Client_Key_Exchange : constant Byte := 16#10#;
   HT_Finished            : constant Byte := 16#14#;

   --  RFC 8422 §5.4: ECCurveType
   EC_Curve_Type_Named : constant Byte := 3;

   --  RFC 8422 §5.1.1: NamedGroup wire values
   Group_Secp256r1 : constant Unsigned_16 := 16#0017#;
   Group_Secp384r1 : constant Unsigned_16 := 16#0018#;
   Group_X25519    : constant Unsigned_16 := 16#001D#;

   --  RFC 8422 §5.4: ECPoint sizes (uncompressed)
   --  P-256: 0x04 || x[32] || y[32] = 65 bytes
   --  P-384: 0x04 || x[48] || y[48] = 97 bytes
   --  X25519: raw u-coordinate = 32 bytes (no 0x04 prefix)
   P256_Point_Len  : constant := 65;
   P384_Point_Len  : constant := 97;
   X25519_Point_Len : constant := 32;

   --  Maximum buffer sizes
   Max_Server_Key_Exchange : constant := 512;
   Max_Client_Key_Exchange : constant := 128;
   Max_Server_Hello_12     : constant := 512;

   --  Finished message: 4-byte header + 12-byte verify_data
   Finished_12_Total_Len : constant := 16;

   --  ServerHelloDone: 4-byte header, empty body
   Server_Hello_Done_Len : constant := 4;

   --================================================================
   --  Ghost functions: RFC behavioral invariants
   --================================================================

   --  RFC 8422: Valid ECDHE group for our implementation.
   function Valid_ECDHE_Group (G : Unsigned_16) return Boolean is
     (G in Group_Secp256r1 | Group_Secp384r1 | Group_X25519);

   --  RFC 8422 §5.4: ECPoint byte length for a given group.
   function Point_Len_For_Group (G : Unsigned_16) return N32 is
     (case G is
        when Group_Secp256r1 => P256_Point_Len,
        when Group_Secp384r1 => P384_Point_Len,
        when Group_X25519    => X25519_Point_Len,
        when others          => 0);

   --  RFC 8422 §5.4: ServerKeyExchange params size (before signature).
   --  = curve_type(1) + named_curve(2) + point_length(1) + point(N)
   function SKE_Params_Len (G : Unsigned_16) return N32 is
     (4 + Point_Len_For_Group (G))
   with Ghost,
        Pre => Valid_ECDHE_Group (G);

   --  RFC 5246 §7.4.3: The signature input for ServerKeyExchange.
   --  MUST be: client_random[32] || server_random[32] || params[N]
   --  Getting the random order wrong or omitting params from the
   --  signature is a critical vulnerability (allows MITM).
   function SKE_Sig_Input_Len (G : Unsigned_16) return N32 is
     (64 + SKE_Params_Len (G))  --  32 + 32 + params
   with Ghost,
        Pre => Valid_ECDHE_Group (G);

   --  RFC 5246 §7.4.9: Finished message is always exactly 16 bytes.
   --  type(1)=0x14 + length(3)=0x00000C + verify_data(12)
   function Valid_Finished_12_Len (Len : N32) return Boolean is
     (Len = Finished_12_Total_Len)
   with Ghost;

   --  RFC 5246 §7.4.5: ServerHelloDone is always exactly 4 bytes.
   --  type(1)=0x0E + length(3)=0x000000 (empty body)
   function Valid_SHD_Len (Len : N32) return Boolean is
     (Len = Server_Hello_Done_Len)
   with Ghost;

   --  RFC 5246 §7.4.1.2: Valid TLS 1.2 cipher suite (ECDHE+AEAD only).
   function Valid_TLS12_Suite (S : Unsigned_16) return Boolean is
     (S in Suite_ECDHE_RSA_AES128_GCM_SHA256
        | Suite_ECDHE_RSA_AES256_GCM_SHA384
        | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
        | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
        | Suite_ECDHE_RSA_CHACHA20_SHA256
        | Suite_ECDHE_ECDSA_CHACHA20_SHA256)
   with Ghost;

   --  RFC 5246 §7.4.1.2: Is this an ECDHE_RSA suite (vs ECDHE_ECDSA)?
   --  Determines whether the ServerKeyExchange signature uses RSA or ECDSA.
   function Is_ECDHE_RSA_Suite (S : Unsigned_16) return Boolean is
     (S in Suite_ECDHE_RSA_AES128_GCM_SHA256
        | Suite_ECDHE_RSA_AES256_GCM_SHA384
        | Suite_ECDHE_RSA_CHACHA20_SHA256)
   with Ghost;

   --  RFC 5246: Does this suite use SHA-384 for PRF?
   function Suite_Uses_SHA384 (S : Unsigned_16) return Boolean is
     (S in Suite_ECDHE_RSA_AES256_GCM_SHA384
        | Suite_ECDHE_ECDSA_AES256_GCM_SHA384)
   with Ghost;

   --  RFC 5246 §8.1 / RFC 7627: Master secret derivation label
   --  MUST match the negotiated extensions.
   --  Using EMS label without EMS extension (or vice versa) produces
   --  a valid-looking but incompatible master secret.
   function Correct_Master_Label
     (Use_EMS : Boolean;
      Label   : String) return Boolean is
     (if Use_EMS then Label = "extended master secret"
      else Label = "master secret")
   with Ghost;

   --  TLS 1.2 wire suite → internal AEAD suite mapping.
   --  This is the normative mapping; using the wrong internal suite
   --  causes silent key derivation failure (Bug 1 pattern).
   function Internal_Suite_For (S : Unsigned_16) return Unsigned_16 is
     (case S is
         when Suite_ECDHE_RSA_AES128_GCM_SHA256
            | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
               Suite_AES_128_GCM_SHA256,
         when Suite_ECDHE_RSA_AES256_GCM_SHA384
            | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
               Suite_AES_256_GCM_SHA384,
         when Suite_ECDHE_RSA_CHACHA20_SHA256
            | Suite_ECDHE_ECDSA_CHACHA20_SHA256 =>
               Suite_CHACHA20_POLY1305_SHA256,
         when others => 0)
   with Ghost;

   --  ClientHello cipher suite list covers the version policy.
   --  A ClientHello that only offers TLS 1.3 suites will be rejected
   --  by TLS 1.2-only servers.
   function Suites_Cover_Policy
     (Has_TLS13_Suite : Boolean;
      Has_TLS12_Suite : Boolean;
      Policy          : Version_Policy) return Boolean is
     (case Policy is
         when Allow_Both    => Has_TLS13_Suite and Has_TLS12_Suite,
         when TLS_1_3_Only  => Has_TLS13_Suite,
         when TLS_1_2_Only  => Has_TLS12_Suite)
   with Ghost;

   --================================================================
   --  Procedures
   --================================================================

   --  RFC 8422 §5.4 + RFC 5246 §7.4.3: Build ServerKeyExchange.
   --
   --  Wire format (inside handshake header):
   --    ec_params:
   --      curve_type[1] = 0x03 (named_curve)
   --      named_curve[2] (e.g., 0x0017 for secp256r1)
   --    ec_point:
   --      point_len[1]
   --      point[N] (uncompressed for NIST, raw for X25519)
   --    signature:
   --      hash_alg[1] || sig_alg[1] || sig_len[2] || sig[M]
   --
   --  The signature MUST cover:
   --    client_random[32] || server_random[32] ||
   --    curve_type[1] || named_curve[2] || point_len[1] || point[N]
   --
   --  RFC 5246 §7.4.3: "Sending handshake messages in an unexpected
   --  order results in a fatal error."
   --
   --  Precondition: HC.Selected_Group must be set to a valid group,
   --  and the ephemeral keypair must already be generated in HC.
   procedure Build_Server_Key_Exchange
     (HC     : in     Handshake_Context;
      Id     : in     Identity;
      Random : in     Random_Bytes_Fn;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= Max_Server_Key_Exchange - 1
                and Random /= null
                and Id.Has_Identity
                and Valid_ECDHE_Group (HC.Selected_Group),
        Post => Len <= Max_Server_Key_Exchange;

   --  RFC 5246 §7.4.5: Build ServerHelloDone.
   --
   --  This message has NO body — just the 4-byte handshake header:
   --    type[1] = 0x0E || length[3] = 0x000000
   --
   --  Its only purpose is to signal the end of the server's first flight.
   --  RFC 5246 §7.4.5: "This message means that the server is done
   --  sending messages to support the key exchange, and the client
   --  can proceed with its phase of the key exchange."
   procedure Build_Server_Hello_Done
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= Server_Hello_Done_Len - 1,
        Post => Valid_SHD_Len (Len)               --  exactly 4 bytes
                and Result (0) = HT_Server_Hello_Done  --  type = 0x0E
                and Result (1) = 0                     --  length = 0
                and Result (2) = 0
                and Result (3) = 0;

   --  RFC 8422 §5.7 + RFC 5246 §7.4.7: Build ClientKeyExchange for ECDHE.
   --
   --  Wire format (inside handshake header):
   --    point_len[1] || point[N]
   --
   --  The point is the client's ephemeral ECDHE public key, encoded:
   --    P-256: 0x04 || x[32] || y[32] = 65 bytes
   --    P-384: 0x04 || x[48] || y[48] = 97 bytes
   --    X25519: raw u-coordinate = 32 bytes
   --
   --  Wrapped in handshake header: type[1]=0x10 || length[3] || body
   procedure Build_Client_Key_Exchange
     (HC     : in     Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= Max_Client_Key_Exchange - 1
                and Valid_ECDHE_Group (HC.Selected_Group),
        Post => Len <= Max_Client_Key_Exchange;

   --  RFC 8422 §5.4: Parse ServerKeyExchange.
   --
   --  Extracts:
   --    1. Named curve ID → validates against supported groups
   --    2. Server's ephemeral public key → stored in HC
   --    3. Signature → verified against server's certificate
   --
   --  RFC 5246 §7.4.3: The signature verification MUST cover:
   --    client_random || server_random || params
   --  Omitting the randoms from verification would allow MITM.
   --
   --  RFC 5246 §7.4.3: "If the client has offered the
   --  'signature_algorithms' extension, the signature algorithm and
   --  hash algorithm MUST be a pair listed in that extension."
   procedure Parse_Server_Key_Exchange
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre  => Data'First = 0 and Data'Length >= 4,
        Post => (if OK then
                   Valid_ECDHE_Group (HC.Selected_Group));

   --  RFC 8422 §5.7: Parse ClientKeyExchange.
   --
   --  Extracts the client's ephemeral ECDHE public key.
   --  The curve MUST match HC.Selected_Group (set during ServerKeyExchange).
   --  Stores the peer's public key in HC for shared secret computation.
   procedure Parse_Client_Key_Exchange
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre  => Data'First = 0 and Data'Length >= 4
                and Valid_ECDHE_Group (HC.Selected_Group),
        Post => (if OK then
                   HC.Selected_Group = HC.Selected_Group'Old);

   --  RFC 5246 §7.4.9: Build TLS 1.2 Finished message.
   --
   --  Wire format: type[1]=0x14 || length[3]=0x00000C || verify_data[12]
   --  Total: exactly 16 bytes.
   --
   --  verify_data = PRF(master_secret, finished_label,
   --                    Hash(handshake_messages))[0..11]
   --
   --  RFC 5246 §7.4.9: "It is a fatal error if a Finished message is
   --  not preceded by a ChangeCipherSpec message at the appropriate
   --  point in the handshake."
   --
   --  RFC 5246 §7.4.9: "Recipients MUST verify that the contents
   --  of the Finished message are correct."
   --
   --  The Label MUST be "client finished" or "server finished".
   --  Using the wrong label produces valid-looking but incompatible output.
   procedure Build_Finished_12
     (Master          : in     Bytes_48;
      Label           : in     String;
      Transcript_Hash : in     Byte_Seq;
      Use_SHA384      : in     Boolean;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= Finished_12_Total_Len - 1
                and Key_Schedule_12.Valid_Finished_Label (Label)
                and Transcript_Hash'First = 0
                and Transcript_Hash'Length in 32 | 48,
        Post => Valid_Finished_12_Len (Len)        --  exactly 16 bytes
                and Result (0) = HT_Finished       --  type = 0x14
                and Result (1) = 0                 --  length = 12
                and Result (2) = 0
                and Result (3) = 12;

   --  RFC 5246 §7.4.8: Build TLS 1.2 CertificateVerify.
   --
   --  In TLS 1.2, the signed data is Hash(handshake_messages) — the
   --  transcript hash directly. There is NO context string prefix
   --  (unlike TLS 1.3 which prepends "TLS 1.3, server CertificateVerify\x00").
   --
   --  Wire format:
   --    type[1]=0x0F || length[3] ||
   --    hash_algorithm[1] || signature_algorithm[1] ||
   --    signature_length[2] || signature[N]
   procedure Build_Certificate_Verify_12
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= 523
                and Transcript_Hash'First = 0
                and Transcript_Hash'Length in 32 | 48
                and Random /= null
                and Id.Has_Identity;

   --  RFC 5246 §7.4.1.2: Build TLS 1.2 ServerHello.
   --
   --  Wire format (inside handshake header):
   --    server_version[2] = 0x0303 (TLS 1.2, real version not legacy)
   --    random[32]
   --    session_id_length[1] + session_id[0..32]
   --    cipher_suite[2]
   --    compression_method[1] = 0x00 (null)
   --    extensions_length[2] + extensions[...]
   --
   --  Required extensions:
   --    renegotiation_info (0xFF01) — empty for initial handshake
   --
   --  RFC 5246 §7.4.1.2: "The server MUST NOT send a version lower
   --  than the client's minimum version."
   procedure Build_Server_Hello_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and Result'Last >= Max_Server_Hello_12 - 1
                and HC.Cfg.Random /= null
                and HC.Version = TLS_1_2,
        --  Frame postcondition: S.State is not modified by ServerHello
        --  construction. Callers (Build_Server_Flight_12) need this so
        --  subsequent Set_State / Send_Alert_And_Error preconditions
        --  about S.State stay provable through the flight body.
        Post => Len <= Max_Server_Hello_12
                and S.State = S.State'Old;

   --  RFC 5246 §7.4.1.2: Parse TLS 1.2 ServerHello.
   --
   --  Validates:
   --    - server_version = 0x0303
   --    - cipher_suite is one we offered and support
   --    - compression_method = 0x00 (we don't support compression)
   --    - Extracts server_random
   --    - Extracts session_id (for resumption)
   --
   --  RFC 5246 §7.4.3: "The cipher suite list ... contains the
   --  cipher suites in the order of the client's preference."
   --  The server MUST select a suite from the client's list.
   procedure Parse_Server_Hello_12
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre  => Data'First = 0 and Data'Length > 0
                and HC.Version = TLS_1_2,
        Post => (if OK then
                   Valid_TLS12_Suite (S.Negotiated_Suite)
                   and HC.Version = TLS_1_2);

   --  RFC 5246 §7.4.2: Build TLS 1.2 Certificate message.
   --
   --  TLS 1.2 format (no certificate_request_context, no per-cert extensions):
   --    type[1]=0x0B || length[3] ||
   --    certificate_list_length[3] ||
   --    { certificate_length[3] || certificate_data[N] }*
   --
   --  Difference from TLS 1.3: no context byte, no per-cert extensions.
   procedure Build_Certificate_Chain_12
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0 and Result'Last >= 15
               and Id.Has_Identity;

end SPARKTLS.Handshake.TLS12;
