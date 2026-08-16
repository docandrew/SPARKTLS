with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with RFLX.RFLX_Builtin_Types;
with X509;

package SPARKTLS with
   SPARK_Mode => On
is
   --  Needed because Session is now a private type: contracts that used to
   --  say S.State'Old now say State (S)'Old, and Ada only permits 'Old on a
   --  function call in a potentially-unevaluated context (inside an "if" in
   --  a postcondition) when this pragma is present. The accessors are
   --  precondition-free expression functions over one component each, so
   --  evaluating them unconditionally is harmless. Same pragma RecordFlux
   --  emits in its own generated specs.
   pragma Unevaluated_Use_Of_Old (Allow);
   ----------------------------------------------------------------------------
   --  Constants
   ----------------------------------------------------------------------------

   --  48-byte sequence (for SHA-384 digests/secrets)
   subtype Index_48 is N32 range 0 .. 47;
   subtype Bytes_48 is Byte_Seq (Index_48);

   --  Heap-allocated byte sequence (for reassembly buffers)
   type Byte_Seq_Access is access Byte_Seq;
   procedure Free_Byte_Seq (Ptr : in out Byte_Seq_Access)
      with Post => Ptr = null;

   --  Validated wire-length subtypes.
   --  Any value parsed from the network that will be used as an array
   --  bound MUST be converted to one of these subtypes first. SPARK
   --  then requires a proof that the value is in range, enforcing
   --  "validate before allocate" at the type level.
   --
   --  Using a raw N32 as an array bound when the source is the network
   --  is a Heartbleed-class vulnerability. These subtypes make it
   --  impossible to forget the validation.
   subtype Wire_Ext_Len is N32 range 1 .. 131072;
   --  Extension data length (sig_algs, key_share body, etc.)
   --  Upper bound matches Max_HS_Msg (128 KB) for reassembled messages.

   subtype Wire_Small_Ext_Len is N32 range 1 .. 512;
   --  Small extensions (ALPN, supported_groups, supported_versions)

   subtype Wire_Key_Share_Len is N32 range 1 .. 16384;
   --  Total key_share extension body. RFC 8446 §4.2.8 allows the
   --  client to offer multiple `KeyShareEntry` values, and modern
   --  clients (Go default, Chrome) include PQ hybrids — each
   --  X25519MLKEM768 entry alone is 1220 bytes, X25519Kyber768 is
   --  1188 bytes, ML-KEM-1024 is 1572 bytes. With ~7 default
   --  entries the body easily reaches several KB. The upper bound
   --  is set to 16 KB: large enough to accept legitimate multi-PQ
   --  key_share extensions while still bounding heap allocation
   --  in Parse_KS_Extension. Was 256 — matched a single P-384
   --  entry only and silently dropped real-world TLS 1.3 clients.

   --  Handshake message length (3 bytes on wire, max 2^24 - 1).
   --  Bounded to Max_HS_Msg (128 KB) for reassembled messages.
   Max_HS_Msg : constant := 131072;
   subtype HS_Msg_Len is N32 range 0 .. Max_HS_Msg;

   --  Reassembly buffer pointer. The two facts every indexing site needs
   --  from the buffer itself -- zero-based, and short enough that
   --  N32 (Buf'Length) cannot overflow -- are carried here rather than
   --  threaded through contracts. Max_HS_Msg (131072) is well under
   --  N32'Last, so the N32 conversions are discharged by the subtype.
   --  The obligation lands only where the pointer is assigned; every
   --  allocation site is 0 .. X - 1 with X bounded by Max_HS_Msg or
   --  IO_Buffer_Capacity (33280).
   subtype Reasm_Buf_Access is Byte_Seq_Access
     with Dynamic_Predicate =>
       Reasm_Buf_Access = null
       or else (Reasm_Buf_Access'First = 0
                and then Reasm_Buf_Access'Length <= Max_HS_Msg);

   --  Handshake message type code (1 byte on wire).
   --  RFC 8446 Section 4 defines the valid values.
   subtype HS_Msg_Type is Byte;

   --  TLS record fragment length after Parse_Record_Header.
   --  Always 1 .. Max_Fragment + 256 (encrypted records).
   subtype Record_Frag_Len is N32 range 1 .. 16384 + 256;

   Max_Record_Plaintext : constant := 16384;  --  RFC 8446 limit
   Max_Record_Overhead  : constant := 256;    --  tag + content type
   Max_Record_Size      : constant :=
      Max_Record_Plaintext + Max_Record_Overhead;

   --  I/O buffer capacity. Large enough for two max-size records
   --  so the caller doesn't have to drain after every record.
   IO_Buffer_Capacity : constant N32 := 2 * Max_Record_Size;

   Transcript_Capacity  : constant N32 := 32768;  --  32 KB

   --  Sufficient for all real-world handshakes. Typical transcript is
   --  ~2 KB. Pathological inputs (32K sig_algs) require reassembly
   --  but the transcript only includes the final parsed result.
   --
   --  TODO: Replace with streaming SHA-256/384 hash (Init/Update/Final
   --  in SPARKNaCl) to eliminate this buffer entirely. The building
   --  blocks exist (Hashblocks_256/512) but SPARKNaCl needs a public
   --  streaming API with proper test coverage before we use it here.
   Max_Hostname_Len     : constant := 255;
   Max_Cert_DER_Len     : constant N32 := 8192;

   --  Signature algorithm negotiation
   Max_Sig_Algos : constant := 16;
   subtype Sig_Algo_Index is Natural range 0 .. Max_Sig_Algos - 1;
   type Sig_Algo_List is array (Sig_Algo_Index) of Unsigned_16;
   function Sig_Scheme_In_List
     (Scheme : Unsigned_16;
      List   : Sig_Algo_List;
      Count  : Natural) return Boolean is
     (Count <= Max_Sig_Algos
        and then (for some I in 0 .. Count - 1 => List (I) = Scheme));

   --  CH1 extension order tracking (for HRR CH2 validation)
   --  Uses a rolling polynomial hash (fingerprint * 31 xor code).
   --  Reordering extensions changes the hash. No array needed.

   ----------------------------------------------------------------------------
   --  Cipher suite
   ----------------------------------------------------------------------------

   type TLS_Role is (Role_Client, Role_Server);

   type Cipher_Suite is
     (TLS_AES_128_GCM_SHA256,
      TLS_CHACHA20_POLY1305_SHA256,
      TLS_AES_256_GCM_SHA384);

   --  TLS 1.3 cipher suite code values
   Suite_AES_128_GCM_SHA256        : constant Unsigned_16 := 16#1301#;
   Suite_CHACHA20_POLY1305_SHA256  : constant Unsigned_16 := 16#1303#;
   Suite_AES_256_GCM_SHA384        : constant Unsigned_16 := 16#1302#;

   --  TLS 1.2 cipher suite code values (ECDHE + AEAD only)
   Suite_ECDHE_RSA_AES128_GCM_SHA256   : constant Unsigned_16 := 16#C02F#;
   Suite_ECDHE_RSA_AES256_GCM_SHA384   : constant Unsigned_16 := 16#C030#;
   Suite_ECDHE_ECDSA_AES128_GCM_SHA256 : constant Unsigned_16 := 16#C02B#;
   Suite_ECDHE_ECDSA_AES256_GCM_SHA384 : constant Unsigned_16 := 16#C02C#;
   Suite_ECDHE_RSA_CHACHA20_SHA256     : constant Unsigned_16 := 16#CCA8#;
   Suite_ECDHE_ECDSA_CHACHA20_SHA256   : constant Unsigned_16 := 16#CCA9#;

   Max_Config_Cipher_Suites : constant := 16;
   subtype Cipher_Pref_Index is Natural range 1 .. Max_Config_Cipher_Suites;
   type Cipher_Suite_List is array (Cipher_Pref_Index) of Unsigned_16;
   type Cipher_Suite_Preference_Groups is
     array (Cipher_Pref_Index) of Natural range 0 .. Max_Config_Cipher_Suites;

   ----------------------------------------------------------------------------
   --  Connection state
   --
   --  The handshake proceeds through these states in order.
   --  Client and server share the same enum; unused states for
   --  a given role are simply never entered.
   ----------------------------------------------------------------------------

   --  Protocol version
   type TLS_Version is (TLS_1_3, TLS_1_2);

   --  Version policy — controls which protocol versions are offered/accepted.
   --  Default: offer both, prefer 1.3.
   type Version_Policy is
     (Allow_Both,     --  Offer TLS 1.3 and 1.2; prefer 1.3 (default)
      TLS_1_3_Only,   --  Only accept TLS 1.3; reject 1.2 clients
      TLS_1_2_Only);  --  Only accept TLS 1.2; do not offer 1.3

   type Connection_State is
     (Idle,

      --  Client-side handshake
      Client_Hello_Sent,
      Wait_Server_Hello,
      Wait_Encrypted_Extensions,
      Wait_Certificate_Request,   --  mTLS: optional CertificateRequest
      Wait_Certificate,
      Wait_Certificate_Verify,
      Wait_Server_Finished,
      Client_Certificate_Sent,    --  mTLS: sent our Certificate
      Client_Cert_Verify_Sent,    --  mTLS: sent our CertificateVerify
      Client_Finished_Sent,

      --  Server-side handshake
      Wait_Client_Hello,
      Wait_Client_Hello_Retry,    --  HRR sent, waiting for second CH
      Server_Hello_Sent,
      Sent_Certificate_Request,   --  mTLS: sent CertificateRequest
      Wait_Client_Certificate,    --  mTLS: waiting for client cert
      Wait_Client_Cert_Verify,    --  mTLS: waiting for client CertVerify
      Wait_Client_Finished,

      --  Post-handshake (both roles)
      Connected,
      Closing,
      Closed,
      Error_State);

   ----------------------------------------------------------------------------
   --  Protocol requirements as ghost functions (RFC 8446)
   --
   --  These are formally verified by SPARK — the prover checks that
   --  the implementation never violates these properties.
   ----------------------------------------------------------------------------

   --  RFC 8446 §5: CCS is only valid during the handshake.
   --  CCS after server Finished MUST be rejected.
   function CCS_Allowed (State : Connection_State) return Boolean is
     (State not in Connected | Closing | Closed | Error_State | Idle)
   with Ghost;

   --  RFC 8446 §5.1: Handshake is complete.
   function Handshake_Complete (State : Connection_State) return Boolean is
     (State in Connected | Closing | Closed)
   with Ghost;

   --  RFC 8446 §7.3, §7.5: Key phase.
   --  Before server Finished is sent, handshake traffic keys are used.
   --  After server Finished, application traffic keys are used.
   function In_Handshake_Key_Phase (State : Connection_State) return Boolean is
     (State in Wait_Client_Hello | Wait_Client_Hello_Retry |
              Server_Hello_Sent |
              Sent_Certificate_Request | Wait_Client_Certificate |
              Wait_Client_Cert_Verify | Wait_Client_Finished |
              Client_Hello_Sent | Wait_Server_Hello |
              Wait_Encrypted_Extensions | Wait_Certificate_Request |
              Wait_Certificate | Wait_Certificate_Verify |
              Wait_Server_Finished | Client_Certificate_Sent |
              Client_Cert_Verify_Sent)
   with Ghost;

   function In_App_Key_Phase (State : Connection_State) return Boolean is
     (State in Connected | Closing | Client_Finished_Sent)
   with Ghost;

   --  RFC 8446 §6: Valid alert constraints.
   --  Post-handshake: only close_notify may use Warning level.
   --  All other alerts MUST be Fatal.
   function Valid_Alert (State : Connection_State;
                         Level : Byte;
                         Desc  : Byte) return Boolean is
     (Level in 1 .. 2 and then
      (if Handshake_Complete (State) and Desc /= 0
       then Level = 2
       else True))
   with Ghost;

   --  RFC 8446 §4: Expected handshake message type per state.
   --  Server expects these message types from the client:
   --    Wait_Client_Hello    → ClientHello (type 0x01)
   --    Wait_Client_Finished → Finished (type 0x14)
   --    Wait_Client_Certificate → Certificate (type 0x0B)
   --    Wait_Client_Cert_Verify → CertificateVerify (type 0x0F)
   --  Returns 0 if no specific handshake type is expected (e.g., Connected).
   function Expected_HS_Type (State : Connection_State) return Byte is
     (case State is
        when Wait_Client_Hello         => 16#01#,  --  ClientHello
        when Wait_Client_Hello_Retry  => 16#01#,  --  ClientHello (retry)
        when Wait_Client_Finished     => 16#14#,  --  Finished
        when Wait_Client_Certificate => 16#0B#,  --  Certificate
        when Wait_Client_Cert_Verify => 16#0F#,  --  CertificateVerify
        when Wait_Server_Hello    => 16#02#,  --  ServerHello
        when Wait_Server_Finished => 16#14#,  --  Finished
        when others               => 0)
   with Ghost;

   --  RFC 8446 §4: Is this state expecting encrypted records?
   --  Before ServerHello, records are plaintext.
   --  After ServerHello, records are encrypted with traffic keys.
   function Expects_Encrypted (State : Connection_State) return Boolean is
     (State not in Idle | Wait_Client_Hello | Wait_Client_Hello_Retry |
                   Client_Hello_Sent |
                   Wait_Server_Hello)
   with Ghost;

   --  RFC 8446 §4.2.9: Key share group MUST match what the client offered.
   --  Server MUST NOT select a group the client didn't offer a key share for.
   --  (Ghost predicate for documentation; enforcement is in Parse_Client_Hello)

   --  RFC 8446 §4.4.4: Finished verify_data MUST be verified.
   --  If verification fails, a "decrypt_error" alert MUST be sent.
   --  (Enforced in Process_Client_Finished via HC.Server_HS_Secret)

   --  RFC 8446 §5.1: Record fragment size limits.
   --  Plaintext: max 2^14 = 16384 bytes.
   --  Ciphertext: max 2^14 + 256 = 16640 bytes.
   function Valid_Fragment_Len (Len : N32) return Boolean is
     (Len <= Max_Record_Plaintext)
   with Ghost;

   function Valid_Record_Len (Len : N32) return Boolean is
     (Len <= Max_Record_Size)
   with Ghost;

   --  RFC 8446 §5.1: Content type MUST be valid.
   function Valid_Content_Type (CT : Byte) return Boolean is
     (CT in 16#14# | 16#15# | 16#16# | 16#17#)  --  CCS/alert/hs/appdata
   with Ghost;

   --  RFC 8446 §4.6.1: Session ticket constraints.
   function Valid_Ticket_Lifetime (Secs : Unsigned_32) return Boolean is
     (Secs <= 604800)  --  max 7 days per RFC 8446 §4.6.1
   with Ghost;

   --  RFC 8446 §7.1: Key derivation chain ordering.
   --  The key schedule proceeds: Early → Handshake → Master → App.
   --  Each secret depends on the previous one.
   type Key_Phase is (Phase_None, Phase_Early, Phase_Handshake,
                      Phase_Master, Phase_Application)
   with Ghost;

   function Key_Phase_Order (A, B : Key_Phase) return Boolean is
     (Key_Phase'Pos (A) < Key_Phase'Pos (B))
   with Ghost;

   ----------------------------------------------------------------------------
   --  Action result - tells the caller what to do next
   ----------------------------------------------------------------------------

   type Action is
     (OK,             --  Progress made, call Advance again
      Need_Input,     --  Feed more bytes from the transport
      Has_Output,     --  Drain output and send over transport
      Plaintext_Ready, --  Decrypted app data available
      Handshake_Done, --  Handshake complete, now Connected
      Shutdown,       --  Clean close complete
      Error_Alert);   --  Fatal error, see Last_Error

   ----------------------------------------------------------------------------
   --  Error codes
   ----------------------------------------------------------------------------

   type Error_Code is
     (No_Error,
      Unexpected_Message,
      Bad_Record_MAC,
      Record_Overflow,
      Handshake_Failure,
      Bad_Certificate,
      Certificate_Expired,
      Certificate_Verify_Failed,
      Certificate_Required,        --  RFC 8446 §6 alert 116
      Decode_Error,
      Illegal_Parameter,
      Protocol_Version,
      Unsupported_Extension,       --  RFC 8446 §6 alert 110
      Missing_Extension,           --  RFC 8446 §6 alert 109
      No_Application_Protocol,     --  RFC 7301 §3.2 alert 120
      Internal_Error,
      Insufficient_Buffer,
      Unsupported_Cipher_Suite);

   ----------------------------------------------------------------------------
   --  TLS extension policy table (RFC 8446 §4.2)
   --
   --  Single source of truth for every TLS extension we recognise.
   --  Each entry says (a) which message types the extension may
   --  appear in, (b) whether a server may include it only after the
   --  client offered it in CH, and (c) whether the server's echo
   --  body must be empty (RFC 6066 §3 server_name ack, etc.).
   --
   --  All client-side server-extension validation goes through
   --  Validate_Server_Ext below — adding a new extension means
   --  adding one row to Ext_Policy_For, not peppering checks at
   --  every parse site.
   ----------------------------------------------------------------------------

   --  TLS messages that can carry extensions. The split SH13/SH12 is
   --  necessary because RFC 8446 §4.2 says key_share, pre_shared_key,
   --  supported_versions are SH-only-in-TLS-1.3 while RFC 6066 / 7301
   --  / 5746 / etc. let TLS 1.2 SH echo server_name, ALPN,
   --  ec_point_formats, renegotiation_info, EMS, status_request, etc.
   type Ext_Where is
     (E_CH,      --  ClientHello
      E_SH13,    --  TLS 1.3 ServerHello
      E_SH12,    --  TLS 1.2 ServerHello
      E_HRR,     --  HelloRetryRequest
      E_EE,      --  EncryptedExtensions
      E_CR,      --  CertificateRequest
      E_CT,      --  Certificate (per-cert extensions)
      E_NST);    --  NewSessionTicket

   type Ext_Where_Set is array (Ext_Where) of Boolean
     with Default_Component_Value => False;

   type Ext_Policy is record
      --  False for tags not in the IANA registry / not modelled
      --  here. Per RFC 8446 §4.2: "If an implementation receives
      --  an extension which it recognizes and which is not
      --  specified for the message in which it appears, it MUST
      --  abort..." — recognition matters. Unknown extensions are
      --  ignored where the RFC says to (e.g. RFC 8446 §4.3.2 CR);
      --  rejected where the RFC forbids unsolicited extensions
      --  (RFC 8446 §4.2 SH/EE).
      Known          : Boolean       := False;
      --  Set of message types where this extension MAY appear.
      Where_Allowed  : Ext_Where_Set := (others => False);
      --  When True, the extension MAY only appear in a server-
      --  generated message if the client offered the same tag in
      --  CH. RFC 8446 §4.2.
      Requires_Offer : Boolean       := True;
      --  When True, the server's echo body MUST be exactly zero
      --  bytes (RFC 6066 §3 server_name ack, RFC 7627 EMS, etc.).
      Empty_Echo     : Boolean       := False;
      --  When True, our CH builder always emits this extension
      --  regardless of Cfg state. Used by Tag_Is_Offered to answer
      --  "did we offer this?" for the matrix Requires_Offer check.
      --  Conditional offerings (SNI iff Cfg.Server_Name set, ALPN
      --  iff Cfg.ALPN set) override this via the HC-aware overload.
      Always_In_CH   : Boolean       := False;
   end record;

   --  Returns the policy row for a given extension type tag.
   --  Unknown tags get an empty Where_Allowed set, so any appearance
   --  in a server-generated message rejects as unsupported_extension.
   --  Add a `when` arm here to register a new extension; nothing
   --  else needs to change.
   function Ext_Policy_For (Tag : Interfaces.Unsigned_16) return Ext_Policy;

   --  "Did our CH builder always emit this extension?" — derived
   --  from `Ext_Policy_For (Tag).Always_In_CH`. Update by setting
   --  Always_In_CH on the matrix row, not by editing this function.
   --  Conditional offerings (SNI, ALPN, mTLS) are answered by the
   --  HC-aware overload below.
   function Tag_Is_Offered_Static
     (Tag : Interfaces.Unsigned_16) return Boolean is
     (Ext_Policy_For (Tag).Always_In_CH);

   --  RFC 5246 §8.1 / RFC 7627: Master secret derivation invariant.
   --  The derivation label MUST match the EMS negotiation.
   --  Using "extended master secret" without EMS extension, or
   --  "master secret" when EMS was negotiated, produces a
   --  valid-looking but incompatible master secret that causes
   --  Finished verification failure on the peer.
   function EMS_Label_Consistent
     (Use_EMS : Boolean;
      Label   : String) return Boolean is
     (if Use_EMS then Label = "extended master secret"
      else Label = "master secret")
   with Ghost;

   --  ----- RFC 7748 §6.1 / RFC 8422 §5.10 small-subgroup defence ---
   --  An X25519 shared secret of all zeros indicates the peer used a
   --  point of small order (orders 1, 2, 4, 8 — eight specific 32-byte
   --  strings). Without rejecting these, an attacker who feeds such a
   --  point can predict the master secret. RFC 7748 §6.1 mandates the
   --  rejection; RFC 8422 §5.10 mirrors it for TLS-1.2 ECDHE-X25519.
   --
   --  The Post-condition is the formal RFC criterion: the function
   --  returns True iff at least one byte of the shared secret is
   --  non-zero (equivalently, the secret is not the all-zeros string
   --  that small-subgroup attacks coerce). gnatprove discharges the
   --  contract from the loop invariant in the body.
   function Shared_Secret_Is_Acceptable_X25519
     (Shared_Secret : Byte_Seq) return Boolean
   with Post => Shared_Secret_Is_Acceptable_X25519'Result =
                  (for some I in Shared_Secret'Range
                     => Shared_Secret (I) /= 0);

   --  ----- Phase 1 structural pinning: wire-format constants -------
   --  Each ghost predicate captures one normative MUST value from
   --  TLS 1.2 / 1.3 / EMS / Renegotiation / GCM. Pinned at the
   --  emission site via pragma Assert so a future edit that
   --  introduces a non-conforming value fails SPARK proof.

   --  RFC 5246 §7.4.1.3 / RFC 8446 §4.1.3: ServerHello.legacy_version
   --  MUST be 0x0303 (the wire encoding of TLS_1_2). For TLS 1.3 the
   --  real version is signalled in the supported_versions extension;
   --  legacy_version stays 0x0303 for middlebox compatibility.
   function ServerHello_Legacy_Version_RFC_8446_4_1_3
     (V : TLS_Version) return Boolean is
     (V = TLS_1_2)
     with Ghost;

   --  RFC 5246 §7.4.1.2 / §7.4.1.3 / RFC 8446 §4.1.2/§4.1.3: the
   --  Random fields are exactly 32 bytes. Already type-enforced via
   --  Bytes_32; this ghost lifts the constraint to a named clause for
   --  RFC traceability.
   function Random_Length_RFC_5246_7_4_1_2
     (Ignored_R : Bytes_32) return Boolean is
     (Ignored_R'Length = 32)
     with Ghost;

   --  RFC 5246 §6.2.2 / §7.4.1.4 / RFC 8446 §4.1.2: the only
   --  compression method TLS 1.2 servers MAY negotiate is
   --  null (0x00); compression is removed from TLS 1.3 entirely.
   --  Anything else is a CRIME-class attack vector.
   function Compression_Method_None_RFC_5246_6_2_2
     (M : Byte) return Boolean is
     (M = 0)
     with Ghost;

   --  RFC 8446 §4.2.1: server's supported_versions ServerHello
   --  extension carries exactly one selected_version. For a server
   --  that selected TLS 1.3, the wire bytes are exactly (0x03, 0x04).
   function Supported_Versions_Server_TLS13_RFC_8446_4_2_1
     (Data : Byte_Seq) return Boolean is
     (Data'Length = 2 and then Data (Data'First) = 16#03#
        and then Data (Data'First + 1) = 16#04#)
     with Ghost;

   --  RFC 8446 §4.1.2: ClientHello.legacy_compression_methods MUST
   --  contain exactly one byte with value 0x00. Anything else is a
   --  protocol violation (real TLS 1.3 has no compression).
   function Legacy_Compression_Methods_TLS13_RFC_8446_4_1_2
     (Methods : Byte_Seq) return Boolean is
     (Methods'Length = 1 and then Methods (Methods'First) = 0)
     with Ghost;

   --  RFC 5746 §3.5 / §3.6: on initial handshake, the
   --  renegotiation_info extension's renegotiated_connection field
   --  MUST be empty. On the wire that's a single 0x00 byte (the
   --  length prefix) — total ext data = 1 byte.
   function RI_Empty_Initial_RFC_5746_3_5
     (Data : Byte_Seq) return Boolean is
     (Data'Length = 1 and then Data (Data'First) = 0)
     with Ghost;

   --  RFC 7627 §5.1: the extended_master_secret extension carries
   --  no data. Extension data length MUST be 0; presence alone
   --  signals EMS support.
   function EMS_Extension_Empty_Body_RFC_7627_5_1
     (Data_Len : N32) return Boolean is
     (Data_Len = 0)
     with Ghost;

   --  RFC 5288 §3 / RFC 5246 §6.2.3.3: AES-GCM nonce is always
   --  12 bytes (4 implicit + 8 explicit). Already type-enforced
   --  via Bytes_12.
   function GCM_Nonce_Length_RFC_5288_3
     (Ignored_N : Bytes_12) return Boolean is
     (Ignored_N'Length = 12)
     with Ghost;

   --  RFC 5246 §7.4.9: TLS 1.2 Finished.verify_data is exactly
   --  12 bytes regardless of cipher suite. Already type-enforced
   --  via SPARKTLS.Key_Schedule_12.Verify_Data_12 (constant 12).
   function Verify_Data_Length_TLS12_RFC_5246_7_4_9
     (VD : Byte_Seq) return Boolean is
     (VD'Length = 12)
     with Ghost;

   --  RFC 8446 §4.4.4: TLS 1.3 Finished.verify_data is Hash.length
   --  bytes — 32 for SHA-256, 48 for SHA-384.
   function Verify_Data_Length_TLS13_RFC_8446_4_4_4
     (VD : Byte_Seq) return Boolean is
     (VD'Length = 32 or else VD'Length = 48)
     with Ghost;

   --  ----- RFC 5246 §A.5 / RFC 5288 / RFC 7905 AEAD-only deviation
   --  RFC 5246 Appendix A.5 lists all standard TLS 1.2 cipher suites,
   --  including CBC modes (MAC-then-encrypt), 3DES, and RC4. We
   --  deliberately deviate: this implementation supports only the
   --  RFC 5288 GCM and RFC 7905 ChaCha20-Poly1305 AEAD suites — no
   --  CBC, no MAC-then-encrypt, no 3DES, no RC4. This eliminates the
   --  Lucky13, padding-oracle, BEAST, and CRIME attack classes by
   --  construction. The predicate captures the exact accepted set.
   function Negotiated_Suite_AEAD_Only_RFC_5288_RFC_7905
     (Suite : Unsigned_16) return Boolean is
     (Suite = Suite_ECDHE_RSA_AES128_GCM_SHA256
        or else Suite = Suite_ECDHE_RSA_AES256_GCM_SHA384
        or else Suite = Suite_ECDHE_ECDSA_AES128_GCM_SHA256
        or else Suite = Suite_ECDHE_ECDSA_AES256_GCM_SHA384
        or else Suite = Suite_ECDHE_RSA_CHACHA20_SHA256
        or else Suite = Suite_ECDHE_ECDSA_CHACHA20_SHA256
        or else Suite = Suite_AES_128_GCM_SHA256
        or else Suite = Suite_AES_256_GCM_SHA384
        or else Suite = Suite_CHACHA20_POLY1305_SHA256)
     with Ghost;

   --  ----- RFC 8422 §5.1.2 ec_point_formats compliance -------------
   --  RFC 8422 §5.1.2 deprecates point formats 1
   --  (ansiX962_compressed_prime) and 2 (ansiX962_compressed_char2);
   --  only 0 (uncompressed) is recommended. **However**, a server
   --  MUST NOT reject a ClientHello that lists deprecated formats —
   --  RFC 8446 §4.2.6 says TLS 1.3 ignores this extension entirely,
   --  and OpenSSL / Go / NSS clients all include {0, 1, 2} by
   --  default for backward-compat. The acceptable check here is
   --  therefore "does the list include format 0", not "is the list
   --  exactly {0}".
   --
   --  An empty list is still rejected because RFC 8422 §5.1.1
   --  requires the field be non-empty when the extension is sent.
   function EC_Point_Formats_Acceptable
     (List : Byte_Seq) return Boolean
   with Post => EC_Point_Formats_Acceptable'Result =
                  (List'Length > 0 and then
                   (for some I in List'Range => List (I) = 0));

   --  ----- RFC 5246 §7.4.1.4.1 sig_algs negotiated-from-offered ----
   --  RFC 5246 §7.4.1.4.1 / RFC 8446 §4.2.3: if the client sent the
   --  signature_algorithms extension, the server MUST select a
   --  scheme present in that list. Selecting an unoffered scheme
   --  breaks downgrade resistance and may signal a misnegotiation
   --  bug.
   --
   --  This predicate captures the membership constraint: a non-zero
   --  Negotiated value MUST appear in the first `Count` slots of
   --  `Offered`. (Negotiated = 0 means we're on the default-fallback
   --  path; that case is governed by the strong-hash predicate
   --  below.)
   function Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
     (Negotiated : Unsigned_16;
      Offered    : Sig_Algo_List;
      Count      : Natural) return Boolean is
     (Negotiated = 0
        or else (for some I in 0 .. Count - 1
                   => Offered (I) = Negotiated))
     with Ghost,
          Pre => Count <= Max_Sig_Algos;

   --  ----- RFC 8446 §4.4.3 CertificateVerify modern schemes only ---
   --  RFC 8446 §4.4.3: a TLS 1.3 CertificateVerify signature MUST
   --  use rsa_pss_rsae_sha{256,384,512} (0x0804/0x0805/0x0806),
   --  ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
   --  (0x0403/0x0504/0x0603), or ed25519/ed448 (0x0807/0x0808).
   --  RFC 8446 explicitly forbids RSASSA-PKCS1-v1_5 schemes
   --  (0x0401/0x0501/0x0601) for CertificateVerify because PKCS#1 v1.5
   --  is malleable and historically vulnerable to Bleichenbacher-style
   --  attacks; PSS supersedes it.
   --
   --  This implementation does not support PKCS#1 v1.5 server signing
   --  at all (no Sign_RSA_PKCS1 in Sign_Algo). The predicate captures
   --  the wire-scheme constraint for traceability.
   function CertificateVerify_Modern_Scheme_RFC_8446_4_4_3
     (Scheme : Unsigned_16) return Boolean is
     (Scheme = 16#0804# or else Scheme = 16#0805#
        or else Scheme = 16#0806#
        or else Scheme = 16#0403#
        or else Scheme = 16#0503#
        or else Scheme = 16#0807#)
     with Ghost;

   --  ----- RFC 5246 §7.4.1.4.1 sig_algs default fallback -----------
   --  When the client omits the signature_algorithms extension, the
   --  RFC's literal text says the server "MUST act as if [...]
   --  {sha1, *}" was sent. We deliberately deviate: SHA-1 is broken
   --  and we don't support it. Our default uses SHA-256 (or SHA-384)
   --  matched to the server cert's algorithm.
   --
   --  This predicate captures the security-relevant property: any
   --  Negotiated sig scheme produced by our default fallback MUST be
   --  SHA-256 or stronger. The 16-bit scheme codes in TLS 1.2:
   --    rsa_pkcs1_sha256 = 0x0401, rsa_pkcs1_sha384 = 0x0501,
   --    rsa_pkcs1_sha512 = 0x0601, ecdsa_secp256r1_sha256 = 0x0403,
   --    ecdsa_secp384r1_sha384 = 0x0503, rsa_pss_rsae_sha256 = 0x0804,
   --    rsa_pss_rsae_sha384 = 0x0805, rsa_pss_rsae_sha512 = 0x0806,
   --    ed25519 = 0x0807. The low byte ≥ 4 distinguishes SHA-256+
   --    schemes (SHA-1 schemes are 0x0201/0x0202/0x0203, low byte 1-3).
   function Sig_Scheme_Has_Strong_Hash_RFC_5246_7_4_1_4_1
     (Scheme : Unsigned_16) return Boolean is
     (Scheme = 16#0804# or else Scheme = 16#0805#
        or else Scheme = 16#0806#
        or else Scheme = 16#0403# or else Scheme = 16#0503#
        or else Scheme = 16#0807#)
     with Ghost;

   --  RFC 8446 §6: Error handling invariant.
   --  When entering Error_State, the implementation MUST have queued
   --  an alert record in the output buffer (unless the error is from
   --  a plaintext record where the peer can't decrypt our response).
   --
   --  This property would have caught the missing-alert bugs found by
   --  tlsfuzzer (Finished verify failure, decryption failure, wrong
   --  handshake type, record overflow — all silently closed without alert).
   function Error_Has_Alert (S_State : Connection_State;
                             Pending : N32;
                             Err     : Error_Code) return Boolean is
     (if S_State = Error_State then
        Pending > 0 or else Err = Unexpected_Message)
   with Ghost;

   --  RFC 8446 §6.2 / RFC 5246 §7.2: map an Error_Code to its on-wire
   --  AlertDescription byte. Single source of truth — used both at
   --  runtime (by Send_*_Alert helpers across client / server, TLS 1.2
   --  and TLS 1.3 paths) and as a Ghost in proof contracts via the
   --  Expected_Alert_Desc rename below.
   function Alert_Desc (E : Error_Code) return Byte is
     (case E is
         when Unexpected_Message       => 10,
         when Bad_Record_MAC           => 20,
         when Record_Overflow          => 22,
         when Handshake_Failure        => 40,
         when Bad_Certificate          => 42,
         when Certificate_Expired      => 45,
         when Illegal_Parameter        => 47,
         when Decode_Error             => 50,
         when Certificate_Verify_Failed => 51,
         when Protocol_Version         => 70,
         when Unsupported_Extension    => 110,
         when Missing_Extension        => 109,
         when Certificate_Required     => 116,
         when No_Application_Protocol  => 120,
         when Internal_Error
            | Insufficient_Buffer
            | No_Error                 => 80,
         when Unsupported_Cipher_Suite => 40);

   function Expected_Alert_Desc (E : Error_Code) return Byte
     renames Alert_Desc;
   --  Ghost-callable alias — proof contracts use this name.

   ----------------------------------------------------------------------------
   --  I/O Buffer
   --
   --  Linear buffer with read/write cursors. The caller fills it
   --  via Feed_Ciphertext and drains it via Drain_Ciphertext. Compacted
   --  when the read cursor advances past the midpoint.
   --
   --  This is the BIO equivalent: the TLS engine never touches
   --  sockets, files, or any OS resource. It only reads from
   --  and writes to these buffers.
   ----------------------------------------------------------------------------

   subtype Buffer_Size is N32 range 0 .. IO_Buffer_Capacity;

   type IO_Buffer is record
      Data       : Byte_Seq (0 .. IO_Buffer_Capacity - 1)
                     := (others => 0);
      Read_Pos   : Buffer_Size := 0;  --  next byte to consume
      Write_Pos  : Buffer_Size := 0;  --  next byte to write
   end record
     with Predicate => IO_Buffer.Write_Pos >= IO_Buffer.Read_Pos;

   function Available (Buf : IO_Buffer) return N32 is
      (Buf.Write_Pos - Buf.Read_Pos);

   function Free_Space (Buf : IO_Buffer) return N32 is
      (IO_Buffer_Capacity - Buf.Write_Pos);

   ----------------------------------------------------------------------------
   --  Hostname storage (for SNI)
   ----------------------------------------------------------------------------

   type Hostname_Buf is record
      Data : String (1 .. Max_Hostname_Len) := (others => ASCII.NUL);
      Len  : Natural := 0;
   end record
     with Predicate => Hostname_Buf.Len <= Max_Hostname_Len;

   Max_Config_ALPN_Protocols : constant := 8;
   subtype ALPN_Index is Natural range 1 .. Max_Config_ALPN_Protocols;
   type ALPN_Protocol_List is array (ALPN_Index) of Hostname_Buf;

   ----------------------------------------------------------------------------
   --  Traffic keys for one direction (key + IV + nonce counter)
   ----------------------------------------------------------------------------

   --  RFC 8446 §7.3: Traffic keys with suite constraint.
   type Traffic_Keys is record
      Key     : Bytes_32          := (others => 0);
      IV      : Bytes_12          := (others => 0);
      Counter : Unsigned_64       := 0;
      Suite   : Unsigned_16       := Suite_CHACHA20_POLY1305_SHA256;
   end record
     with Predicate =>
       Traffic_Keys.Suite in Suite_AES_128_GCM_SHA256 |
                             Suite_AES_256_GCM_SHA384 |
                             Suite_CHACHA20_POLY1305_SHA256;

   --  RFC 8446 §5.3: Nonce space must not be exhausted.
   function Nonce_Space_Available (K : Traffic_Keys) return Boolean is
     (K.Counter < Unsigned_64'Last);

   ----------------------------------------------------------------------------
   --  Random byte generation callback
   --
   --  The caller must supply a CSPRNG. This is the only callback;
   --  everything else is buffer-based.
   ----------------------------------------------------------------------------

   type Random_Bytes_Fn is access
      procedure (Output : out Byte_Seq);

   --  Time callback for certificate validation.
   --  Called at validation time, not at configuration time.
   type Get_Time_Fn is access
      function return X509.Date_Time;

   ----------------------------------------------------------------------------
   --  Certificate pool types
   --
   --  Used by Trust_Store, Identity, and Validate_Chain.
   --  Each pool entry holds a parsed cert and its own DER buffer
   --  starting at index 0 (required by X509 span offsets).
   ----------------------------------------------------------------------------

   --  Max entries in an intermediate cert pool (Peer_Ints, Identity.Ints).
   --  Real cert chains have ≤ 6 intermediates; 8 is comfortably above that.
   --  Previously 40, which cost ~400 KB per Session (Cert_Pool dominates
   --  Session size) and made it impractical to hold many sessions in BSS
   --  or on the stack. The trust store uses a separate larger pool
   --  (Max_Root_Pool_Size = 200) since OS CA bundles have 130+ roots.
   Max_Pool_Size : constant := 8;
   Max_Cert_DER  : constant := 8192;   --  max DER bytes per cert

   subtype Cert_DER_Buf is X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1);

   type Pool_Entry is record
      Cert    : X509.Certificate;
      DER     : Cert_DER_Buf      := (others => 0);
      DER_Len : X509.N32          := 0;
      Present : Boolean           := False;
   end record
     with Predicate =>
       (if Pool_Entry.Present then
          Pool_Entry.DER_Len > 0
          and Pool_Entry.DER_Len <= X509.N32 (Max_Cert_DER)
          and X509.Spans_Valid (Pool_Entry.Cert, Pool_Entry.DER_Len - 1));

   type Cert_Pool is array (0 .. Max_Pool_Size - 1) of Pool_Entry;
   type Used_Set  is array (0 .. Max_Pool_Size - 1) of Boolean;

   ----------------------------------------------------------------------------
   --  Trust Store
   --
   --  Holds root CA certificates for chain validation.
   --  Allocated once at application startup, shared across sessions
   --  via Trust_Store_Access (access-to-constant, read-only).
   --
   --  Uses a larger pool than Cert_Pool (200 vs 40) because OS
   --  certificate bundles typically contain 130+ root CAs.
   --  Not embedded in Session — referenced by pointer, so the
   --  larger size doesn't affect per-connection memory.
   ----------------------------------------------------------------------------

   Max_Root_Pool_Size : constant := 200;
   type Root_Pool is array (0 .. Max_Root_Pool_Size - 1) of Pool_Entry;

   type Trust_Store is record
      Roots      : Root_Pool;
      Root_Count : Natural := 0;
   end record
     with Predicate => Trust_Store.Root_Count <= Max_Root_Pool_Size;

   type Trust_Store_Access is access constant Trust_Store;

   ----------------------------------------------------------------------------
   --  Identity
   --
   --  Local certificate chain and signing key.  The signing algorithm
   --  is inferred from the leaf certificate's public key algorithm.
   --  Required for servers; optional for clients (mTLS only).
   --  Allocated once, shared across sessions via Identity_Access.
   ----------------------------------------------------------------------------

   type Signing_Algorithm is
     (Sign_Ed25519, Sign_ECDSA_P256, Sign_ECDSA_P384, Sign_RSA_PSS, Sign_None);

   Max_RSA_Key_Bytes : constant := 512;  --  RSA-4096

   type Identity is record
      --  Leaf cert in X509 format (for chain validation)
      Cert_DER     : X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1)
                       := (others => 0);
      Cert_DER_Len : X509.N32 := 0;
      Cert         : X509.Certificate;
      Cert_Valid   : Boolean := False;

      --  Leaf cert in SPARKNaCl format (for handshake message building)
      NaCl_Cert_DER : Byte_Seq (0 .. N32 (Max_Cert_DER) - 1)
                        := (others => 0);
      NaCl_Cert_Len : N32 := 0;

      --  Intermediate certificates (sent to peer in Certificate message)
      Ints         : Cert_Pool;
      Int_Count    : Natural := 0;

      --  Signing key (algorithm inferred from cert's PK_Algorithm)
      Sign_Algo      : Signing_Algorithm := Sign_None;
      Ed25519_Key    : Bytes_64 := (others => 0);
      ECDSA_P256_Key : Bytes_32 := (others => 0);
      ECDSA_P384_Key : Bytes_48 := (others => 0);
      RSA_Modulus    : Byte_Seq (0 .. Max_RSA_Key_Bytes - 1) := (others => 0);
      RSA_Mod_Len    : N32 := 0;
      RSA_Priv_Exp   : Byte_Seq (0 .. Max_RSA_Key_Bytes - 1) := (others => 0);
      RSA_Pub_Exp    : Unsigned_32 := 0;

      Has_Identity : Boolean := False;
   end record;

   type Identity_Access is access constant Identity;

   --  Length bounds every Identity must satisfy for the certificate and
   --  signature paths to index it safely. Identical in content to
   --  SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid, restated here
   --  because that child package is not visible from this spec.
   --
   --  Carried in the subtype rather than threaded through contracts: SPARK
   --  cannot frame an access-typed record component by equality (there is no
   --  legal `HC.Cfg.Local = HC.Cfg.Local'Old`), so every `HC : in out` call
   --  otherwise loses the fact unless the callee restates it -- which is why
   --  Local_Config_Valid appears in ~170 contracts. As a subtype predicate it
   --  holds by construction and the threading becomes unnecessary.
   --
   --  Deliberately weaker than Selected_Identity_Access below, which also
   --  demands Has_Identity: a non-null Identity without Has_Identity is a
   --  legal state (the `Local /= null and then Local.Has_Identity` guard
   --  appears throughout the codebase).
   subtype Valid_Identity_Access is Identity_Access
     with Dynamic_Predicate =>
       Valid_Identity_Access = null
       or else
         (Valid_Identity_Access.NaCl_Cert_Len <= N32 (Max_Cert_DER)
          and then Valid_Identity_Access.Int_Count <= Max_Pool_Size
          and then
            (for all I in 0 .. Max_Pool_Size - 1 =>
               Valid_Identity_Access.Ints (I).DER_Len
                 <= X509.N32 (Max_Cert_DER))
          and then
            (if Valid_Identity_Access.Sign_Algo = Sign_RSA_PSS
             then Valid_Identity_Access.RSA_Mod_Len in 64 .. 512));

   subtype Selected_Identity_Access is Identity_Access
     with Dynamic_Predicate =>
       Selected_Identity_Access = null
       or else
	         (Selected_Identity_Access.Has_Identity
	          and then Selected_Identity_Access.NaCl_Cert_Len <= N32 (Max_Cert_DER)
	          and then Selected_Identity_Access.Int_Count <= Max_Pool_Size
	          and then
	            (for all I in 0 .. Max_Pool_Size - 1 =>
	               Selected_Identity_Access.Ints (I).DER_Len
                 <= X509.N32 (Max_Cert_DER))
          and then
            (if Selected_Identity_Access.Sign_Algo = Sign_RSA_PSS
             then Selected_Identity_Access.RSA_Mod_Len in 64 .. 512));

   ----------------------------------------------------------------------------
   --  SNI-based certificate selection (RFC 6066 §3, RFC 8446 §4.4.2.4)
   --
   --  Servers that host multiple virtual hosts on one listener install
   --  a Select_Identity callback in Config. The callback receives the
   --  hostname from the client's server_name extension and returns the
   --  matching Identity_Access. Returning null means "no match" —
   --  per RFC 6066, the server MAY proceed with the default identity
   --  (the more permissive choice, matches openssl). Strict-SNI mode
   --  (alert on no-match) is not supported today but can be added by
   --  having the callback raise an alert via a side channel.
   --
   --  The callback runs after CH-extension parsing and BEFORE the
   --  cert chain / SKE / Finished are built. The hostname passed in
   --  is the raw bytes the client sent (RFC 6066 §3 says ASCII; the
   --  caller is responsible for any case-folding / Punycode
   --  normalization).
   --
   --  Safety: the callback MUST be pure (no side effects) and MUST
   --  return either null or an Identity_Access that remains valid for
   --  the lifetime of the session. Identities returned here are
   --  typically allocated once at server startup and immutable.
   ----------------------------------------------------------------------------

   type SNI_Cert_Selector is access function
     (Server_Name : in String) return Selected_Identity_Access;

   ----------------------------------------------------------------------------
   --  Ticket Store (for session resumption)
   --  Defined here so Config can reference it. Implementation in
   --  SPARKTLS.Ticket_Cache child package.
   ----------------------------------------------------------------------------

   Max_Cached_Tickets : constant := 1024;
   Ticket_ID_Len      : constant := 16;
   subtype Ticket_ID is Byte_Seq (0 .. Ticket_ID_Len - 1);

   type Ticket_Entry is record
      ID      : Ticket_ID := (others => 0);
      PSK     : Bytes_48 := (others => 0);
      PSK_Len : N32 := 0;
      Suite   : Unsigned_16 := 0;
      Age_Add : Unsigned_32 := 0;
      Valid   : Boolean := False;
   end record
     with Predicate =>
       --  RFC 8446 §4.6.1: PSK is SHA-256 (32 byte) or SHA-384 (48
       --  byte) only when Valid; zero-length on invalid slots is OK
       --  because they're never read.
       (if Ticket_Entry.Valid
        then Ticket_Entry.PSK_Len in 32 | 48
        else Ticket_Entry.PSK_Len = 0);

   type Ticket_Array is array (Natural range 0 .. Max_Cached_Tickets - 1)
      of Ticket_Entry;

   type Ticket_Store is record
      Entries : Ticket_Array;
      Next    : Natural range 0 .. Max_Cached_Tickets - 1 := 0;
   end record;

   type Ticket_Store_Access is access all Ticket_Store;

   ----------------------------------------------------------------------------
   --  Session Ticket (RFC 8446 §4.6.1)
   --
   --  Stand-alone, copyable record so the caller can persist it
   --  across connections. Defined here (before Config) because
   --  Cfg.Resume_Ticket embeds it.
   ----------------------------------------------------------------------------

   Max_Ticket_Len : constant := 256;

   type Session_Ticket is record
      Ticket       : Byte_Seq (0 .. Max_Ticket_Len - 1) := (others => 0);
      Ticket_Len   : N32 := 0;
      Lifetime     : Unsigned_32 := 0;       --  seconds
      Age_Add      : Unsigned_32 := 0;       --  obfuscation value
      Received_At  : Unsigned_64 := 0;       --  Unix seconds, 0 if unknown
      PSK          : Bytes_48 := (others => 0);  --  derived PSK
      PSK_Len      : N32 := 0;              --  32 (SHA-256) or 48 (SHA-384)
      Suite        : Unsigned_16 := 0;       --  cipher suite
      Server_Name  : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Resumption_Across_Names : Boolean := False;
      Valid        : Boolean := False;
   end record;

   ----------------------------------------------------------------------------
   --  TLS 1.2 ticket encryption key (RFC 5077 §4)
   --
   --  Caller-supplied 32-byte AES-256 key plus a 4-byte Key_ID for
   --  rotation. Up to TLS12_Max_Keys keys can be active at once; the
   --  server tries each in turn when decrypting a peer-supplied
   --  ticket (rotation = add new key, drop oldest). Server encrypts
   --  outgoing tickets with key at TLS12_Active_TEK_Idx. A ticket
   --  carries the Key_ID in its header so decryption is O(1) lookup.
   ----------------------------------------------------------------------------

   TLS12_Max_Keys : constant := 4;

   type TLS12_Ticket_Key is record
      Key_ID     : Byte_Seq (0 .. 3) := (others => 0);    --  4-byte ident
      TEK        : Byte_Seq (0 .. 31) := (others => 0);   --  AES-256 raw
      Valid      : Boolean := False;
      Created_At : Interfaces.Unsigned_64 := 0;
      --  Unix seconds when this slot was last populated. Drives the
      --  auto-rotation timer (`Now - Created_At >= Interval` →
      --  rotate). Callers populating the array manually at startup
      --  should set Created_At to the wall-clock time so the first
      --  rotation fires Interval seconds later, not immediately.
   end record;

   type TLS12_Ticket_Key_Array is array (Natural range 0 .. TLS12_Max_Keys - 1)
      of TLS12_Ticket_Key;

   type TLS12_Ticket_Keys_Access is access all TLS12_Ticket_Key_Array;

   ----------------------------------------------------------------------------
   --  TLS 1.2 cached session ticket (client side, RFC 5077 §3.4)
   --
   --  Stand-alone copyable record so the caller can persist it
   --  across processes. The ticket bytes are opaque blobs; the
   --  meaningful state for resumption is Master_Secret + Suite.
   ----------------------------------------------------------------------------

   Max_TLS12_Ticket_Len : constant := 2048;
   --  RFC 5077 allows up to 2^16-1 bytes, but practical tickets are
   --  much smaller. OpenSSL's default is 1024 bytes (full session
   --  state + GCM tag); BoringSSL ~256 bytes. 2048 covers all
   --  observed implementations with margin.

   type Session_Ticket_12 is record
      Ticket        : Byte_Seq (0 .. Max_TLS12_Ticket_Len - 1)
                         := (others => 0);
      Ticket_Len    : N32 := 0;
      Master_Secret : Byte_Seq (0 .. 47) := (others => 0);
      Suite         : Unsigned_16 := 0;
      Lifetime_Hint : Unsigned_32 := 0;   --  seconds (from server)
      Server_Name   : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Valid         : Boolean := False;
   end record;

   ----------------------------------------------------------------------------
   --  Validation modes (used by Config and Cert_Verify)
   ----------------------------------------------------------------------------

   --  Mode_RFC5280: RFC 5280 rules only.
   --  Mode_WebPKI: RFC 5280 + CA/Browser Forum Baseline Requirements.
   type Validation_Mode is (Mode_RFC5280, Mode_WebPKI);

   --  Validation purpose (controls EKU requirements on the leaf)
   type Validation_Purpose is (Purpose_Server, Purpose_Client, Purpose_Any);

   ----------------------------------------------------------------------------
   --  DoS resource limits (§2.13 in ROADMAP)
   --
   --  Policy caps on per-handshake parser work, defending against
   --  malicious peers that send valid-looking but pathologically
   --  large CHs (thousands of cipher suites, sig_algs, etc.). Each
   --  cap bounds the iteration count: entries beyond the cap are
   --  silently dropped from consideration; the handshake continues
   --  with whatever was processed in-cap (cipher suites and other
   --  list-typed fields are prioritized by the client, so picking
   --  from the leading N entries still negotiates the best mutual
   --  choice). The defaults are 5-10x typical real-world client
   --  populations so legitimate peers never hit them.
   --
   --  These caps are PER-CONNECTION; cross-connection budgets
   --  (accept rate, concurrent half-open) are the caller's
   --  responsibility (see ROADMAP §2.13).
   ----------------------------------------------------------------------------

   type DoS_Caps is record
      --  Max cipher_suite entries consumed from a CH. Wire allows
      --  ~32767. Real clients send 5-30; cap of 256 is comfortably
      --  above any legitimate peer.
      Max_Cipher_Suites    : N32 := 256;

	      --  Max supported_groups entries consumed from the named-group
	      --  extension. Real clients send 4-12; cap of 64.
	      Max_Supported_Groups : N32 := 64;

	      --  Max key_share entries consumed from a TLS 1.3 ClientHello.
	      --  Real clients send 1-3; cap of 64 leaves ample room while
	      --  bounding duplicate/share parsing work.
	      Max_Key_Shares       : N32 := 64;

      --  Max signature_algorithms entries CONSUMED from the wire
      --  (distinct from Max_Sig_Algos which caps how many we STORE
      --  in HC.Peer_Sig_Algos). Wire allows ~32767. Real clients
      --  send 6-15; cap of 64.
      Max_Sig_Algs_Wire    : N32 := 64;

      --  Max ALPN protocol entries in the client's offer. Real
      --  clients send 1-5 (typically just "h2" or "http/1.1"+"h2").
      --  Cap of 32.
      Max_ALPN_Protocols   : N32 := 32;

      --  Max warning-level alerts the server will tolerate during
      --  a single handshake before treating the next as fatal
      --  decode_error (BoGo SendWarningAlerts-TooMany).
      Max_Warning_Alerts   : N32 := 4;
   end record;

	   Default_DoS_Caps : constant DoS_Caps :=
	     (Max_Cipher_Suites    => 256,
	      Max_Supported_Groups => 64,
	      Max_Key_Shares       => 64,
	      Max_Sig_Algs_Wire    => 64,
      Max_ALPN_Protocols   => 32,
      Max_Warning_Alerts   => 4);

   ----------------------------------------------------------------------------
   --  Configuration (set once before Init)
   ----------------------------------------------------------------------------

   type Config is record
      Suite        : Cipher_Suite    := TLS_CHACHA20_POLY1305_SHA256;
      Random       : Random_Bytes_Fn := null;
      Server_Name  : Hostname_Buf;
      Skip_Verify  : Boolean         := False;  --  accept any cert

      --  Client-side hostname verification opt-out (RFC 6125 §6.4).
      --  When Server_Name is non-empty AND this is False (default),
      --  the client checks that the server's leaf cert contains a
      --  matching SAN dNSName or iPAddress (or Subject CN as a
      --  fallback per the prevailing CN-in-SAN rules). On mismatch
      --  the handshake is aborted with `bad_certificate`. This check
      --  runs INDEPENDENTLY of `Skip_Verify` / `Trust` / `Get_Time`
      --  — those gate full chain validation; hostname binding stays
      --  on so dev mode (Skip_Verify=True) doesn't silently accept a
      --  cert for the wrong host. Set this to True only when you
      --  explicitly do not want hostname binding (rare; usually
      --  better to leave Server_Name empty instead).
      Skip_Hostname_Verify : Boolean := False;

      --  Server-side DoS resource limits (RFC-defensive caps on
      --  parser iteration counts). See DoS_Caps documentation for
      --  rationale. Tunable for high-trust environments (raise
      --  caps) or extra-paranoid servers (lower them).
      DoS_Caps : SPARKTLS.DoS_Caps := Default_DoS_Caps;
      Versions     : Version_Policy  := Allow_Both;  --  TLS version control

      --  Client: preferred initial TLS 1.3 key_share group. Zero keeps
      --  the default browser-like behavior: advertise X25519/P-256/P-384
      --  in supported_groups and send an initial X25519 key_share. Set to
      --  16#001D# (X25519), 16#0017# (secp256r1), or 16#0018#
      --  (secp384r1) to advertise and send only that group in CH1.
      Client_Key_Share_Group : Unsigned_16 := 0;

      --  Validation settings
      Verify_Mode     : Validation_Mode := Mode_WebPKI;
      Verify_Purpose  : Validation_Purpose := Purpose_Server;
      Get_Time : Get_Time_Fn := null;

      --  Trust store for verifying the peer's certificate chain.
      --  Required for verified client handshakes unless Skip_Verify
      --  is explicitly enabled or a valid TLS 1.3 resume ticket is
      --  supplied. Required on the server when Request_Client_Cert is
      --  True unless Skip_Verify is explicitly enabled for
      --  "require any client certificate" deployments.
      Trust : Trust_Store_Access := null;

      --  Local identity (certificate + signing key).
      --  Required for server.  Optional for client (mTLS only).
      --  On the server side, this is the default identity used when
      --  Select_Identity is null OR when Select_Identity returns null
      --  for the client's SNI hostname.
      Local : Valid_Identity_Access := null;

      --  Server-side SNI acknowledgement. When True, the server emits
      --  the empty server_name extension if the client sent SNI. Set
      --  False to parse SNI and allow SNI-based identity selection
      --  without acknowledging it in ServerHello / EncryptedExtensions.
      Ack_Server_Name : Boolean := True;

      --  Server-side SNI-based identity selector. When non-null AND
      --  the client sent a non-empty server_name extension, the
      --  callback fires after CH parse and the returned identity
      --  (if non-null) overrides Local for this session. See the
      --  SNI_Cert_Selector type comments above for the contract.
      Select_Identity : SNI_Cert_Selector := null;

      --  ALPN: Application-Layer Protocol Negotiation (RFC 7301).
      --  Set to e.g. "h2" for HTTP/2 or "http/1.1" for HTTP/1.1.
      --  Empty (Len=0) means no ALPN extension is sent unless
      --  ALPN_Count > 0.
      ALPN : Hostname_Buf := (Len => 0, Data => (others => ' '));
      --  Optional ordered ALPN preference list. When ALPN_Count > 0,
      --  clients advertise ALPN_List (1 .. ALPN_Count), and servers
      --  select the first configured entry also offered by the client.
      --  ALPN remains as the backwards-compatible single-protocol API.
      ALPN_List  : ALPN_Protocol_List :=
        (others => (Len => 0, Data => (others => ' ')));
      ALPN_Count : Natural range 0 .. Max_Config_ALPN_Protocols := 0;
      --  Server-side ALPN policy. When True, abort the handshake with
      --  no_application_protocol if no configured ALPN value overlaps the
      --  client offer. The default False keeps RFC 7301's ordinary "decline
      --  ALPN by omitting the extension" behavior.
      Require_ALPN : Boolean := False;

      --  Optional ordered TLS 1.2 server cipher policy. When
      --  TLS12_Cipher_Count = 0, the server preserves the historical
      --  behavior of selecting the first compatible client-offered
      --  modern ECDHE AEAD suite. Otherwise, only suites in
      --  TLS12_Cipher_List (1 .. TLS12_Cipher_Count) are eligible.
      --  Lower group numbers are preferred; equal group numbers use
      --  the client's order as the tie-breaker.
      TLS12_Cipher_List : Cipher_Suite_List := (others => 0);
      TLS12_Cipher_Groups : Cipher_Suite_Preference_Groups := (others => 0);
      TLS12_Cipher_Count : Natural range 0 .. Max_Config_Cipher_Suites := 0;

      --  Optional signature_algorithms preference/allow-list. When
      --  Verify_Sig_Algo_Count = 0, the client advertises SPARKTLS's default
      --  modern list. Otherwise, clients advertise exactly
      --  Verify_Sig_Algos (0 .. Count - 1), and CertificateVerify messages
      --  from peers must use a listed scheme.
      Verify_Sig_Algos      : Sig_Algo_List := (others => 0);
      Verify_Sig_Algo_Count : Natural range 0 .. Max_Sig_Algos := 0;

      --  Optional local signing preference/allow-list. When
      --  Sign_Sig_Algo_Count = 0, the signer uses the peer's offered order
      --  and the local identity's key type. Otherwise, signing selects the
      --  first configured scheme that is also peer-offered and compatible with
      --  the local identity.
      Sign_Sig_Algos      : Sig_Algo_List := (others => 0);
      Sign_Sig_Algo_Count : Natural range 0 .. Max_Sig_Algos := 0;

      --  Server: request a client certificate (mTLS). When True the
      --  server sends a CertificateRequest in the handshake.
      Request_Client_Cert : Boolean := False;

      --  Server: also REQUIRE that the client present a cert.
      --  Only meaningful when Request_Client_Cert is True. When True
      --  and the client sends an empty Certificate or one that fails
      --  to parse / validate, the server aborts the handshake with
      --  certificate_required (TLS 1.3) or handshake_failure (TLS 1.2).
      --  If Skip_Verify is True, a non-empty client certificate still
      --  must prove possession with CertificateVerify, but chain
      --  validation is skipped.
      --  When False (default) the server falls back to anonymous
      --  authentication if the client doesn't present a cert — the
      --  classic OpenSSL SSL_VERIFY_PEER vs
      --  SSL_VERIFY_FAIL_IF_NO_PEER_CERT distinction.
      Require_Client_Cert : Boolean := False;

      --  Server: ticket cache for session resumption.
      --  If non-null, server sends NewSessionTicket after handshake.
      Ticket_Store : Ticket_Store_Access := null;

      --  Server: mark TLS 1.3 NewSessionTicket values as usable across
      --  hostnames via the ticket_flags resumption_across_names bit.
      --  Default False is the conservative policy: tickets are scoped to
      --  the name the client verified. Set True only for an intentionally
      --  shared deployment where the same trust boundary, ticket store, and
      --  resumption policy apply across those hostnames.
      TLS13_Resumption_Across_Names : Boolean := False;

      --  Server: TLS 1.2 ticket encryption keys (RFC 5077).
      --  When non-null and at least one key has Valid=True, the server
      --  parses session_ticket extension on CH and emits a stateless
      --  NewSessionTicket after the first server Finished. Caller is
      --  responsible for generating + rotating the keys. The active
      --  key index is the one used for outgoing tickets; all valid
      --  keys are tried in turn for inbound ticket decryption (via the
      --  embedded Key_ID).
      TLS12_Ticket_Keys     : TLS12_Ticket_Keys_Access := null;
      TLS12_Active_TEK_Idx  : Natural := 0;

      --  Server: lifetime hint (seconds) sent in NewSessionTicket.
      --  The server itself also enforces this as a hard expiry on
      --  decrypted tickets (RFC 5077 §5.6 advises ≤7 days). Default
      --  3600 seconds (1 hour) — refreshes ticket-derived forward
      --  secrecy hourly. Set 0 to disable issuing tickets entirely.
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;

      --  Server-side automatic TEK rotation. When True (default),
      --  the server checks at the start of each incoming TLS 1.2
      --  handshake whether the active key has exceeded
      --  TEK_Rotation_Interval_Secs since its Created_At; if so,
      --  generates a fresh Key_ID + TEK via Cfg.Random and rotates
      --  it into the active slot via Rotate_TLS12_Ticket_Key
      --  (oldest slot shifts out; previously-active slot keeps its
      --  Valid=True so prior tickets still decrypt during the
      --  grace window).
      --
      --  Set this to FALSE for multi-process / multi-host / HSM
      --  deployments where the TEK is managed externally:
      --    * Fork-inherit + worker recycling: parent generates one
      --      TEK before fork(); workers inherit; rotation = recycle
      --      workers. No library-level rotation needed.
      --    * Shared file + SIGHUP: an orchestrator writes new keys
      --      to disk; workers read on signal and call
      --      Rotate_TLS12_Ticket_Key explicitly.
      --    * KV store (Cloudflare model): each worker polls Redis /
      --      etcd; on key change, calls Rotate_TLS12_Ticket_Key.
      --    * HSM-backed: keys live in the HSM and the library must
      --      not generate fresh ones in process memory.
      --
      --  Requires Cfg.Get_Time AND Cfg.Random to be non-null. If
      --  either is null, auto-rotation silently does nothing
      --  regardless of this flag.
      Auto_Rotate_TEK : Boolean := True;

      --  Interval (seconds) between automatic TEK rotations. Default
      --  24 hours, matching Go crypto/tls and CABF guidance ("regular
      --  schedule, such as daily"). Tighter intervals are defensible
      --  for high-value deployments where a TEK leak's blast radius
      --  must be smaller; the cost is more key-generation calls and
      --  more clients hitting "old ticket, full handshake" right
      --  after a rotation. The grace window is fixed at
      --  TLS12_Max_Keys * Interval (default 4 days at 24h interval).
      TEK_Rotation_Interval_Secs : Unsigned_32 := 24 * 3600;

      --  Client: previously-cached TLS 1.2 session ticket. When
      --  Valid, sent in the session_ticket extension on CH; on
      --  server-side resume, the cached Master_Secret is reused
      --  via the abbreviated TLS 1.2 flight (RFC 5077 §3.4).
      TLS12_Resume_Ticket   : Session_Ticket_12;

      --  Client: previously-saved resumption ticket (RFC 8446
      --  §4.6.1). When Valid, Init copies this into S.Ticket before
      --  building CH so the pre_shared_key extension is offered.
      --  Default-init (Valid=False) means a fresh full handshake.
      --
      --  Note: 0-RTT (RFC 8446 §2.3 / §4.2.10) is intentionally not
      --  supported. The replay + forward-secrecy trade-off is
      --  incompatible with a high-integrity stack; resumption (this
      --  field) is forward-secret + replay-safe because we require
      --  psk_dhe_ke mode (fresh DH mixed into the handshake secret).
      Resume_Ticket : Session_Ticket;
   end record;

   ----------------------------------------------------------------------------
   --  Session
   --
   --  All TLS connection state in one record. No hidden heap
   --  allocations. Intended for stack or caller-managed heap.
   --
   --  The caller interacts with a Session exclusively through:
   --    Feed_Ciphertext   - push received bytes into Input buffer
   --    Drain_Ciphertext - pull bytes to send from Output buffer
   --    Advance      - step the state machine (in Client/Server)
   --    Write_Plaintext  - encrypt and queue application data
   --    Read_Plaintext   - read decrypted application data
   --    Close_Notify    - initiate clean shutdown
   ----------------------------------------------------------------------------

   ----------------------------------------------------------------------------
   --  Handshake Context
   --
   --  Contains all state needed only during the TLS handshake.
   --  Heap-allocated at Init, freed when handshake completes.
   --  Handshake procedures receive this as `in out` — they never
   --  see the pointer, only the record.
   ----------------------------------------------------------------------------

   --  RFC 7627 §4 ghost type: tracks which TLS 1.2 master_secret PRF
   --  was used. Set inside Derive_Keys_12 along the matching code
   --  path. The companion predicate EMS_PRF_Binding_RFC_7627_4 ties
   --  the choice of PRF to HC.Use_EMS — the property whose absence
   --  caused the v9→v12 TLS-Anvil regression.
   type Master_Secret_Derivation_Mode is
     (Not_Derived, Legacy, Extended);

   --  Bounded array of seen CH extension type codes (RFC 8446 §4.2
   --  duplicate-extension check). Modern CHs carry ~10-20 extensions;
   --  64 is comfortably above realistic peers and bounds the linear
   --  scan cost in Apply_CH_Extension.
   type Ext_Tag_Array is array (1 .. 64) of Unsigned_32;

   type Handshake_Context is record
      --  Protocol version (set during Parse_Client_Hello / Parse_Server_Hello)
      Version : TLS_Version := TLS_1_3;

      --  Configuration (callbacks, trust store, identity)
      Cfg : Config;

      --  Server-side: SNI hostname received in the client's
      --  server_name extension (RFC 6066 §3). Captured during
      --  CH-extension parsing in `Apply_CH_Extension` and consumed
      --  by the SNI cert-selection step. Empty (Len = 0) if the
      --  client didn't send a server_name extension or sent one with
      --  no host_name entries.
      Peer_SNI : Hostname_Buf := (Len => 0, Data => (others => ' '));

      --  Ephemeral key exchange (X25519, P-256, or P-384 ECDHE)
      Local_SK      : Bytes_32 := (others => 0);
      Client_Random : Bytes_32 := (others => 0);
      Server_Random : Bytes_32 := (others => 0);
      Peer_PK       : Bytes_32 := (others => 0);
      Shared_Secret : Bytes_48 := (others => 0);

      --  P-256 ECDHE key exchange state
      P256_Local_SK : Bytes_32 := (others => 0);
      P256_Peer_PK  : Byte_Seq (0 .. 64) := (others => 0);
      Use_P256_KE   : Boolean := False;

      --  P-384 ECDHE key exchange state
      P384_Local_SK : Bytes_48 := (others => 0);
      P384_Peer_PK  : Byte_Seq (0 .. 96) := (others => 0);
      Use_P384_KE   : Boolean := False;

      --  Server-side: which groups did the client offer in key_share?
      --  (actual key exchange data present)
      Client_Has_X25519 : Boolean := False;
      Client_Has_P256   : Boolean := False;
      Client_Has_P384   : Boolean := False;
      --  TLS 1.3 client sent the key_share extension at all. This is
      --  distinct from Client_Has_*: an empty key_share vector can be
      --  HRR-recoverable, while an absent key_share extension is a
      --  missing_extension error.
      Client_Saw_Key_Share : Boolean := False;
      --  Which groups did the client offer in supported_groups?
      --  (may not have key_share data — triggers HRR if preferred)
      Client_Saw_Supported_Groups : Boolean := False;
      Client_Supports_X25519 : Boolean := False;
      Client_Supports_P256   : Boolean := False;
      Client_Supports_P384   : Boolean := False;
      Selected_Group    : Unsigned_16 := 0;
      --  HelloRetryRequest state (server-side: we sent HRR)
      HRR_Sent          : Boolean := False;
      --  HelloRetryRequest state (client-side: we received HRR)
      --  RFC 8446 §4.1.4: at most one HRR per connection; a second
      --  HRR is an unexpected_message. Got_HRR latches the first
      --  reception so the SH handler rejects subsequent HRRs.
      Got_HRR              : Boolean := False;
      --  RFC 8446 §4.1.4: HRR carries (cipher_suite + supported_versions)
      --  and (key_share with selected_group OR cookie OR both). When
      --  the second SH arrives, its cipher_suite MUST match the HRR's
      --  (BoGo HelloRetryRequest-CipherChange-TLS13). Stash for
      --  comparison.
      HRR_Cipher_Suite     : Unsigned_16 := 0;
      HRR_Selected_Group   : Unsigned_16 := 0;
      HRR_Cookie_Len       : N32 := 0;
      HRR_Cookie           : Byte_Seq (0 .. 1023) := (others => 0);
      --  RFC 8446 §D.4: the dummy CCS is emitted exactly once per
      --  connection. On the HRR retry path we emit it between HRR
      --  and CH2 (server's `expectChangeCipherSpec` then fires on
      --  the CCS, not on CH2). If we then emitted another CCS in
      --  the post-SH client flight, the server would reject it as
      --  `received unexpected ChangeCipherSpec`. Track to gate.
      Sent_HRR_CCS         : Boolean := False;
      --  RFC 8446 §4.1.2: CH extension order fingerprint.
      --  Rolling polynomial hash of extension type codes in order.
      --  CH2 must produce the same hash as CH1 (modulo cookie).
      CH_Ext_Hash       : Unsigned_32 := 0;
      CH_Ext_Count      : Natural := 0;

      --  RFC 8446 §4.2: "the same extension type MUST NOT appear in
      --  a given extension list more than once". Track seen tag codes
      --  to enforce. Modern CHs use ~10-20 extensions; cap at 64.
      Seen_Ext_Tags     : Ext_Tag_Array := (others => 0);
      Seen_Ext_Count    : Natural range 0 .. Ext_Tag_Array'Last := 0;

      --  Handshake traffic keys
      Client_HS     : Traffic_Keys;
      Server_HS     : Traffic_Keys;

      --  Traffic secrets (for finished key derivation)
      Client_HS_Secret : Bytes_48 := (others => 0);
      Server_HS_Secret : Bytes_48 := (others => 0);

      --  Key schedule intermediates
      Handshake_Secret : Bytes_48 := (others => 0);
      Master_Secret    : Bytes_48 := (others => 0);

      --  Hash length for negotiated cipher suite (32 or 48)
      Hash_Len : N32 := 32;

      --  Transcript accumulator
      Transcript     : Byte_Seq (0 .. Transcript_Capacity - 1)
                         := (others => 0);
      Transcript_Len : N32 := 0;

      --  Peer certificate (raw DER for verification)
      Peer_Cert_DER     : Byte_Seq (0 .. Max_Cert_DER_Len - 1)
                            := (others => 0);
      Peer_Cert_DER_Len : N32 := 0;
      Peer_Cert         : X509.Certificate;
      Peer_Cert_Valid   : Boolean := False;

      --  Peer intermediate certificates
      Peer_Ints      : Cert_Pool;
      Peer_Int_Count : Natural := 0;

      --  Legacy session ID (middlebox compatibility)
      Legacy_Session_ID : Bytes_32 := (others => 0);
      --  RFC 8446 §4.1.3: server's ServerHello MUST echo the client's
      --  legacy_session_id (whatever its length, 0..32). We store
      --  both the bytes and the length so we can echo accurately
      --  rather than always padding to 32.
      Legacy_Session_ID_Len : N32 range 0 .. 32 := 0;

      --  Signature algorithm negotiation
      Peer_Sig_Algos      : Sig_Algo_List := (others => 0);
      --  Bounded by Max_Sig_Algos: parse site at
      --  Parse_Sig_Algs_Extension gates increment on
      --  `Peer_Sig_Algo_Count < Max_Sig_Algos`. Encoding the bound
      --  in the type lets cross-procedure proofs discharge
      --  Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1's
      --  precondition directly.
      Peer_Sig_Algo_Count : Natural range 0 .. Max_Sig_Algos := 0;
      Negotiated_Sig_Algo : Unsigned_16 := 0;

      --  Handshake tracking
      CCS_Received          : Boolean := False;
      Cert_Request_Received : Boolean := False;
      --  TLS 1.2 client side: the configured local identity matches both
      --  CertificateRequest.certificate_types and signature_algorithms.
      TLS12_Client_Cert_Allowed : Boolean := False;

      --  Version negotiation (set during Parse_Client_Hello)
      --  True if the client's supported_versions extension contains 0x0304.
      --  If False, we negotiate TLS 1.2 (if legacy_version = 0x0303).
      Has_TLS_1_3 : Boolean := False;
      --  RFC 8446 §4.2.1: client sent supported_versions extension.
      Saw_Supported_Versions : Boolean := False;
      --  RFC 8446 §4.2.1: supported_versions listed at least one
      --  version we can negotiate (TLS 1.2 or TLS 1.3). When the
      --  client sent the extension but none of the listed versions
      --  match our policy, the server MUST reply with
      --  protocol_version. BoGo NoSupportedVersions.
      SV_Has_Acceptable : Boolean := False;

      --  TLS 1.2: ClientKeyExchange already received
      CKE_Received_12 : Boolean := False;

      --  TLS 1.2 session-ticket (RFC 5077) state.
      --
      --  Client side:
      --    * TLS12_Sent_Ticket_Ext  — we offered session_ticket ext
      --      in CH (so we accept a server-issued NST).
      --    * TLS12_Server_Will_Issue — server echoed the empty
      --      session_ticket ext in SH; expect a NewSessionTicket
      --      message after server CCS+Finished (full HS) or before
      --      server CCS+Finished (abbreviated HS — and we use the
      --      cached master_secret).
      --    * TLS12_Resuming — server elected to resume; skip Cert/
      --      SKE/CKE/CertVerify, jump straight to CCS+Finished.
      --
      --  Server side:
      --    * TLS12_Ticket_Offered — client sent session_ticket ext
      --      (empty or with ticket bytes).
      --    * TLS12_Ticket_Resume_OK — client-provided ticket
      --      decrypted + validated; we'll abbreviate.
      --    * TLS12_Ticket_Will_Issue — we'll emit a NewSessionTicket
      --      after first client Finished (full handshake) or before
      --      our own CCS+Finished (abbreviated).
      --    * TLS12_Resumed_Master_Secret — restored MS from a valid
      --      peer ticket (overrides the freshly-derived MS path).
      --    * TLS12_Resumed_Suite — cipher suite we MUST use in SH
      --      when resuming (peer's original).
      TLS12_Sent_Ticket_Ext     : Boolean := False;
      TLS12_Server_Will_Issue   : Boolean := False;
      TLS12_Resuming            : Boolean := False;
      TLS12_Ticket_Offered      : Boolean := False;
      TLS12_Ticket_Resume_OK    : Boolean := False;
      TLS12_Ticket_Will_Issue   : Boolean := False;
      TLS12_Resumed_Master_Secret : Byte_Seq (0 .. 47) := (others => 0);
      TLS12_Resumed_Suite       : Unsigned_16 := 0;
      TLS12_Peer_Ticket_Len     : N32 := 0;
      TLS12_Peer_Ticket         : Byte_Seq (0 .. Max_TLS12_Ticket_Len - 1)
                                    := (others => 0);

      --  TLS 1.2: Extended Master Secret (RFC 7627) negotiated
      Use_EMS : Boolean := False;
      --  RFC 7627 §3: EMS session_hash covers ClientHello through
      --  ClientKeyExchange, inclusive. Capture that transcript length
      --  immediately after CKE so later CertificateVerify / Finished
      --  appends cannot affect master_secret derivation.
      TLS12_EMS_Transcript_Len : N32 range 0 .. Transcript_Capacity := 0;

      --  TLS 1.2: client offered renegotiation_info extension (RFC 5746)
      --  or sent the TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) in
      --  cipher_suites. Servers echo the extension only when one of
      --  these signals is present (RFC 5746 §3.6).
      Saw_Reneg_Info : Boolean := False;

      --  RFC 8446 §4.2.9: client offered psk_key_exchange_modes with
      --  the psk_dhe_ke (0x01) mode. Required before the server may
      --  issue a NewSessionTicket on this connection (RFC 8446 §4.6.1
      --  / BoGo TLS13-ExpectNoSessionTicketOnBadKEMode-Server).
      Has_PSK_DHE_KE : Boolean := False;

      --  Per-extension parse error surface. Apply_CH_Extension only
      --  has access to HC, not S — so when an extension's contents
      --  violate its RFC (e.g. RFC 7301 §3.1 empty ALPN protocol_name),
      --  the parser stores the alert code here and the caller of
      --  Parse_Client_Hello propagates it to Last_Error (S).
      Ext_Parse_Err : Error_Code := No_Error;

      --  Client's offered ALPN protocol (parsed from ClientHello)
      Client_ALPN : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Client_ALPN_List : ALPN_Protocol_List :=
        (others => (Len => 0, Data => (others => ' ')));
      Client_ALPN_Count : Natural range 0 .. Max_Config_ALPN_Protocols := 0;

      --  TLS 1.2 key material (set during Derive_Keys_12)
      Master_Secret_12   : Bytes_48 := (others => 0);
      --  TLS 1.2 implicit IV. AES-GCM (RFC 5288 §3) uses the first
      --  4 bytes as `salt`; ChaCha20-Poly1305 (RFC 7905 §2) uses the
      --  full 12 bytes XOR'd with the padded sequence number. Sized
      --  for the larger usage and zero-padded on the AES-GCM side.
      Client_Write_IV_12 : Byte_Seq (0 .. 11) := (others => 0);
      Server_Write_IV_12 : Byte_Seq (0 .. 11) := (others => 0);
      Client_Seq_12      : Unsigned_64 := 0;
      Server_Seq_12      : Unsigned_64 := 0;

      --  RFC 7627 §4: tracks which PRF path produced Master_Secret_12.
      --  Use_EMS ↔ extended PRF; (not Use_EMS) ↔ legacy PRF. The
      --  v9→v12 bug we hit during the TLS-Anvil drive-down was a
      --  violation of this binding (we always emitted EMS in SH but
      --  always derived with legacy PRF). Updated only inside
      --  Derive_Keys_12. We keep this as a real field (not Ghost)
      --  because Ada record components cannot carry the Ghost aspect
      --  directly. The runtime overhead is one byte per HC.
      MS_Derivation : Master_Secret_Derivation_Mode := Not_Derived;

      --  Resumption
      Using_PSK     : Boolean := False;
      PSK_Offered   : Boolean := False;
      PSK_Ticket_ID : Ticket_ID := (others => 0);
      PSK_Value     : Bytes_48 := (others => 0);  --  zeros if no PSK
      PSK_Value_Len : N32 := 0;                   --  0 = no PSK
      PSK_Binder    : Bytes_48 := (others => 0);  --  received binder
      PSK_Binder_Len : N32 := 0;
      PSK_Binders_Offset : N32 := 0;              --  offset of binders in ClientHello

      --  RFC 8446 §2.3 / §4.2.10 0-RTT (early data).
      --
      --  We do NOT support 0-RTT — replay + lack of forward secrecy
      --  is incompatible with the project's high-integrity posture.
      --  The two fields below are the minimal residual defense:
      --
      --  Early_Data_Offered : set when the client's CH carried an
      --                       early_data extension. We never echo it
      --                       in EE (= rejection per §4.2.10), but
      --                       the client may still send 0-RTT records
      --                       on the wire encrypted with a key we
      --                       never derived; the flag gates the
      --                       silent-drop loop below.
      --  Skipped_Early_Data_Records : counts dropped records when
      --                       Early_Data_Offered. Capped to defend
      --                       against a peer pinning us in skip mode
      --                       indefinitely. RFC 8446 §4.6.1.
      Early_Data_Offered  : Boolean := False;
      Skipped_Early_Data_Records : Natural := 0;

      --  Handshake message reassembly (multi-record handshake messages).
      --  When a handshake record fragment contains only part of a
      --  handshake message (declared length > fragment), accumulate
      --  fragments here until the full message is available.
      Reasm_Buf  : Reasm_Buf_Access := null;
      Reasm_Len  : HS_Msg_Len := 0;   --  bytes accumulated so far
      Reasm_Need : HS_Msg_Len := 0;   --  total bytes needed (type+len+body)
      --  When fragmentation splits the 4-byte handshake header itself
      --  (BoGo MaxHandshakeRecordLength=1), Reasm_Need is initialized
      --  to 4 with this flag set; the reassembly path decodes the
      --  real HS_Total once 4 bytes are present and clears the flag.
      Reasm_Hdr_Pending : Boolean := False;

      --  Heap budget: total bytes allocated for extensions/reassembly.
      --  Prevents DoS via large extensions in ClientHello/ServerHello.
      Heap_Used : N32 := 0;

      --  NOTE: a 17 KB scratch buffer field and its size constant used to
      --  live here, declared for a stack-allocation design that was never
      --  implemented -- every RFLX buffer is heap-allocated via `new`. Both
      --  were removed. If the no-`new` work is picked up (pointing
      --  RecordFlux's Initialize/Take_Buffer at non-heap storage), note that
      --  server_msgs.adb holds a message buffer and an extension buffer live
      --  simultaneously, so a single shared block is not sufficient.
   end record
     with Predicate =>
       --  RFC 5246 §7.4.9 transcript bound: every Append_Transcript
       --  guards against overrun. Pin the runtime invariant so the
       --  prover doesn't have to re-derive it at every callsite.
       Handshake_Context.Transcript_Len <= Transcript_Capacity
       and Handshake_Context.Hash_Len <= 48
       and Handshake_Context.Peer_Cert_DER_Len <= Max_Cert_DER_Len
       and Handshake_Context.Peer_Int_Count <= Max_Pool_Size
       and Handshake_Context.PSK_Binder_Len <= 64
       and Handshake_Context.PSK_Value_Len <= 48
       and Handshake_Context.TLS12_Peer_Ticket_Len <= Max_TLS12_Ticket_Len;

   Max_Handshake_Heap : constant := 262_144;  --  256 KB per handshake

   function Heap_Budget_OK
     (HC : Handshake_Context; Size : N32) return Boolean
   is (Size <= Max_Handshake_Heap
       and then HC.Heap_Used <= Max_Handshake_Heap - Size);

   --  Reassembly predicates.
   --
   --  Reasm_Buffer_Shaped pins the concrete buffer bounds that every site
   --  indexing Reasm_Buf depends on, including Reasm_Buf'Length <= N32'Last,
   --  which the N32 (HC.Reasm_Buf'Length) conversions need.
   --
   --  Reasm_Coherent is the name actually threaded through the handshake
   --  contracts (~155 Pre/Post across 84 subprograms). It carries the shape
   --  across calls: a callee that does not touch Reasm_* gets it for free,
   --  and a caller regains it on return. It was briefly reduced to True,
   --  which silently dropped the buffer bounds from every one of those
   --  contracts and broke the callers that index the buffer.
   --  Only the buffer-RELATIVE facts live here. Reasm_Buf'First = 0,
   --  'Length <= Max_HS_Msg and 'Length <= N32'Last now come from the
   --  Reasm_Buf_Access subtype, so they cost nothing to carry.
   function Reasm_Buffer_Shaped (HC : Handshake_Context) return Boolean is
     (HC.Reasm_Buf = null
      or else
        (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
         and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
         --  Reassembly state machine: Need = 0 means idle, which means
         --  no buffered bytes; otherwise the target total always
         --  includes the 4-byte handshake header. All 83 Reasm_Need
         --  assignment sites are 0, 4, or a header-inclusive total, and
         --  every ":= 0" site zeroes Reasm_Len alongside.
         --  Deliberately stated INSIDE the buffer-exists branch: hoisting
         --  it above costs every Reasm_Buf = null path (which previously
         --  discharged this predicate for free) a new obligation to frame
         --  Reasm_Len/Reasm_Need, which regresses flights that never
         --  reassemble at all (e.g. Build_Abbreviated_Server_Flight_12).
         and then (if HC.Reasm_Need = 0
                   then HC.Reasm_Len = 0
                   else HC.Reasm_Need >= 4)
         and then
           (if HC.Reasm_Hdr_Pending then
              HC.Reasm_Need = 4
              and then HC.Reasm_Len <= 4
              and then HC.Reasm_Buf'Length = Max_HS_Msg)))
     with Ghost;

   function Reasm_Coherent (HC : Handshake_Context) return Boolean is
     (Reasm_Buffer_Shaped (HC))
     with Ghost;

   --  Build mode excludes temporary packed-flight dispatch, where Reasm_Len
   --  may exceed Reasm_Need while leftover bytes are shifted down. This is
   --  deliberately independent of the buffer shape above.
   function Reasm_Building (HC : Handshake_Context) return Boolean is
     (HC.Reasm_Buf = null or else HC.Reasm_Len <= HC.Reasm_Need)
     with Ghost;

   --  ----- RFC 5246 §7.4.7 single-ClientKeyExchange invariant ------
   --  TLS 1.2 §7.4.7: the client sends exactly one ClientKeyExchange
   --  per handshake, immediately after the (optional) Certificate.
   --  A second CKE in the same handshake is a state-machine violation
   --  and MUST be rejected with an unexpected_message alert (§7.2.2).
   --
   --  HC.CKE_Received_12 starts False and transitions monotonically
   --  to True on the first successful CKE. After that, the flag is
   --  the predicate guarding rejection of any further CKE messages
   --  in the same handshake.
   function Single_CKE_RFC_5246_7_4_7
     (HC : Handshake_Context) return Boolean is
     (HC.CKE_Received_12)
     with Ghost;

   --  ----- RFC 7627 §4 EMS PRF binding ------------------------------
   --  RFC 7627 §4: when the extended_master_secret extension is
   --  negotiated (HC.Use_EMS = True), the master_secret MUST be
   --  derived using the extended PRF (label "extended master secret",
   --  seed = transcript hash). Otherwise the legacy RFC 5246 §8.1
   --  PRF (label "master secret", seed = client_random ||
   --  server_random) MUST be used.
   --
   --  The binding is symmetric: both peers see the same ServerHello
   --  EMS extension presence; both compute the same master_secret
   --  iff they take the same PRF branch.
   --
   --  This predicate captures the binding precisely. The ghost field
   --  HC.MS_Derivation is updated inside Derive_Keys_12 to match the
   --  branch that was actually executed; the Post on Derive_Keys_12
   --  asserts the binding holds.
   function EMS_PRF_Binding_RFC_7627_4
     (HC : Handshake_Context) return Boolean is
     (case HC.MS_Derivation is
        when Not_Derived => True,  --  not yet derived; vacuously true
        when Extended    => HC.Use_EMS,
        when Legacy      => not HC.Use_EMS)
     with Ghost;

   --  ----- RFC 8446 §4.3.2 CertificateRequest empty context --------
   --  RFC 8446 §4.3.2: for a server-initiated CertificateRequest
   --  during a normal handshake, the certificate_request_context
   --  MUST be empty (length 0). Non-zero is reserved for
   --  post-handshake-auth where the context binds the request to
   --  a specific re-auth round.
   function CR_Context_Empty_Initial_RFC_8446_4_3_2
     (Ctx_Len : N32) return Boolean is (Ctx_Len = 0)
     with Ghost;

   --  ----- RFC 8446 §4 handshake_type recognition ------------------
   --  RFC 8446 §4 / RFC 5246 §7.4: every handshake message begins
   --  with a 1-byte HandshakeType field. The set of valid types in
   --  this implementation:
   --    0x01 client_hello
   --    0x02 server_hello
   --    0x08 encrypted_extensions (TLS 1.3)
   --    0x0B certificate
   --    0x0C server_key_exchange (TLS 1.2)
   --    0x0D certificate_request
   --    0x0E server_hello_done (TLS 1.2)
   --    0x0F certificate_verify
   --    0x10 client_key_exchange (TLS 1.2)
   --    0x14 finished
   --    0x04 new_session_ticket
   --  Anything else is decode_error per RFC 8446 §6.2.
   function Handshake_Type_Valid_RFC_8446_4
     (T : Byte) return Boolean is
     (T = 16#01# or else T = 16#02# or else T = 16#04#
        or else T = 16#08# or else T = 16#0B# or else T = 16#0C#
        or else T = 16#0D# or else T = 16#0E# or else T = 16#0F#
        or else T = 16#10# or else T = 16#14#)
     with Ghost;

   --  ----- RFC 8446 §5.1 outer record content_type recognition -----
   --  RFC 8446 §5.1 (and RFC 5246 §6.2.1): the outer record header's
   --  type field MUST be one of:
   --    0x14 = change_cipher_spec
   --    0x15 = alert
   --    0x16 = handshake
   --    0x17 = application_data
   --  Any other value MUST cause the record to be rejected
   --  (unexpected_message). This is the OUTER counterpart to
   --  Inner_Type_Valid_RFC_8446_5_4 — outer accepts CCS, inner
   --  does not.
   function Outer_Content_Type_Valid_RFC_8446_5_1
     (T : Byte) return Boolean is
     (T = 16#14# or else T = 16#15#
        or else T = 16#16# or else T = 16#17#)
     with Ghost;

   --  ----- RFC 8446 §5.1 record-layer legacy_record_version --------
   --  RFC 8446 §5.1: the TLSPlaintext.legacy_record_version field
   --  MUST be 0x0303 ("TLS 1.2") for all records other than the
   --  initial ClientHello (which MAY use 0x0301 for old-server
   --  middlebox compatibility). Servers MUST reject any other value.
   --  RFC 5246 §6.2.1: same — the wire version stays at the
   --  negotiated TLS 1.2 record-layer version.
   function Record_Version_RFC_8446_5_1
     (Major, Minor : Byte) return Boolean is
     (Major = 16#03# and then Minor = 16#03#)
     with Ghost;

   --  ----- RFC 8446 §6.1 / §6.2 alert level/description binding ----
   --  RFC 8446 §6.1: warning (level 1) is ONLY valid with
   --  close_notify (description 0) or user_canceled (90).
   --  RFC 8446 §6.2: fatal (level 2) is for everything else; in
   --  particular close_notify and user_canceled MUST NOT be sent
   --  at fatal level.
   --
   --  TLS 1.3 §6: implementations SHOULD emit any non-zero alert
   --  at fatal level even when TLS 1.2 would have used warning.
   --  We follow the strict RFC binding via the predicate below;
   --  the matching Pre on Build_Plaintext_Alert / Build_Alert_Record
   --  enforces it at every emission site.
   function Alert_Level_Description_Valid_RFC_8446_6_1
     (Level : Byte; Desc : Byte) return Boolean is
     (Level in 1 .. 2
        and then (if Level = 1 then Desc = 0 or else Desc = 90)
        and then (if Level = 2 then Desc /= 0 and then Desc /= 90))
     with Ghost;

   --  ----- RFC 8446 §4.1.3 downgrade-protection sentinel -----------
   --  RFC 8446 §4.1.3: a TLS 1.3 server MUST set the last 8 bytes of
   --  ServerHello.Random to the specific sentinel
   --  44 4F 57 4E 47 52 44 01 ("DOWNGRD" + 0x01) when responding to
   --  a TLS 1.2 client (it doesn't, but RFC requires it for protocol
   --  layer downgrade detection). The TLS 1.3 client checks this:
   --  if the server's random ends with the sentinel but the server
   --  did NOT offer supported_versions = TLS 1.3, an active MITM is
   --  stripping the extension. Client MUST abort.
   --
   --  This predicate identifies the sentinel pattern. Used at the
   --  client check site to pin the literal bytes; any future edit
   --  that changes the comparison would fail SPARK proof.
   function TLS13_Downgrade_Sentinel_RFC_8446_4_1_3
     (Random_Tail : Byte_Seq) return Boolean is
     (Random_Tail'Length = 8 and then
        Random_Tail (Random_Tail'First) = 16#44# and then
        Random_Tail (Random_Tail'First + 1) = 16#4F# and then
        Random_Tail (Random_Tail'First + 2) = 16#57# and then
        Random_Tail (Random_Tail'First + 3) = 16#4E# and then
        Random_Tail (Random_Tail'First + 4) = 16#47# and then
        Random_Tail (Random_Tail'First + 5) = 16#52# and then
        Random_Tail (Random_Tail'First + 6) = 16#44# and then
        Random_Tail (Random_Tail'First + 7) = 16#01#)
     with Ghost;

   --  ----- RFC 5246 §7.4.2 / RFC 8446 §6.2 cert validation alert --
   --  RFC 5246 §7.4.2: "If the validation fails, the [server | client]
   --  SHOULD send a fatal bad_certificate alert."
   --  RFC 8446 §6.2: same, mandatory for fatal cert errors.
   --
   --  Predicate captures the post-failure invariant: Error_State,
   --  encrypted alert queued, Last_Error pinned to a cert-related
   --  code (Bad_Certificate covers the chain-validation path; other
   --  cert errors map to Certificate_Expired or
   --  Certificate_Verify_Failed elsewhere).
   function Cert_Validation_Alerted_RFC_5246_7_4_2
     (State : Connection_State; Pending : N32; Err : Error_Code)
      return Boolean is
     (State = Error_State and then Pending > 0
        and then Err in Bad_Certificate | Certificate_Expired
                       | Certificate_Verify_Failed
                       | Certificate_Required)
     with Ghost;

   --  ----- RFC 5246 §7.4.9 / RFC 8446 §4.4.4 Finished-mismatch ----
   --  RFC 5246 §7.4.9: "It is a fatal error if a Finished message is
   --  not preceded by a ChangeCipherSpec message at the appropriate
   --  point in the handshake." (Sequencing covered by
   --  CCS_Precedes_Finished_RFC_5246_7_1 above.)
   --
   --  RFC 8446 §4.4.4: "Recipients of Finished messages MUST verify
   --  that the contents are correct and if incorrect MUST terminate
   --  the connection with a 'decrypt_error' alert."
   --
   --  This predicate captures the post-mismatch state: Error_State
   --  reached, fatal alert queued, Last_Error in the set of valid
   --  Finished-mismatch responses (Handshake_Failure for TLS 1.2,
   --  Bad_Record_MAC for TLS 1.3 since our enum lacks Decrypt_Error).
   function Finished_Mismatch_Alerted_RFC_8446_4_4_4
     (State : Connection_State; Pending : N32; Err : Error_Code)
      return Boolean is
     (State = Error_State and then Pending > 0
        and then Err in Handshake_Failure | Bad_Record_MAC)
     with Ghost;

   --  ----- RFC 8446 §5.4 inner content type after AEAD decrypt ----
   --  RFC 8446 §5.4: after stripping padding zeros from a decrypted
   --  TLSInnerPlaintext, the last byte is the type field. It MUST
   --  be one of:
   --    0x15 = alert
   --    0x16 = handshake
   --    0x17 = application_data
   --  (0x14 = change_cipher_spec only appears in plaintext records,
   --  never inside AEAD.) Anything else MUST be a fatal alert
   --  (unexpected_message). Without this check, an attacker who
   --  forges a record with type 0x00 or other could probe state-
   --  machine reactions.
   function Inner_Type_Valid_RFC_8446_5_4
     (T : Byte) return Boolean is
     (T = 16#15# or else T = 16#16# or else T = 16#17#)
     with Ghost;

   --  ----- RFC 8446 §5.2 / §5.4 AEAD-failure → bad_record_mac ------
   --  RFC 8446 §5.2 (and RFC 5246 §6.2.3.3): "If the decryption
   --  fails, a fatal bad_record_mac alert MUST be generated."
   --  The receiver MUST NOT distinguish in the alert between
   --  decrypt failure, tag-mismatch, and (for TLS 1.3) wrong
   --  inner content type — all three resolve to bad_record_mac
   --  (or decrypt_error in TLS 1.3 §6.2). This denies attackers
   --  the timing/error oracle that enables padding-oracle attacks.
   --
   --  This predicate captures the post-failure state: Error_State,
   --  alert queued (Pending > 0), and Last_Error is one of the
   --  three RFC-mandated codes for AEAD failure.
   function AEAD_Failure_Alerted_RFC_8446_5_2
     (State : Connection_State; Pending : N32; Err : Error_Code)
      return Boolean is
     (State = Error_State and then Pending > 0
        and then Err = Bad_Record_MAC)
     with Ghost;

   --  ----- RFC 8446 §5.1 / §5.2 record-fragment length bound -------
   --  RFC 8446 §5.1: plaintext fragment ≤ 2^14 = 16384 bytes.
   --  RFC 8446 §5.2: encrypted (application_data) fragment ≤
   --  2^14 + 256 = 16640 bytes (the +256 allows for AEAD overhead).
   --  RFC 5246 §6.2.1 (TLS 1.2): same limits apply.
   --
   --  A receiver MUST send record_overflow alert (22) on any
   --  record exceeding these bounds. Without this, an attacker can
   --  exhaust receiver memory or trigger oversized-buffer bugs.
   function Record_Length_Bound_RFC_8446_5_1
     (Content_Type : Byte; Frag_Len : N32) return Boolean is
     (if Content_Type = 16#17# then Frag_Len <= 16384 + 256
      else Frag_Len <= 16384)
     with Ghost;

   --  ----- RFC 8446 §4.2.11.2 PSK binder validated before use ------
   --  RFC 8446 §4.2.11.2: on receipt of a ClientHello PSK extension,
   --  the server MUST validate the PSK binder (HMAC of the truncated
   --  transcript with a binder_key derived from the PSK) BEFORE
   --  installing the PSK or deriving any session keys from it. A
   --  server that derives keys from an unvalidated PSK is vulnerable
   --  to selective-PSK injection: an attacker who knows a peer's
   --  ticket but not the PSK could trigger key derivation that
   --  reveals timing/error oracles.
   --
   --  This predicate captures the structural pre-condition: at any
   --  call site that installs PSK_Value, the binder check MUST have
   --  succeeded. The runtime guard is the if-Binder_OK gate.
   function PSK_Binder_Validated_RFC_8446_4_2_11_2
     (Binder_Verified : Boolean) return Boolean is
     (Binder_Verified)
     with Ghost;

   --  ----- RFC 5246 §7.2.1 / RFC 8446 §6.1 close_notify reply ------
   --  RFC 5246 §7.2.1 (and RFC 8446 §6.1): on receipt of a close_notify
   --  alert, the receiver MUST send its own close_notify in reply
   --  before closing the write side. After the reply is queued the
   --  connection enters the Closing state. This predicate captures
   --  the post-receipt invariant: State (S) = Closing AND the output
   --  buffer holds the queued close_notify (or the reply attempt
   --  filled the buffer beyond capacity, in which case the caller
   --  drains then retries — Output_Pending > 0 still holds).
   function Close_Notify_Reply_State_RFC_5246_7_2_1
     (State : Connection_State; Pending : N32) return Boolean is
     (State = Closing and then Pending > 0)
     with Ghost;

   --  ----- RFC 8446 §4.2.8 key_share group bounded by client offer
   --  RFC 8446 §4.2.8: the server's selected_group in its KeyShareEntry
   --  MUST be one that the client offered in either its key_share or
   --  supported_groups extensions. A server that selects an
   --  unoffered group breaks key agreement and (more importantly)
   --  signals a serious negotiation bug — clients refuse to derive
   --  shared secrets with mismatched groups.
   --
   --  This predicate cross-references HC.Selected_Group against the
   --  per-group `Client_Has_*` flags (key_share data present) and
   --  the `Client_Supports_*` flags (offered in supported_groups).
   --  Selected_Group = 0 means "not yet selected" and is allowed
   --  prior to ServerHello build.
   function Selected_Group_Was_Offered_RFC_8446_4_2_8
     (HC : Handshake_Context) return Boolean is
     (HC.Selected_Group = 0
        or else (HC.Selected_Group = 16#001D#
                   and then (HC.Client_Has_X25519
                               or else HC.Client_Supports_X25519))
        or else (HC.Selected_Group = 16#0017#
                   and then (HC.Client_Has_P256
                               or else HC.Client_Supports_P256))
        or else (HC.Selected_Group = 16#0018#
                   and then (HC.Client_Has_P384
                               or else HC.Client_Supports_P384)))
     with Ghost;

   --  ----- RFC 8446 §4.1.4 HelloRetryRequest at most once -----------
   --  TLS 1.3 §4.1.4: a server MUST send at most one HRR per
   --  connection. HRR is a one-shot mechanism to coax the client
   --  into a recoverable ClientHello (different group, missing
   --  cookie, etc.); a second HRR signals an infinite-loop server
   --  bug or attempted DoS amplification.
   --
   --  HC.HRR_Sent transitions monotonically False → True; the
   --  guard `if not HC.HRR_Sent` at the HRR build site enforces
   --  the at-most-once property at runtime.
   function HRR_Sent_At_Most_Once_RFC_8446_4_1_4
     (HC : Handshake_Context) return Boolean is
     (HC.HRR_Sent)
     with Ghost;

   --  ----- RFC 5246 §7.1 single-ChangeCipherSpec invariant ----------
   --  TLS 1.2 §7.1: each direction sends exactly one CCS per
   --  handshake, immediately before the encrypted Finished. A second
   --  CCS in the same handshake is a state-machine violation
   --  (CVE-2014-0224 "ChangeCipherSpec injection" was a class of
   --  bugs where servers accepted out-of-sequence CCS).
   --
   --  HC.CCS_Received transitions monotonically False → True. A
   --  second CCS is rejected at sparktls-server-tls12.adb:399 with
   --  unexpected_message; the runtime guard is `not HC.CCS_Received`.
   function Single_CCS_RFC_5246_7_1
     (HC : Handshake_Context) return Boolean is
     (HC.CCS_Received)
     with Ghost;

   --  ----- RFC 5246 §7.1 CCS-precedes-Finished sequence ------------
   --  RFC 5246 §7.1 (and §7.4.9): the ChangeCipherSpec record MUST
   --  arrive between ClientKeyExchange and Finished — never standalone,
   --  never before CKE, never twice. The Finished message that follows
   --  is encrypted with the freshly-installed keys; receiving Finished
   --  without a prior CCS means we either skipped key activation
   --  (decryption would fail) or accepted a plaintext Finished
   --  (protocol violation).
   --
   --  This predicate captures the sequencing invariant on the
   --  Handshake_Context: CKE_Received_12 implies keys are derived;
   --  CCS_Received implies the client has signaled switch-to-encrypted.
   --  Both MUST hold when the server admits a TLS 1.2 Finished record.
   function CCS_Precedes_Finished_RFC_5246_7_1
     (HC : Handshake_Context) return Boolean is
     (HC.CKE_Received_12 and then HC.CCS_Received)
     with Ghost;

   ----------------------------------------------------------------------------
   --  Ghost predicates added 2026-05-09 covering the BoGo morning
   --  fix batch. Each pins a specific RFC clause so a later
   --  refactor that re-introduces the bug will be flagged at
   --  proof time, not runtime.
   ----------------------------------------------------------------------------

   --  RFC 8446 §6 / RFC 5246 §7.2: alert level MUST be 1 (warning)
   --  or 2 (fatal). Anything else is a fatal protocol violation
   --  (BoGo SendBogusAlertType: level = 0x42 → illegal_parameter).
   function Alert_Level_Valid_RFC_8446_6
     (Level : Byte) return Boolean is
     (Level = 1 or Level = 2)
     with Ghost;

   --  RFC 8446 §6.1 / §6: TLS 1.3 deprecates warning alerts but
   --  keeps user_canceled (90) for back-compat. To bound DoS via
   --  alert flooding, BoringSSL/NSS/OpenSSL tolerate ≤ 4 in a row;
   --  the 5th triggers fatal too_many_warning_alerts.
   Max_Warning_Alerts : constant := 4;

   --  RFC 8446 §5.2 / RFC 5246 §6.2.1: zero-length-plaintext
   --  records waste decrypt CPU without delivering progress.
   --  BoringSSL caps consecutive empty records at 32; the 33rd
   --  triggers fatal too_many_empty_fragments.
   Max_Empty_Records : constant := 32;

   --  RFC 8446 §5.1 / RFC 5246 §6.2.1: record-layer version is
   --  always 0x03xx with minor in 1..4. Anything else is a
   --  framing violation — Parse_Record_Header rejects with
   --  Bad_Version.
   function Record_Version_Valid_RFC_8446_5_1
     (Major, Minor : Byte) return Boolean is
     (Major = 16#03# and Minor in 16#01# .. 16#04#)
     with Ghost;

   --  RFC 8446 §4.1.2: TLS 1.3 ClientHello legacy_compression_methods
   --  MUST be exactly the single byte 0x00. Other lists, even if
   --  they include 0x00, are rejected with illegal_parameter.
   function Compression_Methods_Valid_TLS13_RFC_8446_4_1_2
     (Bytes : Byte_Seq) return Boolean is
     (Bytes'Length = 1 and then Bytes (Bytes'First) = 16#00#)
     with Ghost;

   --  RFC 8446 §4.2: each extension type MUST appear at most once
   --  in a given extensions list. Tracked per-CH via HC.Seen_Ext_Tags;
   --  Apply_CH_Extension scans the list before recording a new tag.
   function No_Duplicate_Extensions_RFC_8446_4_2
     (HC : Handshake_Context) return Boolean is
     (HC.Seen_Ext_Count <= HC.Seen_Ext_Tags'Last)
     with Ghost;

   --  RFC 8446 §4.1.3: the server's ServerHello legacy_session_id
   --  MUST be a byte-for-byte copy of the client's. Captured at
   --  parse time and replayed at build time.
   function Session_ID_Echo_RFC_8446_4_1_3
     (HC : Handshake_Context) return Boolean is
     (HC.Legacy_Session_ID_Len in 0 .. 32)
     with Ghost;

   --  RFC 8446 §4.4.4 / RFC 5246 §7.4.9: Finished is the LAST
   --  handshake message in its flight. The decrypted plaintext
   --  byte count must equal exactly 4 (HS header) + verify_data
   --  size; trailing data is excess_handshake_data.
   function Finished_Frame_Tight_RFC_8446_4_4_4
     (Plain_Len, Verify_Len : N32) return Boolean is
     (Verify_Len <= N32'Last - 4 and then Plain_Len = 4 + Verify_Len)
     with Ghost;

   type Handshake_Context_Access is access Handshake_Context;

   ----------------------------------------------------------------------------
   --  TLS extension policy: HC-aware Tag_Is_Offered + Validate_Server_Ext
   ----------------------------------------------------------------------------

   --  Combines Tag_Is_Offered_Static with the conditional CH
   --  offerings: server_name (iff Cfg.Server_Name.Len > 0), ALPN
   --  (iff Cfg.ALPN.Len > 0). We don't currently offer
   --  pre_shared_key (0x0029) under any circumstance.
   function Tag_Is_Offered
     (Tag : Interfaces.Unsigned_16;
      HC  : Handshake_Context) return Boolean is
     (Tag_Is_Offered_Static (Tag)
      or else (Tag = 16#0000# and then HC.Cfg.Server_Name.Len > 0)
      or else (Tag = 16#0010# and then HC.Cfg.ALPN.Len > 0)
      or else (Tag = 16#0023# and then HC.TLS12_Sent_Ticket_Ext)
      or else (Tag = 16#0029# and then HC.PSK_Offered)
      or else (Tag = 16#002A# and then HC.Early_Data_Offered));

   --  RFC 8446 §4.2 single-call validator for any server-generated
   --  extension. Returns OK = True on success; otherwise sets
   --  Err to the alert that should be raised:
   --   * Unsupported_Extension — extension type not allowed in this
   --     message, or not offered when Requires_Offer is True
   --   * Decode_Error          — body present where it must be empty
   --
   --  Caller is responsible for body-shape / content validation
   --  beyond the empty-or-not boundary (RFC 7301 §3.2 ALPN proto
   --  match, RFC 8446 §4.2.8 key_share single-entry tile, etc.) —
   --  those need per-tag knowledge.
   procedure Validate_Server_Ext
     (Where    : in     Ext_Where;
      Tag      : in     Interfaces.Unsigned_16;
      Body_Len : in     N32;
      HC       : in     Handshake_Context;
      OK       :    out Boolean;
      Err      :    out Error_Code);

   ----------------------------------------------------------------------------
   --  Session Ticket (for resumption)
   --  Definition was moved earlier (before Config) so Config can
   --  embed a Resume_Ticket.
   ----------------------------------------------------------------------------

   --  Opaque session state. The full definition is in the private part
   --  below: consumers must go through the query functions rather than
   --  reading or assigning components directly, so the state machine
   --  cannot be corrupted from outside the library.
   --
   --  SIZE: a Session is large -- roughly 100 KB (103,240 bytes measured on
   --  x86-64, 2026-08-16). It embeds its own I/O buffers and a
   --  Max_Record_Plaintext (16 KB) application-data staging area rather than
   --  allocating them, which is what lets the record path run without
   --  per-record heap traffic.
   --
   --  Practical consequences:
   --
   --    * Declaring one as an ordinary local variable puts ~100 KB on the
   --      stack. Fine on a default main-task stack; NOT fine inside an Ada
   --      task with a small stack, or on an embedded target. Prefer a
   --      library-level object, or allocate it.
   --    * A server holding N concurrent connections needs ~100 KB * N of
   --      session state alone. At 1000 connections that is ~100 MB. Size
   --      your connection pool accordingly -- see examples/tls_web_epoll.adb,
   --      which keeps its Connection array at library level (BSS) for
   --      exactly this reason.
   --    * Passing a Session by value copies all of it. The API takes
   --      "in out Session" throughout; do not introduce copies.
   --
   --  Config is ~5.9 KB and Session_Ticket ~600 bytes, for comparison.
   type Session is private;

   ---------------------------------------------------------------------------
   --  Session query functions.
   --
   --  Session is a private type, so contracts and callers reach its state
   --  through these rather than by naming components. Each is an expression
   --  function returning exactly one field (completions in the private part),
   --  so every contract that used to say S.X and now says X (S) has the same
   --  logical content -- the prover unfolds the definition either way.
   --
   --  The Ghost ones exist only so contracts can keep their original form.
   --  They are usable in Pre/Post but NOT callable from ordinary code, so
   --  internals like Traffic_Keys and the TLS 1.2 sequence counters are not
   --  committed to the public API.
   ---------------------------------------------------------------------------

   function State (S : Session) return Connection_State;

   --  Human-readable description of an error code.
   --
   --  Error_Code'Image yields the enumeration identifier ("BAD_RECORD_MAC"),
   --  which is fine for logs and poor in anything a user reads. This returns
   --  a short sentence and, where the code corresponds to a TLS alert, cites
   --  the RFC clause. Total: every Error_Code value has a description, so
   --  there is no fallback case to go stale when the type grows.
   function Describe (E : Error_Code) return String;

   --  Map a received TLS alert description (RFC 8446 s6.2 / RFC 5246 s7.2)
   --  onto our Error_Code.
   --
   --  When a peer rejects us it says why, in the alert's description byte.
   --  Discarding that and reporting a generic failure throws away the only
   --  diagnostic the peer gave us -- "server sent handshake_failure" is
   --  actionable, "unexpected message" is not. Unrecognised descriptions map
   --  to Handshake_Failure rather than Internal_Error: an unknown alert from
   --  the peer is a negotiation outcome, not a fault on our side.
   function Error_From_Alert (Description : Byte) return Error_Code;
   function Role (S : Session) return TLS_Role;
   function Last_Error (S : Session) return Error_Code;
   function Negotiated_Suite (S : Session) return Unsigned_16;
   function Negotiated_Suite_12 (S : Session) return Unsigned_16;

   function Client_App (S : Session) return Traffic_Keys with Ghost;
   function Server_App (S : Session) return Traffic_Keys with Ghost;
   function Input (S : Session) return IO_Buffer with Ghost;
   function Output (S : Session) return IO_Buffer with Ghost;
   function Client_Seq_12 (S : Session) return Unsigned_64 with Ghost;
   function Server_Seq_12 (S : Session) return Unsigned_64 with Ghost;
   function Res_Master (S : Session) return Bytes_48 with Ghost;
   function Exporter_Secret (S : Session) return Bytes_48 with Ghost;
   function App_Data_Len (S : Session) return N32 with Ghost;


   --  RFC 7301 §3.1/§3.2: validate the server's ALPN-echo body in a
   --  SH or EE extension and (on success) copy the chosen protocol
   --  name into S.Negotiated_ALPN. Body shape:
   --     list_len(2) + proto_len(1) + proto_name(proto_len)
   --
   --  Body_Start is the index of the list_len byte in Data; E_Len is
   --  the declared extension body length. Caller must guarantee
   --  Body_Start + E_Len <= Data'Last + 1.
   --
   --  On failure:
   --    Decode_Error      — body too short, empty proto, list/body
   --                        length mismatch
   --    Illegal_Parameter — chosen proto doesn't match the one we
   --                        offered in CH (RFC 7301 §3.2)
   procedure Validate_ALPN_Echo_Body
     (Data       : in     Byte_Seq;
      Body_Start : in     N32;
      E_Len      : in     N32;
      HC         : in     Handshake_Context;
      S          : in out Session;
      OK         :    out Boolean;
      Err        :    out Error_Code)
   with Pre  => Data'Length > 0
                and then Data'Last < N32'Last
                and then Body_Start >= Data'First
                and then Body_Start <= Data'Last + 1
                and then E_Len >= 0
                and then E_Len <= Data'Last + 1 - Body_Start,
        Post => State (S) = State (S)'Old
                and then Client_App (S) = Client_App (S)'Old
                and then Negotiated_Suite (S) = Negotiated_Suite (S)'Old;

   ----------------------------------------------------------------------------
   --  Buffer operations (transport layer interface)
   ----------------------------------------------------------------------------

   --  Transition to a new state. All state changes should go through this
   --  procedure so callers retain the frame facts below.
   procedure Set_State (S : in out Session; To : Connection_State)
     with Post => State (S) = To
                  --  Frame: Set_State only mutates State (S). Pin the
                  --  unchanged fields so callers don't have to
                  --  re-establish Pre's like Nonce_Space_Available
                  --  (Server_App (S)) across the call.
                  and Role (S) = Role (S)'Old
                  and Server_App (S) = Server_App (S)'Old
                  and Client_App (S) = Client_App (S)'Old
                  and Input (S) = Input (S)'Old
                  and Output (S) = Output (S)'Old
                  and Server_Seq_12 (S) = Server_Seq_12 (S)'Old
                  and Client_Seq_12 (S) = Client_Seq_12 (S)'Old
                  and Last_Error (S) = Last_Error (S)'Old
                  and Negotiated_Suite (S) = Negotiated_Suite (S)'Old
                  and Negotiated_Suite_12 (S) = Negotiated_Suite_12 (S)'Old;

   --  Push received ciphertext bytes into the session's input buffer.
   --  RFC 8446 §5.1: the record layer accepts bytes from the transport.
   --  State is not modified by feeding data.
   procedure Feed_Ciphertext
     (S         : in out Session;
      Data      : in     Byte_Seq;
      Bytes_Fed :    out N32)
   with Pre  => Data'First = 0
                and Data'Last < N32'Last,
        Post => Bytes_Fed <= N32 (Data'Length)
                and State (S) = State (S)'Old;         --  feeding doesn't change state

   --  Pull ciphertext bytes from the session's output buffer to send.
   --  State is not modified by draining data.
   procedure Drain_Ciphertext
     (S              : in out Session;
      Dest           :    out Byte_Seq;
      Bytes_Drained  :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last,
        Relaxed_Initialization => Dest,
        Post => Bytes_Drained <= N32 (Dest'Length)
                and State (S) = State (S)'Old         --  draining doesn't change state
                and (for all I in 0 .. Bytes_Drained - 1 =>
                       Dest (I)'Initialized);

   --  How many bytes are waiting to be sent?
   function Output_Pending (S : Session) return N32;

   ----------------------------------------------------------------------------
   --  Session-scoped ghost predicates (added 2026-05-09 alongside
   --  the alert-handling / DoS-bound fixes). Each pins an RFC
   --  clause so a regression that re-introduces the unbounded
   --  behavior is caught at proof time.
   ----------------------------------------------------------------------------

   --  RFC 8446 §6.1 / §6: warning-alert flood cap. Holds whenever
   --  the receiver is still in a non-error state — once we exceed
   --  Max_Warning_Alerts (4) we MUST transition to Error_State.
   function Warning_Alerts_Bounded_RFC_8446_6_1
     (S : Session) return Boolean
     with Ghost;

   --  RFC 8446 §5.2 / RFC 5246 §6.2.1: empty-record flood cap.
   --  Same shape: ≤ 32 in the live state, > 32 only if we've
   --  already transitioned to Error_State with the alert queued.
   function Empty_Records_Bounded_RFC_8446_5_2
     (S : Session) return Boolean
     with Ghost;

   --  RFC 8446 §5.2 / RFC 5246 §7.2: AEAD verification failure
   --  MUST queue a fatal bad_record_mac alert and enter Error_State.
   --  The previous behaviour returned Error_Alert without queuing,
   --  so peers saw TCP RST and couldn't tell what went wrong.
   function AEAD_Failure_Alert_Queued_RFC_8446_5_2
     (S : Session) return Boolean
     with Ghost;

   --  How many input bytes are buffered?
   function Input_Available (S : Session) return N32;

   --  Is decrypted application data waiting to be read?
   function Has_Plaintext (S : Session) return Boolean;

   --  Which TLS version was negotiated?
   --  Only meaningful after Handshake_Done.
   function Get_Version (S : Session) return TLS_Version;

   --  Which cipher suite was negotiated? (wire value)
   --  Only meaningful after Handshake_Done.
   function Get_Cipher_Suite (S : Session) return Unsigned_16;

   --  Which ALPN protocol was negotiated?
   --  Empty string if no ALPN or not yet negotiated.
   function Get_ALPN (S : Session) return String;

   --  Zero all key material in a Session.
   --  Call after Close_Notify or on error to prevent key leakage.
   --  Uses volatile writes to prevent compiler from optimizing
   --  the zeroing away.
   procedure Sanitize_Keys (S : in out Session)
   with Post => Client_App (S).Key = Bytes_32'(others => 0)
                and Server_App (S).Key = Bytes_32'(others => 0)
                and Client_App (S).IV = Bytes_12'(others => 0)
                and Server_App (S).IV = Bytes_12'(others => 0)
                and Res_Master (S) = Bytes_48'(others => 0)
                and Exporter_Secret (S) = Bytes_48'(others => 0);

   --  RFC 5705 / RFC 8446 §7.5: derive application-specific exporter
   --  bytes from a completed TLS session. Label is an ASCII exporter label.
   --  TLS 1.2 permits an empty label; TLS 1.3 requires a non-empty label
   --  because it is embedded in an HKDF label. For TLS 1.2,
   --  Use_Context controls whether the RFC
   --  5705 context length prefix is included. For TLS 1.3 the context is
   --  always hashed as part of RFC 8446 exporter derivation.
   procedure Export_Keying_Material
     (S           : in     Session;
      Label       : in     String;
      Context     : in     Byte_Seq;
      Use_Context : in     Boolean;
      Output      :    out Byte_Seq;
      OK          :    out Boolean)
   with Pre => Output'First = 0
               and Output'Length > 0
               and Output'Length <= 1024
               and Label'Length <= 64
               and Context'Length <= 62
               and (if Context'Length > 0 then Context'First = 0),
        Relaxed_Initialization => Output,
        Post => (for all I in Output'Range => Output (I)'Initialized);

   --  Read decrypted application data.
   procedure Read_Plaintext
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last
                and App_Data_Len (S) <= Max_Record_Plaintext,
        Relaxed_Initialization => Dest,
        Post => Bytes_Read <= N32 (Dest'Length)
                and (for all I in 0 .. Bytes_Read - 1 =>
                       Dest (I)'Initialized);

   --  RFC 8446 §7.5: Encrypt and queue application data.
   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   with Pre  => State (S) = Connected and
                In_App_Key_Phase (State (S)) and
                Plaintext'First = 0 and
                Plaintext'Length > 0 and
                Plaintext'Last < N32'Last and
                (if Role (S) = Role_Client then
                   Nonce_Space_Available (Client_App (S)) and
                   Client_Seq_12 (S) < Unsigned_64'Last
                 else
                   Nonce_Space_Available (Server_App (S)) and
                   Server_Seq_12 (S) < Unsigned_64'Last),
        Post => Bytes_Written <= N32 (Plaintext'Length) and
                State (S) = Connected;

private

   --  Completions of the query functions and ghost predicates declared
   --  above. Bodies are verbatim -- this is a relocation, not a rewrite.
   --  The visible part of a package cannot name its own private
   --  components, but the private part can, and GNATprove reads
   --  expression-function completions here exactly as it did before.

   type Session is record
      --  State
      State        : Connection_State := Idle;
      Last_Error   : Error_Code       := No_Error;
      Role         : TLS_Role         := Role_Client;

      --  I/O buffers
      Input        : IO_Buffer;
      Output       : IO_Buffer;

      --  Application traffic keys (set during handshake, used after)
      Client_App    : Traffic_Keys;
      Server_App    : Traffic_Keys;

      --  Decrypted application data staging area
      App_Data     : Byte_Seq (0 .. Max_Record_Plaintext - 1)
                       := (others => 0);
      App_Data_Len : N32 := 0;

      --  Negotiated cipher suite (wire value from ServerHello)
      Negotiated_Suite    : Unsigned_16 := 0;  --  TLS 1.3 suite (0x13xx)
      Negotiated_Suite_12 : Unsigned_16 := 0;  --  TLS 1.2 suite (0xC0xx/0xCCxx)

      --  Peer certificate valid (copied from HC before free)
      Peer_Cert_Valid : Boolean := False;

      --  Resumption: cached session ticket (client side, TLS 1.3 PSK)
      Ticket : Session_Ticket;

      --  Client-side server name mirror. TLS 1.3 tickets can arrive after
      --  the handshake context has been freed, so the session keeps the
      --  configured name needed to bind future resumption tickets.
      Server_Name : Hostname_Buf := (Len => 0, Data => (others => ' '));

      --  Resumption: cached session ticket (client side, TLS 1.2 RFC 5077).
      --  Populated by the TLS 1.2 client when it receives a
      --  NewSessionTicket message. The caller extracts via
      --  Client.Get_TLS12_Ticket / Client.Has_TLS12_Ticket and can
      --  inject into the next Config.TLS12_Resume_Ticket for a
      --  follow-up abbreviated handshake.
      TLS12_New_Ticket : Session_Ticket_12;

      --  Resumption: snapshot of HC.Using_PSK captured before the
      --  handshake context is freed. The Advance loop nulls HC_Ptr
      --  at state→Connected so callers who want to know "did we
      --  resume?" need a Session-level mirror.
      Resumed_From_PSK   : Boolean := False;

      --  Resumption master secret (copied from HC before free,
      --  needed to derive PSK when NewSessionTicket arrives post-handshake)
      Res_Master     : Bytes_48 := (others => 0);
      Res_Master_Len : N32 := 0;  --  32 or 48

      --  Session-level wall clock mirror. Client TLS 1.3 tickets arrive
      --  post-handshake, after HC is freed, and later resumption attempts
      --  need the same configured clock to serialize obfuscated_ticket_age.
      Get_Time : Get_Time_Fn := null;

      --  RFC 5705 / RFC 8446 §7.5 exporter material retained after
      --  the handshake context is freed. TLS 1.2 stores master_secret
      --  plus randoms; TLS 1.3 stores exporter_master_secret.
      Exporter_Secret        : Bytes_48 := (others => 0);
      Exporter_Secret_Len    : N32 := 0;  --  32 or 48; 0 means unavailable
      Exporter_Client_Random : Bytes_32 := (others => 0);
      Exporter_Server_Random : Bytes_32 := (others => 0);

      --  True on first Advance in Connected state (to deliver Handshake_Done)
      Handshake_Just_Done : Boolean := False;

      --  TLS 1.3 post-handshake handshake-message reassembly. Servers may
      --  fragment NewSessionTicket across encrypted application_data records.
      Post_HS_Buf  : Byte_Seq (0 .. Max_Record_Plaintext - 1)
                       := (others => 0);
      Post_HS_Len  : N32 := 0;
      Post_HS_Need : N32 := 0;

      --  Counter for received warning-level user_canceled alerts.
      --  RFC 8446 §6.1: TLS 1.3 deprecates warning alerts but keeps
      --  user_canceled (90) for compatibility with TLS 1.2 stacks
      --  (notably JDK11). BoringSSL/NSS/OpenSSL convention is to
      --  tolerate up to 4 in a row; 5+ → fatal "too_many_warning_alerts"
      --  to limit DoS via alert-flooding. Resets on application data.
      Warning_Alerts_Recvd : Natural := 0;

      --  Counter for received empty (zero-length plaintext) records.
      --  RFC 8446 §5.2 / RFC 5246 §6.2.1: zero-length-plaintext
      --  records waste decrypt CPU without delivering progress.
      --  BoringSSL caps at 32; 33+ → fatal too_many_empty_fragments.
      --  Resets on any non-empty record.
      Empty_Records_Recvd : Natural := 0;

      --  TLS 1.2: GCM implicit nonces and sequence numbers
      --  (persist past handshake for Connected-state encrypt/decrypt)
      Negotiated_Version  : TLS_Version := TLS_1_3;
      Negotiated_ALPN     : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Client_IV_12        : Byte_Seq (0 .. 11) := (others => 0);
      Server_IV_12        : Byte_Seq (0 .. 11) := (others => 0);
      Client_Seq_12       : Unsigned_64 := 0;
      Server_Seq_12       : Unsigned_64 := 0;

      --  Handshake context (heap-allocated, freed after handshake)
      HC_Ptr : Handshake_Context_Access := null;
   end record;

   --  Query function completions: one field each, verbatim.

   function State (S : Session) return Connection_State is (S.State);
   function Role (S : Session) return TLS_Role is (S.Role);
   function Last_Error (S : Session) return Error_Code is (S.Last_Error);
   function Negotiated_Suite (S : Session) return Unsigned_16 is (S.Negotiated_Suite);
   function Negotiated_Suite_12 (S : Session) return Unsigned_16 is (S.Negotiated_Suite_12);
   function Client_App (S : Session) return Traffic_Keys is (S.Client_App);
   function Server_App (S : Session) return Traffic_Keys is (S.Server_App);
   function Input (S : Session) return IO_Buffer is (S.Input);
   function Output (S : Session) return IO_Buffer is (S.Output);
   function Client_Seq_12 (S : Session) return Unsigned_64 is (S.Client_Seq_12);
   function Server_Seq_12 (S : Session) return Unsigned_64 is (S.Server_Seq_12);
   function Res_Master (S : Session) return Bytes_48 is (S.Res_Master);
   function Exporter_Secret (S : Session) return Bytes_48 is (S.Exporter_Secret);
   function App_Data_Len (S : Session) return N32 is (S.App_Data_Len);

   function Output_Pending (S : Session) return N32 is
      (Available (S.Output));

   function Warning_Alerts_Bounded_RFC_8446_6_1
     (S : Session) return Boolean is
     (S.Warning_Alerts_Recvd <= Max_Warning_Alerts
      or else S.State = Error_State);

   function Empty_Records_Bounded_RFC_8446_5_2
     (S : Session) return Boolean is
     (S.Empty_Records_Recvd <= Max_Empty_Records
      or else S.State = Error_State);

   function AEAD_Failure_Alert_Queued_RFC_8446_5_2
     (S : Session) return Boolean is
     (S.State = Error_State
      and then S.Last_Error = Bad_Record_MAC
      and then Output_Pending (S) > 0);

   function Input_Available (S : Session) return N32 is
      (Available (S.Input));

   function Has_Plaintext (S : Session) return Boolean is
      (S.App_Data_Len > 0);

   function Get_Version (S : Session) return TLS_Version is
      (S.Negotiated_Version);

   function Get_Cipher_Suite (S : Session) return Unsigned_16 is
      (S.Negotiated_Suite);

   function Get_ALPN (S : Session) return String is
      (S.Negotiated_ALPN.Data (1 .. S.Negotiated_ALPN.Len));

end SPARKTLS;
