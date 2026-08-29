with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with SPARKTLS_Reassembly;
with SPARKTLS_Reassembly_G;
with SPARKTLS_Post_HS_Reasm;
use SPARKTLS_Reassembly;
with SPARKTLS_Transcript;
with RFLX.RFLX_Builtin_Types;
with X509;

package SPARKTLS
  with SPARK_Mode => On
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


   --  Reassembly state now lives in SPARKTLS_Reassembly.Buffer, which owns
   --  the bytes and the accounting together. Reasm_Phase, Reasm_Info and
   --  Reasm_Buffer are gone: the phase is a QUERY (Header_Ready,
   --  Has_Message), not stored state that can disagree with the buffer.

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
   --  Total key_share extension body. RFC 8446 Â§4.2.8 allows the
   --  client to offer multiple `KeyShareEntry` values, and modern
   --  clients (Go default, Chrome) include PQ hybrids â each
   --  X25519MLKEM768 entry alone is 1220 bytes, X25519Kyber768 is
   --  1188 bytes, ML-KEM-1024 is 1572 bytes. With ~7 default
   --  entries the body easily reaches several KB. The upper bound
   --  is set to 16 KB: large enough to accept legitimate multi-PQ
   --  key_share extensions while still bounding heap allocation
   --  in Parse_KS_Extension. Was 256 â matched a single P-384
   --  entry only and silently dropped real-world TLS 1.3 clients.

   --  Handshake message length (3 bytes on wire, max 2^24 - 1).
   --  Bounded to Max_HS_Msg (128 KB) for reassembled messages.

   --  Reassembly buffer pointer. The two facts every indexing site needs
   --  from the buffer itself -- zero-based, and short enough that
   --  N32 (Buf'Length) cannot overflow -- are carried here rather than
   --  threaded through contracts. Max_HS_Msg (131072) is well under
   --  N32'Last, so the N32 conversions are discharged by the subtype.
   --  Handshake message type code (1 byte on wire).
   --  RFC 8446 Section 4 defines the valid values.
   subtype HS_Msg_Type is Byte;

   --  TLS record fragment length after Parse_Record_Header.
   --  Always 1 .. Max_Fragment + 256 (encrypted records).
   subtype Record_Frag_Len is N32 range 1 .. 16384 + 256;

   Transcript_Capacity : constant N32 := 32768;  --  32 KB

   --  Sufficient for all real-world handshakes. Typical transcript is
   --  ~2 KB. Pathological inputs (32K sig_algs) require reassembly
   --  but the transcript only includes the final parsed result.
   --
   --  TODO: Replace with streaming SHA-256/384 hash (Init/Update/Final
   --  in SPARKNaCl) to eliminate this buffer entirely. The building
   --  blocks exist (Hashblocks_256/512) but SPARKNaCl needs a public
   --  streaming API with proper test coverage before we use it here.
   Max_Hostname_Len : constant := 255;
   Max_Cert_DER_Len : constant N32 := 8192;

   --  Signature algorithm negotiation
   Max_Sig_Algos : constant := 16;
   subtype Sig_Algo_Index is Natural range 0 .. Max_Sig_Algos - 1;
   type Sig_Algo_List is array (Sig_Algo_Index) of Unsigned_16;
   function Sig_Scheme_In_List
     (Scheme : Unsigned_16; List : Sig_Algo_List; Count : Natural) return Boolean
   is (Count <= Max_Sig_Algos and then (for some I in 0 .. Count - 1 => List (I) = Scheme));

   --  CH1 extension order tracking (for HRR CH2 validation)
   --  Uses a rolling polynomial hash (fingerprint * 31 xor code).
   --  Reordering extensions changes the hash. No array needed.

   ----------------------------------------------------------------------------
   --  Cipher suite
   ----------------------------------------------------------------------------

   type TLS_Role is (Role_Client, Role_Server);

   type Cipher_Suite is
     (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384);

   --  The cipher suites we implement, as a CLOSED ENUMERATION (#118).
   --  Negotiated_Suite is peer-influenced but WE assign it, from this
   --  menu, at the negotiation boundary: the hostile wire Unsigned_16
   --  is filtered exactly once through To_Suite (unsupported -> the
   --  sanity checks reject, so interior code never sees a value outside
   --  this type). Every "Suite in ..." membership precondition this
   --  replaces is now true by construction.
   type Supported_Suite is
     (Suite_None,
      --  TLS 1.3 (RFC 8446)
      Suite_AES_128_GCM_SHA256,
      Suite_CHACHA20_POLY1305_SHA256,
      Suite_AES_256_GCM_SHA384,
      --  TLS 1.2 ECDHE + AEAD only (RFC 5289 / RFC 7905)
      Suite_ECDHE_RSA_AES128_GCM_SHA256,
      Suite_ECDHE_RSA_AES256_GCM_SHA384,
      Suite_ECDHE_ECDSA_AES128_GCM_SHA256,
      Suite_ECDHE_ECDSA_AES256_GCM_SHA384,
      Suite_ECDHE_RSA_CHACHA20_SHA256,
      Suite_ECDHE_ECDSA_CHACHA20_SHA256);

   subtype TLS13_Suite is
     Supported_Suite range Suite_AES_128_GCM_SHA256 .. Suite_AES_256_GCM_SHA384;
   subtype TLS12_Suite is
     Supported_Suite range Suite_ECDHE_RSA_AES128_GCM_SHA256 .. Suite_ECDHE_ECDSA_CHACHA20_SHA256;

   --  Wire code points. Only the negotiation boundary and serializers
   --  touch these; interior code speaks Supported_Suite.
   Wire_Suite_AES_128_GCM_SHA256            : constant Unsigned_16 := 16#1301#;
   Wire_Suite_CHACHA20_POLY1305_SHA256      : constant Unsigned_16 := 16#1303#;
   Wire_Suite_AES_256_GCM_SHA384            : constant Unsigned_16 := 16#1302#;
   Wire_Suite_ECDHE_RSA_AES128_GCM_SHA256   : constant Unsigned_16 := 16#C02F#;
   Wire_Suite_ECDHE_RSA_AES256_GCM_SHA384   : constant Unsigned_16 := 16#C030#;
   Wire_Suite_ECDHE_ECDSA_AES128_GCM_SHA256 : constant Unsigned_16 := 16#C02B#;
   Wire_Suite_ECDHE_ECDSA_AES256_GCM_SHA384 : constant Unsigned_16 := 16#C02C#;
   Wire_Suite_ECDHE_RSA_CHACHA20_SHA256     : constant Unsigned_16 := 16#CCA8#;
   Wire_Suite_ECDHE_ECDSA_CHACHA20_SHA256   : constant Unsigned_16 := 16#CCA9#;

   --  The single filter for the hostile wire value. Total: anything we
   --  do not implement maps to Suite_None, which the negotiation sanity
   --  checks already reject.
   function To_Suite (Wire : Unsigned_16) return Supported_Suite
   is (case Wire is
         when 16#1301# => Suite_AES_128_GCM_SHA256,
         when 16#1303# => Suite_CHACHA20_POLY1305_SHA256,
         when 16#1302# => Suite_AES_256_GCM_SHA384,
         when 16#C02F# => Suite_ECDHE_RSA_AES128_GCM_SHA256,
         when 16#C030# => Suite_ECDHE_RSA_AES256_GCM_SHA384,
         when 16#C02B# => Suite_ECDHE_ECDSA_AES128_GCM_SHA256,
         when 16#C02C# => Suite_ECDHE_ECDSA_AES256_GCM_SHA384,
         when 16#CCA8# => Suite_ECDHE_RSA_CHACHA20_SHA256,
         when 16#CCA9# => Suite_ECDHE_ECDSA_CHACHA20_SHA256,
         when others => Suite_None);

   function Wire_Of (S : Supported_Suite) return Unsigned_16
   is (case S is
         when Suite_None => 0,
         when Suite_AES_128_GCM_SHA256 => 16#1301#,
         when Suite_CHACHA20_POLY1305_SHA256 => 16#1303#,
         when Suite_AES_256_GCM_SHA384 => 16#1302#,
         when Suite_ECDHE_RSA_AES128_GCM_SHA256 => 16#C02F#,
         when Suite_ECDHE_RSA_AES256_GCM_SHA384 => 16#C030#,
         when Suite_ECDHE_ECDSA_AES128_GCM_SHA256 => 16#C02B#,
         when Suite_ECDHE_ECDSA_AES256_GCM_SHA384 => 16#C02C#,
         when Suite_ECDHE_RSA_CHACHA20_SHA256 => 16#CCA8#,
         when Suite_ECDHE_ECDSA_CHACHA20_SHA256 => 16#CCA9#);

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

   --  Version policy â controls which protocol versions are offered/accepted.
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
   --  These are formally verified by SPARK â the prover checks that
   --  the implementation never violates these properties.
   ----------------------------------------------------------------------------

   --  RFC 8446 Â§5: CCS is only valid during the handshake.
   --  CCS after server Finished MUST be rejected.
   function CCS_Allowed (State : Connection_State) return Boolean
   is (State not in Connected | Closing | Closed | Error_State | Idle)
   with Ghost;

   --  RFC 8446 Â§5.1: Handshake is complete.
   function Handshake_Complete (State : Connection_State) return Boolean
   is (State in Connected | Closing | Closed)
   with Ghost;

   --  RFC 8446 Â§7.3, Â§7.5: Key phase.
   --  Before server Finished is sent, handshake traffic keys are used.
   --  After server Finished, application traffic keys are used.
   function In_Handshake_Key_Phase (State : Connection_State) return Boolean
   is (State in
         Wait_Client_Hello
         | Wait_Client_Hello_Retry
         | Server_Hello_Sent
         | Sent_Certificate_Request
         | Wait_Client_Certificate
         | Wait_Client_Cert_Verify
         | Wait_Client_Finished
         | Client_Hello_Sent
         | Wait_Server_Hello
         | Wait_Encrypted_Extensions
         | Wait_Certificate_Request
         | Wait_Certificate
         | Wait_Certificate_Verify
         | Wait_Server_Finished
         | Client_Certificate_Sent
         | Client_Cert_Verify_Sent)
   with Ghost;

   function In_App_Key_Phase (State : Connection_State) return Boolean
   is (State in Connected | Closing | Client_Finished_Sent)
   with Ghost;

   --  RFC 8446 Â§6: Valid alert constraints.
   --  Post-handshake: only close_notify may use Warning level.
   --  All other alerts MUST be Fatal.
   function Valid_Alert (State : Connection_State; Level : Byte; Desc : Byte) return Boolean
   is (Level in 1 .. 2
       and then (if Handshake_Complete (State) and Desc /= 0 then Level = 2 else True))
   with Ghost;

   --  RFC 8446 Â§4: Expected handshake message type per state.
   --  Server expects these message types from the client:
   --    Wait_Client_Hello    â ClientHello (type 0x01)
   --    Wait_Client_Finished â Finished (type 0x14)
   --    Wait_Client_Certificate â Certificate (type 0x0B)
   --    Wait_Client_Cert_Verify â CertificateVerify (type 0x0F)
   --  Returns 0 if no specific handshake type is expected (e.g., Connected).
   function Expected_HS_Type (State : Connection_State) return Byte
   is (case State is
         when Wait_Client_Hello => 16#01#,  --  ClientHello
         when Wait_Client_Hello_Retry => 16#01#,  --  ClientHello (retry)
         when Wait_Client_Finished => 16#14#,  --  Finished
         when Wait_Client_Certificate => 16#0B#,  --  Certificate
         when Wait_Client_Cert_Verify => 16#0F#,  --  CertificateVerify
         when Wait_Server_Hello => 16#02#,  --  ServerHello
         when Wait_Server_Finished => 16#14#,  --  Finished
         when others => 0)
   with Ghost;

   --  RFC 8446 Â§4: Is this state expecting encrypted records?
   --  Before ServerHello, records are plaintext.
   --  After ServerHello, records are encrypted with traffic keys.
   function Expects_Encrypted (State : Connection_State) return Boolean
   is (State not in
         Idle
         | Wait_Client_Hello
         | Wait_Client_Hello_Retry
         | Client_Hello_Sent
         | Wait_Server_Hello)
   with Ghost;

   --  RFC 8446 Â§4.2.9: Key share group MUST match what the client offered.
   --  Server MUST NOT select a group the client didn't offer a key share for.
   --  (Ghost predicate for documentation; enforcement is in Parse_Client_Hello)

   --  RFC 8446 Â§4.4.4: Finished verify_data MUST be verified.
   --  If verification fails, a "decrypt_error" alert MUST be sent.
   --  (Enforced in Process_Client_Finished via HC.Server_HS_Secret)

   --  RFC 8446 Â§5.1: Record fragment size limits.
   --  Plaintext: max 2^14 = 16384 bytes.
   --  Ciphertext: max 2^14 + 256 = 16640 bytes.
   function Valid_Fragment_Len (Len : N32) return Boolean
   is (Len <= Max_Record_Plaintext)
   with Ghost;

   function Valid_Record_Len (Len : N32) return Boolean
   is (Len <= Max_Record_Size)
   with Ghost;

   --  RFC 8446 Â§5.1: Content type MUST be valid.
   function Valid_Content_Type (CT : Byte) return Boolean
   is (CT in 16#14# | 16#15# | 16#16# | 16#17#)  --  CCS/alert/hs/appdata
   with Ghost;

   --  RFC 8446 Â§4.6.1: Session ticket constraints.
   function Valid_Ticket_Lifetime (Secs : Unsigned_32) return Boolean
   is (Secs <= 604800)  --  max 7 days per RFC 8446 Â§4.6.1
   with Ghost;

   --  RFC 8446 Â§7.1: Key derivation chain ordering.
   --  The key schedule proceeds: Early â Handshake â Master â App.
   --  Each secret depends on the previous one.
   type Key_Phase is (Phase_None, Phase_Early, Phase_Handshake, Phase_Master, Phase_Application)
   with Ghost;

   function Key_Phase_Order (A, B : Key_Phase) return Boolean
   is (Key_Phase'Pos (A) < Key_Phase'Pos (B))
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
      Certificate_Required,        --  RFC 8446 Â§6 alert 116
      Decode_Error,
      Illegal_Parameter,
      Protocol_Version,
      Unsupported_Extension,       --  RFC 8446 Â§6 alert 110
      Missing_Extension,           --  RFC 8446 Â§6 alert 109
      No_Application_Protocol,     --  RFC 7301 Â§3.2 alert 120
      Internal_Error,
      Insufficient_Buffer,
      Unsupported_Cipher_Suite);

   ----------------------------------------------------------------------------
   --  TLS extension policy table (RFC 8446 Â§4.2)
   --
   --  Single source of truth for every TLS extension we recognise.
   --  Each entry says (a) which message types the extension may
   --  appear in, (b) whether a server may include it only after the
   --  client offered it in CH, and (c) whether the server's echo
   --  body must be empty (RFC 6066 Â§3 server_name ack, etc.).
   --
   --  All client-side server-extension validation goes through
   --  Validate_Server_Ext below â adding a new extension means
   --  adding one row to Ext_Policy_For, not peppering checks at
   --  every parse site.
   ----------------------------------------------------------------------------

   --  TLS messages that can carry extensions. The split SH13/SH12 is
   --  necessary because RFC 8446 Â§4.2 says key_share, pre_shared_key,
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

   type Ext_Where_Set is array (Ext_Where) of Boolean with Default_Component_Value => False;

   type Ext_Policy is record
      --  False for tags not in the IANA registry / not modelled
      --  here. Per RFC 8446 Â§4.2: "If an implementation receives
      --  an extension which it recognizes and which is not
      --  specified for the message in which it appears, it MUST
      --  abort..." â recognition matters. Unknown extensions are
      --  ignored where the RFC says to (e.g. RFC 8446 Â§4.3.2 CR);
      --  rejected where the RFC forbids unsolicited extensions
      --  (RFC 8446 Â§4.2 SH/EE).
      Known          : Boolean := False;
      --  Set of message types where this extension MAY appear.
      Where_Allowed  : Ext_Where_Set := (others => False);
      --  When True, the extension MAY only appear in a server-
      --  generated message if the client offered the same tag in
      --  CH. RFC 8446 Â§4.2.
      Requires_Offer : Boolean := True;
      --  When True, the server's echo body MUST be exactly zero
      --  bytes (RFC 6066 Â§3 server_name ack, RFC 7627 EMS, etc.).
      Empty_Echo     : Boolean := False;
      --  When True, our CH builder always emits this extension
      --  regardless of Cfg state. Used by Tag_Is_Offered to answer
      --  "did we offer this?" for the matrix Requires_Offer check.
      --  Conditional offerings (SNI iff Cfg.Server_Name set, ALPN
      --  iff Cfg.ALPN set) override this via the HC-aware overload.
      Always_In_CH   : Boolean := False;
   end record;

   --  Returns the policy row for a given extension type tag.
   --  Unknown tags get an empty Where_Allowed set, so any appearance
   --  in a server-generated message rejects as unsupported_extension.
   --  Add a `when` arm here to register a new extension; nothing
   --  else needs to change.
   function Ext_Policy_For (Tag : Interfaces.Unsigned_16) return Ext_Policy;

   --  "Did our CH builder always emit this extension?" â derived
   --  from `Ext_Policy_For (Tag).Always_In_CH`. Update by setting
   --  Always_In_CH on the matrix row, not by editing this function.
   --  Conditional offerings (SNI, ALPN, mTLS) are answered by the
   --  HC-aware overload below.
   function Tag_Is_Offered_Static (Tag : Interfaces.Unsigned_16) return Boolean
   is (Ext_Policy_For (Tag).Always_In_CH);

   --  RFC 5246 Â§8.1 / RFC 7627: Master secret derivation invariant.
   --  The derivation label MUST match the EMS negotiation.
   --  Using "extended master secret" without EMS extension, or
   --  "master secret" when EMS was negotiated, produces a
   --  valid-looking but incompatible master secret that causes
   --  Finished verification failure on the peer.
   function EMS_Label_Consistent (Use_EMS : Boolean; Label : String) return Boolean
   is (if Use_EMS then Label = "extended master secret" else Label = "master secret")
   with Ghost;

   --  ----- RFC 7748 Â§6.1 / RFC 8422 Â§5.10 small-subgroup defence ---
   --  An X25519 shared secret of all zeros indicates the peer used a
   --  point of small order (orders 1, 2, 4, 8 â eight specific 32-byte
   --  strings). Without rejecting these, an attacker who feeds such a
   --  point can predict the master secret. RFC 7748 Â§6.1 mandates the
   --  rejection; RFC 8422 Â§5.10 mirrors it for TLS-1.2 ECDHE-X25519.
   --
   --  The Post-condition is the formal RFC criterion: the function
   --  returns True iff at least one byte of the shared secret is
   --  non-zero (equivalently, the secret is not the all-zeros string
   --  that small-subgroup attacks coerce). gnatprove discharges the
   --  contract from the loop invariant in the body.
   function Shared_Secret_Is_Acceptable_X25519 (Shared_Secret : Byte_Seq) return Boolean
   with
     Post =>
       Shared_Secret_Is_Acceptable_X25519'Result
       = (for some I in Shared_Secret'Range => Shared_Secret (I) /= 0);

   --  ----- Phase 1 structural pinning: wire-format constants -------
   --  Each ghost predicate captures one normative MUST value from
   --  TLS 1.2 / 1.3 / EMS / Renegotiation / GCM. Pinned at the
   --  emission site via pragma Assert so a future edit that
   --  introduces a non-conforming value fails SPARK proof.

   --  RFC 5246 Â§7.4.1.3 / RFC 8446 Â§4.1.3: ServerHello.legacy_version
   --  MUST be 0x0303 (the wire encoding of TLS_1_2). For TLS 1.3 the
   --  real version is signalled in the supported_versions extension;
   --  legacy_version stays 0x0303 for middlebox compatibility.
   function ServerHello_Legacy_Version_RFC_8446_4_1_3 (V : TLS_Version) return Boolean
   is (V = TLS_1_2)
   with Ghost;

   --  RFC 5246 Â§7.4.1.2 / Â§7.4.1.3 / RFC 8446 Â§4.1.2/Â§4.1.3: the
   --  Random fields are exactly 32 bytes. Already type-enforced via
   --  Bytes_32; this ghost lifts the constraint to a named clause for
   --  RFC traceability.
   function Random_Length_RFC_5246_7_4_1_2 (Ignored_R : Bytes_32) return Boolean
   is (Ignored_R'Length = 32)
   with Ghost;

   --  RFC 5246 Â§6.2.2 / Â§7.4.1.4 / RFC 8446 Â§4.1.2: the only
   --  compression method TLS 1.2 servers MAY negotiate is
   --  null (0x00); compression is removed from TLS 1.3 entirely.
   --  Anything else is a CRIME-class attack vector.
   function Compression_Method_None_RFC_5246_6_2_2 (M : Byte) return Boolean
   is (M = 0)
   with Ghost;

   --  RFC 8446 Â§4.2.1: server's supported_versions ServerHello
   --  extension carries exactly one selected_version. For a server
   --  that selected TLS 1.3, the wire bytes are exactly (0x03, 0x04).
   function Supported_Versions_Server_TLS13_RFC_8446_4_2_1 (Data : Byte_Seq) return Boolean
   is (Data'Length = 2 and then Data (Data'First) = 16#03# and then Data (Data'First + 1) = 16#04#)
   with Ghost;

   --  RFC 5746 Â§3.5 / Â§3.6: on initial handshake, the
   --  renegotiation_info extension's renegotiated_connection field
   --  MUST be empty. On the wire that's a single 0x00 byte (the
   --  length prefix) â total ext data = 1 byte.
   function RI_Empty_Initial_RFC_5746_3_5 (Data : Byte_Seq) return Boolean
   is (Data'Length = 1 and then Data (Data'First) = 0)
   with Ghost;

   --  RFC 7627 Â§5.1: the extended_master_secret extension carries
   --  no data. Extension data length MUST be 0; presence alone
   --  signals EMS support.
   function EMS_Extension_Empty_Body_RFC_7627_5_1 (Data_Len : N32) return Boolean
   is (Data_Len = 0)
   with Ghost;

   --  RFC 5246 Â§7.4.9: TLS 1.2 Finished.verify_data is exactly
   --  12 bytes regardless of cipher suite. Already type-enforced
   --  via SPARKTLS.Key_Schedule_12.Verify_Data_12 (constant 12).
   function Verify_Data_Length_TLS12_RFC_5246_7_4_9 (VD : Byte_Seq) return Boolean
   is (VD'Length = 12)
   with Ghost;

   --  RFC 8446 Â§4.4.4: TLS 1.3 Finished.verify_data is Hash.length
   --  bytes â 32 for SHA-256, 48 for SHA-384.
   function Verify_Data_Length_TLS13_RFC_8446_4_4_4 (VD : Byte_Seq) return Boolean
   is (VD'Length = 32 or else VD'Length = 48)
   with Ghost;

   --  ----- RFC 8422 Â§5.1.2 ec_point_formats compliance -------------
   --  RFC 8422 Â§5.1.2 deprecates point formats 1
   --  (ansiX962_compressed_prime) and 2 (ansiX962_compressed_char2);
   --  only 0 (uncompressed) is recommended. **However**, a server
   --  MUST NOT reject a ClientHello that lists deprecated formats â
   --  RFC 8446 Â§4.2.6 says TLS 1.3 ignores this extension entirely,
   --  and OpenSSL / Go / NSS clients all include {0, 1, 2} by
   --  default for backward-compat. The acceptable check here is
   --  therefore "does the list include format 0", not "is the list
   --  exactly {0}".
   --
   --  An empty list is still rejected because RFC 8422 Â§5.1.1
   --  requires the field be non-empty when the extension is sent.
   function EC_Point_Formats_Acceptable (List : Byte_Seq) return Boolean
   with
     Post =>
       EC_Point_Formats_Acceptable'Result
       = (List'Length > 0 and then (for some I in List'Range => List (I) = 0));

   --  ----- RFC 5246 Â§7.4.1.4.1 sig_algs negotiated-from-offered ----
   --  RFC 5246 Â§7.4.1.4.1 / RFC 8446 Â§4.2.3: if the client sent the
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
     (Negotiated : Unsigned_16; Offered : Sig_Algo_List; Count : Natural) return Boolean
   is (Negotiated = 0 or else (for some I in 0 .. Count - 1 => Offered (I) = Negotiated))
   with Ghost, Pre => Count <= Max_Sig_Algos;

   --  ----- RFC 5246 Â§7.4.1.4.1 sig_algs default fallback -----------
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
   --    ed25519 = 0x0807. The low byte â¥ 4 distinguishes SHA-256+
   --    schemes (SHA-1 schemes are 0x0201/0x0202/0x0203, low byte 1-3).
   function Sig_Scheme_Has_Strong_Hash_RFC_5246_7_4_1_4_1 (Scheme : Unsigned_16) return Boolean
   is (Scheme = 16#0804#
       or else Scheme = 16#0805#
       or else Scheme = 16#0806#
       or else Scheme = 16#0403#
       or else Scheme = 16#0503#
       or else Scheme = 16#0807#)
   with Ghost;

   --  RFC 8446 Â§6: Error handling invariant.
   --  When entering Error_State, the implementation MUST have queued
   --  an alert record in the output buffer (unless the error is from
   --  a plaintext record where the peer can't decrypt our response).
   --
   --  This property would have caught the missing-alert bugs found by
   --  tlsfuzzer (Finished verify failure, decryption failure, wrong
   --  handshake type, record overflow â all silently closed without alert).
   function Error_Has_Alert
     (S_State : Connection_State; Pending : N32; Err : Error_Code) return Boolean
   is (if S_State = Error_State then Pending > 0 or else Err = Unexpected_Message)
   with Ghost;

   --  RFC 8446 Â§6.2 / RFC 5246 Â§7.2: map an Error_Code to its on-wire
   --  AlertDescription byte. Single source of truth â used both at
   --  runtime (by Send_*_Alert helpers across client / server, TLS 1.2
   --  and TLS 1.3 paths) and as a Ghost in proof contracts via the
   --  Expected_Alert_Desc rename below.
   function Alert_Desc (E : Error_Code) return Byte
   is (case E is
         when Unexpected_Message => 10,
         when Bad_Record_MAC => 20,
         when Record_Overflow => 22,
         when Handshake_Failure => 40,
         when Bad_Certificate => 42,
         when Certificate_Expired => 45,
         when Illegal_Parameter => 47,
         when Decode_Error => 50,
         when Certificate_Verify_Failed => 51,
         when Protocol_Version => 70,
         when Unsupported_Extension => 110,
         when Missing_Extension => 109,
         when Certificate_Required => 116,
         when No_Application_Protocol => 120,
         when Internal_Error | Insufficient_Buffer | No_Error => 80,
         when Unsupported_Cipher_Suite => 40);

   function Expected_Alert_Desc (E : Error_Code) return Byte renames Alert_Desc;
   --  Ghost-callable alias â proof contracts use this name.

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
      Data      : Byte_Seq (0 .. IO_Buffer_Capacity - 1) := (others => 0);
      Read_Pos  : Buffer_Size := 0;  --  next byte to consume
      Write_Pos : Buffer_Size := 0;  --  next byte to write
   end record
   with Predicate => IO_Buffer.Write_Pos >= IO_Buffer.Read_Pos;

   --  REMOVED 2026-08-18, and why -- do not reinstate without reading this.
   --
   --  This predicate used to also assert the compaction invariant:
   --      (if IO_Buffer.Write_Pos = IO_Buffer.Read_Pos
   --       then IO_Buffer.Write_Pos = 0)
   --  on the reasoning that Drain_Ciphertext and Compact reset the pair
   --  once Available reaches 0, so "nothing pending" implies the whole
   --  capacity is free.
   --
   --  That reasoning describes where the code SETTLES, not what is true at
   --  every point, and a predicate is checked on every component
   --  assignment. The consuming paths advance Read_Pos and only compact
   --  afterwards:
   --      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
   --      ... return;                    <-- Read_Pos = Write_Pos /= 0 here
   --  so the invariant is transiently FALSE, not merely unproven. A
   --  checked build would raise Assertion_Error at exactly those points.
   --
   --  It accounted for 159 of the 204 owned proof findings in the
   --  2026-08-18 full run (78%), spread across every line range of the
   --  four largest units -- the signature of a predicate that is false in
   --  ordinary operation rather than one that is hard to discharge.
   --
   --  This is the same mistake, and the same fix, as the RFC 8446 6.1/5.2
   --  flood caps reverted on 2026-08-17: an invariant that holds between
   --  operations is not an invariant of the TYPE. If a specific caller
   --  needs "drained implies compacted", it belongs in that subprogram's
   --  precondition where it can actually be established, not here.

   function Available (Buf : IO_Buffer) return N32
   is (Buf.Write_Pos - Buf.Read_Pos);

   function Free_Space (Buf : IO_Buffer) return N32
   is (IO_Buffer_Capacity - Buf.Write_Pos);

   ----------------------------------------------------------------------------
   --  Hostname storage (for SNI)
   ----------------------------------------------------------------------------

   --  Bound lives on the field, not on a record predicate: a predicate is
   --  re-checked on every component assignment and at every call boundary
   --  that passes a Hostname_Buf, whereas a subtype costs one range check
   --  where the length is actually written.
   subtype Hostname_Length is Natural range 0 .. Max_Hostname_Len;

   type Hostname_Buf is record
      Data : String (1 .. Max_Hostname_Len) := (others => ASCII.NUL);
      Len  : Hostname_Length := 0;
   end record;

   Max_Config_ALPN_Protocols : constant := 8;
   subtype ALPN_Index is Natural range 1 .. Max_Config_ALPN_Protocols;
   type ALPN_Protocol_List is array (ALPN_Index) of Hostname_Buf;

   ----------------------------------------------------------------------------
   --  Traffic keys for one direction (key + IV + nonce counter)
   ----------------------------------------------------------------------------

   --  RFC 8446 Â§7.3: Traffic keys with suite constraint.
   --  RFC 8446 Â§5.3: the per-record nonce is the static write IV XORed
   --  with this sequence number, so the nonce is DERIVED, not chosen.
   --
   --  Unsigned_64 is a MODULAR type: Counter + 1 at 'Last wraps silently to
   --  0 with no overflow check, because wrapping is what modular arithmetic
   --  is defined to do. That would restart the nonce sequence under an
   --  unchanged key -- nonce reuse, which is catastrophic for AEAD, and
   --  entirely silent in a release build where preconditions are not
   --  evaluated.
   --
   --  The counter's TYPE bound IS the cryptographic budget (user call,
   --  2026-08-24): a bound of 2**64 defending a 2**23 fact made every
   --  counter VC reason over intervals ~2**40 too wide. The cap value
   --  itself stays representable -- it is the legitimate "channel
   --  exhausted" state after the final permitted record -- so Space_Left
   --  remains a real two-state query, but every increment, comparison
   --  and frame now works in 23-bit intervals. The old arithmetic-wrap
   --  backstop is subsumed: a wrap is now ~2**40 range-check failures
   --  away instead of one.
   Rekey_After_Records : constant := 2 ** 23;

   --  The TYPE bound is the RECEIVE-side / arithmetic limit: a conforming
   --  peer (TLS 1.3 ChaCha with no rekey obligation, or any TLS 1.2 peer)
   --  may legitimately send far more than the 2**23 WRITE budget, which is
   --  enforced separately by Write_Budget_Reached/Write_Limit_Reached
   --  against Rekey_After_Records. 2**62 cannot be reached in practice
   --  (58,000 years at 2M records/s) and keeps increment arithmetic
   --  provably in range. See task #115.
   Max_Record_Counter : constant := 2 ** 62;
   subtype Record_Counter is Unsigned_64 range 0 .. Max_Record_Counter;

   --  Lengths bounded by the record-plaintext limit. These were Session
   --  predicate conjuncts; as subtypes the bound travels with the field
   --  and is discharged by a range check at assignment instead of being
   --  re-proved as part of the whole-record predicate every time any
   --  component of a Session is written.
   subtype Plaintext_Length is N32 range 0 .. Max_Record_Plaintext;

   type Traffic_Keys is record
      Key     : Bytes_32 := (others => 0);
      IV      : Bytes_12 := (others => 0);
      Counter : Record_Counter := 0;
      --  Closed enum (#118): the membership predicate this used to carry
      --  is now true by construction.
      Suite   : Supported_Suite := Suite_CHACHA20_POLY1305_SHA256;
   end record;

   --  RFC 8446 Â§5.5 "Limits on Key Usage". For AES-GCM the guidance is at
   --  most 2**24.5 (~23.7 million) full-size records under one key, to keep
   --  the AEAD security margin at roughly 2**-57. ChaCha20-Poly1305 has no
   --  comparable confidentiality limit, so this conservative bound is
   --  applied uniformly rather than per-suite.
   --
   --  We rotate well below the limit -- 2**23 records -- so the rekey
   --  happens with margin rather than at the cliff edge. That matters
   --  because rotation needs output-buffer space: if the buffer is full we
   --  retry on the next write, and the margin is what makes those retries
   --  harmless.
   --
   --  NOTE the two bounds are different things and both are needed:
   --    * this one is the CRYPTOGRAPHIC limit (now also the type bound
   --      of Record_Counter), and rotating keeps the connection alive
   --      and within the AEAD margin. See #46 for the old split.



   --  The write-side AEAD confidentiality cap (RFC 8446 Â§5.5 for 1.3,
   --  the same 2**23 bound adopted for 1.2 where no rekey exists), as a
   --  query on the channel that owns the counter. This is BOTH the
   --  runtime branch callers take and the precondition Encrypt-side ops
   --  carry -- one object, one query, so the discharge is local at every
   --  call site instead of threaded (the r41 lesson: a cap fact that
   --  lives apart from its counter does not travel).
   function Space_Left (K : Traffic_Keys) return Boolean
   is (K.Counter < Rekey_After_Records);

   --  Control-record headroom (2026-08-24, exposed by the tight counter
   --  bound): rotation/close must trigger BEFORE the cap so the records
   --  that perform them -- KeyUpdate, close_notify, a final alert --
   --  still fit inside the budget. The old wide type silently let those
   --  ride PAST the stated RFC 8446 Section 5.5 budget; the tight type
   --  turned that into a refusal deadlock, which this margin resolves
   --  conformantly. 16 covers rotation plus a worst-case alert tail.
   Rekey_Margin : constant := 16;

   --  The app-data write budget: the trigger for KeyUpdate (1.3) or
   --  connection close (1.2). Distinct from Space_Left, which is the
   --  hard refusal line the channel enforces on itself.
   function Write_Budget_Reached (K : Traffic_Keys) return Boolean
   is (K.Counter >= Rekey_After_Records - Rekey_Margin);

   ----------------------------------------------------------------------------
   --  Random byte generation callback
   --
   --  The caller must supply a CSPRNG. This is the only callback;
   --  everything else is buffer-based.
   ----------------------------------------------------------------------------

   type Random_Bytes_Fn is access procedure (Output : out Byte_Seq);

   --  The null-excluding view: subprograms that WILL call the generator
   --  take this subtype, so "is there a generator?" is answered by the
   --  type at the boundary instead of a threaded null-check Pre. The
   --  fact originates at Ready_Config's predicate and flows down.
   subtype Live_Random_Fn is not null Random_Bytes_Fn;

   --  Time callback for certificate validation.
   --  Called at validation time, not at configuration time.
   type Get_Time_Fn is access function return X509.Date_Time;


   ----------------------------------------------------------------------------
   --  Certificate pool types
   --
   --  Used by Trust_Store, Identity, and Validate_Chain.
   --  Each pool entry holds a parsed cert and its own DER buffer
   --  starting at index 0 (required by X509 span offsets).
   ----------------------------------------------------------------------------

   --  Max entries in an intermediate cert pool (Peer_Ints, Identity.Ints).
   --  Real cert chains have â¤ 6 intermediates; 8 is comfortably above that.
   --  Previously 40, which cost ~400 KB per Session (Cert_Pool dominates
   --  Session size) and made it impractical to hold many sessions in BSS
   --  or on the stack. The trust store uses a separate larger pool
   --  (Max_Root_Pool_Size = 200) since OS CA bundles have 130+ roots.
   --  Handshake data-plane pool sizing (#106). Slot types live here so
   --  Session can hold its slot; the pool itself is SPARKTLS.HS_Pool.
   Max_Inflight : constant := 16;
   type Slot_Count is range 0 .. Max_Inflight;
   subtype Slot_Index is Slot_Count range 1 .. Max_Inflight;
   No_Slot : constant Slot_Count := 0;

   Max_Pool_Size : constant := 8;
   Max_Cert_DER : constant := 8192;   --  max DER bytes per cert

   subtype Cert_DER_Buf is X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1);

   --  Bounded by construction: every write site holds the bound locally
   --  (parse-length guards / slice assigns), and every read gets
   --  DER_Len <= Max_Cert_DER for free -- the predicate no longer needs
   --  to restate it, which is what drowned the Present-write VCs (r46).
   subtype Pool_DER_Length is X509.N32 range 0 .. Max_Cert_DER;

   type Pool_Entry is record
      Cert    : X509.Certificate;
      DER     : Cert_DER_Buf := (others => 0);
      DER_Len : Pool_DER_Length := 0;
      Present : Boolean := False;
   end record
   with
     Predicate =>
       (if Pool_Entry.Present
        then Pool_Entry.DER_Len > 0 and X509.Spans_Valid (Pool_Entry.Cert, Pool_Entry.DER_Len - 1));

   type Cert_Pool is array (0 .. Max_Pool_Size - 1) of Pool_Entry;
   type Used_Set is array (0 .. Max_Pool_Size - 1) of Boolean;

   ----------------------------------------------------------------------------
   --  Trust Store
   --
   --  Holds root CA certificates for chain validation.
   --  Allocated once at application startup, shared across sessions
   --  via Trust_Store_Access (access-to-constant, read-only).
   --
   --  Uses a larger pool than Cert_Pool (200 vs 40) because OS
   --  certificate bundles typically contain 130+ root CAs.
   --  Not embedded in Session â referenced by pointer, so the
   --  larger size doesn't affect per-connection memory.
   ----------------------------------------------------------------------------

   Max_Root_Pool_Size : constant := 200;
   type Root_Pool is array (0 .. Max_Root_Pool_Size - 1) of Pool_Entry;

   --  Same reasoning as Hostname_Length: single-field bound belongs on the
   --  field's subtype rather than on a whole-record predicate.
   subtype Root_Pool_Count is Natural range 0 .. Max_Root_Pool_Size;

   type Trust_Store is record
      Roots      : Root_Pool;
      Root_Count : Root_Pool_Count := 0;
   end record;

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
      Cert_DER     : X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1) := (others => 0);
      Cert_DER_Len : X509.N32 := 0;
      Cert         : X509.Certificate;
      Cert_Valid   : Boolean := False;

      --  Leaf cert in SPARKNaCl format (for handshake message building)
      NaCl_Cert_DER : Byte_Seq (0 .. N32 (Max_Cert_DER) - 1) := (others => 0);
      NaCl_Cert_Len : N32 := 0;

      --  Intermediate certificates (sent to peer in Certificate message)
      Ints      : Cert_Pool;
      Int_Count : Natural := 0;

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
   with
     Dynamic_Predicate =>
       Valid_Identity_Access = null
       or else (Valid_Identity_Access.NaCl_Cert_Len <= N32 (Max_Cert_DER)
                and then Valid_Identity_Access.Int_Count <= Max_Pool_Size
                and then (for all I in 0 .. Max_Pool_Size - 1
                          => Valid_Identity_Access.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER))
                and then (if Valid_Identity_Access.Sign_Algo = Sign_RSA_PSS
                          then Valid_Identity_Access.RSA_Mod_Len in 64 .. 512));

   subtype Selected_Identity_Access is Identity_Access
   with
     Dynamic_Predicate =>
       Selected_Identity_Access = null
       or else (Selected_Identity_Access.Has_Identity
                and then Selected_Identity_Access.NaCl_Cert_Len <= N32 (Max_Cert_DER)
                and then Selected_Identity_Access.Int_Count <= Max_Pool_Size
                and then (for all I in 0 .. Max_Pool_Size - 1
                          => Selected_Identity_Access.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER))
                and then (if Selected_Identity_Access.Sign_Algo = Sign_RSA_PSS
                          then Selected_Identity_Access.RSA_Mod_Len in 64 .. 512));

   ----------------------------------------------------------------------------
   --  SNI-based certificate selection (RFC 6066 Â§3, RFC 8446 Â§4.4.2.4)
   --
   --  Servers that host multiple virtual hosts on one listener install
   --  a Select_Identity callback in Config. The callback receives the
   --  hostname from the client's server_name extension and returns the
   --  matching Identity_Access. Returning null means "no match" â
   --  per RFC 6066, the server MAY proceed with the default identity
   --  (the more permissive choice, matches openssl). Strict-SNI mode
   --  (alert on no-match) is not supported today but can be added by
   --  having the callback raise an alert via a side channel.
   --
   --  The callback runs after CH-extension parsing and BEFORE the
   --  cert chain / SKE / Finished are built. The hostname passed in
   --  is the raw bytes the client sent (RFC 6066 Â§3 says ASCII; the
   --  caller is responsible for any case-folding / Punycode
   --  normalization).
   --
   --  Safety: the callback MUST be pure (no side effects) and MUST
   --  return either null or an Identity_Access that remains valid for
   --  the lifetime of the session. Identities returned here are
   --  typically allocated once at server startup and immutable.
   ----------------------------------------------------------------------------

   type SNI_Cert_Selector is
     access function (Server_Name : in String) return Selected_Identity_Access;

   ----------------------------------------------------------------------------
   --  Ticket Store (for session resumption)
   --  Defined here so Config can reference it. Implementation in
   --  SPARKTLS.Ticket_Cache child package.
   ----------------------------------------------------------------------------

   Max_Cached_Tickets : constant := 1024;
   Ticket_ID_Len : constant := 16;
   subtype Ticket_ID is Byte_Seq (0 .. Ticket_ID_Len - 1);

   --  Length fields carry their own bounds (#84/#82): the check moves to
   --  the assignment that produces the value and every read gets it free.
   subtype PSK_Length is N32 range 0 .. 48;

   type Ticket_Entry is record
      ID      : Ticket_ID := (others => 0);
      PSK     : Bytes_48 := (others => 0);
      PSK_Len : PSK_Length := 0;
      Suite   : Unsigned_16 := 0;
      Age_Add : Unsigned_32 := 0;
      Valid   : Boolean := False;
   end record
   with
     Predicate =>
     --  RFC 8446 Â§4.6.1: PSK is SHA-256 (32 byte) or SHA-384 (48
     --  byte) only when Valid; zero-length on invalid slots is OK
     --  because they're never read.
       (if Ticket_Entry.Valid then Ticket_Entry.PSK_Len in 32 | 48 else Ticket_Entry.PSK_Len = 0);

   type Ticket_Array is array (Natural range 0 .. Max_Cached_Tickets - 1) of Ticket_Entry;

   type Ticket_Store is record
      Entries : Ticket_Array;
      Next    : Natural range 0 .. Max_Cached_Tickets - 1 := 0;
   end record;


   ----------------------------------------------------------------------------
   --  Session Ticket (RFC 8446 Â§4.6.1)
   --
   --  Stand-alone, copyable record so the caller can persist it
   --  across connections. Defined here (before Config) because
   --  Cfg.Resume_Ticket embeds it.
   ----------------------------------------------------------------------------

   Max_Ticket_Len : constant := 256;

   subtype Ticket_Length is N32 range 0 .. Max_Ticket_Len;

   type Session_Ticket is record
      Ticket                  : Byte_Seq (0 .. Max_Ticket_Len - 1) := (others => 0);
      Ticket_Len              : Ticket_Length := 0;
      Lifetime                : Unsigned_32 := 0;       --  seconds
      Age_Add                 : Unsigned_32 := 0;       --  obfuscation value
      Received_At             : Unsigned_64 := 0;       --  Unix seconds, 0 if unknown
      PSK                     : Bytes_48 := (others => 0);  --  derived PSK
      PSK_Len                 : PSK_Length := 0;       --  32 (SHA-256) or 48 (SHA-384)
      Suite                   : Unsigned_16 := 0;       --  cipher suite
      Server_Name             : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Resumption_Across_Names : Boolean := False;
      Valid                   : Boolean := False;
   end record;

   ----------------------------------------------------------------------------
   --  TLS 1.2 ticket encryption key (RFC 5077 Â§4)
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
      --  auto-rotation timer (`Now - Created_At >= Interval` â
      --  rotate). Callers populating the array manually at startup
      --  should set Created_At to the wall-clock time so the first
      --  rotation fires Interval seconds later, not immediately.
   end record;

   type TLS12_Ticket_Key_Array is array (Natural range 0 .. TLS12_Max_Keys - 1) of TLS12_Ticket_Key;


   ----------------------------------------------------------------------------
   --  TLS 1.2 cached session ticket (client side, RFC 5077 Â§3.4)
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

   --  RFC 7627 Â§5.3: whether the session a ticket represents negotiated
   --  Extended Master Secret. Persisted with the ticket so a resumption
   --  attempt can be compared against the ORIGINAL session's state --
   --  Â§5.3 requires aborting when a non-EMS session is resumed as EMS or
   --  vice versa, and that comparison is the triple-handshake defence
   --  itself. Distinct from HC.MS_Derivation, which records which PRF
   --  path ran within a single handshake (RFC 7627 Â§4).
   --
   --  A two-value enum rather than a Boolean so the wire/stored states
   --  are named at the point of use and a future third state (e.g.
   --  "unknown, ticket predates this field") is a compile error to
   --  ignore rather than a silently-false Boolean.
   type EMS_Status is (EMS_Absent, EMS_Negotiated);

   type Session_Ticket_12 is record
      Ticket        : Byte_Seq (0 .. Max_TLS12_Ticket_Len - 1) := (others => 0);
      Ticket_Len    : N32 range 0 .. Max_TLS12_Ticket_Len := 0;
      Master_Secret : Byte_Seq (0 .. 47) := (others => 0);
      Suite         : Unsigned_16 := 0;
      Lifetime_Hint : Unsigned_32 := 0;   --  seconds (from server)
      Server_Name   : Hostname_Buf := (Len => 0, Data => (others => ' '));
      --  RFC 7627 Â§5.3 resumption consistency; see EMS_Status above.
      EMS           : EMS_Status := EMS_Absent;
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
   --  DoS resource limits (Â§2.13 in ROADMAP)
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
   --  responsibility (see ROADMAP Â§2.13).
   ----------------------------------------------------------------------------

   type DoS_Caps is record
      --  Max cipher_suite entries consumed from a CH. Wire allows
      --  ~32767. Real clients send 5-30; cap of 256 is comfortably
      --  above any legitimate peer.
      Max_Cipher_Suites : N32 := 256;

      --  Max supported_groups entries consumed from the named-group
      --  extension. Real clients send 4-12; cap of 64.
      Max_Supported_Groups : N32 := 64;

      --  Max key_share entries consumed from a TLS 1.3 ClientHello.
      --  Real clients send 1-3; cap of 64 leaves ample room while
      --  bounding duplicate/share parsing work.
      Max_Key_Shares : N32 := 64;

      --  Max signature_algorithms entries CONSUMED from the wire
      --  (distinct from Max_Sig_Algos which caps how many we STORE
      --  in HC.Peer_Sig_Algos). Wire allows ~32767. Real clients
      --  send 6-15; cap of 64.
      Max_Sig_Algs_Wire : N32 := 64;

      --  Max ALPN protocol entries in the client's offer. Real
      --  clients send 1-5 (typically just "h2" or "http/1.1"+"h2").
      --  Cap of 32.
      Max_ALPN_Protocols : N32 := 32;

      --  Max warning-level alerts the server will tolerate during
      --  a single handshake before treating the next as fatal
      --  decode_error (BoGo SendWarningAlerts-TooMany).
      Max_Warning_Alerts : N32 := 4;
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

   ----------------------------------------------------------------------------
   --  Server ticket storage callbacks
   --
   --  Session resumption needs storage that outlives a single connection,
   --  and whose concurrency and durability properties only the application
   --  knows. Rather than hold a pointer to a shared mutable store, the
   --  library calls out. This keeps SPARKTLS free of global state and free
   --  of owning pointers -- access-to-subprogram carries no ownership, so
   --  Config stays a copyable value type and Init/Configure stay in SPARK.
   --
   --  Leave them null to disable resumption entirely; an embedded caller
   --  then pays nothing for it.
   --
   --  THREAD SAFETY is the implementation's responsibility. SPARKTLS holds
   --  no shared state of its own, so sessions are independent; anything
   --  these callbacks touch is shared by the application's choice. See
   --  SPARKTLS.Ticket_Store.Protected_Impl for a ready-made thread-safe one.
   --
   --  DO NOT BLOCK. These run inside handshake processing. A cache miss is
   --  always safe -- it falls back to a full handshake -- so a distributed
   --  implementation should time out and report Found => False rather than
   --  stall the state machine.
   ----------------------------------------------------------------------------

   --  Persist a resumption PSK; return the identity to put on the wire.
   type Store_Session_Fn is
     access procedure
       (PSK     : Bytes_48;
        PSK_Len : PSK_Length;
        Suite   : Unsigned_16;
        Age_Add : Unsigned_32;
        ID_Out  : out Ticket_ID)
   with Pre => PSK_Len in 32 | 48;

   --  Retrieve a PSK by identity. Found => False on miss, wrong suite,
   --  expiry, or any error: all mean "do a full handshake".
   --  Post mirrors SPARKTLS.Ticket_Cache.Lookup, which already PROVES it.
   --  Without it here the guarantee was lost three times over -- Ticket_Cache
   --  -> protected Cache.Lookup -> Session_Cache.Lookup_Session -> this access
   --  type -- so the server could not discharge
   --  "if Found then Suite = S.Negotiated_Suite" at the call site even though
   --  the reference implementation establishes it. The contract belongs on the
   --  access type: that is the boundary a caller can see, and it obligates
   --  every implementation rather than one.
   type Lookup_Session_Fn is
     access procedure
       (ID         : Byte_Seq;
        Want_Suite : Unsigned_16;
        PSK        : out Bytes_48;
        PSK_Len    : out N32;
        Suite      : out Unsigned_16;
        Found      : out Boolean)
   with
     Pre => ID'First = 0 and then ID'Length = Ticket_ID_Len,
     Post => (if Found then Suite = Want_Suite and then PSK_Len in 32 | 48);
   --  Mirrors SPARKTLS.Ticket_Cache.Lookup, which already proves it.
   --  Requires Ada 2022 (postcondition on an access-to-subprogram type);
   --  see ada_version in alire.toml.
   --
   --  THIS CONTRACT DOES NOT MAKE THE RESULT TRUSTWORTHY, and the server
   --  still re-checks it at the call site. Deleting that check because
   --  gnatprove calls it redundant would be a mistake, for two reasons:
   --    * SPARK obligates only implementations whose 'Access is taken in
   --      SPARK-verified code. An application may supply this callback
   --      from ordinary Ada -- or any language -- and is bound by nothing.
   --    * Postconditions are checked at runtime only while assertions are
   --      enabled. A release build checks nothing.
   --  So for a caller, this Post is an ASSUMPTION the library cannot
   --  enforce. The call site derives the same fact from an explicit test
   --  instead, which is why the proof does not depend on trusting the
   --  application. Keep both.

   --  TLS 1.2 stateless tickets (RFC 5077): the key that seals outgoing
   --  tickets, and lookup by the Key_ID carried in an inbound ticket.
   --  Replaces the old shared key array, and lets an HSM-backed
   --  deployment supply keys without the library holding them.
   type Get_Active_TEK_Fn is
     access procedure (Key_ID : out Byte_Seq; TEK : out Byte_Seq; Found : out Boolean)
   with Pre => Key_ID'Length = 4 and then TEK'Length = 32;

   type Get_TEK_By_Id_Fn is
     access procedure (Key_ID : Byte_Seq; TEK : out Byte_Seq; Found : out Boolean)
   with Pre => TEK'Length = 32;

   type Config is record
      Suite       : Cipher_Suite := TLS_CHACHA20_POLY1305_SHA256;
      Random      : Random_Bytes_Fn := null;
      Server_Name : Hostname_Buf;
      Skip_Verify : Boolean := False;  --  accept any cert

      --  Client-side hostname verification opt-out (RFC 6125 Â§6.4).
      --  When Server_Name is non-empty AND this is False (default),
      --  the client checks that the server's leaf cert contains a
      --  matching SAN dNSName or iPAddress (or Subject CN as a
      --  fallback per the prevailing CN-in-SAN rules). On mismatch
      --  the handshake is aborted with `bad_certificate`. This check
      --  runs INDEPENDENTLY of `Skip_Verify` / `Trust` / `Get_Time`
      --  â those gate full chain validation; hostname binding stays
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
      Versions : Version_Policy := Allow_Both;  --  TLS version control

      --  Client: preferred initial TLS 1.3 key_share group. Zero keeps
      --  the default browser-like behavior: advertise X25519/P-256/P-384
      --  in supported_groups and send an initial X25519 key_share. Set to
      --  16#001D# (X25519), 16#0017# (secp256r1), or 16#0018#
      --  (secp384r1) to advertise and send only that group in CH1.
      Client_Key_Share_Group : Unsigned_16 := 0;

      --  Validation settings
      Verify_Mode    : Validation_Mode := Mode_WebPKI;
      Verify_Purpose : Validation_Purpose := Purpose_Server;
      Get_Time       : Get_Time_Fn := null;

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
      ALPN         : Hostname_Buf := (Len => 0, Data => (others => ' '));
      --  Optional ordered ALPN preference list. When ALPN_Count > 0,
      --  clients advertise ALPN_List (1 .. ALPN_Count), and servers
      --  select the first configured entry also offered by the client.
      --  ALPN remains as the backwards-compatible single-protocol API.
      ALPN_List    : ALPN_Protocol_List := (others => (Len => 0, Data => (others => ' ')));
      ALPN_Count   : Natural range 0 .. Max_Config_ALPN_Protocols := 0;
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
      TLS12_Cipher_List   : Cipher_Suite_List := (others => 0);
      TLS12_Cipher_Groups : Cipher_Suite_Preference_Groups := (others => 0);
      TLS12_Cipher_Count  : Natural range 0 .. Max_Config_Cipher_Suites := 0;

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
      --  authentication if the client doesn't present a cert â the
      --  classic OpenSSL SSL_VERIFY_PEER vs
      --  SSL_VERIFY_FAIL_IF_NO_PEER_CERT distinction.
      Require_Client_Cert : Boolean := False;

      --  Server: resumption storage callbacks. When both are non-null the
      --  server sends NewSessionTicket after the handshake and accepts
      --  PSK identities on resumption. Null disables resumption.
      Store_Session  : Store_Session_Fn := null;
      Lookup_Session : Lookup_Session_Fn := null;

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
      Get_Active_TEK : Get_Active_TEK_Fn := null;
      Get_TEK_By_Id  : Get_TEK_By_Id_Fn := null;

      --  Server: lifetime hint (seconds) sent in NewSessionTicket.
      --  The server itself also enforces this as a hard expiry on
      --  decrypted tickets (RFC 5077 Â§5.6 advises â¤7 days). Default
      --  3600 seconds (1 hour) â refreshes ticket-derived forward
      --  secrecy hourly. Set 0 to disable issuing tickets entirely.
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;

      --  TICKET-ENCRYPTION KEY (TEK) ROTATION IS NOT CONFIGURED HERE.
      --  There is no Auto_Rotate_TEK flag and no interval in Cfg: the
      --  mechanism lives in SPARKTLS.Session_Cache, which is where the
      --  key material and the CSPRNG already are.
      --
      --  Rotation is ON BY DEFAULT (24 h) once the app calls
      --      Session_Cache.Initialize (Random, Clock, Rotation_Interval)
      --  and is LAZY: Get_Active_TEK checks the active key's age on each
      --  ticket issuance and rotates in place, so the check rides on real
      --  traffic and an idle server does no work. No timer task.
      --
      --  Rotation shifts a ring of TLS12_Max_Keys slots: the new key
      --  becomes active, older keys stay valid for DECRYPT so tickets
      --  issued under them still resume during the grace window, and the
      --  oldest drops out.
      --
      --  Rotation_Interval => 0 disables it and hands control back to the
      --  app via Session_Cache.Rotate_TEK -- the right choice for HSM keys
      --  or a fleet kept in sync by an orchestrator, where independent
      --  per-node rotation would break cross-node resume.
      --
      --  CAVEAT: all of the above is Session_Cache, the reference cache.
      --  An app that supplies its OWN Store_Session/Get_Active_TEK
      --  callbacks owns rotation entirely and gets none of this for free.

      TLS12_Resume_Ticket : Session_Ticket_12;

      --  Client: previously-saved resumption ticket (RFC 8446
      --  Â§4.6.1). When Valid, Init copies this into S.Ticket before
      --  building CH so the pre_shared_key extension is offered.
      --  Default-init (Valid=False) means a fresh full handshake.
      --
      --  Note: 0-RTT (RFC 8446 Â§2.3 / Â§4.2.10) is intentionally not
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
   --  Handshake procedures receive this as `in out` â they never
   --  see the pointer, only the record.
   ----------------------------------------------------------------------------

   --  RFC 7627 Â§4 ghost type: tracks which TLS 1.2 master_secret PRF
   --  was used. Set inside Derive_Keys_12 along the matching code
   --  path. The companion predicate EMS_PRF_Binding_RFC_7627_4 ties
   --  the choice of PRF to HC.Use_EMS â the property whose absence
   --  caused the v9âv12 TLS-Anvil regression.
   type Master_Secret_Derivation_Mode is (Not_Derived, Legacy, Extended);

   --  Bounded array of seen CH extension type codes (RFC 8446 Â§4.2
   --  duplicate-extension check). Modern CHs carry ~10-20 extensions;
   --  64 is comfortably above realistic peers and bounds the linear
   --  scan cost in Apply_CH_Extension.
   type Ext_Tag_Array is array (1 .. 64) of Unsigned_32;

   --  Length/count bounds for Handshake_Context fields.
   --
   --  These were Handshake_Context PREDICATE conjuncts. A predicate is
   --  re-checked on every assignment to ANY component of the record and at
   --  every call boundary that passes an HC, so a single-field bound stated
   --  there costs a proof obligation at every unrelated write elsewhere in
   --  the record. As a subtype the bound is discharged by one range check at
   --  the assignment that actually touches the field.
   --
   --  The record already used this idiom for Seen_Ext_Count,
   --  Legacy_Session_ID_Len and Peer_Sig_Algo_Count -- note none of those
   --  three has a predicate conjunct. These seven are the ones that were
   --  missed; moving them leaves the predicate with only the genuine
   --  multi-field relationship (reassembly buffer shape), which cannot
   --  become a subtype.
   subtype Transcript_Length is N32 range 0 .. Transcript_Capacity;
   subtype Hash_Length is N32 range 0 .. 48;
   subtype Cert_DER_Length is N32 range 0 .. Max_Cert_DER_Len;
   subtype Cert_Pool_Count is Natural range 0 .. Max_Pool_Size;
   subtype PSK_Binder_Length is N32 range 0 .. 64;
   subtype PSK_Value_Length is N32 range 0 .. 48;
   subtype TLS12_Ticket_Length is N32 range 0 .. Max_TLS12_Ticket_Len;

   --  Uncompressed EC point buffers for the peer's key_share (RFC 8446
   --  Â§4.2.8.2): 0x04 || X || Y, so 65 bytes for P-256 and 97 for P-384.
   --  Named so Copy_P256_KS / Copy_P384_KS can take the buffer alone as an
   --  out parameter instead of the whole Handshake_Context -- a parameter
   --  cannot carry an inline constraint, and sharing one subtype between
   --  field and parameter keeps the call boundary conversion-free.
   subtype P256_Peer_Key is Byte_Seq (0 .. 64);
   subtype P384_Peer_Key is Byte_Seq (0 .. 96);

   --  Named so the TLS 1.2 session-ID and ticket helpers can take just the
   --  buffer they fill instead of the whole Handshake_Context.
   subtype Session_ID_Length is N32 range 0 .. 32;
   subtype TLS12_Ticket_Buffer is Byte_Seq (0 .. Max_TLS12_Ticket_Len - 1);

   --  0 = not yet selected / absent. The predicate makes
   --  Valid_ECDHE_Group free at every /= 0 use site (#82); the check
   --  moves to the two guarded parse sites that produce the value.
   --  Constants live in the Handshake.TLS12 child, hence literals
   --  (16#001D# X25519, 16#0017# secp256r1, 16#0018# secp384r1).
   subtype Maybe_ECDHE_Group is Unsigned_16
   with Static_Predicate => Maybe_ECDHE_Group in 0 | 16#001D# | 16#0017# | 16#0018#;

   --  Carve 3a: negotiated-curve seed of the KE ADT. Validity is BY TYPE
   --  (no zero member), so Valid_ECDHE_Group demands on this value are
   --  tautologies; Negotiated carries only the phase â whether Curve is
   --  the peer-agreed group or the meaningless default. No predicate:
   --  there is no cross-field relation to state (user rule 2026-08-24 â
   --  predicates only for what the base type system cannot express).
   subtype ECDHE_Group is Unsigned_16
   with Static_Predicate => ECDHE_Group in 16#001D# | 16#0017# | 16#0018#;

   --  Carve 3b: the key material joins the seed. The 1.3 client
   --  generates shares for several curves BEFORE negotiation, so
   --  material-presence is NOT gated on Negotiated; Curve selects the
   --  live pair once Negotiated. No predicate: there is no cross-field
   --  relation the base type system cannot express (arrays are always
   --  initialized; Curve is valid by type; Negotiated is pure phase).
   type KE_State is record
      Negotiated : Boolean := False;
      Curve      : ECDHE_Group := 16#001D#;
      Local_SK   : Bytes_32 := (others => 0);  --  X25519
      Peer_PK    : Bytes_32 := (others => 0);  --  X25519
      P256_SK    : Bytes_32 := (others => 0);
      P256_PK    : P256_Peer_Key := (others => 0);
      P384_SK    : Bytes_48 := (others => 0);
      P384_PK    : P384_Peer_Key := (others => 0);
      Shared     : Bytes_48 := (others => 0);
   end record;

   --  TLS 1.2 session-ticket / resumption state machine (RFC 5077),
   --  folded from Handshake_Context (carve 5, 2026-08-25). Server side:
   --    * Sent_Ticket_Ext  -- we offered the session_ticket extension
   --    * Server_Will_Issue -- server echoed the empty extension
   --    * Resuming -- server elected to resume; skip Cert/SKE
   --  Client side:
   --    * Ticket_Offered -- client sent session_ticket ext
   --    * Ticket_Resume_OK -- client-provided ticket validated
   --    * Ticket_Will_Issue -- we'll emit a NewSessionTicket
   --    * Resumed_Master_Secret -- restored MS from a valid ticket
   --    * Resumed_Suite -- cipher suite we MUST use in SH
   --  NOTE: Resumed_Master_Secret is KEY MATERIAL. Never construct a
   --  whole-record aggregate of this type over a live value (the KE
   --  wipe lesson, carve 3b); write components individually.
   --  TLS 1.3 PSK / resumption offer state (RFC 8446 4.2.11), folded
   --  from Handshake_Context (carve 6, 2026-08-25). Binder hashes are
   --  the server-side draw-before-append snapshots from carve 2.
   --  NOTE: Value is KEY MATERIAL -- no whole-record aggregates over a
   --  live value; write components individually (carve 3b lesson).
   type PSK_State is record
      Offered           : Boolean := False;
      Offer_ID          : Ticket_ID := (others => 0);
      Value             : Bytes_48 := (others => 0);   --  zeros if no PSK
      Value_Len         : PSK_Value_Length := 0;       --  0 = no PSK
      Binder            : Bytes_48 := (others => 0);   --  received binder
      Binder_Len        : PSK_Binder_Length := 0;
      Has_DHE_KE        : Boolean := False;
      Binder_Hash_256   : Bytes_32 := (others => 0);
      Binder_Hash_384   : Bytes_48 := (others => 0);
      Binder_Hash_Taken : Boolean := False;
   end record;

   type TLS12_State is record
      Client_Cert_Allowed   : Boolean := False;
      Sent_Ticket_Ext       : Boolean := False;
      Server_Will_Issue     : Boolean := False;
      Resuming              : Boolean := False;
      Ticket_Offered        : Boolean := False;
      Ticket_Resume_OK      : Boolean := False;
      Ticket_Will_Issue     : Boolean := False;
      Resumed_Master_Secret : Byte_Seq (0 .. 47) := (others => 0);
      Resumed_Suite         : Unsigned_16 := 0;
      Peer_Ticket_Len       : TLS12_Ticket_Length := 0;
      Peer_Ticket           : TLS12_Ticket_Buffer := (others => 0);
   end record;

   --  Handshake phase (phase carve 2026-08-26). Setup: from allocation
   --  until the local/peer ClientHello has been ingested; there is NO
   --  transcript in this phase â it cannot be hashed, appended to, or
   --  forgotten, because it does not exist. Engaged: the ClientHello is
   --  in the transcript, which is Started by construction; every
   --  post-CH handler takes Engaged_Context and gets that fact
   --  structurally (flow-level, no contracts).
   --  HS_Phase (Setup/Engaged discriminant) DELETED, MEASURED (r70,
   --  2026-08-29): the discriminant drove no behavior (both runtime uses
   --  were variant-existence guards) and its proof rent was 69
   --  discriminant checks plus a ~55-conjunct Pre-threading apparatus.
   --  The facts it coarsely encoded live in finer types already: the
   --  transcript carries Started, the Engage aggregate forces full
   --  initialization, and the State machine gates dispatch.

   --  Negotiated cipher-suite parameters (#117). The hash length is
   --  DERIVED from the discriminant, so the suite<->hash correlation
   --  holds by construction -- no predicate, no contract threading.
   --  Suite 0 = not yet negotiated (hash defaults to 32, matching the
   --  old Hash_Len field default). Assigned whole at negotiation.
   type Negotiated_Params (Suite : Supported_Suite := Suite_None) is null record;

   function Hash_Len (N : Negotiated_Params) return Hash_Length
   is (if N.Suite = Suite_AES_256_GCM_SHA384 then 48 else 32);

   type Handshake_Context is record
      --  Protocol version (set during Parse_Client_Hello / Parse_Server_Hello)
      Version : TLS_Version := TLS_1_3;

      --  Configuration (callbacks, trust store, identity)
      Cfg : Config;

      --  Server-side: SNI hostname received in the client's
      --  server_name extension (RFC 6066 Â§3). Captured during
      --  CH-extension parsing in `Apply_CH_Extension` and consumed
      --  by the SNI cert-selection step. Empty (Len = 0) if the
      --  client didn't send a server_name extension or sent one with
      --  no host_name entries.
      Peer_SNI : Hostname_Buf := (Len => 0, Data => (others => ' '));

      --  Ephemeral key exchange (X25519, P-256, or P-384 ECDHE)
      Client_Random : Bytes_32 := (others => 0);
      Server_Random : Bytes_32 := (others => 0);

      --  P-256 ECDHE key exchange state

      --  P-384 ECDHE key exchange state

      --  Server-side: which groups did the client offer in key_share?
      --  (actual key exchange data present)
      Client_Has_X25519           : Boolean := False;
      Client_Has_P256             : Boolean := False;
      Client_Has_P384             : Boolean := False;
      --  TLS 1.3 client sent the key_share extension at all. This is
      --  distinct from Client_Has_*: an empty key_share vector can be
      --  HRR-recoverable, while an absent key_share extension is a
      --  missing_extension error.
      Client_Saw_Key_Share        : Boolean := False;
      --  Which groups did the client offer in supported_groups?
      --  (may not have key_share data â triggers HRR if preferred)
      Client_Saw_Supported_Groups : Boolean := False;
      Client_Supports_X25519      : Boolean := False;
      Client_Supports_P256        : Boolean := False;
      Client_Supports_P384        : Boolean := False;
      KE                          : KE_State;
      --  HelloRetryRequest state (server-side: we sent HRR)
      HRR_Sent                    : Boolean := False;
      --  HelloRetryRequest state (client-side: we received HRR)
      --  RFC 8446 Â§4.1.4: at most one HRR per connection; a second
      --  HRR is an unexpected_message. Got_HRR latches the first
      --  reception so the SH handler rejects subsequent HRRs.
      Got_HRR                     : Boolean := False;
      --  RFC 8446 Â§4.1.4: HRR carries (cipher_suite + supported_versions)
      --  and (key_share with selected_group OR cookie OR both). When
      --  the second SH arrives, its cipher_suite MUST match the HRR's
      --  (BoGo HelloRetryRequest-CipherChange-TLS13). Stash for
      --  comparison.
      HRR_Cipher_Suite            : Unsigned_16 := 0;
      HRR_Selected_Group          : Maybe_ECDHE_Group := 0;
      HRR_Cookie_Len              : N32 range 0 .. 1024 := 0;
      HRR_Cookie                  : Byte_Seq (0 .. 1023) := (others => 0);
      --  RFC 8446 Â§D.4: the dummy CCS is emitted exactly once per
      --  connection. On the HRR retry path we emit it between HRR
      --  and CH2 (server's `expectChangeCipherSpec` then fires on
      --  the CCS, not on CH2). If we then emitted another CCS in
      --  the post-SH client flight, the server would reject it as
      --  `received unexpected ChangeCipherSpec`. Track to gate.
      Sent_HRR_CCS                : Boolean := False;
      --  RFC 8446 Â§4.1.2: CH extension order fingerprint.
      --  Rolling polynomial hash of extension type codes in order.
      --  CH2 must produce the same hash as CH1 (modulo cookie).
      CH_Ext_Hash                 : Unsigned_32 := 0;
      CH_Ext_Count                : Natural := 0;

      --  RFC 8446 Â§4.2: "the same extension type MUST NOT appear in
      --  a given extension list more than once". Track seen tag codes
      --  to enforce. Modern CHs use ~10-20 extensions; cap at 64.
      Seen_Ext_Tags  : Ext_Tag_Array := (others => 0);
      Seen_Ext_Count : Natural range 0 .. Ext_Tag_Array'Last := 0;

      --  Handshake traffic keys
      Client_HS : Traffic_Keys;
      Server_HS : Traffic_Keys;

      --  Traffic secrets (for finished key derivation)
      Client_HS_Secret : Bytes_48 := (others => 0);
      Server_HS_Secret : Bytes_48 := (others => 0);

      --  Key schedule intermediates
      Handshake_Secret : Bytes_48 := (others => 0);
      Master_Secret    : Bytes_48 := (others => 0);

      --  Negotiated suite parameters; hash length derives from the
      --  discriminant via function Hash_Len (#117).
      Neg : Negotiated_Params;

      --  Streaming transcript (carve 2): dual SHA-256/384 contexts
      --  replace the 32 KB buffer -- no capacity, no Len, no non-RFC
      --  size restrictions. See sparktls_transcript.ads.

      --  Peer certificate (raw DER for verification)
      --  The peer's leaf certificate as ONE predicated record (#101):
      --  Present implies DER_Len in 1 .. Max and Spans_Valid -- the
      --  facts the old four loose fields threaded through contracts.
      --  WHOLE-AGGREGATE ASSIGNMENT ONLY (multi-field predicate).

      --  Peer intermediate certificates

      --  Legacy session ID (middlebox compatibility)
      Legacy_Session_ID     : Bytes_32 := (others => 0);
      --  RFC 8446 Â§4.1.3: server's ServerHello MUST echo the client's
      --  legacy_session_id (whatever its length, 0..32). We store
      --  both the bytes and the length so we can echo accurately
      --  rather than always padding to 32.
      Legacy_Session_ID_Len : Session_ID_Length := 0;

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
      T12                   : TLS12_State;
      PSK                   : PSK_State;
      Cert_Request_Received : Boolean := False;

      --  Version negotiation (set during Parse_Client_Hello)
      --  True if the client's supported_versions extension contains 0x0304.
      --  If False, we negotiate TLS 1.2 (if legacy_version = 0x0303).
      Has_TLS_1_3            : Boolean := False;
      --  RFC 8446 Â§4.2.1: client sent supported_versions extension.
      Saw_Supported_Versions : Boolean := False;
      --  RFC 8446 Â§4.2.1: supported_versions listed at least one
      --  version we can negotiate (TLS 1.2 or TLS 1.3). When the
      --  client sent the extension but none of the listed versions
      --  match our policy, the server MUST reply with
      --  protocol_version. BoGo NoSupportedVersions.
      SV_Has_Acceptable      : Boolean := False;

      --  TLS 1.2: ClientKeyExchange already received
      CKE_Received_12 : Boolean := False;


      --  TLS 1.2: Extended Master Secret (RFC 7627) negotiated
      Use_EMS          : Boolean := False;
      --  RFC 7627 Â§3: EMS session_hash covers ClientHello through
      --  ClientKeyExchange, inclusive. Capture that transcript length
      --  immediately after CKE so later CertificateVerify / Finished
      --  appends cannot affect master_secret derivation.
      --  EMS session hash (RFC 7627), DRAWN at its protocol point
      --  (CKE) rather than remembered as a buffer offset. 48 bytes
      --  covers both digests; Hash_Len says how many are live.
      EMS_Session_Hash : Bytes_48 := (others => 0);
      EMS_Hash_Taken   : Boolean := False;

      --  TLS 1.2: client offered renegotiation_info extension (RFC 5746)
      --  or sent the TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) in
      --  cipher_suites. Servers echo the extension only when one of
      --  these signals is present (RFC 5746 Â§3.6).
      Saw_Reneg_Info : Boolean := False;

      --  RFC 8446 Â§4.2.9: client offered psk_key_exchange_modes with
      --  the psk_dhe_ke (0x01) mode. Required before the server may
      --  issue a NewSessionTicket on this connection (RFC 8446 Â§4.6.1
      --  / BoGo TLS13-ExpectNoSessionTicketOnBadKEMode-Server).

      --  Per-extension parse error surface. Apply_CH_Extension only
      --  has access to HC, not S â so when an extension's contents
      --  violate its RFC (e.g. RFC 7301 Â§3.1 empty ALPN protocol_name),
      --  the parser stores the alert code here and the caller of
      --  Parse_Client_Hello propagates it to Last_Error (S).
      Ext_Parse_Err : Error_Code := No_Error;

      --  Client's offered ALPN protocol (parsed from ClientHello)
      Client_ALPN       : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Client_ALPN_List  : ALPN_Protocol_List := (others => (Len => 0, Data => (others => ' ')));
      Client_ALPN_Count : Natural range 0 .. Max_Config_ALPN_Protocols := 0;

      --  TLS 1.2 key material (set during Derive_Keys_12)
      Master_Secret_12   : Bytes_48 := (others => 0);
      --  TLS 1.2 implicit IV. AES-GCM (RFC 5288 Â§3) uses the first
      --  4 bytes as `salt`; ChaCha20-Poly1305 (RFC 7905 Â§2) uses the
      --  full 12 bytes XOR'd with the padded sequence number. Sized
      --  for the larger usage and zero-padded on the AES-GCM side.
      Client_Write_IV_12 : Byte_Seq (0 .. 11) := (others => 0);
      Server_Write_IV_12 : Byte_Seq (0 .. 11) := (others => 0);
      --  NO loose sequence counters here (sealed-channel carve 5a): the
      --  TLS 1.2 counters live inside the Traffic_Keys channels
      --  (S.Client_App / S.Server_App), where the nonce derives from a
      --  counter only the record ops can advance. The old HC/Session
      --  twin-counter design needed a handoff copy at handshake
      --  completion and rewind bookkeeping on error paths -- all gone by
      --  construction.

      --  RFC 7627 Â§4: tracks which PRF path produced Master_Secret_12.
      --  Use_EMS â extended PRF; (not Use_EMS) â legacy PRF. The
      --  v9âv12 bug we hit during the TLS-Anvil drive-down was a
      --  violation of this binding (we always emitted EMS in SH but
      --  always derived with legacy PRF). Updated only inside
      --  Derive_Keys_12. We keep this as a real field (not Ghost)
      --  because Ada record components cannot carry the Ghost aspect
      --  directly. The runtime overhead is one byte per HC.
      MS_Derivation : Master_Secret_Derivation_Mode := Not_Derived;

      --  Resumption
      Using_PSK : Boolean := False;              --  offset of binders in ClientHello

      --  RFC 8446 Â§2.3 / Â§4.2.10 0-RTT (early data).
      --
      --  We do NOT support 0-RTT â replay + lack of forward secrecy
      --  is incompatible with the project's high-integrity posture.
      --  The two fields below are the minimal residual defense:
      --
      --  Early_Data_Offered : set when the client's CH carried an
      --                       early_data extension. We never echo it
      --                       in EE (= rejection per Â§4.2.10), but
      --                       the client may still send 0-RTT records
      --                       on the wire encrypted with a key we
      --                       never derived; the flag gates the
      --                       silent-drop loop below.
      --  Skipped_Early_Data_Records : counts dropped records when
      --                       Early_Data_Offered. Capped to defend
      --                       against a peer pinning us in skip mode
      --                       indefinitely. RFC 8446 Â§4.6.1.
      Early_Data_Offered         : Boolean := False;
      Skipped_Early_Data_Records : Natural := 0;

      --  Handshake message reassembly (multi-record handshake messages).
      --  When a handshake record fragment contains only part of a
      --  handshake message (declared length > fragment), accumulate
      --  fragments here until the full message is available.
      --  INLINE, not a pointer. One buffer per Handshake_Context, and HC is
      --  itself heap-allocated once per session via HC_Alloc, so this costs
      --  no extra allocation. Being unconditionally present retires every
      --  '/= null' obligation and the whole Free/double-free proof surface.

      --  Heap budget: total bytes allocated for extensions/reassembly.
      --  Prevents DoS via large extensions in ClientHello/ServerHello.

      --  NOTE: a 17 KB scratch buffer field and its size constant used to
      --  live here, declared for a stack-allocation design that was never
      --  implemented -- every RFLX buffer is heap-allocated via `new`. Both
      --  were removed. If the no-`new` work is picked up (pointing
      --  RecordFlux's Initialize/Take_Buffer at non-heap storage), note that
      --  server_msgs.adb holds a message buffer and an extension buffer live
      --  simultaneously, so a single shared block is not sufficient.

      --  Streaming transcript. Fresh (not Started) until the Engage
      --  aggregate absorbs the ClientHello; Started from then on. The
      --  Started fact is carried by SPARKTLS_Transcript's own contracts,
      --  not by this record's shape.
      TS : SPARKTLS_Transcript.Transcript_State;
   end record;

   --  Historical names from the phase-discriminant era; now plain views
   --  of the flat record. Kept so the formal-subtype references read as
   --  documentation of which handshake stage a subprogram serves.
   subtype Setup_Context is Handshake_Context;
   subtype Engaged_Context is Handshake_Context;
   --  No Predicate on this record any more. Every field bound lives on a
   --  FIELD SUBTYPE, and the one genuine MULTI-field relationship -- the
   --  reassembly state machine -- moved into Reasm_Info, which carries its
   --  own predicate and is updated by a single aggregate assignment. That
   --  removes Handshake_Context from the task #60 class entirely.

   --  Heap budget accounting deleted with the heap itself (#106):
   --  handshake memory is now bounded by the HS_Pool slot count.

   --  ----- RFC 5246 Â§7.4.7 single-ClientKeyExchange invariant ------
   --  TLS 1.2 Â§7.4.7: the client sends exactly one ClientKeyExchange
   --  per handshake, immediately after the (optional) Certificate.
   --  A second CKE in the same handshake is a state-machine violation
   --  and MUST be rejected with an unexpected_message alert (Â§7.2.2).
   --
   --  HC.CKE_Received_12 starts False and transitions monotonically
   --  to True on the first successful CKE. After that, the flag is
   --  the predicate guarding rejection of any further CKE messages
   --  in the same handshake.
   function Single_CKE_RFC_5246_7_4_7 (HC : Handshake_Context) return Boolean
   is (HC.CKE_Received_12)
   with Ghost;

   --  ----- RFC 7627 Â§4 EMS PRF binding ------------------------------
   --  RFC 7627 Â§4: when the extended_master_secret extension is
   --  negotiated (HC.Use_EMS = True), the master_secret MUST be
   --  derived using the extended PRF (label "extended master secret",
   --  seed = transcript hash). Otherwise the legacy RFC 5246 Â§8.1
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
   function EMS_PRF_Binding_RFC_7627_4 (HC : Handshake_Context) return Boolean
   is (case HC.MS_Derivation is
         when Not_Derived => True,  --  not yet derived; vacuously true
         when Extended => HC.Use_EMS,
         when Legacy => not HC.Use_EMS)
   with Ghost;

   --  ----- RFC 8446 Â§5.1 outer record content_type recognition -----
   --  RFC 8446 Â§5.1 (and RFC 5246 Â§6.2.1): the outer record header's
   --  type field MUST be one of:
   --    0x14 = change_cipher_spec
   --    0x15 = alert
   --    0x16 = handshake
   --    0x17 = application_data
   --  Any other value MUST cause the record to be rejected
   --  (unexpected_message). This is the OUTER counterpart to
   --  Inner_Type_Valid_RFC_8446_5_4 â outer accepts CCS, inner
   --  does not.
   function Outer_Content_Type_Valid_RFC_8446_5_1 (T : Byte) return Boolean
   is (T = 16#14# or else T = 16#15# or else T = 16#16# or else T = 16#17#)
   with Ghost;

   --  ----- RFC 8446 Â§5.1 record-layer legacy_record_version --------
   --  RFC 8446 Â§5.1: the TLSPlaintext.legacy_record_version field
   --  MUST be 0x0303 ("TLS 1.2") for all records other than the
   --  initial ClientHello (which MAY use 0x0301 for old-server
   --  middlebox compatibility). Servers MUST reject any other value.
   --  RFC 5246 Â§6.2.1: same â the wire version stays at the
   --  negotiated TLS 1.2 record-layer version.
   function Record_Version_RFC_8446_5_1 (Major, Minor : Byte) return Boolean
   is (Major = 16#03# and then Minor = 16#03#)
   with Ghost;

   --  ----- RFC 8446 Â§6.1 / Â§6.2 alert level/description binding ----
   --  RFC 8446 Â§6.1: warning (level 1) is ONLY valid with
   --  close_notify (description 0) or user_canceled (90).
   --  RFC 8446 Â§6.2: fatal (level 2) is for everything else; in
   --  particular close_notify and user_canceled MUST NOT be sent
   --  at fatal level.
   --
   --  TLS 1.3 Â§6: implementations SHOULD emit any non-zero alert
   --  at fatal level even when TLS 1.2 would have used warning.
   --  We follow the strict RFC binding via the predicate below;
   --  the matching Pre on Build_Plaintext_Alert / Build_Alert_Record
   --  enforces it at every emission site.
   function Alert_Level_Description_Valid_RFC_8446_6_1 (Level : Byte; Desc : Byte) return Boolean
   is (Level in 1 .. 2
       and then (if Level = 1 then Desc = 0 or else Desc = 90)
       and then (if Level = 2 then Desc /= 0 and then Desc /= 90))
   with Ghost;

   --  ----- RFC 5246 Â§7.4.9 / RFC 8446 Â§4.4.4 Finished-mismatch ----
   --  RFC 5246 Â§7.4.9: "It is a fatal error if a Finished message is
   --  not preceded by a ChangeCipherSpec message at the appropriate
   --  point in the handshake." (Sequencing covered by
   --  CCS_Precedes_Finished_RFC_5246_7_1 above.)
   --
   --  RFC 8446 Â§4.4.4: "Recipients of Finished messages MUST verify
   --  that the contents are correct and if incorrect MUST terminate
   --  the connection with a 'decrypt_error' alert."
   --
   --  This predicate captures the post-mismatch state: Error_State
   --  reached, fatal alert queued, Last_Error in the set of valid
   --  Finished-mismatch responses (Handshake_Failure for TLS 1.2,
   --  Bad_Record_MAC for TLS 1.3 since our enum lacks Decrypt_Error).
   function Finished_Mismatch_Alerted_RFC_8446_4_4_4
     (State : Connection_State; Pending : N32; Err : Error_Code) return Boolean
   is (State = Error_State and then Pending > 0 and then Err in Handshake_Failure | Bad_Record_MAC)
   with Ghost;

   --  ----- RFC 8446 Â§5.4 inner content type after AEAD decrypt ----
   --  RFC 8446 Â§5.4: after stripping padding zeros from a decrypted
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
   function Inner_Type_Valid_RFC_8446_5_4 (T : Byte) return Boolean
   is (T = 16#15# or else T = 16#16# or else T = 16#17#)
   with Ghost;

   --  ----- RFC 8446 Â§5.1 / Â§5.2 record-fragment length bound -------
   --  RFC 8446 Â§5.1: plaintext fragment â¤ 2^14 = 16384 bytes.
   --  RFC 8446 Â§5.2: encrypted (application_data) fragment â¤
   --  2^14 + 256 = 16640 bytes (the +256 allows for AEAD overhead).
   --  RFC 5246 Â§6.2.1 (TLS 1.2): same limits apply.
   --
   --  A receiver MUST send record_overflow alert (22) on any
   --  record exceeding these bounds. Without this, an attacker can
   --  exhaust receiver memory or trigger oversized-buffer bugs.
   function Record_Length_Bound_RFC_8446_5_1 (Content_Type : Byte; Frag_Len : N32) return Boolean
   is (if Content_Type = 16#17# then Frag_Len <= 16384 + 256 else Frag_Len <= 16384)
   with Ghost;

   --  ----- RFC 8446 Â§4.2.11.2 PSK binder validated before use ------
   --  RFC 8446 Â§4.2.11.2: on receipt of a ClientHello PSK extension,
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
   function PSK_Binder_Validated_RFC_8446_4_2_11_2 (Binder_Verified : Boolean) return Boolean
   is (Binder_Verified)
   with Ghost;

   --  ----- RFC 5246 Â§7.2.1 / RFC 8446 Â§6.1 close_notify reply ------
   --  RFC 5246 Â§7.2.1 (and RFC 8446 Â§6.1): on receipt of a close_notify
   --  alert, the receiver MUST send its own close_notify in reply
   --  before closing the write side. After the reply is queued the
   --  connection enters the Closing state. This predicate captures
   --  the post-receipt invariant: State (S) = Closing AND the output
   --  buffer holds the queued close_notify (or the reply attempt
   --  filled the buffer beyond capacity, in which case the caller
   --  drains then retries â Output_Pending > 0 still holds).
   function Close_Notify_Reply_State_RFC_5246_7_2_1
     (State : Connection_State; Pending : N32) return Boolean
   is (State = Closing and then Pending > 0)
   with Ghost;

   --  ----- RFC 8446 Â§4.2.8 key_share group bounded by client offer
   --  RFC 8446 Â§4.2.8: the server's selected_group in its KeyShareEntry
   --  MUST be one that the client offered in either its key_share or
   --  supported_groups extensions. A server that selects an
   --  unoffered group breaks key agreement and (more importantly)
   --  signals a serious negotiation bug â clients refuse to derive
   --  shared secrets with mismatched groups.
   --
   --  This predicate cross-references HC.KE.Curve against the
   --  per-group `Client_Has_*` flags (key_share data present) and
   --  the `Client_Supports_*` flags (offered in supported_groups).
   --  Selected_Group = 0 means "not yet selected" and is allowed
   --  prior to ServerHello build.
   function Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC : Handshake_Context) return Boolean
   is (not HC.KE.Negotiated
       or else (HC.KE.Curve = 16#001D#
                and then (HC.Client_Has_X25519 or else HC.Client_Supports_X25519))
       or else (HC.KE.Curve = 16#0017#
                and then (HC.Client_Has_P256 or else HC.Client_Supports_P256))
       or else (HC.KE.Curve = 16#0018#
                and then (HC.Client_Has_P384 or else HC.Client_Supports_P384)))
   with Ghost;

   --  ----- RFC 8446 Â§4.1.4 HelloRetryRequest at most once -----------
   --  TLS 1.3 Â§4.1.4: a server MUST send at most one HRR per
   --  connection. HRR is a one-shot mechanism to coax the client
   --  into a recoverable ClientHello (different group, missing
   --  cookie, etc.); a second HRR signals an infinite-loop server
   --  bug or attempted DoS amplification.
   --
   --  HC.HRR_Sent transitions monotonically False â True; the
   --  guard `if not HC.HRR_Sent` at the HRR build site enforces
   --  the at-most-once property at runtime.
   function HRR_Sent_At_Most_Once_RFC_8446_4_1_4 (HC : Handshake_Context) return Boolean
   is (HC.HRR_Sent)
   with Ghost;

   --  ----- RFC 5246 Â§7.1 single-ChangeCipherSpec invariant ----------
   --  TLS 1.2 Â§7.1: each direction sends exactly one CCS per
   --  handshake, immediately before the encrypted Finished. A second
   --  CCS in the same handshake is a state-machine violation
   --  (CVE-2014-0224 "ChangeCipherSpec injection" was a class of
   --  bugs where servers accepted out-of-sequence CCS).
   --
   --  HC.CCS_Received transitions monotonically False â True. A
   --  second CCS is rejected at sparktls-server-tls12.adb:399 with
   --  unexpected_message; the runtime guard is `not HC.CCS_Received`.
   function Single_CCS_RFC_5246_7_1 (HC : Handshake_Context) return Boolean
   is (HC.CCS_Received)
   with Ghost;

   --  ----- RFC 5246 Â§7.1 CCS-precedes-Finished sequence ------------
   --  RFC 5246 Â§7.1 (and Â§7.4.9): the ChangeCipherSpec record MUST
   --  arrive between ClientKeyExchange and Finished â never standalone,
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
   function CCS_Precedes_Finished_RFC_5246_7_1 (HC : Handshake_Context) return Boolean
   is (HC.CKE_Received_12 and then HC.CCS_Received)
   with Ghost;

   ----------------------------------------------------------------------------
   --  Ghost predicates added 2026-05-09 covering the BoGo morning
   --  fix batch. Each pins a specific RFC clause so a later
   --  refactor that re-introduces the bug will be flagged at
   --  proof time, not runtime.
   ----------------------------------------------------------------------------

   --  RFC 8446 Â§6.1 / Â§6: TLS 1.3 deprecates warning alerts but
   --  keeps user_canceled (90) for back-compat. To bound DoS via
   --  alert flooding, BoringSSL/NSS/OpenSSL tolerate â¤ 4 in a row;
   --  the 5th triggers fatal too_many_warning_alerts.
   Max_Warning_Alerts : constant := 4;

   --  RFC 8446 4.6.3 places no bound on how often a peer may send
   --  KeyUpdate, and each one costs a KDF plus key re-derivation. Cap the
   --  count so rekeying cannot be used as a cheap asymmetric DoS. The
   --  legitimate need is one rotation per AEAD usage limit (RFC 8446 5.5),
   --  so a healthy peer sends single digits over a connection's life.
   --  Leaky bucket for inbound KeyUpdate (RFC 8446 Â§4.6.3 sets no bound on
   --  how often a peer may rekey, and each one costs a KDF).
   --
   --  Max_Key_Updates is the BUCKET DEPTH, not a lifetime cap. An absolute
   --  cap is wrong here: a well-behaved peer rotating at its own Â§5.5 AEAD
   --  limit would exhaust a lifetime cap on a long-lived connection and we
   --  would drop it with unexpected_message -- a self-inflicted interop
   --  bug. The bucket must therefore drain.
   --
   --  The leak is driven by RECORDS READ rather than a clock, which the
   --  core deliberately does not have (Get_Time is an optional callback).
   --  Records read is also the better signal: it distinguishes the two
   --  cases directly.
   --
   --    * legitimate peer -- rotates after millions of records, so the read
   --      counter is large at each KeyUpdate; it refunds a token and never
   --      drains the bucket;
   --    * abusive peer -- sends KeyUpdates back-to-back with no data, so
   --      the read counter is ~0 each time; no refund, bucket empties, and
   --      the connection is dropped.
   Max_Key_Updates : constant := 32;

   --  Records that must have been read under the previous key for an
   --  inbound KeyUpdate to be considered legitimate work rather than
   --  flooding. Far below our own rotation threshold so a peer rekeying on
   --  any sane schedule always refunds.
   Rekey_Refill_Records : constant := 2 ** 16;

   --  Rekey_After_Records moved up beside Traffic_Keys / Space_Left,
   --  which need it in their declarations.

   --  RFC 8446 Â§5.2 / RFC 5246 Â§6.2.1: zero-length-plaintext
   --  records waste decrypt CPU without delivering progress.
   --  BoringSSL caps consecutive empty records at 32; the 33rd
   --  triggers fatal too_many_empty_fragments.
   Max_Empty_Records : constant := 32;

   --  RFC 8446 Â§5.1 / RFC 5246 Â§6.2.1: record-layer version is
   --  always 0x03xx with minor in 1..4. Anything else is a
   --  framing violation â Parse_Record_Header rejects with
   --  Bad_Version.
   function Record_Version_Valid_RFC_8446_5_1 (Major, Minor : Byte) return Boolean
   is (Major = 16#03# and Minor in 16#01# .. 16#04#)
   with Ghost;

   --  RFC 8446 Â§4.2: each extension type MUST appear at most once
   --  in a given extensions list. Tracked per-CH via HC.Seen_Ext_Tags;
   --  Apply_CH_Extension scans the list before recording a new tag.
   function No_Duplicate_Extensions_RFC_8446_4_2 (HC : Handshake_Context) return Boolean
   is (HC.Seen_Ext_Count <= HC.Seen_Ext_Tags'Last)
   with Ghost;

   --  RFC 8446 Â§4.1.3: the server's ServerHello legacy_session_id
   --  MUST be a byte-for-byte copy of the client's. Captured at
   --  parse time and replayed at build time.
   function Session_ID_Echo_RFC_8446_4_1_3 (HC : Handshake_Context) return Boolean
   is (HC.Legacy_Session_ID_Len in 0 .. 32)
   with Ghost;

   --  Heap wrapper (phase carve, 2026-08-26): objects created by an
   --  allocator are CONSTRAINED to their initial discriminants
   --  (RM 4.8(6)), so a bare heap Handshake_Context could never change
   --  Phase. A record component without a constraint is mutable
   --  (RM 3.7), so the box's C can. Allocation is max-variant-size.
   --  #106: the handshake context is now INLINE in Session (control
   --  plane) with jumbo data in SPARKTLS.HS_Pool. The heap box and its
   --  access type are gone -- with them the borrow dance, the leak
   --  obligations, and the cross-object seam that kept the state<->phase
   --  and version<->suite couplings unprovable.

   ----------------------------------------------------------------------------
   --  TLS extension policy: HC-aware Tag_Is_Offered + Validate_Server_Ext
   ----------------------------------------------------------------------------

   --  Combines Tag_Is_Offered_Static with the conditional CH
   --  offerings: server_name (iff Cfg.Server_Name.Len > 0), ALPN
   --  (iff Cfg.ALPN.Len > 0). We don't currently offer
   --  pre_shared_key (0x0029) under any circumstance.
   function Tag_Is_Offered (Tag : Interfaces.Unsigned_16; HC : Handshake_Context) return Boolean
   is (Tag_Is_Offered_Static (Tag)
       or else (Tag = 16#0000# and then HC.Cfg.Server_Name.Len > 0)
       or else (Tag = 16#0010# and then HC.Cfg.ALPN.Len > 0)
       or else (Tag = 16#0023# and then HC.T12.Sent_Ticket_Ext)
       or else (Tag = 16#0029# and then HC.PSK.Offered)
       or else (Tag = 16#002A# and then HC.Early_Data_Offered)
               --  RFC 7627 EMS is a CONDITIONAL offering: the CH builder emits it
               --  iff Cfg.Versions /= TLS_1_3_Only (see Offer_EMS in
               --  Handshake.Client_Msgs.Build_Client_Hello), so Always_In_CH is
               --  False on its policy row and Tag_Is_Offered_Static cannot answer
               --  for it. Without this arm the server's legitimate EMS echo failed
               --  the Requires_Offer check and the client replied
               --  unsupported_extension -- BoGo ExtendedMasterSecret-TLS12-Client.
               --  The condition MUST track Offer_EMS exactly; if one changes so
               --  must the other.
       or else (Tag = 16#0017# and then HC.Cfg.Versions /= TLS_1_3_Only));

   --  RFC 8446 Â§4.2 single-call validator for any server-generated
   --  extension. Returns OK = True on success; otherwise sets
   --  Err to the alert that should be raised:
   --   * Unsupported_Extension â extension type not allowed in this
   --     message, or not offered when Requires_Offer is True
   --   * Decode_Error          â body present where it must be empty
   --
   --  Caller is responsible for body-shape / content validation
   --  beyond the empty-or-not boundary (RFC 7301 Â§3.2 ALPN proto
   --  match, RFC 8446 Â§4.2.8 key_share single-entry tile, etc.) â
   --  those need per-tag knowledge.
   procedure Validate_Server_Ext
     (Where    : in Ext_Where;
      Tag      : in Interfaces.Unsigned_16;
      Body_Len : in N32;
      HC       : in Handshake_Context;
      OK       : out Boolean;
      Err      : out Error_Code);

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
   --  SPIKE 2026-08-20: Role is a DISCRIMINANT, not a field. There is no
   --  variant part -- no component's subtype depends on Role, so SPARK's
   --  mutable-discriminant restrictions largely do not apply. The point is
   --  the constrained subtypes below: a subprogram taking Server_Session
   --  cannot be called with a client session, so ~50 "Role = Role_Server"
   --  preconditions become UNSTATEABLE rather than merely satisfied.
   --  Existing "S : SPARKTLS.Session;" keeps compiling via the default.
   --  16 KB instance of the reassembly ADT (#90): post-handshake
   --  messages (KeyUpdate, NewSessionTicket) are handshake-framed and
   --  never exceed one record's plaintext in this design. Same proven
   --  body as the 128 KB handshake instance; the Len/Need relation the
   --  loose fields used to thread is structural here.
   package Post_HS_Reasm renames SPARKTLS_Post_HS_Reasm;

   type Session (Role : TLS_Role := Role_Client) is private;

   subtype Client_Session is Session (Role_Client);
   subtype Server_Session is Session (Role_Server);

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

   --  True when this session's WRITE direction has reached the RFC 8446 s5.5
   --  AEAD usage limit and no more records may be encrypted under the current
   --  key.
   --
   --  TLS 1.3 rotates automatically at Rekey_After_Records, so this is
   --  normally False there and only becomes True if rotation could not happen.
   --  TLS 1.2 has no KeyUpdate and renegotiation is deprecated, so there is no
   --  way to continue safely: the application MUST close the connection.
   --  Write_Plaintext will write 0 bytes once this is True, which is otherwise
   --  indistinguishable from ordinary output-buffer backpressure.
   --
   --  DELIBERATELY NOT Ghost. This is exactly Write_Plaintext's nonce-space
   --  precondition, which until 2026-08-20 was stated via Client_App /
   --  Client_Seq_12 -- both Ghost, hence unevaluable by the caller. A
   --  precondition the caller cannot check is unenforceable, and that only
   --  became reachable when the TLS 1.2 bound dropped from 2**64 to 2**23.
   function Write_Limit_Reached (S : Session) return Boolean;

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

   --  RFC 8446 Â§6.1: True only if the peer sent close_notify.
   --
   --  Check this when YOUR transport reports EOF. The library performs no
   --  I/O, so it cannot see the connection close; you can, and only the
   --  two facts together mean anything:
   --
   --      transport closed  AND NOT Peer_Closed_Cleanly (S)
   --          =>  the byte stream may have been TRUNCATED
   --
   --  close_notify exists precisely so that truncation is detectable. An
   --  attacker able to close the TCP connection can otherwise cut the
   --  plaintext at a point of their choosing, and the receiver cannot tell
   --  that from the peer having finished. Do not treat received data as
   --  complete unless this is True.
   --
   --  Most applications running HTTP over TLS are already protected by
   --  Content-Length or chunked framing, which catches truncation a layer
   --  up. Raw TLS streams without their own length framing are the case
   --  that needs this.
   --
   --  This is a QUERY, not a command -- contrast Client.Close_Notify /
   --  Server.Close_Notify, which SEND our own close_notify.
   function Peer_Closed_Cleanly (S : Session) return Boolean;
   function Negotiated_Suite (S : Session) return Unsigned_16;
   --  Enum view for contracts (#118); the Unsigned_16 forms above stay
   --  for API compatibility and return the wire code point.
   function Suite (S : Session) return Supported_Suite;
   function Negotiated_Suite_12 (S : Session) return Unsigned_16;

   function Client_App (S : Session) return Traffic_Keys
   with Ghost;
   function Server_App (S : Session) return Traffic_Keys
   with Ghost;
   function Input (S : Session) return IO_Buffer
   with Ghost;
   function Output (S : Session) return IO_Buffer
   with Ghost;
   function Client_Seq_12 (S : Session) return Unsigned_64
   with Ghost;
   function Server_Seq_12 (S : Session) return Unsigned_64
   with Ghost;
   function Res_Master (S : Session) return Bytes_48
   with Ghost;
   function Exporter_Secret (S : Session) return Bytes_48
   with Ghost;
   function App_Data_Len (S : Session) return N32
   with Ghost;

   --  Ghost: True when the session currently owns a handshake context.
   --
   --  Exists so Set_State can frame the handshake-context pointer. Two
   --  constraints force this shape. The visible part cannot name S.HC_Ptr,
   --  since Session is private; and "S.HC_Ptr = S.HC_Ptr'Old" would be
   --  illegal anyway, because 'Old on an owning access type is a move.
   --  Reducing the pointer to its null-ness sidesteps both: the prefix of
   --  'Old becomes a Boolean, and null-ness is exactly what SPARK's
   --  memory-leak check consumes when deciding whether an assignment
   --  overwrites a live pointer.
   function Has_Context (S : Session) return Boolean
   with Ghost;


   --  RFC 7301 Â§3.1/Â§3.2: validate the server's ALPN-echo body in a
   --  SH or EE extension and (on success) copy the chosen protocol
   --  name into S.Negotiated_ALPN. Body shape:
   --     list_len(2) + proto_len(1) + proto_name(proto_len)
   --
   --  Body_Start is the index of the list_len byte in Data; E_Len is
   --  the declared extension body length. Caller must guarantee
   --  Body_Start + E_Len <= Data'Last + 1.
   --
   --  On failure:
   --    Decode_Error      â body too short, empty proto, list/body
   --                        length mismatch
   --    Illegal_Parameter â chosen proto doesn't match the one we
   --                        offered in CH (RFC 7301 Â§3.2)
   procedure Validate_ALPN_Echo_Body
     (Data       : in Byte_Seq;
      Body_Start : in N32;
      E_Len      : in N32;
      HC         : in Handshake_Context;
      ALPN       : in out Hostname_Buf;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre =>
       Data'Length > 0
       and then Data'Last < N32'Last
       and then Body_Start >= Data'First
       and then Body_Start <= Data'Last + 1
       and then E_Len <= Data'Last + 1 - Body_Start;

   ----------------------------------------------------------------------------
   --  Buffer operations (transport layer interface)
   ----------------------------------------------------------------------------

   --  Transition to a new state. All state changes should go through this
   --  procedure so callers retain the frame facts below.
   procedure Set_State (S : in out Session; To : Connection_State)
   with
     Post =>
       State (S)
       = To
         --  Frame: Set_State only mutates State (S). Pin the
         --  unchanged fields so callers don't have to
         --  re-establish Pre's like Nonce_Space_Available
         --  (Server_App (S)) across the call.
       and Role (S) = Role (S)'Old
       and Has_Context (S) = Has_Context (S)'Old
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
   --  RFC 8446 Â§5.1: the record layer accepts bytes from the transport.
   --  State is not modified by feeding data.
   procedure Feed_Ciphertext (S : in out Session; Data : in Byte_Seq; Bytes_Fed : out N32)
   with
     Pre => Data'First = 0 and Data'Last < N32'Last,
     Post =>
       Bytes_Fed <= N32 (Data'Length)
       and State (S) = State (S)'Old;         --  feeding doesn't change state

   --  Pull ciphertext bytes from the session's output buffer to send.
   --  State is not modified by draining data.
   procedure Drain_Ciphertext (S : in out Session; Dest : out Byte_Seq; Bytes_Drained : out N32)
   with
     Pre => Dest'First = 0 and Dest'Last < N32'Last,
     Relaxed_Initialization => Dest,
     Post =>
       Bytes_Drained <= N32 (Dest'Length)
       and State (S) = State (S)'Old
       and (for all I in 0 .. Bytes_Drained - 1 => Dest (I)'Initialized);

   --  How many bytes are waiting to be sent?
   function Output_Pending (S : Session) return N32;

   ----------------------------------------------------------------------------
   --  Session-scoped ghost predicates (added 2026-05-09 alongside
   --  the alert-handling / DoS-bound fixes). Each pins an RFC
   --  clause so a regression that re-introduces the unbounded
   --  behavior is caught at proof time.
   ----------------------------------------------------------------------------

   --  RFC 8446 Â§6.1 / Â§6: warning-alert flood cap. Holds whenever
   --  the receiver is still in a non-error state â once we exceed
   --  Max_Warning_Alerts (4) we MUST transition to Error_State.
   function Warning_Alerts_Bounded_RFC_8446_6_1 (S : Session) return Boolean
   with Ghost;

   --  RFC 8446 Â§5.2 / RFC 5246 Â§6.2.1: empty-record flood cap.
   --  Same shape: â¤ 32 in the live state, > 32 only if we've
   --  already transitioned to Error_State with the alert queued.
   function Empty_Records_Bounded_RFC_8446_5_2 (S : Session) return Boolean
   with Ghost;

   --  RFC 8446 Â§5.2 / RFC 5246 Â§7.2: AEAD verification failure
   --  MUST queue a fatal bad_record_mac alert and enter Error_State.
   --  The previous behaviour returned Error_Alert without queuing,
   --  so peers saw TCP RST and couldn't tell what went wrong.
   function AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S : Session) return Boolean
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
   with
     Post =>
       Client_App (S).Key = Bytes_32'(others => 0)
       and Server_App (S).Key = Bytes_32'(others => 0)
       and Client_App (S).IV = Bytes_12'(others => 0)
       and Server_App (S).IV = Bytes_12'(others => 0)
       and Res_Master (S) = Bytes_48'(others => 0)
       and Exporter_Secret (S) = Bytes_48'(others => 0);

   --  RFC 5705 / RFC 8446 Â§7.5: derive application-specific exporter
   --  bytes from a completed TLS session. Label is an ASCII exporter label.
   --  TLS 1.2 permits an empty label; TLS 1.3 requires a non-empty label
   --  because it is embedded in an HKDF label. For TLS 1.2,
   --  Use_Context controls whether the RFC
   --  5705 context length prefix is included. For TLS 1.3 the context is
   --  always hashed as part of RFC 8446 exporter derivation.
   procedure Export_Keying_Material
     (S           : in Session;
      Label       : in String;
      Context     : in Byte_Seq;
      Use_Context : in Boolean;
      Output      : out Byte_Seq;
      OK          : out Boolean)
   with
     Pre =>
       Output'First = 0
       and Output'Length > 0
       and Output'Length <= 1024
       and Label'Length <= 64
       and Context'Length <= 62
       and (if Context'Length > 0 then Context'First = 0)
       and Context'Last < N32'Last - 256,
     Relaxed_Initialization => Output,
     Post => (for all I in Output'Range => Output (I)'Initialized);

   --  Read decrypted application data.
   procedure Read_Plaintext (S : in out Session; Dest : out Byte_Seq; Bytes_Read : out N32)
   with
     Pre => Dest'First = 0 and Dest'Last < N32'Last and App_Data_Len (S) <= Max_Record_Plaintext,
     Relaxed_Initialization => Dest,
     Post =>
       Bytes_Read <= N32 (Dest'Length)
       and (for all I in 0 .. Bytes_Read - 1 => Dest (I)'Initialized);

   --  RFC 8446 Â§7.5: Encrypt and queue application data.
   --  RFC 8446 Â§4.6.3: rotate our own write key now.
   --
   --  Queues a KeyUpdate (request_update = update_not_requested -- we are
   --  not asking the peer to rotate, only telling them we have), then
   --  advances our write traffic secret and resets the write sequence to
   --  zero. Drain the output afterwards as usual.
   --
   --  The library already rotates automatically as it approaches the RFC
   --  8446 Â§5.5 AEAD usage limit (see Rekey_After_Records), so calling this
   --  is never required for safety. It exists because an application may
   --  have its own policy -- rekey hourly, or per N bytes, or on a
   --  privilege change -- and because rekeying more often narrows the
   --  window a compromised key exposes.
   --
   --  Note this rotates OUR write direction only; a KeyUpdate never
   --  rotates the peer's. There is deliberately no way to demand that the
   --  peer rotate: request_update exists in the protocol but invites a
   --  ping-pong, and a peer under our control can be asked out of band.
   --
   --  TLS 1.3 only. A TLS 1.2 session has no rekey mechanism and this is a
   --  no-op there.
   procedure Request_Key_Update (S : in out Session)
   with Pre => State (S) = Connected;

   procedure Write_Plaintext (S : in out Session; Plaintext : in Byte_Seq; Bytes_Written : out N32)
   with
     Pre =>
       State (S) = Connected
       and In_App_Key_Phase (State (S))
       and Plaintext'First = 0
       and Plaintext'Length > 0
       and Plaintext'Last < N32'Last
       and not Write_Limit_Reached (S),
     Post => Bytes_Written <= N32 (Plaintext'Length);

private

   --  Completions of the query functions and ghost predicates declared
   --  above. Bodies are verbatim -- this is a relocation, not a rewrite.
   --  The visible part of a package cannot name its own private
   --  components, but the private part can, and GNATprove reads
   --  expression-function completions here exactly as it did before.

   type Session (Role : TLS_Role := Role_Client) is record
      --  State
      State      : Connection_State := Idle;
      Last_Error : Error_Code := No_Error;

      --  I/O buffers
      Input  : IO_Buffer;
      Output : IO_Buffer;

      --  Application traffic keys (set during handshake, used after)
      Client_App : Traffic_Keys;
      Server_App : Traffic_Keys;

      --  Decrypted application data staging area
      App_Data     : Byte_Seq (0 .. Max_Record_Plaintext - 1) := (others => 0);
      App_Data_Len : Plaintext_Length := 0;

      --  Negotiated cipher suite (wire value from ServerHello)
      Negotiated_Suite    : Supported_Suite := Suite_None;  --  TLS 1.3
      Negotiated_Suite_12 : Supported_Suite := Suite_None;  --  TLS 1.2

      --  Peer certificate valid (copied from HC before free)
      Peer_Cert_Valid : Boolean := False;

      --  RFC 7627 Extended Master Secret negotiated for this TLS 1.2
      --  session (copied from HC before free, same as Peer_Cert_Valid).
      --  Always False for TLS 1.3, which binds the transcript inherently
      --  and has no EMS extension. Mirrored purely so the negotiated
      --  outcome outlives the handshake context; read via
      --  SPARKTLS.Test_Support, not by consumers.
      Use_EMS : Boolean := False;

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
      --  at stateâConnected so callers who want to know "did we
      --  resume?" need a Session-level mirror.
      Resumed_From_PSK : Boolean := False;

      --  Resumption master secret (copied from HC before free,
      --  needed to derive PSK when NewSessionTicket arrives post-handshake)
      Res_Master     : Bytes_48 := (others => 0);
      Res_Master_Len : N32 range 0 .. 48 := 0;  --  32 or 48

      --  Session-level wall clock mirror. Client TLS 1.3 tickets arrive
      --  post-handshake, after HC is freed, and later resumption attempts
      --  need the same configured clock to serialize obfuscated_ticket_age.
      Get_Time : Get_Time_Fn := null;

      --  RFC 5705 / RFC 8446 Â§7.5 exporter material retained after
      --  the handshake context is freed. TLS 1.2 stores master_secret
      --  plus randoms; TLS 1.3 stores exporter_master_secret.
      Exporter_Secret        : Bytes_48 := (others => 0);
      Exporter_Secret_Len    : N32 range 0 .. 48 := 0;  --  32 or 48; 0 means unavailable
      Exporter_Client_Random : Bytes_32 := (others => 0);
      Exporter_Server_Random : Bytes_32 := (others => 0);

      --  RFC 8446 Â§4.6.3 KeyUpdate: the application traffic SECRETS are
      --  retained, not just the derived key/IV, because the next generation
      --  is derived from the current secret:
      --
      --    application_traffic_secret_N+1 =
      --      HKDF-Expand-Label (secret_N, "traffic upd", "", Hash.length)
      --
      --  The key and IV alone are a dead end -- they are outputs of the
      --  secret, and the KDF is one-way. These survive the handshake
      --  context being freed, which is why they live on Session rather
      --  than Handshake_Context.
      --
      --  TLS 1.3 only. TLS 1.2 has no rekey mechanism; a TLS 1.2 connection
      --  that exhausts its sequence space must be closed.
      Client_App_Secret : Bytes_48 := (others => 0);
      Server_App_Secret : Bytes_48 := (others => 0);
      App_Secret_Len    : N32 range 0 .. 48 := 0;  --  0 = none, else 32 (SHA-256)/48 (384)

      --  RFC 8446 Â§4.6.3 does not bound how often a peer may request a
      --  rekey, and each one costs a KDF plus key re-derivation. Counted
      --  so a peer cannot use KeyUpdate as a cheap asymmetric DoS, in the
      --  same shape as the warning-alert and empty-record flood caps.
      Key_Updates_Recvd : Natural := 0;

      --  RFC 8446 Â§4.6.3: a peer's request_update obliges us to send a
      --  KeyUpdate "prior to sending its next Application Data record" --
      --  the obligation is tied to the next application WRITE, not to each
      --  message received. Five requests arriving back-to-back therefore
      --  warrant ONE response, not five. Responding immediately per
      --  message makes every reply after the first look unsolicited to the
      --  peer (BoGo KeyUpdate-Requested, with RejectUnsolicitedKeyUpdate).
      --  So the reply is deferred: set here, flushed by Write_Plaintext.
      Key_Update_Pending : Boolean := False;

      --  RFC 8446 Â§6.1: set when the peer's close_notify has been
      --  received. Exposed via Peer_Closed_Cleanly so an application can
      --  tell an orderly close from a truncated stream -- see there for
      --  why that distinction is a security property.
      Peer_Closed_Cleanly : Boolean := False;

      --  True on first Advance in Connected state (to deliver Handshake_Done)
      Handshake_Just_Done : Boolean := False;

      --  TLS 1.3 post-handshake handshake-message reassembly. Servers may
      --  fragment NewSessionTicket across encrypted application_data records.
      Post_HS : Post_HS_Reasm.Buffer;

      --  Counter for received warning-level user_canceled alerts.
      --  RFC 8446 Â§6.1: TLS 1.3 deprecates warning alerts but keeps
      --  user_canceled (90) for compatibility with TLS 1.2 stacks
      --  (notably JDK11). BoringSSL/NSS/OpenSSL convention is to
      --  tolerate up to 4 in a row; 5+ â fatal "too_many_warning_alerts"
      --  to limit DoS via alert-flooding. Resets on application data.
      --  Bounded BY CONSTRUCTION: every site checks the cap BEFORE
      --  incrementing, so the increment only runs when the counter is
      --  strictly below it. That is what makes this subtype provable --
      --  narrowing alone would just move the obligation onto the '+ 1'.
      Warning_Alerts_Recvd : Natural range 0 .. Max_Warning_Alerts := 0;

      --  Counter for received empty (zero-length plaintext) records.
      --  RFC 8446 Â§5.2 / RFC 5246 Â§6.2.1: zero-length-plaintext
      --  records waste decrypt CPU without delivering progress.
      --  BoringSSL caps at 32; 33+ â fatal too_many_empty_fragments.
      --  Resets on any non-empty record.
      --  Same construction as Warning_Alerts_Recvd above.
      Empty_Records_Recvd : Natural range 0 .. Max_Empty_Records := 0;

      --  TLS 1.2: GCM implicit nonces and sequence numbers
      --  (persist past handshake for Connected-state encrypt/decrypt)
      Negotiated_Version : TLS_Version := TLS_1_3;
      Negotiated_ALPN    : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Client_IV_12       : Byte_Seq (0 .. 11) := (others => 0);
      Server_IV_12       : Byte_Seq (0 .. 11) := (others => 0);
      --  Record_Counter, not Unsigned_64: the "< Unsigned_64'Last" bound
      --  belongs to the FIELD, not to the Session. As a subtype it is
      --  checked once at assignment; as a Session predicate conjunct it
      --  had to be re-proved at every component assignment anywhere in
      --  the record, and at every call boundary.

      --  Handshake control-plane, inline (#106). Data-plane lives in
      --  SPARKTLS.HS_Pool at index Slot (No_Slot when no handshake is
      --  in flight -- admission control refuses when the pool is full).
      HC   : Handshake_Context;
      Slot : Slot_Count := No_Slot;
   end record;
   --  NO Type_Invariant on Session, MEASURED (r69, 2026-08-29): the
   --  state<->phase coupling as an invariant cost ~101 checks -- the
   --  invariant is verified at every INTERNAL call to any public
   --  subprogram (State, Output_Pending, ... are called everywhere),
   --  not just at true boundaries. The coupling lives instead as
   --  one-conjunct `S.HC.Phase = Engaged` Pres on the handler chain,
   --  rooted in Advance_Handshake's state-conditional Pre with a single
   --  honest residual at the public Advance boundary.

   --  NO Dynamic_Predicate on Session. Deliberately.
   --
   --  WHAT WOULD LIVE HERE AND WHY NOTHING DOES.
   --
   --  A Dynamic_Predicate is re-checked on EVERY assignment to ANY component
   --  of the record, and at every call boundary that passes a Session. So a
   --  conjunct constraining a single field costs a proof obligation at every
   --  unrelated write elsewhere in the record. A subtype on that field costs
   --  one range check at the assignment that actually touches it.
   --
   --  Single-field bounds therefore belong on the FIELD's subtype. Moved out
   --  2026-08-18, when they were 78% of all owned proof findings (159
   --  VC_PREDICATE_CHECK across the four largest units):
   --    Client_App.Counter / Server_App.Counter  -> Record_Counter
   --    Client_Seq_12 / Server_Seq_12            -> Record_Counter
   --    App_Data_Len, Post_HS_Len, Post_HS_Need  -> Plaintext_Length
   --
   --  That left ONE conjunct, the post-handshake reassembly relation
   --  (Post_HS_Need = 0 -> Post_HS_Len = 0, else Need >= 4 and Len <= Need).
   --  Removed 2026-08-22: it was a genuine two-field relationship, but as the
   --  sole survivor it made every Session write and every call boundary pay a
   --  predicate check to carry one fact about two fields -- and it was still
   --  unproved. Session is passed to nearly every subprogram in the library,
   --  and 13 of the 18 "precondition might fail" findings in server.adb were
   --  Send_Alert_And_Error (S, ...) calls whose own Pre is a single state
   --  test; the cost was this predicate riding along.
   --
   --  The individual bounds survive on Plaintext_Length. What is NOT
   --  reinstated here is Len <= Need: see #90, which makes it STRUCTURAL by
   --  moving the buffer and its accounting into the reassembly ADT, the same
   --  way round 30 did for handshake reassembly. Until then, any site that
   --  genuinely depends on the relation must show it as an honest AoRTE
   --  check rather than inherit it from a predicate nothing could prove.
   --
   --  NOTE: the output-buffer compaction invariant deliberately lives on
   --  IO_Buffer's own predicate, not here -- see the comment there.

   --  Query function completions: one field each, verbatim.

   function State (S : Session) return Connection_State
   is (S.State);

   --  On the CHANNEL counter since the sealed-channel carve: the TLS 1.3
   --  arithmetic backstop, plus the TLS 1.2 crypto cap. The cap disjunct
   --  is now VERSION-GATED where it used to apply to both: the counter is
   --  shared with TLS 1.3, where sitting at 2**23 is the normal
   --  about-to-rotate state, not a terminal condition.
   function Write_Limit_Reached (S : Session) return Boolean
   is (S.Negotiated_Version = TLS_1_2
       and then (if S.Role = Role_Client then Write_Budget_Reached (S.Client_App)
                 else Write_Budget_Reached (S.Server_App)));
   function Role (S : Session) return TLS_Role
   is (S.Role);
   function Last_Error (S : Session) return Error_Code
   is (S.Last_Error);
   function Peer_Closed_Cleanly (S : Session) return Boolean
   is (S.Peer_Closed_Cleanly);
   function Negotiated_Suite (S : Session) return Unsigned_16
   is (Wire_Of (S.Negotiated_Suite));
   function Suite (S : Session) return Supported_Suite
   is (S.Negotiated_Suite);
   function Negotiated_Suite_12 (S : Session) return Unsigned_16
   is (Wire_Of (S.Negotiated_Suite_12));
   function Client_App (S : Session) return Traffic_Keys
   is (S.Client_App);
   function Server_App (S : Session) return Traffic_Keys
   is (S.Server_App);
   function Input (S : Session) return IO_Buffer
   is (S.Input);
   function Output (S : Session) return IO_Buffer
   is (S.Output);
   function Client_Seq_12 (S : Session) return Unsigned_64
   is (S.Client_App.Counter);
   function Server_Seq_12 (S : Session) return Unsigned_64
   is (S.Server_App.Counter);
   function Res_Master (S : Session) return Bytes_48
   is (S.Res_Master);
   function Exporter_Secret (S : Session) return Bytes_48
   is (S.Exporter_Secret);
   function App_Data_Len (S : Session) return N32
   is (S.App_Data_Len);
   function Has_Context (S : Session) return Boolean
   is (S.Slot /= No_Slot);

   function Output_Pending (S : Session) return N32
   is (Available (S.Output));

   function Warning_Alerts_Bounded_RFC_8446_6_1 (S : Session) return Boolean
   is (S.Warning_Alerts_Recvd <= Max_Warning_Alerts or else S.State = Error_State);

   function Empty_Records_Bounded_RFC_8446_5_2 (S : Session) return Boolean
   is (S.Empty_Records_Recvd <= Max_Empty_Records or else S.State = Error_State);

   function AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S : Session) return Boolean
   is (S.State = Error_State
       and then S.Last_Error = Bad_Record_MAC
       and then Output_Pending (S) > 0);

   function Input_Available (S : Session) return N32
   is (Available (S.Input));

   function Has_Plaintext (S : Session) return Boolean
   is (S.App_Data_Len > 0);

   function Get_Version (S : Session) return TLS_Version
   is (S.Negotiated_Version);

   function Get_Cipher_Suite (S : Session) return Unsigned_16
   is (Wire_Of (S.Negotiated_Suite));

   function Get_ALPN (S : Session) return String
   is (S.Negotiated_ALPN.Data (1 .. S.Negotiated_ALPN.Len));

end SPARKTLS;
