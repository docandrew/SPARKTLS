with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with RFLX.RFLX_Builtin_Types;
with X509;

package SPARKTLS with
   SPARK_Mode => On
is
   --================================================================
   --  Constants
   --================================================================

   --  48-byte sequence (for SHA-384 digests/secrets)
   subtype Index_48 is N32 range 0 .. 47;
   subtype Bytes_48 is Byte_Seq (Index_48);

   --  Heap-allocated byte sequence (for reassembly buffers)
   type Byte_Seq_Access is access Byte_Seq;
   procedure Free_Byte_Seq (Ptr : in out Byte_Seq_Access);

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

   subtype Wire_Key_Share_Len is N32 range 1 .. 256;
   --  Single key share entry (max P-384 = 101 bytes)

   --  Handshake message length (3 bytes on wire, max 2^24 - 1).
   --  Bounded to Max_HS_Msg (128 KB) for reassembled messages.
   Max_HS_Msg : constant := 131072;
   subtype HS_Msg_Len is N32 range 0 .. Max_HS_Msg;

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

   --  CH1 extension order tracking (for HRR CH2 validation)
   --  Uses a rolling polynomial hash (fingerprint * 31 xor code).
   --  Reordering extensions changes the hash. No array needed.

   --  RFLX scratch buffer sizes (stack-allocated, no heap)
   RFLX_Main_Size : constant := 17000;  --  Holds largest message (incoming record)

   --================================================================
   --  Cipher suite
   --================================================================

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

   --================================================================
   --  Connection state
   --
   --  The handshake proceeds through these states in order.
   --  Client and server share the same enum; unused states for
   --  a given role are simply never entered.
   --================================================================

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

   --================================================================
   --  Protocol requirements as ghost functions (RFC 8446)
   --
   --  These are formally verified by SPARK — the prover checks that
   --  the implementation never violates these properties.
   --================================================================

   --  RFC 8446 §5: CCS is only valid during the handshake.
   --  CCS after server Finished MUST be rejected.
   function CCS_Allowed (State : Connection_State) return Boolean is
     (State not in Connected | Closing | Closed | Error_State | Idle)
   with Ghost;

   --  RFC 8446 §5.1: Handshake is complete.
   function Handshake_Complete (State : Connection_State) return Boolean is
     (State in Connected | Closing | Closed)
   with Ghost;

   --  RFC 8446 §4.1: Valid state transitions.
   --  The handshake state machine may only transition along defined paths.
   --  Error_State is reachable from any non-terminal state.
   function Valid_Transition (From, To : Connection_State) return Boolean is
     (case From is
        when Idle =>
           To in Wait_Client_Hello | Client_Hello_Sent,
        when Client_Hello_Sent =>
           To in Wait_Server_Hello | Error_State,
        when Wait_Server_Hello =>
           To in Wait_Encrypted_Extensions | Error_State,
        when Wait_Encrypted_Extensions =>
           To in Wait_Certificate_Request | Wait_Certificate | Error_State,
        when Wait_Certificate_Request =>
           To in Wait_Certificate | Error_State,
        when Wait_Certificate =>
           To in Wait_Certificate_Verify | Error_State,
        when Wait_Certificate_Verify =>
           To in Wait_Server_Finished | Error_State,
        when Wait_Server_Finished =>
           To in Client_Certificate_Sent | Client_Finished_Sent | Error_State,
        when Client_Certificate_Sent =>
           To in Client_Cert_Verify_Sent | Error_State,
        when Client_Cert_Verify_Sent =>
           To in Client_Finished_Sent | Error_State,
        when Client_Finished_Sent =>
           To in Connected | Error_State,
        when Wait_Client_Hello =>
           To in Server_Hello_Sent | Wait_Client_Hello_Retry | Error_State,
        when Wait_Client_Hello_Retry =>
           To in Server_Hello_Sent | Error_State,
        when Server_Hello_Sent =>
           To in Wait_Client_Certificate | Wait_Client_Finished | Error_State,
        when Sent_Certificate_Request =>
           To in Wait_Client_Certificate | Error_State,
        when Wait_Client_Certificate =>
           To in Wait_Client_Cert_Verify | Wait_Client_Finished | Error_State,
        when Wait_Client_Cert_Verify =>
           To in Wait_Client_Finished | Error_State,
        when Wait_Client_Finished =>
           To in Connected | Error_State,
        when Connected =>
           To in Closing | Error_State | Closed,
        when Closing =>
           To in Closed,
        when Closed =>
           False,
        when Error_State =>
           To = Closed)
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

   --================================================================
   --  Action result - tells the caller what to do next
   --================================================================

   type Action is
     (OK,             --  Progress made, call Advance again
      Need_Input,     --  Feed more bytes from the transport
      Has_Output,     --  Drain output and send over transport
      Plaintext_Ready, --  Decrypted app data available
      Handshake_Done, --  Handshake complete, now Connected
      Shutdown,       --  Clean close complete
      Error_Alert);   --  Fatal error, see Last_Error

   --================================================================
   --  Error codes
   --================================================================

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
      Internal_Error,
      Insufficient_Buffer,
      Unsupported_Cipher_Suite);

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

   --  RFC 8446 §6.2: Alert description MUST match the error condition.
   function Expected_Alert_Desc (E : Error_Code) return Byte is
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
         when Certificate_Required     => 116,
         when Internal_Error
            | Insufficient_Buffer
            | No_Error                 => 80,
         when Unsupported_Cipher_Suite => 40)
   with Ghost;

   --================================================================
   --  I/O Buffer
   --
   --  Linear buffer with read/write cursors. The caller fills it
   --  via Feed_Ciphertext and drains it via Drain_Ciphertext. Compacted
   --  when the read cursor advances past the midpoint.
   --
   --  This is the BIO equivalent: the TLS engine never touches
   --  sockets, files, or any OS resource. It only reads from
   --  and writes to these buffers.
   --================================================================

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

   --================================================================
   --  Hostname storage (for SNI)
   --================================================================

   type Hostname_Buf is record
      Data : String (1 .. Max_Hostname_Len) := (others => ASCII.NUL);
      Len  : Natural := 0;
   end record
     with Predicate => Hostname_Buf.Len <= Max_Hostname_Len;

   --================================================================
   --  Traffic keys for one direction (key + IV + nonce counter)
   --================================================================

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

   --================================================================
   --  Random byte generation callback
   --
   --  The caller must supply a CSPRNG. This is the only callback;
   --  everything else is buffer-based.
   --================================================================

   type Random_Bytes_Fn is access
      procedure (Output : out Byte_Seq);

   --  Time callback for certificate validation.
   --  Called at validation time, not at configuration time.
   type Get_Time_Fn is access
      function return X509.Date_Time;

   --================================================================
   --  Certificate pool types
   --
   --  Used by Trust_Store, Identity, and Validate_Chain.
   --  Each pool entry holds a parsed cert and its own DER buffer
   --  starting at index 0 (required by X509 span offsets).
   --================================================================

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

   --================================================================
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
   --================================================================

   Max_Root_Pool_Size : constant := 200;
   type Root_Pool is array (0 .. Max_Root_Pool_Size - 1) of Pool_Entry;

   type Trust_Store is record
      Roots      : Root_Pool;
      Root_Count : Natural := 0;
   end record;

   type Trust_Store_Access is access constant Trust_Store;

   --================================================================
   --  Identity
   --
   --  Local certificate chain and signing key.  The signing algorithm
   --  is inferred from the leaf certificate's public key algorithm.
   --  Required for servers; optional for clients (mTLS only).
   --  Allocated once, shared across sessions via Identity_Access.
   --================================================================

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

   --================================================================
   --  Ticket Store (for session resumption)
   --  Defined here so Config can reference it. Implementation in
   --  SPARKTLS.Ticket_Cache child package.
   --================================================================

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
   end record;

   type Ticket_Array is array (Natural range 0 .. Max_Cached_Tickets - 1)
      of Ticket_Entry;

   type Ticket_Store is record
      Entries : Ticket_Array;
      Next    : Natural := 0;
   end record;

   type Ticket_Store_Access is access all Ticket_Store;

   --================================================================
   --  Validation modes (used by Config and Cert_Verify)
   --================================================================

   --  Mode_RFC5280: RFC 5280 rules only.
   --  Mode_WebPKI: RFC 5280 + CA/Browser Forum Baseline Requirements.
   type Validation_Mode is (Mode_RFC5280, Mode_WebPKI);

   --  Validation purpose (controls EKU requirements on the leaf)
   type Validation_Purpose is (Purpose_Server, Purpose_Client, Purpose_Any);

   --================================================================
   --  Configuration (set once before Init)
   --================================================================

   type Config is record
      Suite        : Cipher_Suite    := TLS_CHACHA20_POLY1305_SHA256;
      Random       : Random_Bytes_Fn := null;
      Server_Name  : Hostname_Buf;
      Skip_Verify  : Boolean         := False;  --  accept any cert
      Versions     : Version_Policy  := Allow_Both;  --  TLS version control

      --  Validation settings
      Verify_Mode     : Validation_Mode := Mode_WebPKI;
      Verify_Purpose  : Validation_Purpose := Purpose_Server;
      Get_Time : Get_Time_Fn := null;

      --  Trust store for verifying the peer's certificate chain.
      --  Required for client (unless Skip_Verify).
      --  Optional for server (only needed for mTLS).
      Trust : Trust_Store_Access := null;

      --  Local identity (certificate + signing key).
      --  Required for server.  Optional for client (mTLS only).
      Local : Identity_Access := null;

      --  ALPN: Application-Layer Protocol Negotiation (RFC 7301).
      --  Set to e.g. "h2" for HTTP/2 or "http/1.1" for HTTP/1.1.
      --  Empty (Len=0) means no ALPN extension is sent.
      ALPN : Hostname_Buf := (Len => 0, Data => (others => ' '));

      --  Server: request a client certificate (mTLS). When True the
      --  server sends a CertificateRequest in the handshake.
      Request_Client_Cert : Boolean := False;

      --  Server: also REQUIRE that the client present a valid cert.
      --  Only meaningful when Request_Client_Cert is True. When True
      --  and the client sends an empty Certificate or one that fails
      --  to parse / validate, the server aborts the handshake with
      --  certificate_required (TLS 1.3) or handshake_failure (TLS 1.2).
      --  When False (default) the server falls back to anonymous
      --  authentication if the client doesn't present a cert — the
      --  classic OpenSSL SSL_VERIFY_PEER vs
      --  SSL_VERIFY_FAIL_IF_NO_PEER_CERT distinction.
      Require_Client_Cert : Boolean := False;

      --  Server: ticket cache for session resumption.
      --  If non-null, server sends NewSessionTicket after handshake.
      Ticket_Store : Ticket_Store_Access := null;
   end record;

   --================================================================
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
   --================================================================

   --================================================================
   --  Handshake Context
   --
   --  Contains all state needed only during the TLS handshake.
   --  Heap-allocated at Init, freed when handshake completes.
   --  Handshake procedures receive this as `in out` — they never
   --  see the pointer, only the record.
   --================================================================

   type Handshake_Context is record
      --  Protocol version (set during Parse_Client_Hello / Parse_Server_Hello)
      Version : TLS_Version := TLS_1_3;

      --  Configuration (callbacks, trust store, identity)
      Cfg : Config;

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
      --  Which groups did the client offer in supported_groups?
      --  (may not have key_share data — triggers HRR if preferred)
      Client_Supports_X25519 : Boolean := False;
      Client_Supports_P256   : Boolean := False;
      Client_Supports_P384   : Boolean := False;
      Selected_Group    : Unsigned_16 := 0;
      --  HelloRetryRequest state
      HRR_Sent          : Boolean := False;
      --  RFC 8446 §4.1.2: CH extension order fingerprint.
      --  Rolling polynomial hash of extension type codes in order.
      --  CH2 must produce the same hash as CH1 (modulo cookie).
      CH_Ext_Hash       : Unsigned_32 := 0;
      CH_Ext_Count      : Natural := 0;

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

      --  Signature algorithm negotiation
      Peer_Sig_Algos      : Sig_Algo_List := (others => 0);
      Peer_Sig_Algo_Count : Natural := 0;
      Negotiated_Sig_Algo : Unsigned_16 := 0;

      --  Handshake tracking
      CCS_Received          : Boolean := False;
      Cert_Request_Received : Boolean := False;

      --  Version negotiation (set during Parse_Client_Hello)
      --  True if the client's supported_versions extension contains 0x0304.
      --  If False, we negotiate TLS 1.2 (if legacy_version = 0x0303).
      Has_TLS_1_3 : Boolean := False;

      --  TLS 1.2: ClientKeyExchange already received
      CKE_Received_12 : Boolean := False;

      --  TLS 1.2: Extended Master Secret (RFC 7627) negotiated
      Use_EMS : Boolean := False;

      --  Client's offered ALPN protocol (parsed from ClientHello)
      Client_ALPN : Hostname_Buf := (Len => 0, Data => (others => ' '));

      --  TLS 1.2 key material (set during Derive_Keys_12)
      Master_Secret_12   : Bytes_48 := (others => 0);
      Client_Write_IV_12 : Byte_Seq (0 .. 3) := (others => 0);
      Server_Write_IV_12 : Byte_Seq (0 .. 3) := (others => 0);
      Client_Seq_12      : Unsigned_64 := 0;
      Server_Seq_12      : Unsigned_64 := 0;

      --  Resumption
      Using_PSK     : Boolean := False;
      PSK_Offered   : Boolean := False;
      PSK_Ticket_ID : Ticket_ID := (others => 0);
      PSK_Value     : Bytes_48 := (others => 0);  --  zeros if no PSK
      PSK_Value_Len : N32 := 0;                   --  0 = no PSK
      PSK_Binder    : Bytes_48 := (others => 0);  --  received binder
      PSK_Binder_Len : N32 := 0;
      PSK_Binders_Offset : N32 := 0;              --  offset of binders in ClientHello

      --  Handshake message reassembly (multi-record handshake messages).
      --  When a handshake record fragment contains only part of a
      --  handshake message (declared length > fragment), accumulate
      --  fragments here until the full message is available.
      Reasm_Buf  : Byte_Seq_Access := null;
      Reasm_Len  : N32 := 0;   --  bytes accumulated so far
      Reasm_Need : N32 := 0;   --  total bytes needed (type+length+body)

      --  Heap budget: total bytes allocated for extensions/reassembly.
      --  Prevents DoS via large extensions in ClientHello/ServerHello.
      Heap_Used : N32 := 0;

      --  RFLX scratch buffer
      RFLX_Main : aliased RFLX.RFLX_Builtin_Types.Bytes
                    (1 .. RFLX.RFLX_Builtin_Types.Index (RFLX_Main_Size))
                    := (others => 0);
   end record;

   Max_Handshake_Heap : constant := 262_144;  --  256 KB per handshake

   function Heap_Budget_OK
     (HC : Handshake_Context; Size : N32) return Boolean
   is (Size <= Max_Handshake_Heap
       and then HC.Heap_Used <= Max_Handshake_Heap - Size);

   type Handshake_Context_Access is access Handshake_Context;

   --================================================================
   --  Session Ticket (for resumption)
   --================================================================

   Max_Ticket_Len : constant := 256;

   type Session_Ticket is record
      Ticket       : Byte_Seq (0 .. Max_Ticket_Len - 1) := (others => 0);
      Ticket_Len   : N32 := 0;
      Lifetime     : Unsigned_32 := 0;       --  seconds
      Age_Add      : Unsigned_32 := 0;       --  obfuscation value
      PSK          : Bytes_48 := (others => 0);  --  derived PSK
      PSK_Len      : N32 := 0;              --  32 (SHA-256) or 48 (SHA-384)
      Suite        : Unsigned_16 := 0;       --  cipher suite
      Valid        : Boolean := False;
   end record;

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

      --  Resumption: cached session ticket (client side)
      Ticket : Session_Ticket;

      --  Resumption master secret (copied from HC before free,
      --  needed to derive PSK when NewSessionTicket arrives post-handshake)
      Res_Master     : Bytes_48 := (others => 0);
      Res_Master_Len : N32 := 0;  --  32 or 48

      --  True on first Advance in Connected state (to deliver Handshake_Done)
      Handshake_Just_Done : Boolean := False;

      --  TLS 1.2: GCM implicit nonces and sequence numbers
      --  (persist past handshake for Connected-state encrypt/decrypt)
      Negotiated_Version  : TLS_Version := TLS_1_3;
      Negotiated_ALPN     : Hostname_Buf := (Len => 0, Data => (others => ' '));
      Client_IV_12        : Byte_Seq (0 .. 3) := (others => 0);
      Server_IV_12        : Byte_Seq (0 .. 3) := (others => 0);
      Client_Seq_12       : Unsigned_64 := 0;
      Server_Seq_12       : Unsigned_64 := 0;

      --  Handshake context (heap-allocated, freed after handshake)
      HC_Ptr : Handshake_Context_Access := null;
   end record;

   --================================================================
   --  Buffer operations (transport layer interface)
   --================================================================

   --  Transition to a new state. The precondition enforces that only
   --  transitions permitted by the RFC 8446 state machine are allowed.
   --  All state changes MUST go through this procedure — never assign
   --  S.State directly.
   procedure Set_State (S : in out Session; To : Connection_State)
     with Pre  => Valid_Transition (S.State, To),
          Post => S.State = To;

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
                and S.State = S.State'Old;         --  feeding doesn't change state

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
                and S.State = S.State'Old         --  draining doesn't change state
                and (for all I in 0 .. Bytes_Drained - 1 =>
                       Dest (I)'Initialized);

   --  How many bytes are waiting to be sent?
   function Output_Pending (S : Session) return N32 is
      (Available (S.Output));

   --  How many input bytes are buffered?
   function Input_Available (S : Session) return N32 is
      (Available (S.Input));

   --  Is decrypted application data waiting to be read?
   function Has_Plaintext (S : Session) return Boolean is
      (S.App_Data_Len > 0);

   --  Which TLS version was negotiated?
   --  Only meaningful after Handshake_Done.
   function Get_Version (S : Session) return TLS_Version is
      (S.Negotiated_Version);

   --  Which cipher suite was negotiated? (wire value)
   --  Only meaningful after Handshake_Done.
   function Get_Cipher_Suite (S : Session) return Unsigned_16 is
      (S.Negotiated_Suite);

   --  Which ALPN protocol was negotiated?
   --  Empty string if no ALPN or not yet negotiated.
   function Get_ALPN (S : Session) return String is
      (S.Negotiated_ALPN.Data (1 .. S.Negotiated_ALPN.Len));

   --  Zero all key material in a Session.
   --  Call after Close_Notify or on error to prevent key leakage.
   --  Uses volatile writes to prevent compiler from optimizing
   --  the zeroing away.
   procedure Sanitize_Keys (S : in out Session)
   with Post => S.Client_App.Key = Bytes_32'(others => 0)
                and S.Server_App.Key = Bytes_32'(others => 0)
                and S.Client_App.IV = Bytes_12'(others => 0)
                and S.Server_App.IV = Bytes_12'(others => 0)
                and S.Res_Master = Bytes_48'(others => 0);

   --  Read decrypted application data.
   procedure Read_Plaintext
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last
                and S.App_Data_Len <= Max_Record_Plaintext,
        Relaxed_Initialization => Dest,
        Post => Bytes_Read <= N32 (Dest'Length)
                and (for all I in 0 .. Bytes_Read - 1 =>
                       Dest (I)'Initialized);

end SPARKTLS;
