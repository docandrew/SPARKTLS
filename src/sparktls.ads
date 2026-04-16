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

   Max_Record_Plaintext : constant := 16384;  --  RFC 8446 limit
   Max_Record_Overhead  : constant := 256;    --  tag + content type
   Max_Record_Size      : constant :=
      Max_Record_Plaintext + Max_Record_Overhead;

   --  I/O buffer capacity. Large enough for two max-size records
   --  so the caller doesn't have to drain after every record.
   IO_Buffer_Capacity : constant N32 := 2 * Max_Record_Size;

   Transcript_Capacity  : constant N32 := 16384;
   Max_Hostname_Len     : constant := 255;
   Max_Cert_DER_Len     : constant N32 := 8192;

   --  Signature algorithm negotiation
   Max_Sig_Algos : constant := 16;
   subtype Sig_Algo_Index is Natural range 0 .. Max_Sig_Algos - 1;
   type Sig_Algo_List is array (Sig_Algo_Index) of Unsigned_16;

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

   --  TLS cipher suite code values
   Suite_AES_128_GCM_SHA256        : constant Unsigned_16 := 16#1301#;
   Suite_CHACHA20_POLY1305_SHA256  : constant Unsigned_16 := 16#1303#;
   Suite_AES_256_GCM_SHA384        : constant Unsigned_16 := 16#1302#;

   --================================================================
   --  Connection state
   --
   --  The handshake proceeds through these states in order.
   --  Client and server share the same enum; unused states for
   --  a given role are simply never entered.
   --================================================================

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
      Decode_Error,
      Illegal_Parameter,
      Internal_Error,
      Insufficient_Buffer,
      Unsupported_Cipher_Suite);

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
   end record;

   --================================================================
   --  Traffic keys for one direction (key + IV + nonce counter)
   --================================================================

   type Traffic_Keys is record
      Key     : Bytes_32          := (others => 0);
      IV      : Bytes_12          := (others => 0);
      Counter : Unsigned_64       := 0;
      Suite   : Unsigned_16       := Suite_CHACHA20_POLY1305_SHA256;
   end record;

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
      DER     : Cert_DER_Buf;
      DER_Len : X509.N32;
      Present : Boolean;
   end record;

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

      --  Server: request a client certificate (mTLS).
      Request_Client_Cert : Boolean := False;

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

      --  Server-side: which key share groups did the client offer?
      Client_Has_X25519 : Boolean := False;
      Client_Has_P256   : Boolean := False;
      Client_Has_P384   : Boolean := False;
      Selected_Group    : Unsigned_16 := 0;

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

      --  Resumption
      Using_PSK     : Boolean := False;
      PSK_Offered   : Boolean := False;
      PSK_Ticket_ID : Ticket_ID := (others => 0);
      PSK_Value     : Bytes_48 := (others => 0);  --  zeros if no PSK
      PSK_Value_Len : N32 := 0;                   --  0 = no PSK
      PSK_Binder    : Bytes_48 := (others => 0);  --  received binder
      PSK_Binder_Len : N32 := 0;
      PSK_Binders_Offset : N32 := 0;              --  offset of binders in ClientHello

      --  RFLX scratch buffer
      RFLX_Main : aliased RFLX.RFLX_Builtin_Types.Bytes
                    (1 .. RFLX.RFLX_Builtin_Types.Index (RFLX_Main_Size))
                    := (others => 0);
   end record;

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
      Negotiated_Suite : Unsigned_16 := 0;

      --  Peer certificate valid (copied from HC before free)
      Peer_Cert_Valid : Boolean := False;

      --  Resumption: cached session ticket (client side)
      Ticket : Session_Ticket;

      --  Resumption master secret (copied from HC before free,
      --  needed to derive PSK when NewSessionTicket arrives post-handshake)
      Res_Master     : Bytes_48 := (others => 0);
      Res_Master_Len : N32 := 0;  --  32 or 48

      --  Handshake context (heap-allocated, freed after handshake)
      HC_Ptr : Handshake_Context_Access := null;
   end record;

   --================================================================
   --  Buffer operations (transport layer interface)
   --================================================================

   --  Push received bytes into the session's input buffer.
   --  Returns the number of bytes actually consumed (may be less
   --  than Data'Length if the buffer is nearly full).
   procedure Feed_Ciphertext
     (S         : in out Session;
      Data      : in     Byte_Seq;
      Bytes_Fed :    out N32)
   with Pre  => Data'First = 0
                and Data'Last < N32'Last,
        Post => Bytes_Fed <= N32 (Data'Length);

   --  Pull bytes from the session's output buffer to send.
   --  Returns the number of bytes written into Dest.
   procedure Drain_Ciphertext
     (S              : in out Session;
      Dest           :    out Byte_Seq;
      Bytes_Drained  :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last,
        Post => Bytes_Drained <= N32 (Dest'Length);

   --  How many bytes are waiting to be sent?
   function Output_Pending (S : Session) return N32 is
      (Available (S.Output));

   --  How many input bytes are buffered?
   function Input_Available (S : Session) return N32 is
      (Available (S.Input));

   --  Is decrypted application data waiting to be read?
   function Has_Plaintext (S : Session) return Boolean is
      (S.App_Data_Len > 0);

   --  Read decrypted application data.
   procedure Read_Plaintext
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last
                and S.App_Data_Len <= Max_Record_Plaintext,
        Post => Bytes_Read <= N32 (Dest'Length);

end SPARKTLS;
