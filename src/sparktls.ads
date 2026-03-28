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

   --  RFLX scratch buffer sizes (stack-allocated, no heap)
   RFLX_Main_Size : constant := 17000;  --  Holds largest message (incoming record)
   RFLX_Sub_Size  : constant := 300;    --  Holds one extension/entry element

   --================================================================
   --  Cipher suite
   --================================================================

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
      Wait_Certificate,
      Wait_Certificate_Verify,
      Wait_Server_Finished,
      Client_Finished_Sent,

      --  Server-side handshake
      Wait_Client_Hello,
      Server_Hello_Sent,
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
      App_Data_Ready, --  Decrypted app data available
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
   --  via Feed_Input and drains it via Drain_Output. Compacted
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

   --================================================================
   --  Configuration (set once before Init)
   --================================================================

   type Config is record
      Suite        : Cipher_Suite    := TLS_CHACHA20_POLY1305_SHA256;
      Random       : Random_Bytes_Fn := null;
      Server_Name  : Hostname_Buf;
      Skip_Verify  : Boolean         := False;  --  -k: accept any cert
   end record;

   --================================================================
   --  Session
   --
   --  All TLS connection state in one record. No hidden heap
   --  allocations. Intended for stack or caller-managed heap.
   --
   --  The caller interacts with a Session exclusively through:
   --    Feed_Input   - push received bytes into Input buffer
   --    Drain_Output - pull bytes to send from Output buffer
   --    Advance      - step the state machine (in Client/Server)
   --    Write_App_Data  - encrypt and queue application data
   --    Read_App_Data   - read decrypted application data
   --    Close_Notify    - initiate clean shutdown
   --================================================================

   type Session is record
      --  Configuration and state
      Cfg          : Config;
      State        : Connection_State := Idle;
      Last_Error   : Error_Code       := No_Error;
      Is_Client    : Boolean          := True;

      --  I/O buffers
      Input        : IO_Buffer;
      Output       : IO_Buffer;

      --  Ephemeral key exchange (X25519, P-256, or P-384 ECDHE)
      Local_SK      : Bytes_32 := (others => 0);
      Client_Random : Bytes_32 := (others => 0);
      Server_Random : Bytes_32 := (others => 0);
      Peer_PK       : Bytes_32 := (others => 0);  --  X25519 peer key
      Shared_Secret : Bytes_48 := (others => 0);  --  up to 48 bytes for P-384

      --  P-256 ECDHE key exchange state
      P256_Local_SK : Bytes_32 := (others => 0);  --  P-256 private scalar
      P256_Peer_PK  : Byte_Seq (0 .. 64) := (others => 0);  --  65-byte uncompressed
      Use_P256_KE   : Boolean := False;  --  True if server selected secp256r1

      --  P-384 ECDHE key exchange state
      P384_Local_SK : Bytes_48 := (others => 0);  --  P-384 private scalar
      P384_Peer_PK  : Byte_Seq (0 .. 96) := (others => 0);  --  97-byte uncompressed
      Use_P384_KE   : Boolean := False;  --  True if server selected secp384r1

      --  Handshake traffic keys
      Client_HS     : Traffic_Keys;
      Server_HS     : Traffic_Keys;

      --  Application traffic keys
      Client_App    : Traffic_Keys;
      Server_App    : Traffic_Keys;

      --  Traffic secrets (needed for finished key derivation)
      --  48 bytes to accommodate both SHA-256 (32) and SHA-384 (48)
      Client_HS_Secret : Bytes_48 := (others => 0);
      Server_HS_Secret : Bytes_48 := (others => 0);

      --  Key schedule intermediates
      --  48 bytes to accommodate both SHA-256 (32) and SHA-384 (48)
      Handshake_Secret : Bytes_48 := (others => 0);
      Master_Secret    : Bytes_48 := (others => 0);

      --  Hash length for the negotiated cipher suite (32 or 48)
      Hash_Len : N32 := 32;

      --  Transcript accumulator (all handshake messages for hashing)
      Transcript     : Byte_Seq (0 .. Transcript_Capacity - 1)
                         := (others => 0);
      Transcript_Len : N32 := 0;

      --  Peer certificate (raw DER for verification)
      Peer_Cert_DER     : Byte_Seq (0 .. Max_Cert_DER_Len - 1)
                            := (others => 0);
      Peer_Cert_DER_Len : N32 := 0;
      Peer_Cert         : X509.Certificate;
      Peer_Cert_Valid   : Boolean := False;

      --  Local certificate (server mode)
      Local_Cert_DER     : Byte_Seq (0 .. Max_Cert_DER_Len - 1)
                             := (others => 0);
      Local_Cert_DER_Len : N32 := 0;

      --  Server signing key (server mode, Ed25519)
      Signing_Key        : Bytes_64 := (others => 0);
      Signing_Key_Valid  : Boolean  := False;

      --  Decrypted application data staging area
      App_Data     : Byte_Seq (0 .. Max_Record_Plaintext - 1)
                       := (others => 0);
      App_Data_Len : N32 := 0;

      --  Negotiated cipher suite (wire value from ServerHello)
      Negotiated_Suite : Unsigned_16 := 0;

      --  Legacy session ID (middlebox compatibility)
      Legacy_Session_ID : Bytes_32 := (others => 0);

      --  Handshake tracking
      CCS_Received : Boolean := False;

      --  RFLX scratch buffers (reused for each serialize/parse operation)
      RFLX_Main : aliased RFLX.RFLX_Builtin_Types.Bytes
                    (1 .. RFLX.RFLX_Builtin_Types.Index (RFLX_Main_Size))
                    := (others => 0);
      RFLX_Sub  : aliased RFLX.RFLX_Builtin_Types.Bytes
                    (1 .. RFLX.RFLX_Builtin_Types.Index (RFLX_Sub_Size))
                    := (others => 0);
   end record;

   --================================================================
   --  Buffer operations (transport layer interface)
   --================================================================

   --  Push received bytes into the session's input buffer.
   --  Returns the number of bytes actually consumed (may be less
   --  than Data'Length if the buffer is nearly full).
   procedure Feed_Input
     (S         : in out Session;
      Data      : in     Byte_Seq;
      Bytes_Fed :    out N32)
   with Pre  => Data'First = 0
                and Data'Last < N32'Last,
        Post => Bytes_Fed <= N32 (Data'Length);

   --  Pull bytes from the session's output buffer to send.
   --  Returns the number of bytes written into Dest.
   procedure Drain_Output
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
   function Has_App_Data (S : Session) return Boolean is
      (S.App_Data_Len > 0);

   --  Read decrypted application data.
   procedure Read_App_Data
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   with Pre  => Dest'First = 0
                and Dest'Last < N32'Last
                and S.App_Data_Len <= Max_Record_Plaintext,
        Post => Bytes_Read <= N32 (Dest'Length);

end SPARKTLS;
