with SPARKNaCl;       use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;
use SPARKTLSCrypto;

--  TLS 1.2 Key Derivation (RFC 5246 Sections 5, 6.3, 7.4.9, 8.1)
--
--  TLS 1.2 uses a PRF based on P_SHA256 (or P_SHA384 for SHA-384 suites):
--
--    P_hash(secret, seed) = HMAC_hash(secret, A(1) || seed) ||
--                           HMAC_hash(secret, A(2) || seed) || ...
--    where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
--
--    PRF(secret, label, seed) = P_hash(secret, label || seed)
--
--  All labels are ASCII strings without length prefix or null terminator.
package SPARKTLS.Key_Schedule_12 with
   SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  Constants from RFC 5246
   ----------------------------------------------------------------------------

   Master_Secret_Len   : constant := 48;  --  RFC 5246 §8.1: always 48 bytes
   Finished_Verify_Len : constant := 12;  --  RFC 5246 §7.4.9

   --  RFC 5288 §3: GCM parameters
   Fixed_IV_Len  : constant := 4;  --  implicit nonce part
   Record_IV_Len : constant := 8;  --  explicit nonce part

   subtype Verify_Data_12 is Byte_Seq (0 .. Finished_Verify_Len - 1);

   --  RFC 5246 §8.1, §6.3: label strings (normative)
   --  Using the wrong label is a silent interop failure, so we
   --  encode the exact strings as constants for static checking.
   Label_Master_Secret   : constant String := "master secret";
   Label_Key_Expansion   : constant String := "key expansion";
   Label_Client_Finished : constant String := "client finished";
   Label_Server_Finished : constant String := "server finished";

   ----------------------------------------------------------------------------
   --  Ghost functions: RFC behavioral invariants
   ----------------------------------------------------------------------------

   --  RFC 5246 §8.1: Seed order for master secret derivation.
   --  The seed is client_random || server_random (client FIRST).
   --  Getting this backwards is a real-world bug that produces
   --  a valid-looking but incompatible master secret.
   --  RFC 5246 §8.1: Seed order for master secret derivation.
   --  The seed is client_random || server_random (client FIRST).
   --  Getting this backwards is a real-world bug that produces
   --  a valid-looking but incompatible master secret.
   subtype Seed_64 is Byte_Seq (0 .. 63);

   function Master_Secret_Seed_Order_Valid
     (Seed          : Seed_64;
      Client_Random : Bytes_32;
      Server_Random : Bytes_32) return Boolean is
     ((for all I in N32 range 0 .. 31 =>
         Seed (I) = Client_Random (I))
      and (for all I in N32 range 0 .. 31 =>
             Seed (32 + I) = Server_Random (I)))
   with Ghost;

   --  RFC 5246 §6.3: Seed order for key expansion.
   --  The seed is server_random || client_random (server FIRST).
   --  This is the OPPOSITE order from master secret derivation.
   function Key_Expansion_Seed_Order_Valid
     (Seed          : Seed_64;
      Server_Random : Bytes_32;
      Client_Random : Bytes_32) return Boolean is
     ((for all I in N32 range 0 .. 31 =>
         Seed (I) = Server_Random (I))
      and (for all I in N32 range 0 .. 31 =>
             Seed (32 + I) = Client_Random (I)))
   with Ghost;

   --  RFC 5246 §6.3: Key block partitioning for AEAD ciphers.
   --  For AEAD, MAC keys are zero-length, so the key block is:
   --    client_write_key [Key_Len] || server_write_key [Key_Len] ||
   --    client_write_IV [IV_Len]   || server_write_IV [IV_Len]
   --  IV_Len = 4 for AES-GCM, 12 for ChaCha20-Poly1305.
   function Key_Block_Len (Key_Len, IV_Len : N32) return N32 is
     (2 * Key_Len + 2 * IV_Len)
   with Ghost,
        Pre => Key_Len in 16 | 32 and IV_Len in 4 | 12;

   --  RFC 5246 §7.4.9: Valid finished labels.
   function Valid_Finished_Label (Label : String) return Boolean is
     (Label = Label_Client_Finished or Label = Label_Server_Finished)
   with Ghost;

   procedure Prove_Client_Finished_Label
   with Ghost,
        Post => Valid_Finished_Label (Label_Client_Finished);

   procedure Prove_Server_Finished_Label
   with Ghost,
        Post => Valid_Finished_Label (Label_Server_Finished);

   ----------------------------------------------------------------------------
   --  Procedures
   ----------------------------------------------------------------------------

   --  RFC 5246 §5: TLS PRF (SHA-256 variant).
   --
   --  PRF(secret, label, seed) = P_SHA256(secret, label || seed)
   --
   --  The PRF is deterministic: same inputs always produce the same output.
   --  The label is concatenated with the seed without any separator.
   --  Output is truncated to Output'Length bytes from the P_hash stream.
   procedure PRF_SHA256
     (Output : out Byte_Seq;
      Secret : in  Byte_Seq;
      Label  : in  String;
      Seed   : in  Byte_Seq)
   with Pre  => Output'First = 0
                and Output'Length > 0
                and Output'Length <= 256    --  practical bound (covers key_block)
                and Secret'First = 0
                and Secret'Length > 0
                and Secret'Length <= 48     --  master secret is largest input
                and Label'Length > 0
                and Label'Length <= 64
                and Seed'First = 0
                and Seed'Length > 0
                and Seed'Length <= 128;

   --  RFC 5246 §5: TLS PRF (SHA-384 variant).
   --  Used for cipher suites with SHA-384 (AES-256-GCM-SHA384).
   --  Identical structure to PRF_SHA256 but uses HMAC-SHA-384.
   procedure PRF_SHA384
     (Output : out Byte_Seq;
      Secret : in  Byte_Seq;
      Label  : in  String;
      Seed   : in  Byte_Seq)
   with Pre  => Output'First = 0
                and Output'Length > 0
                and Output'Length <= 256
                and Secret'First = 0
                and Secret'Length > 0
                and Secret'Length <= 48
                and Label'Length > 0
                and Label'Length <= 64
                and Seed'First = 0
                and Seed'Length > 0
                and Seed'Length <= 128;

   --  RFC 5246 §8.1: Compute the 48-byte master secret.
   --
   --  master_secret = PRF(pre_master_secret, "master secret",
   --                      ClientHello.random || ServerHello.random)[0..47]
   --
   --  CRITICAL: Seed order is client_random FIRST, then server_random.
   --  (Key expansion uses the opposite order.)
   --
   --  For ECDHE: pre_master_secret is the x-coordinate of the shared
   --  ECDH point (32 bytes for X25519/P-256, 48 bytes for P-384).
   --
   --  The master_secret is ALWAYS 48 bytes regardless of PRF hash size.
   procedure Derive_Master_Secret_12
     (Master        :    out Bytes_48;
      Pre_Master    : in     Byte_Seq;
      Client_Random : in     Bytes_32;
      Server_Random : in     Bytes_32;
      Use_SHA384    : in     Boolean)
   with Pre  => Pre_Master'First = 0
                and Pre_Master'Length in 32 | 48;  --  ECDHE shared secret

   --  RFC 5246 §6.3: Expand master secret into per-connection key material.
   --
   --  key_block = PRF(master_secret, "key expansion",
   --                  server_random || client_random)
   --
   --  CRITICAL: Seed order is server_random FIRST, then client_random.
   --  (Master secret derivation uses the opposite order.)
   --
   --  For AEAD ciphers, MAC keys are zero-length, so key_block contains:
   --    client_write_key [Key_Len] || server_write_key [Key_Len] ||
   --    client_write_IV [IV_Len]   || server_write_IV [IV_Len]
   --
   --  IV_Len is 4 for AES-GCM (RFC 5288 §3: salt is 4 bytes, prepended
   --  to the on-wire explicit_nonce[8] to form the 12-byte nonce) and
   --  12 for ChaCha20-Poly1305 (RFC 7905 §2: the entire 12-byte IV is
   --  XOR'd with the padded sequence number; no on-wire explicit nonce).
   --  Output IV buffers are always 12 bytes; bytes beyond IV_Len are
   --  zero-padded so the caller can use a uniform 12-byte type.
   --
   --  RFC 5246 §6.1: The derived keys MUST be used with sequence
   --  numbers starting at zero.
   procedure Expand_Keys_12
     (Client_Key    :    out Byte_Seq;
      Server_Key    :    out Byte_Seq;
      Client_IV     :    out Byte_Seq;
      Server_IV     :    out Byte_Seq;
      Master        : in     Bytes_48;
      Server_Random : in     Bytes_32;
      Client_Random : in     Bytes_32;
      Key_Len       : in     N32;
      IV_Len        : in     N32;
      Use_SHA384    : in     Boolean)
   with Pre  => Key_Len in 16 | 32             --  AES-128 or AES-256/ChaCha20
                and IV_Len in 4 | 12           --  AES-GCM salt or ChaCha20 IV
                and Client_Key'First = 0
                and Client_Key'Last = Key_Len - 1
                and Server_Key'First = 0
                and Server_Key'Last = Key_Len - 1
                and Client_IV'First = 0
                and Client_IV'Last = 11
                and Server_IV'First = 0
                and Server_IV'Last = 11;

   --  RFC 5246 §7.4.9: Compute the 12-byte Finished verify_data.
   --
   --  verify_data = PRF(master_secret, finished_label,
   --                    Hash(handshake_messages))[0..11]
   --
   --  The label MUST be exactly "client finished" or "server finished".
   --  Using the wrong label would produce valid-looking but wrong output,
   --  causing the peer to reject the Finished message.
   --
   --  The transcript hash MUST include all handshake messages from
   --  ClientHello through the message immediately preceding this
   --  Finished, but NOT including the Finished itself (RFC 5246 §7.4.9).
   --
   --  RFC 5246 §7.4.9: "It is a fatal error if a Finished message is
   --  not preceded by a ChangeCipherSpec message at the appropriate
   --  point in the handshake."
   procedure Compute_Finished_12
     (Verify     :    out Verify_Data_12;
      Master     : in     Bytes_48;
      Label      : in     String;
      TH         : in     Byte_Seq;
      Use_SHA384 : in     Boolean)
   with Pre  => Valid_Finished_Label (Label)
                and TH'First = 0
                --  SHA-256 or SHA-384 transcript hash.
                and (TH'Last = 31 or else TH'Last = 47),
        --  RFC 5246 §7.4.9: verify_data is 12 bytes regardless of
        --  cipher suite. Already type-enforced via Verify_Data_12;
        --  the Post lifts to a named ghost predicate for clause
        --  traceability.
        Post => SPARKTLS.Verify_Data_Length_TLS12_RFC_5246_7_4_9 (Verify);

end SPARKTLS.Key_Schedule_12;
