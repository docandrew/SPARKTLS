with SPARKNaCl; use SPARKNaCl;

--  TLS 1.2 Record Layer — AEAD ciphers only (RFC 5246 §6.2.3.3, RFC 5288)
--
--  GCM nonce construction (RFC 5288 §3):
--    nonce[12] = salt[4] || nonce_explicit[8]
--    salt = client_write_IV or server_write_IV (from key expansion)
--    nonce_explicit = 64-bit sequence number (big-endian)
--
--  Record format:
--    TLS record header[5] || nonce_explicit[8] || ciphertext[N] || tag[16]
--
--  AAD (RFC 5246 §6.2.3.3):
--    additional_data[13] = seq_num[8] || content_type[1] || version[2] || length[2]
--    where length = plaintext length BEFORE encryption (not ciphertext length)
--
--  Key differences from TLS 1.3 (RFC 8446 §5):
--    - Explicit 8-byte nonce in record (vs implicit XOR counter)
--    - No inner content type byte (outer header has real type)
--    - No zero-byte padding
--    - AAD includes seq_num explicitly and uses plaintext length
--    - Content type in outer header is the actual type (not always 0x17)
--    - Sequence numbers reset to 0 after CCS (RFC 5246 §6.1)
package SPARKTLS.Records.TLS12 with
   SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  Constants from RFC 5288 and RFC 5246
   ----------------------------------------------------------------------------

   Explicit_Nonce_Len : constant := 8;   --  RFC 5288 §3 (AES-GCM only)
   --  Implicit_IV storage is sized for ChaCha20-Poly1305's 12-byte IV
   --  (RFC 7905 §2). AES-GCM uses only the first 4 bytes as the salt
   --  (RFC 5288 §3); the remaining bytes are zero-padded.
   Implicit_IV_Len    : constant := 12;
   GCM_Tag_Len        : constant := 16;  --  NIST SP 800-38D
   AAD_Len            : constant := 13;  --  RFC 5246 §6.2.3.3

   --  Maximum record overhead for TLS 1.2 AEAD:
   --  explicit_nonce(8 for GCM, 0 for ChaCha20) + tag(16) ≤ 24 bytes.
   TLS12_Record_Overhead : constant := Explicit_Nonce_Len + GCM_Tag_Len;

   --  TLS 1.2 version bytes in record headers and AAD
   TLS12_Version_Major : constant Byte := 3;
   TLS12_Version_Minor : constant Byte := 3;

   ----------------------------------------------------------------------------
   --  Ghost functions: RFC behavioral invariants
   ----------------------------------------------------------------------------

   --  RFC 5288 §3: GCM nonce = implicit_IV[0..3] || explicit_nonce[8].
   --  The nonce MUST be unique for each record under the same key.
   --  Using the sequence number as the explicit nonce guarantees
   --  uniqueness since sequence numbers never repeat (RFC 5246 §6.1).
   --  Implicit_IV storage is sized for the larger ChaCha20-Poly1305
   --  IV (RFC 7905); AES-GCM uses only the first 4 bytes (the salt).
   function Valid_GCM_Nonce
     (Implicit_IV : Byte_Seq;
      Seq_Num     : Unsigned_64) return Boolean is
     (Implicit_IV'Length = Implicit_IV_Len
      and Seq_Num < Unsigned_64'Last)  --  nonce space not exhausted
   with Ghost;

   --  RFC 5246 §6.1: Sequence numbers.
   --  "MUST be set to zero whenever a connection state is made active"
   --  "Sequence numbers do not wrap"
   --  "The first record transmitted under a particular connection
   --   state MUST use sequence number 0"
   function Nonce_Space_Available_12 (Seq : Unsigned_64) return Boolean is
     (Seq < Unsigned_64'Last)
   with Ghost;

   ----------------------------------------------------------------------------
   --  Procedures
   ----------------------------------------------------------------------------

   --  RFC 5246 §6.2.3.3 + RFC 5288: Build an encrypted TLS 1.2 record.
   --
   --  The explicit nonce is the 64-bit sequence number (big-endian),
   --  prepended to the ciphertext in the record.
   --
   --  GCM nonce = Implicit_IV[4] || Seq_Num[8]
   --
   --  AAD = Seq_Num[8] || Content_Type[1] || 0x0303[2] || Plaintext_Len[2]
   --
   --  Output format:
   --    record_header[5]:
   --      content_type[1] || version[2]=0x0303 ||
   --      fragment_length[2] = 8 + plaintext_len + 16
   --    nonce_explicit[8] = Seq_Num (big-endian)
   --    ciphertext[plaintext_len]
   --    tag[16]
   --
   --  RFC 5246 §6.1: Seq_Num increments by 1 for each record.
   --  The caller MUST NOT call this if nonce space is exhausted.
   procedure Build_Encrypted_Record_12
     (Plaintext    : in     Byte_Seq;
      Content_Type : in     Byte;
      Keys         : in     Traffic_Keys;
      Implicit_IV  : in     Byte_Seq;
      Seq_Num      : in out Unsigned_64;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   with Pre  => Plaintext'First = 0
                and Plaintext'Last < Max_Record_Plaintext
                and Content_Type in 16#15# | 16#16# | 16#17#
                and Implicit_IV'First = 0
                and Implicit_IV'Length = Implicit_IV_Len
                and Nonce_Space_Available_12 (Seq_Num),
        Post => Seq_Num = Seq_Num'Old + 1  --  RFC 5246 §6.1
                and Bytes_Out <=
                       Record_Header_Size + Explicit_Nonce_Len +
                       N32 (Plaintext'Length) + GCM_Tag_Len;
                --  Exact size depends on suite: AES-GCM includes an
                --  on-wire explicit_nonce[8], ChaCha20 (RFC 7905 §2)
                --  does not. Either is bounded above by the GCM size.

   --  RFC 5246 §6.2.3.3 + RFC 5288: Decrypt a TLS 1.2 AEAD record.
   --
   --  Encrypted layout: nonce_explicit[8] || ciphertext[N] || tag[16]
   --
   --  Procedure:
   --  1. Extract nonce_explicit from first 8 bytes
   --  2. Construct GCM nonce = Implicit_IV[4] || nonce_explicit[8]
   --  3. Construct AAD from seq_num, content_type (from Record_Hdr),
   --     version (0x0303), and plaintext length
   --  4. Decrypt ciphertext and verify tag
   --
   --  RFC 5246 §6.2.3.3: "If the decryption fails, a fatal
   --  bad_record_mac alert MUST be generated."
   --
   --  RFC 5246 §6.1: Seq_Num increments even on failure.
   --  This prevents nonce reuse on retry.
   procedure Decrypt_Record_12
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in     Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
      Seq_Num     : in out Unsigned_64;
      Plaintext   :    out Byte_Seq;
      Plain_Len   :    out N32;
      Valid       :    out Boolean)
   with Pre  => Encrypted'First = 0
                and Encrypted'Last >= GCM_Tag_Len - 1
                and Encrypted'Last < Max_Record_Plaintext + TLS12_Record_Overhead
                and Record_Hdr'First = 0
                and Record_Hdr'Length = Record_Header_Size
                and Implicit_IV'First = 0
                and Implicit_IV'Length = Implicit_IV_Len
                and Plaintext'First = 0
                and Plaintext'Last >= Encrypted'Last
                and Nonce_Space_Available_12 (Seq_Num),
        Post => Seq_Num = Seq_Num'Old + 1        --  always increments
                and (if Valid then
                   --  Plaintext length = encrypted - nonce - tag
                   Plain_Len <= Max_Record_Plaintext
                   and (Plain_Len = 0
                        or else Plain_Len - 1 <= Plaintext'Last));

   --  Build an encrypted alert record for TLS 1.2.
   --
   --  Alert payload is 2 bytes: level[1] || description[1].
   --  Encrypted as a normal record with Content_Type = 0x15.
   procedure Build_Alert_Record_12
     (Level       : in     Byte;
      Desc        : in     Byte;
      Keys        : in     Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
      Seq_Num     : in out Unsigned_64;
      Output      : in out IO_Buffer;
      Bytes_Out   :    out N32)
   with Pre  => Level in 1 .. 2
                and Implicit_IV'First = 0
                and Implicit_IV'Length = Implicit_IV_Len
                and Nonce_Space_Available_12 (Seq_Num),
        Post => Seq_Num = Seq_Num'Old + 1
                and Bytes_Out <=
                       Record_Header_Size + Explicit_Nonce_Len +
                       2 + GCM_Tag_Len;  --  upper bound (GCM); ChaCha
                                         --  omits the 8-byte exp nonce

end SPARKTLS.Records.TLS12;
