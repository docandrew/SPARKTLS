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
      Seq_Num     : Record_Counter) return Boolean is
     (Implicit_IV'Length = Implicit_IV_Len
      and Seq_Num < Rekey_After_Records)  --  RFC 8446 s5.5 AEAD limit
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
   --  RFC 5246 §6.1: the sequence number increments by 1 per record. It
   --  lives INSIDE Keys (the sealed-channel move, HC_REFACTOR.md carve
   --  5a): the nonce derives from a counter only this operation advances,
   --  so a nonce cannot be reused under a key and the counter cannot be
   --  paired with the wrong keys. Space_Left is both the caller's runtime
   --  branch and the precondition -- same object, same query, so the
   --  discharge is local (the r41 lesson: a cap Pre whose fact lives
   --  elsewhere pushed 5 undischargeable obligations to call sites).
   procedure Build_Encrypted_Record_12
     (Plaintext    : in     Byte_Seq;
      Content_Type : in     Byte;
      Keys         : in out Traffic_Keys;
      Implicit_IV  : in     Byte_Seq;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   with Pre  => Plaintext'First = 0
                and Plaintext'Last < Max_Record_Plaintext
                and Content_Type in 16#15# | 16#16# | 16#17#
                and Implicit_IV'First = 0
                and Implicit_IV'Length = Implicit_IV_Len
                and Space_Left (Keys),
        Post => Keys = (Keys'Old with delta
                          Counter => Keys'Old.Counter + 1)
                --  Increment AND frame in one conjunct: everything but
                --  the counter is untouched.
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
   --  RFC 5246 §6.1: the counter increments even on decrypt FAILURE
   --  (prevents nonce confusion on retry). It lives inside Keys; see
   --  Build_Encrypted_Record_12 for the sealed-channel rationale.
   --
   --  NO cap precondition on the decrypt side, deliberately: the 2**23
   --  AEAD confidentiality bound binds the ENCRYPTING side, and TLS 1.2
   --  has no rekey -- the read path needs only increment safety. The one
   --  unreachable corner (counter at the ARITHMETIC limit, ~584,000
   --  years) fails closed HERE, in one place: Valid comes back False and
   --  the channel is unchanged, rather than wrapping to a reused nonce.
   procedure Decrypt_Record_12
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in out Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
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
                and Plaintext'Last >= Encrypted'Last,
        Post => (if Keys'Old.Counter < Record_Counter'Last
                 then Keys = (Keys'Old with delta
                                Counter => Keys'Old.Counter + 1)
                 else Keys = Keys'Old and not Valid)
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
      Keys        : in out Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
      Output      : in out IO_Buffer;
      Bytes_Out   :    out N32)
   with Pre  => Level in 1 .. 2
                and Implicit_IV'First = 0
                and Implicit_IV'Length = Implicit_IV_Len
                --  Same channel discipline as the op this wraps: callers
                --  branch on Space_Left of the SAME object. A channel at
                --  the cap cannot seal even a final alert -- callers skip
                --  the alert and close (fail closed, no cap overrun).
                and Space_Left (Keys),
        Post => Keys = (Keys'Old with delta
                          Counter => Keys'Old.Counter + 1)
                and Bytes_Out <=
                       Record_Header_Size + Explicit_Nonce_Len +
                       2 + GCM_Tag_Len;  --  upper bound (GCM); ChaCha
                                         --  omits the 8-byte exp nonce

end SPARKTLS.Records.TLS12;
