with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.HKDF;             use SPARKNaCl.HKDF;
with SPARKTLS.HKDF384;

--  TLS 1.3 Key Schedule (RFC 8446 Section 7)
--
--  Implements HKDF-Expand-Label and the full TLS 1.3 key derivation
--  chain: Early Secret -> Handshake Secret -> Master Secret,
--  plus traffic key/IV derivation.
--
--  SHA-256 variants are used for TLS_AES_128_GCM_SHA256 and
--  TLS_CHACHA20_POLY1305_SHA256.
--  SHA-384 variants are used for TLS_AES_256_GCM_SHA384.
package SPARKTLS.Key_Schedule with
   SPARK_Mode => On
is
   --  HKDF-Expand-Label (RFC 8446 Section 7.1)
   --  label is prefixed with "tls13 " automatically.
   procedure Expand_Label
     (OKM     :    out OKM_Seq;
      PRK     : in     Digest;
      Label   : in     String;
      Context : in     Byte_Seq)
   with Pre => Label'Length > 0 and Label'Length <= 245
               and Context'Length <= 255
               and OKM'First = 0 and OKM'Length > 0
               and (if Context'Length > 0 then Context'First = 0);

   --  Derive Early Secret from PSK (or all-zeroes for no PSK)
   procedure Derive_Early_Secret
     (Early : out Digest;
      PSK   : in  Bytes_32);

   --  Derive Handshake Secret from shared ECDHE secret and early secret
   procedure Derive_Handshake_Secret
     (HS_Secret    :    out Digest;
      Shared       : in     Byte_Seq;
      Early_Secret : in     Digest)
   with Pre => Shared'First = 0 and Shared'Length > 0
               and Shared'Length <= 48;  --  Max: P-384 shared secret

   --  Derive handshake traffic secrets from handshake secret + hello hash
   procedure Derive_HS_Traffic_Secrets
     (Client_HS_Secret :    out OKM_Seq;
      Server_HS_Secret :    out OKM_Seq;
      HS_Secret        : in     Digest;
      Hello_Hash       : in     Digest)
   with Pre => Client_HS_Secret'First = 0
               and Client_HS_Secret'Last = 31
               and Server_HS_Secret'First = 0
               and Server_HS_Secret'Last = 31;

   --  Derive traffic key (32 bytes) and IV from a traffic secret
   --  For ChaCha20-Poly1305 (key = 32 bytes)
   procedure Derive_Traffic_Key_IV
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   with Pre => Key'First = 0 and Key'Last = 31
               and IV'First = 0 and IV'Last = 11
               and Secret'First = 0 and Secret'Last = 31;

   --  Derive traffic key (16 bytes) and IV from a traffic secret
   --  For AES-128-GCM (key = 16 bytes)
   procedure Derive_Traffic_Key_IV_128
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   with Pre => Key'First = 0 and Key'Last = 15
               and IV'First = 0 and IV'Last = 11
               and Secret'First = 0 and Secret'Last = 31;

   --  Derive Master Secret from handshake secret
   procedure Derive_Master_Secret
     (Master    :    out Digest;
      HS_Secret : in     Digest);

   --  Derive application traffic secrets from master secret + transcript hash
   procedure Derive_App_Traffic_Secrets
     (Client_App_Secret :    out OKM_Seq;
      Server_App_Secret :    out OKM_Seq;
      Master            : in     Digest;
      Transcript_Hash   : in     Digest)
   with Pre => Client_App_Secret'First = 0
               and Client_App_Secret'Last = 31
               and Server_App_Secret'First = 0
               and Server_App_Secret'Last = 31;

   --  Derive finished key for verify_data computation
   procedure Derive_Finished_Key
     (Finished_Key :    out OKM_Seq;
      Base_Secret  : in     Byte_Seq)
   with Pre => Finished_Key'First = 0 and Finished_Key'Last = 31
               and Base_Secret'First = 0 and Base_Secret'Last = 31;

   --  Derive resumption master secret from master secret + full transcript
   --  (RFC 8446 Section 7.5: includes client Finished)
   procedure Derive_Resumption_Master_Secret
     (Res_Master      :    out OKM_Seq;
      Master          : in     Digest;
      Transcript_Hash : in     Digest)
   with Pre => Res_Master'First = 0 and Res_Master'Last = 31;

   --  Derive PSK from resumption master secret + ticket nonce
   --  PSK = HKDF-Expand-Label(res_master, "resumption", nonce, 32)
   procedure Derive_PSK
     (PSK         :    out OKM_Seq;
      Res_Master  : in     Byte_Seq;
      Nonce       : in     Byte_Seq)
   with Pre => PSK'First = 0 and PSK'Last = 31
               and Res_Master'First = 0 and Res_Master'Last = 31
               and Nonce'First = 0 and Nonce'Length > 0
               and Nonce'Length <= 255;

   --  Derive binder key from PSK (for PSK binder in ClientHello)
   --  binder_key = Derive-Secret(early_secret, "res binder", "")
   procedure Derive_Binder_Key
     (Binder_Key :    out OKM_Seq;
      PSK        : in     Bytes_32)
   with Pre => Binder_Key'First = 0 and Binder_Key'Last = 31;

   --================================================================
   --  SHA-384 variants (for TLS_AES_256_GCM_SHA384)
   --================================================================

   subtype Digest_384 is SPARKNaCl.Hashing.SHA384.Digest;

   procedure Expand_Label_384
     (OKM     :    out HKDF384.OKM384_Seq;
      PRK     : in     Digest_384;
      Label   : in     String;
      Context : in     Byte_Seq)
   with Pre => Label'Length > 0 and Label'Length <= 245
               and Context'Length <= 255
               and OKM'First = 0 and OKM'Length > 0
               and (if Context'Length > 0 then Context'First = 0);

   procedure Derive_Early_Secret_384
     (Early : out Digest_384;
      PSK   : in  Bytes_48);

   procedure Derive_Handshake_Secret_384
     (HS_Secret    :    out Digest_384;
      Shared       : in     Byte_Seq;
      Early_Secret : in     Digest_384)
   with Pre => Shared'First = 0 and Shared'Length > 0
               and Shared'Length <= 48;  --  Max: P-384 shared secret

   procedure Derive_HS_Traffic_Secrets_384
     (Client_HS_Secret :    out HKDF384.OKM384_Seq;
      Server_HS_Secret :    out HKDF384.OKM384_Seq;
      HS_Secret        : in     Digest_384;
      Hello_Hash       : in     Digest_384)
   with Pre => Client_HS_Secret'First = 0
               and Client_HS_Secret'Last = 47
               and Server_HS_Secret'First = 0
               and Server_HS_Secret'Last = 47;

   procedure Derive_Traffic_Key_IV_256
     (Key    :    out HKDF384.OKM384_Seq;
      IV     :    out HKDF384.OKM384_Seq;
      Secret : in     Byte_Seq)
   with Pre => Key'First = 0 and Key'Last = 31
               and IV'First = 0 and IV'Last = 11
               and Secret'First = 0 and Secret'Last = 47;

   procedure Derive_Master_Secret_384
     (Master    :    out Digest_384;
      HS_Secret : in     Digest_384);

   procedure Derive_App_Traffic_Secrets_384
     (Client_App_Secret :    out HKDF384.OKM384_Seq;
      Server_App_Secret :    out HKDF384.OKM384_Seq;
      Master            : in     Digest_384;
      Transcript_Hash   : in     Digest_384)
   with Pre => Client_App_Secret'First = 0
               and Client_App_Secret'Last = 47
               and Server_App_Secret'First = 0
               and Server_App_Secret'Last = 47;

   procedure Derive_Finished_Key_384
     (Finished_Key :    out HKDF384.OKM384_Seq;
      Base_Secret  : in     Byte_Seq)
   with Pre => Finished_Key'First = 0 and Finished_Key'Last = 47
               and Base_Secret'First = 0 and Base_Secret'Last = 47;

   procedure Derive_Resumption_Master_Secret_384
     (Res_Master      :    out HKDF384.OKM384_Seq;
      Master          : in     Digest_384;
      Transcript_Hash : in     Digest_384)
   with Pre => Res_Master'First = 0 and Res_Master'Last = 47;

   procedure Derive_PSK_384
     (PSK         :    out HKDF384.OKM384_Seq;
      Res_Master  : in     Byte_Seq;
      Nonce       : in     Byte_Seq)
   with Pre => PSK'First = 0 and PSK'Last = 47
               and Res_Master'First = 0 and Res_Master'Last = 47
               and Nonce'First = 0 and Nonce'Length > 0
               and Nonce'Length <= 255;

   procedure Derive_Binder_Key_384
     (Binder_Key :    out HKDF384.OKM384_Seq;
      PSK        : in     Bytes_48)
   with Pre => Binder_Key'First = 0 and Binder_Key'Last = 47;

end SPARKTLS.Key_Schedule;
