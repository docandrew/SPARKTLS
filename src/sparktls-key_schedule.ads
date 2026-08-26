with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.HKDF;              use SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.HKDF384;
use SPARKTLSCrypto;

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
   --  RFC 8446 §7.1: HKDF-Expand-Label.
   --  label is prefixed with "tls13 " automatically.
   --  Label must be non-empty and fit in the HkdfLabel structure.
   procedure Expand_Label
     (OKM     :    out OKM_Seq;
      PRK     : in     Digest;
      Label   : in     String;
      Context : in     Byte_Seq)
   with Pre => Label'Length > 0 and Label'Length <= 245  --  RFC 8446 §7.1
               and Context'Length <= 255                  --  RFC 8446 §7.1
               and OKM'First = 0 and OKM'Length > 0
               and (if Context'Length > 0 then Context'First = 0)
               and Context'Last < N32'Last - 256;

   --  RFC 8446 §7.1: Early Secret = HKDF-Extract(0, PSK).
   --  PSK is all zeros for initial handshake (no resumption).
   procedure Derive_Early_Secret
     (Early : out Digest;
      PSK   : in  Bytes_32);

   --  RFC 8446 §7.1: Handshake Secret from ECDHE shared secret.
   --  Shared secret length depends on key exchange group:
   --    X25519: 32 bytes, P-256: 32 bytes, P-384: 48 bytes.
   procedure Derive_Handshake_Secret
     (HS_Secret    :    out Digest;
      Shared       : in     Byte_Seq;
      Early_Secret : in     Digest)
   with Pre => Shared'First = 0 and Shared'Length > 0
               and Shared'Length <= 48;  --  Max: P-384

   --  RFC 8446 §7.1: Derive client and server handshake traffic secrets.
   --  These are used to encrypt handshake messages after ServerHello.
   procedure Derive_HS_Traffic_Secrets
     (Client_HS_Secret :    out OKM_Seq;
      Server_HS_Secret :    out OKM_Seq;
      HS_Secret        : in     Digest;
      Hello_Hash       : in     Digest)
   with Pre => Client_HS_Secret'First = 0
               and Client_HS_Secret'Last = 31       --  SHA-256 output
               and Server_HS_Secret'First = 0
               and Server_HS_Secret'Last = 31;

   --  RFC 8446 §7.3: Derive traffic key and IV from a traffic secret.
   --  Key = 32 bytes for ChaCha20-Poly1305.
   --  IV = 12 bytes (nonce base).
   procedure Derive_Traffic_Key_IV
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   with Pre => Key'First = 0 and Key'Last = 31      --  256-bit key
               and IV'First = 0 and IV'Last = 11     --  96-bit IV
               and Secret'First = 0 and Secret'Last = 31;

   --  RFC 8446 §7.3: Derive AES-128 traffic key (16 bytes) and IV.
   procedure Derive_Traffic_Key_IV_128
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   with Pre => Key'First = 0 and Key'Last = 15       --  128-bit key
               and IV'First = 0 and IV'Last = 11      --  96-bit IV
               and Secret'First = 0 and Secret'Last = 31;

   --  RFC 8446 §7.1: Master Secret = HKDF-Extract(derived, 0).
   --  Derived from handshake secret via Derive-Secret.
   procedure Derive_Master_Secret
     (Master    :    out Digest;
      HS_Secret : in     Digest);

   --  RFC 8446 §7.1: Application traffic secrets from master secret.
   --  These protect all post-handshake application data.
   procedure Derive_App_Traffic_Secrets
     (Client_App_Secret :    out OKM_Seq;
      Server_App_Secret :    out OKM_Seq;
      Master            : in     Digest;
      Transcript_Hash   : in     Digest)
   with Pre => Client_App_Secret'First = 0
               and Client_App_Secret'Last = 31       --  SHA-256 output
               and Server_App_Secret'First = 0
               and Server_App_Secret'Last = 31;

   --  RFC 8446 §4.4.4: Finished key for verify_data HMAC.
   procedure Derive_Finished_Key
     (Finished_Key :    out OKM_Seq;
      Base_Secret  : in     Byte_Seq)
   with Pre => Finished_Key'First = 0 and Finished_Key'Last = 31
               and Base_Secret'First = 0 and Base_Secret'Last = 31;

   --  RFC 8446 §7.5: Resumption master secret.
   --  Derived AFTER client Finished (transcript includes client Finished).
   procedure Derive_Resumption_Master_Secret
     (Res_Master      :    out OKM_Seq;
      Master          : in     Digest;
      Transcript_Hash : in     Digest)
   with Pre => Res_Master'First = 0 and Res_Master'Last = 31;

   --  RFC 8446 §7.5: exporter master secret.
   --  exporter_master_secret = Derive-Secret(master, "exp master",
   --                                         Transcript-Hash(...))
   procedure Derive_Exporter_Master_Secret
     (Exporter_Master :    out OKM_Seq;
      Master          : in     Digest;
      Transcript_Hash : in     Digest)
   with Pre => Exporter_Master'First = 0 and Exporter_Master'Last = 31;

   --  RFC 8446 §7.5: TLS 1.3 exporter.
   --  TLS-Exporter(label, context, L) =
   --    HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
   --                      "exporter", Hash(context), L)
   procedure Export_Keying_Material
     (Output          :    out OKM_Seq;
      Exporter_Master : in     Byte_Seq;
      Label           : in     String;
      Context         : in     Byte_Seq)
   with Pre => Output'First = 0
               and Output'Length > 0
               and Exporter_Master'First = 0
               and Exporter_Master'Last = 31
               and Label'Length > 0
               and Label'Length <= 245
               and Context'Length <= 255
               and (if Context'Length > 0 then Context'First = 0)
               and Context'Last < N32'Last - 256;

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

   ----------------------------------------------------------------------------
   --  SHA-384 variants (for TLS_AES_256_GCM_SHA384)
   ----------------------------------------------------------------------------

   subtype Digest_384 is SPARKNaCl.Hashing.SHA384.Digest;

   procedure Expand_Label_384
     (OKM     :    out HKDF384.OKM384_Seq;
      PRK     : in     Digest_384;
      Label   : in     String;
      Context : in     Byte_Seq)
   with Pre => Label'Length > 0 and Label'Length <= 245
               and Context'Length <= 255
               and OKM'First = 0 and OKM'Length > 0
               and (if Context'Length > 0 then Context'First = 0)
               and Context'Last < N32'Last - 256;

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

   procedure Derive_Exporter_Master_Secret_384
     (Exporter_Master :    out HKDF384.OKM384_Seq;
      Master          : in     Digest_384;
      Transcript_Hash : in     Digest_384)
   with Pre => Exporter_Master'First = 0 and Exporter_Master'Last = 47;

   procedure Export_Keying_Material_384
     (Output          :    out HKDF384.OKM384_Seq;
      Exporter_Master : in     Byte_Seq;
      Label           : in     String;
      Context         : in     Byte_Seq)
   with Pre => Output'First = 0
               and Output'Length > 0
               and Exporter_Master'First = 0
               and Exporter_Master'Last = 47
               and Label'Length > 0
               and Label'Length <= 245
               and Context'Length <= 255
               and (if Context'Length > 0 then Context'First = 0)
               and Context'Last < N32'Last - 256;

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
