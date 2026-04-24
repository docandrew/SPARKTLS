with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKTLS.Hashing.SHA256;
with SPARKTLS.X25519;
with SPARKTLS.HKDF;    use SPARKTLS.HKDF;
with SPARKTLS.MAC;     use SPARKTLS.MAC;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with SPARKTLS.Key_Schedule;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Handshake.CH_Extensions_TLS;
with RFLX.TLS_Handshake.CH_Extension_TLS;
with RFLX.TLS_Handshake.Key_Share_SH;
with RFLX.TLS_Handshake.Cipher_Suites_TLS;
with RFLX.TLS_Handshake.Cipher_Suite_TLS;
with RFLX.TLS_Common;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;

package body SPARKTLS.Handshake.Client_Msgs with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;

   --  Deallocate an RFLX buffer.
   --  Body is SPARK_Mode Off (Unchecked_Deallocation of 'access all').
   --  Spec is On so SPARK can verify call sites.
   use type RBT.Bytes_Ptr;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with SPARK_Mode => Off
   is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   --================================================================
   --  Build procedures (keep manual serialization for simple output)
   --================================================================

   procedure Build_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      use RFLX.TLS_Common;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      --  Extension data sizes
      Host_Len : constant N32 := N32 (HC.Cfg.Server_Name.Len);
      --  SNI data: sni_list_len(2) + host_type(1) + host_len(2) + host
      SNI_Data_Len : constant N32 := 5 + Host_Len;
      --  supported_groups data: list_len(2) + group(2) * 3
      SG_Data_Len  : constant N32 := 8;
      --  signature_algorithms data: list_len(2) + alg(2) * 6
      SA_Data_Len  : constant N32 := 14;
      --  key_share data: shares_len(2) + x25519(36) + secp256r1(69) + secp384r1(101)
      KS_Data_Len  : constant N32 := 208;
      --  psk_key_exchange_modes data: list_len(1) + mode(1)
      PSK_Data_Len : constant N32 := 2;
      --  supported_versions data: list_len(1) + version(2) * 2
      SV_Data_Len  : constant N32 := 5;

      --  ALPN data: protocol_list_len(2) + proto_len(1) + proto(N)
      ALPN_Len : constant Natural := HC.Cfg.ALPN.Len;
      ALPN_Data_Len : constant N32 :=
         (if ALPN_Len > 0 then N32 (3 + ALPN_Len) else 0);
      ALPN_Ext_Len : constant N32 :=
         (if ALPN_Len > 0 then 4 + ALPN_Data_Len else 0);

      --  Each extension: tag(2) + data_length(2) + data
      Ext_Total : constant N32 :=
         (4 + SNI_Data_Len) + (4 + SG_Data_Len) + (4 + SA_Data_Len) +
         (4 + KS_Data_Len) + (4 + PSK_Data_Len) + (4 + SV_Data_Len) +
         ALPN_Ext_Len;

      --  ClientHello body: version(2) + random(32) + sid_len(1) + sid(32)
      --  + suites_len(2) + suites(12) + comp_len(1) + comp(1)
      --  + ext_len(2) + extensions
      CH_Body_Len : constant N32 := 85 + Ext_Total;
      CH_Msg_Len  : constant N32 := 4 + CH_Body_Len;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      PK_Bytes    : Byte_Seq (0 .. 31);   --  X25519 public key
      P256_PK_Enc : Byte_Seq (0 .. 64);   --  P-256 public key (uncompressed)
      P384_PK_Enc : Byte_Seq (0 .. 96);   --  P-384 public key (uncompressed)
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate ephemeral X25519 keypair (Fiat X25519)
      Gen_Random (HC.Local_SK);
      declare
         Basepoint : constant Bytes_32 := (9, others => 0);
      begin
         SPARKTLS.X25519.Scalar_Mult (PK_Bytes, HC.Local_SK, Basepoint);
      end;

      --  Generate ephemeral P-256 keypair
      declare
         P256_Pt : SPARKTLS.P256.Point.P256_Jacobian;
      begin
         Gen_Random (HC.P256_Local_SK);
         --  Compute public key = [private_key] * G
         SPARKTLS.P256.Point.P256_Mulgen
           (P256_Pt, HC.P256_Local_SK, 32);
         SPARKTLS.P256.Point.P256_To_Affine (P256_Pt);
         SPARKTLS.P256.Point.P256_Encode (P256_PK_Enc, P256_Pt);
      end;

      --  Generate ephemeral P-384 keypair
      Gen_Random (HC.P384_Local_SK);
      SPARKTLS.P384.Point.P384_Mulgen (P384_PK_Enc, HC.P384_Local_SK);

      --  Generate client random
      Gen_Random (HC.Client_Random);

      --  Generate 32-byte legacy session ID for middlebox compatibility
      declare
         Legacy_Session_ID : Byte_Seq (0 .. 31);
      begin
         Gen_Random (Legacy_Session_ID);
         HC.Legacy_Session_ID := Legacy_Session_ID;
      end;

      --  PK_Bytes already set by X25519.Scalar_Mult above

      --  Allocate buffer for ClientHello body
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ClientHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);  --  0x0303 per RFC 8446
      Set_Random (Ctx, To_RFLX (HC.Client_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
      --  TLS version routes past cookie fields to cipher_suites_length
      --  6 suites: 3 TLS 1.3 + 3 TLS 1.2 ECDHE-AEAD = 12 bytes
      Set_Cipher_Suites_Length
        (Ctx, RFLX.TLS_Handshake.Cipher_Suites_Length (12));

      --  Build cipher suite sequence
      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

         --  Suite 1: TLS_AES_128_GCM_SHA256 (0x1301)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         --  Suite 2: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         --  Suite 3: TLS_AES_256_GCM_SHA384 (0x1302)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         --  Suite 4: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         --  Suite 5: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         --  Suite 6: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
            RFLX_Free (S_Buf);
         end;

         Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
      end;

      Set_Legacy_Compression_Methods_Length (Ctx, 1);
      Set_Legacy_Compression_Methods
        (Ctx, To_RFLX (Byte_Seq'(0 => 16#00#)));
      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Client_Hello_Extensions_Length (Ext_Total));

      --  Build extensions sequence
      declare
         Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  Extension 1: server_name (0x0000)
         declare
            Ext_Buf  : RBT.Bytes_Ptr;
            Ext_Ctx  : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            SNI_Raw  : Byte_Seq (0 .. SNI_Data_Len - 1);
         begin
            --  SNI list: list_len(2) + type(1) + name_len(2) + name
            SNI_Raw (0) := Byte ((Host_Len + 3) / 256);
            SNI_Raw (1) := Byte ((Host_Len + 3) mod 256);
            SNI_Raw (2) := 16#00#;  --  host_name type
            SNI_Raw (3) := Byte (Host_Len / 256);
            SNI_Raw (4) := Byte (Host_Len mod 256);
            for I in 1 .. HC.Cfg.Server_Name.Len loop
               SNI_Raw (4 + N32 (I)) :=
                  Byte (Character'Pos (HC.Cfg.Server_Name.Data (I)));
            end loop;

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SNI_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Server_Name);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (SNI_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SNI_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 2: supported_groups (0x000A)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            SG_Raw  : constant Byte_Seq (0 .. SG_Data_Len - 1) :=
               (16#00#, 16#06#,          --  list_len=6 (3 groups)
                16#00#, 16#1D#,          --  X25519
                16#00#, 16#17#,          --  secp256r1
                16#00#, 16#18#);         --  secp384r1
         begin
            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SG_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Groups);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (SG_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SG_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 3: signature_algorithms (0x000D)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            SA_Raw  : constant Byte_Seq (0 .. SA_Data_Len - 1) :=
               (16#00#, 16#0C#,          --  list_len=12 (6 algorithms)
                16#04#, 16#03#,          --  ecdsa_secp256r1_sha256
                16#05#, 16#03#,          --  ecdsa_secp384r1_sha384
                16#08#, 16#04#,          --  rsa_pss_rsae_sha256
                16#08#, 16#05#,          --  rsa_pss_rsae_sha384
                16#08#, 16#06#,          --  rsa_pss_rsae_sha512
                16#08#, 16#07#);         --  ed25519
         begin
            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SA_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Signature_Algorithms);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (SA_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SA_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 4: key_share (0x0033)
         --  Contains two key shares: X25519 (36 bytes) + secp256r1 (69 bytes)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            KS_Raw  : Byte_Seq (0 .. KS_Data_Len - 1);
            --  shares_len = 36 + 69 + 101 = 206
         begin
            KS_Raw := (others => 0);
            --  shares_len(2)
            KS_Raw (0) := 16#00#;
            KS_Raw (1) := 16#CE#;  --  206 bytes total
            --  X25519 key share: group(2) + key_len(2) + key(32)
            KS_Raw (2) := 16#00#;
            KS_Raw (3) := 16#1D#;  --  X25519
            KS_Raw (4) := 16#00#;
            KS_Raw (5) := 16#20#;  --  32 bytes
            KS_Raw (6 .. 37) := PK_Bytes;
            --  secp256r1 key share: group(2) + key_len(2) + key(65)
            KS_Raw (38) := 16#00#;
            KS_Raw (39) := 16#17#;  --  secp256r1
            KS_Raw (40) := 16#00#;
            KS_Raw (41) := 16#41#;  --  65 bytes
            KS_Raw (42 .. 106) := P256_PK_Enc;
            --  secp384r1 key share: group(2) + key_len(2) + key(97)
            KS_Raw (107) := 16#00#;
            KS_Raw (108) := 16#18#;  --  secp384r1
            KS_Raw (109) := 16#00#;
            KS_Raw (110) := 16#61#;  --  97 bytes
            KS_Raw (111 .. 207) := P384_PK_Enc;

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + KS_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Key_Share);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (KS_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (KS_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 5: psk_key_exchange_modes (0x002D)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            PSK_Raw : constant Byte_Seq (0 .. PSK_Data_Len - 1) :=
               (16#01#, 16#01#);  --  list_len=1, psk_dhe_ke
         begin
            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + PSK_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Psk_Key_Exchange_Modes);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (PSK_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (PSK_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 6: supported_versions (0x002B)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            SV_Raw  : constant Byte_Seq (0 .. SV_Data_Len - 1) :=
               (16#04#,                  --  list_len=4 (2 versions)
                16#03#, 16#04#,          --  TLS 1.3 (preferred)
                16#03#, 16#03#);         --  TLS 1.2 (fallback)
         begin
            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SV_Data_Len) => 0);
            RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Versions);
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (SV_Data_Len));
            RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SV_Raw));
            RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);
            RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 7: ALPN (0x0010) — if configured
         if ALPN_Len > 0 then
            declare
               Ext_Buf : RBT.Bytes_Ptr;
               Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
               ALPN_Raw : Byte_Seq (0 .. ALPN_Data_Len - 1)
                             := (others => 0);
            begin
               --  protocol_name_list_length (2 bytes)
               ALPN_Raw (0) := Byte ((ALPN_Len + 1) / 256);
               ALPN_Raw (1) := Byte ((ALPN_Len + 1) mod 256);
               --  protocol_name_length (1 byte)
               ALPN_Raw (2) := Byte (ALPN_Len);
               --  protocol_name
               for I in 1 .. ALPN_Len loop
                  ALPN_Raw (N32 (2 + I)) :=
                     Byte (Character'Pos (HC.Cfg.ALPN.Data (I)));
               end loop;

               Ext_Buf := new RBT.Bytes'
                  (1 .. RBT.Index (4 + ALPN_Data_Len) => 0);
               RFLX.TLS_Handshake.CH_Extension_TLS.Initialize
                  (Ext_Ctx, Ext_Buf);
               RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag
                  (Ext_Ctx,
                   RFLX.Tls_Extensiontype_Values
                     .Application_Layer_Protocol_Negotiation);
               RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
                  (Ext_Ctx,
                   RFLX.TLS_Handshake.Data_Length (ALPN_Data_Len));
               RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
                  (Ext_Ctx, To_RFLX (ALPN_Raw));
               RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
                  (Exts_Ctx, Ext_Ctx);
               RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
                  (Ext_Ctx, Ext_Buf);
               RFLX_Free (Ext_Buf);
            end;
         end if;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if CH_Msg_Len > N32 (Result'Length) then
         RFLX_Free (Buf);
         return;
      end if;

      Result (0) := HT_Client_Hello;
      Result (1) := Byte (CH_Body_Len / 65536);
      Result (2) := Byte ((CH_Body_Len / 256) mod 256);
      Result (3) := Byte (CH_Body_Len mod 256);
      Result (4 .. 4 + CH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (CH_Body_Len)));

      RFLX_Free (Buf);
      Len := CH_Msg_Len;

      --  If we have a cached session ticket, append pre_shared_key extension.
      --  This MUST be the last extension per RFC 8446 Section 4.2.11.
      --  We patch the extensions list length and handshake length after.
      if S.Ticket.Valid and then Len > 0 then
         declare
            use SPARKTLS.Hashing.SHA256;
            Tick_Len : constant N32 := S.Ticket.Ticket_Len;
            --  PSK identity: identity_len(2) + ticket + age(4)
            ID_Entry_Len : constant N32 := 2 + Tick_Len + 4;
            --  identities: len(2) + entry
            IDs_Len : constant N32 := 2 + ID_Entry_Len;
            --  binder: binder_len(1) + binder(32 or 48)
            Binder_Size : constant N32 :=
               (if S.Ticket.PSK_Len = 48 then 48 else 32);
            Binder_Entry_Len : constant N32 := 1 + Binder_Size;
            --  binders: len(2) + entry
            Binders_Len : constant N32 := 2 + Binder_Entry_Len;
            --  pre_shared_key extension: tag(2) + data_len(2) + identities + binders
            PSK_Ext_Len : constant N32 := 4 + IDs_Len + Binders_Len;
            --  New total message length
            New_Len     : constant N32 := Len + PSK_Ext_Len;
            P : N32;

            --  Location of the extensions_length field in the ClientHello
            --  After handshake header(4) + version(2) + random(32) + sid_len(1)
            --  + sid(32) + suites_len(2) + suites(6) + comp_len(1) + comp(1)
            Ext_Len_Offset : constant N32 := 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1;
            Old_Ext_Len : N32;
            New_Ext_Len : N32;
         begin
            if New_Len <= N32 (Result'Length) then
               --  Read current extensions length
               Old_Ext_Len := N32 (Result (Ext_Len_Offset)) * 256 +
                               N32 (Result (Ext_Len_Offset + 1));
               New_Ext_Len := Old_Ext_Len + PSK_Ext_Len;

               P := Len;

               --  pre_shared_key extension tag (0x0029)
               Result (P) := 0; Result (P + 1) := 16#29#;
               P := P + 2;
               --  data length
               Result (P) := Byte ((IDs_Len + Binders_Len) / 256);
               Result (P + 1) := Byte ((IDs_Len + Binders_Len) mod 256);
               P := P + 2;
               --  identities length
               Result (P) := Byte (ID_Entry_Len / 256);
               Result (P + 1) := Byte (ID_Entry_Len mod 256);
               P := P + 2;
               --  identity: ticket length + ticket
               Result (P) := Byte (Tick_Len / 256);
               Result (P + 1) := Byte (Tick_Len mod 256);
               P := P + 2;
               Result (P .. P + Tick_Len - 1) :=
                  S.Ticket.Ticket (0 .. Tick_Len - 1);
               P := P + Tick_Len;
               --  obfuscated_ticket_age (simplified: 0)
               Result (P) := 0; Result (P + 1) := 0;
               Result (P + 2) := 0; Result (P + 3) := 0;
               P := P + 4;
               --  binders length
               Result (P) := Byte (Binder_Entry_Len / 256);
               Result (P + 1) := Byte (Binder_Entry_Len mod 256);
               P := P + 2;
               --  binder: length byte + placeholder (zeroed, patched below)
               Result (P) := Byte (Binder_Size);
               P := P + 1;
               declare
                  Binder_Offset : constant N32 := P;
               begin
                  Result (P .. P + Binder_Size - 1) := (others => 0);
                  P := P + Binder_Size;

                  --  Patch handshake length
                  declare
                     New_Body_Len : constant N32 := P - 4;
                  begin
                     Result (1) := Byte (New_Body_Len / 65536);
                     Result (2) := Byte ((New_Body_Len / 256) mod 256);
                     Result (3) := Byte (New_Body_Len mod 256);
                  end;

                  --  Patch extensions length
                  Result (Ext_Len_Offset) := Byte (New_Ext_Len / 256);
                  Result (Ext_Len_Offset + 1) := Byte (New_Ext_Len mod 256);

                  --  Compute binder:
                  --  1. Hash the partial ClientHello up to (not including) binders
                  --  2. HMAC with binder_key derived from PSK
                  declare
                     --  The transcript for binder is just this (first) ClientHello
                     --  truncated: everything up to but not including the binders list
                     Trunc_Len    : constant N32 := Binder_Offset - Binders_Len;
                     Trunc_Hash   : Digest;
                     Binder_Key   : OKM_Seq (0 .. 31);
                     Finished_Key : OKM_Seq (0 .. 31);
                     Binder_Val   : Digest;
                  begin
                     Hash (Trunc_Hash,
                           Result (0 .. Trunc_Len - 1));

                     Key_Schedule.Derive_Binder_Key
                       (Binder_Key,
                        Bytes_32 (S.Ticket.PSK (0 .. 31)));

                     Key_Schedule.Derive_Finished_Key
                       (Finished_Key, Byte_Seq (Binder_Key));

                     HMAC_SHA_256
                       (Output => Binder_Val,
                        M      => Trunc_Hash,
                        K      => Byte_Seq (Finished_Key));

                     --  Write the real binder
                     Result (Binder_Offset .. Binder_Offset + 31) :=
                        Binder_Val;
                  end;
               end;

               Len := P;
            end if;
         end;
      end if;
   end Build_Client_Hello;

   --================================================================
   --  Parse procedures (using RecordFlux-generated parsers)
   --================================================================

   procedure Parse_Server_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      Body_Len : N32;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      OK := False;

      if Data'Length < 39 then
         return;
      end if;

      --  Check handshake type byte
      if Data (Data'First) /= HT_Server_Hello then
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Server_Hello context
      Body_Len := N32 (Data'Length) - 4;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Extract server random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Server_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract and validate cipher suite
      if not Well_Formed (Ctx, F_Cipher_Suite_TLS_Suite) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      declare
         Suite     : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
            Get_Cipher_Suite_TLS_Suite (Ctx);
         Suite_Val : constant Unsigned_16 :=
            Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (Suite));
      begin
         --  Accept TLS 1.3 and TLS 1.2 AEAD suites
         if Suite_Val not in Suite_CHACHA20_POLY1305_SHA256
                           | Suite_AES_128_GCM_SHA256
                           | Suite_AES_256_GCM_SHA384
                           | Suite_ECDHE_RSA_AES128_GCM_SHA256
                           | Suite_ECDHE_RSA_AES256_GCM_SHA384
                           | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                           | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                           | Suite_ECDHE_RSA_CHACHA20_SHA256
                           | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            return;
         end if;
         S.Negotiated_Suite := Suite_Val;
      end;

      --  Iterate extensions to find key_share
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
         begin
            Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

            while RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Element
                    (Exts_Ctx)
            loop
               declare
                  Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
               begin
                  RFLX.TLS_Handshake.SH_Extensions_TLS.Switch
                    (Exts_Ctx, Ext_Ctx);
                  RFLX.TLS_Handshake.SH_Extension_TLS.Verify_Message
                    (Ext_Ctx);

                  if RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message
                       (Ext_Ctx)
                  then
                     declare
                        Tag : constant
                           RFLX.Tls_Extensiontype_Values
                              .TLS_ExtensionType_Values :=
                           RFLX.TLS_Handshake.SH_Extension_TLS.Get_Tag
                             (Ext_Ctx);
                     begin
                        --  Check for supported_versions extension
                        if Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Supported_Versions
                        then
                           --  ServerHello has supported_versions → TLS 1.3
                           HC.Has_TLS_1_3 := True;

                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Key_Share
                        then
                           --  Parse key share via Key_Share_SH
                           declare
                              DLen    : constant N32 := N32
                                 (RFLX.TLS_Handshake.SH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              KS_Buf  : RBT.Bytes_Ptr;
                              KS_Ctx  : RFLX.TLS_Handshake
                                           .Key_Share_SH.Context;
                           begin
                              if DLen not in Wire_Key_Share_Len then
                                 null;  --  skip malformed key_share
                              else
                              declare
                                 VLen : constant Wire_Key_Share_Len := DLen;
                              begin
                              KS_Buf := new RBT.Bytes'(1 .. RBT.Index (VLen) => 0);
                              RFLX.TLS_Handshake.SH_Extension_TLS
                                .Get_Data (Ext_Ctx, KS_Buf.all);
                              RFLX.TLS_Handshake.Key_Share_SH.Initialize
                                (KS_Ctx, KS_Buf,
                                 Written_Last =>
                                    RBT.Bit_Length
                                       (RBT.Length (DLen) * 8));
                              RFLX.TLS_Handshake.Key_Share_SH
                                .Verify_Message (KS_Ctx);

                              if RFLX.TLS_Handshake.Key_Share_SH
                                   .Well_Formed_Message (KS_Ctx)
                              then
                                 declare
                                    Grp : constant
                                       RFLX.Tls_Parameters
                                          .TLS_Supported_Groups :=
                                       RFLX.TLS_Handshake.Key_Share_SH
                                          .Get_Group (KS_Ctx);
                                 begin
                                    if Grp.Known and then
                                       Grp.Enum =
                                          RFLX.Tls_Parameters.X25519
                                    then
                                       declare
                                          KB : RBT.Bytes (1 .. 32);
                                       begin
                                          RFLX.TLS_Handshake.Key_Share_SH
                                            .Get_Key_Exchange
                                              (KS_Ctx, KB);
                                          HC.Peer_PK := To_NaCl (KB);
                                          HC.Use_P256_KE := False;
                                       end;
                                    elsif Grp.Known and then
                                       Grp.Enum =
                                          RFLX.Tls_Parameters.Secp256r1
                                    then
                                       declare
                                          KB : RBT.Bytes (1 .. 65);
                                       begin
                                          RFLX.TLS_Handshake.Key_Share_SH
                                            .Get_Key_Exchange
                                              (KS_Ctx, KB);
                                          for I in 0 .. 64 loop
                                             HC.P256_Peer_PK (N32 (I)) :=
                                                Byte (KB (RBT.Index (I + 1)));
                                          end loop;
                                          HC.Use_P256_KE := True;
                                          HC.Use_P384_KE := False;
                                       end;
                                    elsif Grp.Known and then
                                       Grp.Enum =
                                          RFLX.Tls_Parameters.Secp384r1
                                    then
                                       declare
                                          KB : RBT.Bytes (1 .. 97);
                                       begin
                                          RFLX.TLS_Handshake.Key_Share_SH
                                            .Get_Key_Exchange
                                              (KS_Ctx, KB);
                                          for I in 0 .. 96 loop
                                             HC.P384_Peer_PK (N32 (I)) :=
                                                Byte (KB (RBT.Index (I + 1)));
                                          end loop;
                                          HC.Use_P384_KE := True;
                                          HC.Use_P256_KE := False;
                                       end;
                                    end if;
                                 end;
                              end if;

                              RFLX.TLS_Handshake.Key_Share_SH
                                .Take_Buffer (KS_Ctx, KS_Buf);
                              RFLX_Free (KS_Buf);
                              end;  --  VLen declare
                              end if;  --  DLen validation
                           end;

                        --  ALPN extension (0x0010)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values
                                .Application_Layer_Protocol_Negotiation
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.SH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                           begin
                              --  ALPN data: list_len(2)+proto_len(1)+proto.
                              --  Max useful: 2 + 1 + 255 = 258.
                              if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
                                 declare
                                    VLen     : constant Wire_Small_Ext_Len := DLen;
                                    ALPN_Buf : RBT.Bytes
                                       (1 .. RBT.Index (VLen));
                                 begin
                                    RFLX.TLS_Handshake.SH_Extension_TLS
                                      .Get_Data (Ext_Ctx, ALPN_Buf);
                                    declare
                                       PL : constant Natural :=
                                          Natural (ALPN_Buf (3));
                                    begin
                                       if PL > 0
                                          and PL <= Max_Hostname_Len
                                          and N32 (PL + 3) <= DLen
                                       then
                                          S.Negotiated_ALPN.Len := PL;
                                          for I in 1 .. PL loop
                                             S.Negotiated_ALPN.Data (I) :=
                                                Character'Val
                                                  (ALPN_Buf
                                                     (RBT.Index (3 + I)));
                                          end loop;
                                       end if;
                                    end;
                                 end;
                              end if;
                           end;

                        end if;
                     end;
                  end if;

                  RFLX.TLS_Handshake.SH_Extensions_TLS.Update
                    (Exts_Ctx, Ext_Ctx);
               end;
            end loop;

            Update_Extensions_TLS (Ctx, Exts_Ctx);
         end;
      end if;

      --  Set version based on supported_versions extension
      if HC.Has_TLS_1_3 then
         HC.Version := TLS_1_3;
      else
         HC.Version := TLS_1_2;

         --  RFC 8446 §4.1.3: Check downgrade sentinel.
         --  If server doesn't offer TLS 1.3 but its random ends with the
         --  sentinel, a MITM is stripping supported_versions. Abort.
         declare
            R : Byte_Seq renames HC.Server_Random;
            --  TLS 1.3→1.2 sentinel: "DOWNGRD" + 0x01
            Sentinel : constant Byte_Seq (0 .. 7) :=
              (16#44#, 16#4F#, 16#57#, 16#4E#,
               16#47#, 16#52#, 16#44#, 16#01#);
            Match : Boolean := True;
         begin
            for I in N32 range 0 .. 7 loop
               if R (24 + I) /= Sentinel (I) then
                  Match := False;
                  exit;
               end if;
            end loop;
            if Match then
               --  Downgrade detected — MITM stripping TLS 1.3
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;
         end;
      end if;

      --  For TLS 1.2, skip ECDHE shared secret here
      --  (it's computed after ServerKeyExchange)
      if HC.Version = TLS_1_2 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         OK := True;
         return;
      end if;

      --  Compute shared secret (TLS 1.3 only — key_share in ServerHello)
      if HC.Use_P384_KE then
         --  P-384 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Secret_384 : Bytes_48;
            P384_OK    : Boolean;
         begin
            SPARKTLS.P384.Point.P384_ECDHE
              (Secret  => Secret_384,
               OK      => P384_OK,
               SK      => HC.P384_Local_SK,
               Peer_PK => HC.P384_Peer_PK);
            if not P384_OK then
               OK := False;
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;
            HC.Shared_Secret := Secret_384;
         end;
      elsif HC.Use_P256_KE then
         --  P-256 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Peer_Pt : SPARKTLS.P256.Point.P256_Jacobian;
            Valid   : SPARKNaCl.U32;
            X_Bytes : Byte_Seq (0 .. 31);
         begin
            SPARKTLS.P256.Point.P256_Decode
              (Peer_Pt, HC.P256_Peer_PK, Valid);
            if Valid = 0 then
               OK := False;
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;
            --  Multiply peer's public key by our private scalar
            SPARKTLS.P256.Point.P256_Mul
              (Peer_Pt, HC.P256_Local_SK, 32);
            SPARKTLS.P256.Point.P256_To_Affine (Peer_Pt);
            --  Encode to get x-coordinate (bytes 1..32 of uncompressed point)
            declare
               Encoded : Byte_Seq (0 .. 64);
            begin
               SPARKTLS.P256.Point.P256_Encode (Encoded, Peer_Pt);
               X_Bytes := Encoded (1 .. 32);
            end;
            HC.Shared_Secret := (others => 0);
            HC.Shared_Secret (0 .. 31) := X_Bytes;
         end;
      else
         --  X25519 ECDHE
         HC.Shared_Secret := (others => 0);
         SPARKTLS.X25519.Scalar_Mult
           (HC.Shared_Secret (0 .. 31), HC.Local_SK, HC.Peer_PK);
      end if;

      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

      OK := True;
   end Parse_Server_Hello;

end SPARKTLS.Handshake.Client_Msgs;
