with Interfaces; use Interfaces;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.TLS_Handshake;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Handshake.CH_Extensions_TLS;
with RFLX.TLS_Handshake.CH_Extension_TLS;
with RFLX.TLS_Handshake.Key_Share_SH;
with RFLX.TLS_Handshake.Key_Share_CH;
with RFLX.TLS_Handshake.Key_Share_Entries;
with RFLX.TLS_Handshake.Key_Share_Entry;
with RFLX.TLS_Handshake.Cipher_Suites_TLS;
with RFLX.TLS_Handshake.Cipher_Suite_TLS;
with RFLX.TLS_Common;
with RFLX.TLS_Handshake.Encrypted_Extensions;
with RFLX.TLS_Handshake.Finished;
with RFLX.TLS_Handshake.Certificate;
with RFLX.TLS_Handshake.Certificate_Entries;
with RFLX.TLS_Handshake.Certificate_Entry;
with RFLX.TLS_Handshake.Certificate_Verify;
with RFLX.TLS_Handshake.Certificate_Request;
with RFLX.TLS_Handshake.CR_Extensions;
with RFLX.TLS_Handshake.CR_Extension;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;

package body SPARKTLS.Handshake with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;

   --================================================================
   --  Build procedures (keep manual serialization for simple output)
   --================================================================

   procedure Build_Client_Hello
     (S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      use RFLX.TLS_Common;

      SK : SPARKNaCl.Cryptobox.Secret_Key;
      PK : SPARKNaCl.Cryptobox.Public_Key;

      procedure Gen_Random (Output : out Byte_Seq) renames S.Cfg.Random.all;

      --  Extension data sizes
      Host_Len : constant N32 := N32 (S.Cfg.Server_Name.Len);
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
      --  supported_versions data: list_len(1) + version(2)
      SV_Data_Len  : constant N32 := 3;

      --  Each extension: tag(2) + data_length(2) + data
      Ext_Total : constant N32 :=
         (4 + SNI_Data_Len) + (4 + SG_Data_Len) + (4 + SA_Data_Len) +
         (4 + KS_Data_Len) + (4 + PSK_Data_Len) + (4 + SV_Data_Len);

      --  ClientHello body: version(2) + random(32) + sid_len(1) + sid(32)
      --  + suites_len(2) + suites(6) + comp_len(1) + comp(1)
      --  + ext_len(2) + extensions
      CH_Body_Len : constant N32 := 79 + Ext_Total;
      CH_Msg_Len  : constant N32 := 4 + CH_Body_Len;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      PK_Bytes    : Byte_Seq (0 .. 31);   --  X25519 public key
      P256_PK_Enc : Byte_Seq (0 .. 64);   --  P-256 public key (uncompressed)
      P384_PK_Enc : Byte_Seq (0 .. 96);   --  P-384 public key (uncompressed)
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate ephemeral X25519 keypair
      Gen_Random (S.Local_SK);
      SPARKNaCl.Cryptobox.Keypair (S.Local_SK, PK, SK);

      --  Generate ephemeral P-256 keypair
      declare
         P256_Pt : SPARKTLS.P256.Point.P256_Jacobian;
      begin
         Gen_Random (S.P256_Local_SK);
         --  Compute public key = [private_key] * G
         SPARKTLS.P256.Point.P256_Mulgen
           (P256_Pt, S.P256_Local_SK, 32);
         SPARKTLS.P256.Point.P256_To_Affine (P256_Pt);
         SPARKTLS.P256.Point.P256_Encode (P256_PK_Enc, P256_Pt);
      end;

      --  Generate ephemeral P-384 keypair
      Gen_Random (S.P384_Local_SK);
      SPARKTLS.P384.Point.P384_Mulgen (P384_PK_Enc, S.P384_Local_SK);

      --  Generate client random
      Gen_Random (S.Client_Random);

      --  Generate 32-byte legacy session ID for middlebox compatibility
      declare
         Legacy_Session_ID : Byte_Seq (0 .. 31);
      begin
         Gen_Random (Legacy_Session_ID);
         S.Legacy_Session_ID := Legacy_Session_ID;
      end;

      PK_Bytes := SPARKNaCl.Cryptobox.Serialize (PK);

      --  Allocate buffer for ClientHello body
      S.RFLX_Main := (others => 0);
      Buf := S.RFLX_Main'Unrestricted_Access;
      Initialize (Ctx, Buf);

      --  Set ClientHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);  --  0x0303 per RFC 8446
      Set_Random (Ctx, To_RFLX (S.Client_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (S.Legacy_Session_ID));
      --  TLS version routes past cookie fields to cipher_suites_length
      Set_Cipher_Suites_Length
        (Ctx, RFLX.TLS_Handshake.Cipher_Suites_Length (6));

      --  Build cipher suite sequence (3 suites)
      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

         --  Suite 1: TLS_AES_128_GCM_SHA256 (0x1301)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S.RFLX_Sub := (others => 0);
            S_Buf := S.RFLX_Sub'Unrestricted_Access;
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
         end;

         --  Suite 2: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S.RFLX_Sub := (others => 0);
            S_Buf := S.RFLX_Sub'Unrestricted_Access;
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
         end;

         --  Suite 3: TLS_AES_256_GCM_SHA384 (0x1302)
         declare
            S_Buf : RBT.Bytes_Ptr;
            S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
         begin
            S.RFLX_Sub := (others => 0);
            S_Buf := S.RFLX_Sub'Unrestricted_Access;
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite
              (S_Ctx, RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384);
            RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
              (Suites_Ctx, S_Ctx);
            RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
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
            for I in 1 .. S.Cfg.Server_Name.Len loop
               SNI_Raw (4 + N32 (I)) :=
                  Byte (Character'Pos (S.Cfg.Server_Name.Data (I)));
            end loop;

            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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
            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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
            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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

            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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
         end;

         --  Extension 5: psk_key_exchange_modes (0x002D)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            PSK_Raw : constant Byte_Seq (0 .. PSK_Data_Len - 1) :=
               (16#01#, 16#01#);  --  list_len=1, psk_dhe_ke
         begin
            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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
         end;

         --  Extension 6: supported_versions (0x002B)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            SV_Raw  : constant Byte_Seq (0 .. SV_Data_Len - 1) :=
               (16#02#, 16#03#, 16#04#);  --  list_len=2, TLS 1.3
         begin
            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
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
         end;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if CH_Msg_Len > N32 (Result'Length) then
         return;
      end if;

      Result (0) := HT_Client_Hello;
      Result (1) := Byte (CH_Body_Len / 65536);
      Result (2) := Byte ((CH_Body_Len / 256) mod 256);
      Result (3) := Byte (CH_Body_Len mod 256);
      Result (4 .. 4 + CH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (CH_Body_Len)));

      Len := CH_Msg_Len;
   end Build_Client_Hello;

   --================================================================
   --  Parse procedures (using RecordFlux-generated parsers)
   --================================================================

   procedure Parse_Server_Hello
     (S    : in out Session;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      B        : constant N32 := Data'First;
      Body_Len : N32;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      OK := False;

      if Data'Length < 39 then
         return;
      end if;

      --  Check handshake type byte
      if Data (B) /= HT_Server_Hello then
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Server_Hello context
      Body_Len := N32 (Data'Length) - 4;

      S.RFLX_Main := (others => 0);
      Buf := S.RFLX_Main'Unrestricted_Access;
      Buf.all := To_RFLX (Data (B + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         return;
      end if;

      --  Extract server random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         S.Server_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract and validate cipher suite
      if not Well_Formed (Ctx, F_Cipher_Suite_TLS_Suite) then
         Take_Buffer (Ctx, Buf);
         return;
      end if;

      declare
         Suite     : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
            Get_Cipher_Suite_TLS_Suite (Ctx);
         Suite_Val : constant Unsigned_16 :=
            Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (Suite));
      begin
         if Suite_Val /= Suite_CHACHA20_POLY1305_SHA256 and
            Suite_Val /= Suite_AES_128_GCM_SHA256 and
            Suite_Val /= Suite_AES_256_GCM_SHA384
         then
            Take_Buffer (Ctx, Buf);
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
                        if Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Key_Share
                        then
                           --  Parse key share via Key_Share_SH
                           declare
                              DLen    : constant N32 := N32
                                 (RFLX.TLS_Handshake.SH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              KS_Data : RBT.Bytes (1 .. RBT.Index (DLen));
                              KS_Buf  : RBT.Bytes_Ptr;
                              KS_Ctx  : RFLX.TLS_Handshake
                                           .Key_Share_SH.Context;
                           begin
                              RFLX.TLS_Handshake.SH_Extension_TLS
                                .Get_Data (Ext_Ctx, KS_Data);
                              S.RFLX_Sub := (others => 0);
                              KS_Buf := S.RFLX_Sub'Unrestricted_Access;
                              KS_Buf.all := KS_Data;
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
                                          S.Peer_PK := To_NaCl (KB);
                                          S.Use_P256_KE := False;
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
                                             S.P256_Peer_PK (N32 (I)) :=
                                                Byte (KB (RBT.Index (I + 1)));
                                          end loop;
                                          S.Use_P256_KE := True;
                                          S.Use_P384_KE := False;
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
                                             S.P384_Peer_PK (N32 (I)) :=
                                                Byte (KB (RBT.Index (I + 1)));
                                          end loop;
                                          S.Use_P384_KE := True;
                                          S.Use_P256_KE := False;
                                       end;
                                    end if;
                                 end;
                              end if;

                              RFLX.TLS_Handshake.Key_Share_SH
                                .Take_Buffer (KS_Ctx, KS_Buf);
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

      --  Compute shared secret
      if S.Use_P384_KE then
         --  P-384 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Secret_384 : Bytes_48;
            P384_OK    : Boolean;
         begin
            SPARKTLS.P384.Point.P384_ECDHE
              (Secret  => Secret_384,
               OK      => P384_OK,
               SK      => S.P384_Local_SK,
               Peer_PK => S.P384_Peer_PK);
            if not P384_OK then
               OK := False;
               Take_Buffer (Ctx, Buf);
               return;
            end if;
            S.Shared_Secret := Secret_384;
         end;
      elsif S.Use_P256_KE then
         --  P-256 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Peer_Pt : SPARKTLS.P256.Point.P256_Jacobian;
            Valid   : SPARKNaCl.U32;
            X_Bytes : Byte_Seq (0 .. 31);
         begin
            SPARKTLS.P256.Point.P256_Decode
              (Peer_Pt, S.P256_Peer_PK, Valid);
            if Valid = 0 then
               OK := False;
               Take_Buffer (Ctx, Buf);
               return;
            end if;
            --  Multiply peer's public key by our private scalar
            SPARKTLS.P256.Point.P256_Mul
              (Peer_Pt, S.P256_Local_SK, 32);
            SPARKTLS.P256.Point.P256_To_Affine (Peer_Pt);
            --  Encode to get x-coordinate (bytes 1..32 of uncompressed point)
            declare
               Encoded : Byte_Seq (0 .. 64);
            begin
               SPARKTLS.P256.Point.P256_Encode (Encoded, Peer_Pt);
               X_Bytes := Encoded (1 .. 32);
            end;
            S.Shared_Secret := (others => 0);
            S.Shared_Secret (0 .. 31) := X_Bytes;
         end;
      else
         --  X25519 ECDHE
         S.Shared_Secret := (others => 0);
         S.Shared_Secret (0 .. 31) :=
            SPARKNaCl.Scalar.Mult (S.Local_SK, S.Peer_PK);
      end if;

      Take_Buffer (Ctx, Buf);

      OK := True;
   end Parse_Server_Hello;

   procedure Parse_Handshake_Header
     (Data     : in     Byte_Seq;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      OK       :    out Boolean)
   is
      use RFLX.TLS_Handshake.TLS_Handshake;
      Ctx : Context;
   begin
      Msg_Type := 0;
      Msg_Len  := 0;
      OK       := False;

      if Data'Length < 4 then
         return;
      end if;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Data'Length));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      begin
         Buf.all := To_RFLX (Data);
         Initialize (Ctx, Buf,
                     Written_Last =>
                        RBT.Bit_Length (RBT.Length (Data'Length) * 8));
         Verify_Message (Ctx);

         if Well_Formed_Message (Ctx) then
            Msg_Type := Byte (RFLX.Tls_Parameters.To_Base_Integer
                                (Get_Tag (Ctx)));
            Msg_Len  := N32 (RFLX.TLS_Handshake.To_Base_Integer
                               (Get_Length (Ctx)));
            OK := True;
         end if;

         Take_Buffer (Ctx, Buf);
      end;
   end Parse_Handshake_Header;

   procedure Build_Finished
     (Verify_Data : in     Bytes_32;
      Result      :    out Byte_Seq;
      Len         :    out N32)
   is
      use RFLX.TLS_Handshake.Finished;
      Body_Len : constant N32 := 32;
      Msg_Len  : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Body_Len));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      begin
         Buf_Arr := (others => 0);
         Initialize (Ctx, Buf);
         Set_Verify_Data (Ctx, To_RFLX (Verify_Data));
         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Finished;
         Result (1) := 16#00#;
         Result (2) := 16#00#;
         Result (3) := Byte (Body_Len);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
      end;

      Len := Msg_Len;
   end Build_Finished;

   procedure Parse_Client_Hello
     (S    : in out Session;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      B        : constant N32 := Data'First;
      Body_Len : N32;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      OK := False;

      if Data'Length < 39 then
         return;
      end if;

      if Data (B) /= HT_Client_Hello then
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Client_Hello context
      Body_Len := N32 (Data'Length) - 4;

      S.RFLX_Main := (others => 0);
      Buf := S.RFLX_Main'Unrestricted_Access;
      Buf.all := To_RFLX (Data (B + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         return;
      end if;

      --  Extract client random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         S.Client_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract legacy session ID
      declare
         SID_Len : constant N32 :=
            N32 (Get_Legacy_Session_ID_Length (Ctx));
      begin
         S.Legacy_Session_ID := (others => 0);
         if SID_Len > 0 and SID_Len <= 32 then
            declare
               SID : RBT.Bytes (1 .. RBT.Index (SID_Len));
            begin
               Get_Legacy_Session_ID (Ctx, SID);
               S.Legacy_Session_ID (0 .. SID_Len - 1) := To_NaCl (SID);
            end;
         end if;
      end;

      --  Iterate cipher suites to find one we support
      S.Negotiated_Suite := 0;

      if Well_Formed (Ctx, F_Cipher_Suites_TLS) then
         declare
            Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
         begin
            Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

            while RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Element
                    (Suites_Ctx)
            loop
               declare
                  Suite_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
               begin
                  RFLX.TLS_Handshake.Cipher_Suites_TLS.Switch
                    (Suites_Ctx, Suite_Ctx);
                  RFLX.TLS_Handshake.Cipher_Suite_TLS.Verify_Message
                    (Suite_Ctx);

                  if RFLX.TLS_Handshake.Cipher_Suite_TLS.Well_Formed_Message
                       (Suite_Ctx)
                  then
                     declare
                        Suite : constant
                           RFLX.Tls_Parameters.TLS_Cipher_Suites :=
                           RFLX.TLS_Handshake.Cipher_Suite_TLS.Get_Suite
                             (Suite_Ctx);
                        Val   : Unsigned_16;
                     begin
                        Val := Unsigned_16
                                 (RFLX.Tls_Parameters.To_Base_Integer
                                    (Suite));
                        if (Val = Suite_AES_256_GCM_SHA384 or
                            Val = Suite_AES_128_GCM_SHA256 or
                            Val = Suite_CHACHA20_POLY1305_SHA256) and then
                           S.Negotiated_Suite = 0
                        then
                           S.Negotiated_Suite := Val;
                        end if;
                     end;
                  end if;

                  RFLX.TLS_Handshake.Cipher_Suites_TLS.Update
                    (Suites_Ctx, Suite_Ctx);
               end;
            end loop;

            Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
         end;
      end if;

      if S.Negotiated_Suite = 0 then
         Take_Buffer (Ctx, Buf);
         return;
      end if;

      --  Iterate extensions to find key_share (using RFLX)
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
         begin
            Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

            while RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Element
                    (Exts_Ctx)
            loop
               declare
                  Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
               begin
                  RFLX.TLS_Handshake.CH_Extensions_TLS.Switch
                    (Exts_Ctx, Ext_Ctx);
                  RFLX.TLS_Handshake.CH_Extension_TLS.Verify_Message
                    (Ext_Ctx);

                  if RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message
                       (Ext_Ctx)
                  then
                     declare
                        Tag : constant
                           RFLX.Tls_Extensiontype_Values
                              .TLS_ExtensionType_Values :=
                           RFLX.TLS_Handshake.CH_Extension_TLS.Get_Tag
                             (Ext_Ctx);
                     begin
                        if Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Key_Share
                        then
                           --  Parse key share via Key_Share_CH
                           declare
                              DLen    : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              KS_Data : RBT.Bytes (1 .. RBT.Index (DLen));
                              KS_Buf  : RBT.Bytes_Ptr;
                              KS_Ctx  : RFLX.TLS_Handshake
                                           .Key_Share_CH.Context;
                           begin
                              RFLX.TLS_Handshake.CH_Extension_TLS
                                .Get_Data (Ext_Ctx, KS_Data);
                              S.RFLX_Sub := (others => 0);
                              KS_Buf := S.RFLX_Sub'Unrestricted_Access;
                              KS_Buf.all := KS_Data;
                              RFLX.TLS_Handshake.Key_Share_CH.Initialize
                                (KS_Ctx, KS_Buf,
                                 Written_Last =>
                                    RBT.Bit_Length
                                       (RBT.Length (DLen) * 8));
                              RFLX.TLS_Handshake.Key_Share_CH
                                .Verify_Message (KS_Ctx);

                              if RFLX.TLS_Handshake.Key_Share_CH
                                   .Well_Formed_Message (KS_Ctx)
                              then
                                 --  Iterate key share entries
                                 declare
                                    Shares_Ctx :
                                       RFLX.TLS_Handshake
                                          .Key_Share_Entries.Context;
                                 begin
                                    RFLX.TLS_Handshake.Key_Share_CH
                                      .Switch_To_Shares
                                        (KS_Ctx, Shares_Ctx);

                                    while RFLX.TLS_Handshake
                                            .Key_Share_Entries
                                            .Has_Element (Shares_Ctx)
                                    loop
                                       declare
                                          E_Ctx :
                                             RFLX.TLS_Handshake
                                                .Key_Share_Entry.Context;
                                       begin
                                          RFLX.TLS_Handshake
                                            .Key_Share_Entries.Switch
                                              (Shares_Ctx, E_Ctx);
                                          RFLX.TLS_Handshake
                                            .Key_Share_Entry
                                            .Verify_Message (E_Ctx);

                                          if RFLX.TLS_Handshake
                                               .Key_Share_Entry
                                               .Well_Formed_Message (E_Ctx)
                                          then
                                             declare
                                                Grp : constant
                                                   RFLX.Tls_Parameters
                                                      .TLS_Supported_Groups
                                                   :=
                                                   RFLX.TLS_Handshake
                                                     .Key_Share_Entry
                                                     .Get_Group (E_Ctx);
                                             begin
                                                if Grp.Known and then
                                                   Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .X25519
                                                then
                                                   declare
                                                      KB : RBT.Bytes
                                                             (1 .. 32);
                                                   begin
                                                      RFLX.TLS_Handshake
                                                        .Key_Share_Entry
                                                        .Get_Key_Exchange
                                                          (E_Ctx, KB);
                                                      S.Peer_PK :=
                                                         To_NaCl (KB);
                                                   end;
                                                end if;
                                             end;
                                          end if;

                                          RFLX.TLS_Handshake
                                            .Key_Share_Entries.Update
                                              (Shares_Ctx, E_Ctx);
                                       end;
                                    end loop;

                                    RFLX.TLS_Handshake.Key_Share_CH
                                      .Update_Shares
                                        (KS_Ctx, Shares_Ctx);
                                 end;
                              end if;

                              RFLX.TLS_Handshake.Key_Share_CH
                                .Take_Buffer (KS_Ctx, KS_Buf);
                           end;
                        end if;
                     end;
                  end if;

                  RFLX.TLS_Handshake.CH_Extensions_TLS.Update
                    (Exts_Ctx, Ext_Ctx);
               end;
            end loop;

            Update_Extensions_TLS (Ctx, Exts_Ctx);
         end;
      end if;

      Take_Buffer (Ctx, Buf);

      --  Compute shared secret (server only supports X25519 for now)
      S.Shared_Secret := (others => 0);
      S.Shared_Secret (0 .. 31) :=
         SPARKNaCl.Scalar.Mult (S.Local_SK, S.Peer_PK);

      OK := True;
   end Parse_Client_Hello;

   --================================================================
   --  Server-side build procedures
   --================================================================

   procedure Build_Server_Hello
     (S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      use RFLX.TLS_Common;

      SK : SPARKNaCl.Cryptobox.Secret_Key;
      PK : SPARKNaCl.Cryptobox.Public_Key;

      procedure Gen_Random (Output : out Byte_Seq) renames S.Cfg.Random.all;

      function To_Suite_Enum (Val : Unsigned_16)
         return RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum
      is
      begin
         case Val is
            when Suite_AES_128_GCM_SHA256 =>
               return RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256;
            when Suite_AES_256_GCM_SHA384 =>
               return RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384;
            when others =>
               return RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256;
         end case;
      end To_Suite_Enum;

      --  Extension data sizes (fixed for ServerHello)
      --  key_share: group(2) + key_len(2) + key(32) = 36
      KS_Data_Len : constant := 36;
      --  supported_versions: version(2)
      SV_Data_Len : constant := 2;
      --  Total extensions: (4+36) + (4+2) = 46
      Ext_Total   : constant := (4 + KS_Data_Len) + (4 + SV_Data_Len);

      --  ServerHello body: version(2) + random(32) + sid_len(1) + sid(32)
      --  + suite(2) + comp(1) + ext_len(2) + extensions(46) = 118
      SH_Body_Len : constant N32 := 118;
      SH_Msg_Len  : constant N32 := 4 + SH_Body_Len;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      PK_Bytes : Byte_Seq (0 .. 31);
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate ephemeral X25519 keypair
      Gen_Random (S.Local_SK);
      SPARKNaCl.Cryptobox.Keypair (S.Local_SK, PK, SK);

      --  Generate server random
      Gen_Random (S.Server_Random);

      --  Compute shared secret (server only supports X25519 for now)
      S.Shared_Secret := (others => 0);
      S.Shared_Secret (0 .. 31) :=
         SPARKNaCl.Scalar.Mult (S.Local_SK, S.Peer_PK);

      PK_Bytes := SPARKNaCl.Cryptobox.Serialize (PK);

      --  Allocate buffer for ServerHello body
      S.RFLX_Main := (others => 0);
      Buf := S.RFLX_Main'Unrestricted_Access;
      Initialize (Ctx, Buf);

      --  Set ServerHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);
      Set_Random (Ctx, To_RFLX (S.Server_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (S.Legacy_Session_ID));
      Set_Cipher_Suite_TLS_Suite (Ctx, To_Suite_Enum (S.Negotiated_Suite));
      Set_Legacy_Compression_Method (Ctx, 0);
      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Server_Hello_Extensions_Length (Ext_Total));

      --  Build extensions sequence
      declare
         Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  Extension 1: key_share (0x0033)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
            KS_Raw  : Byte_Seq (0 .. KS_Data_Len - 1);
         begin
            --  Build key_share data: group(2) + key_len(2) + key(32)
            KS_Raw (0) := 16#00#;
            KS_Raw (1) := 16#1D#;  --  X25519
            KS_Raw (2) := 16#00#;
            KS_Raw (3) := 16#20#;  --  32 bytes
            KS_Raw (4 .. 35) := PK_Bytes;

            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Key_Share);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, KS_Data_Len);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (KS_Raw));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
         end;

         --  Extension 2: supported_versions (0x002B)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
            SV_Raw  : Byte_Seq (0 .. SV_Data_Len - 1);
         begin
            SV_Raw (0) := 16#03#;
            SV_Raw (1) := 16#04#;  --  TLS 1.3

            S.RFLX_Sub := (others => 0);
            Ext_Buf := S.RFLX_Sub'Unrestricted_Access;
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Versions);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, SV_Data_Len);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SV_Raw));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
         end;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if SH_Msg_Len > N32 (Result'Length) then
         return;
      end if;

      Result (0) := HT_Server_Hello;
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);
      Result (4 .. 4 + SH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (SH_Body_Len)));

      Len := SH_Msg_Len;
   end Build_Server_Hello;

   procedure Build_Encrypted_Extensions
     (Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Encrypted_Extensions;
      Body_Len : constant N32 := 2;  --  length(2) with empty extensions
      Msg_Len  : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Body_Len));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      begin
         Buf_Arr := (others => 0);
         Initialize (Ctx, Buf);
         Set_Length (Ctx, 0);
         Set_Extensions_Empty (Ctx);
         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Encrypted_Extensions;
         Result (1) := 16#00#;
         Result (2) := 16#00#;
         Result (3) := Byte (Body_Len);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
      end;

      Len := Msg_Len;
   end Build_Encrypted_Extensions;

   procedure Build_Certificate
     (Cert_DER : in     Byte_Seq;
      Cert_Len : in     N32;
      Result   :    out Byte_Seq;
      Len      :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate;
      --  Certificate entry: cert_data_len(3) + cert_data + ext_len(2) = 5 + Cert_Len
      Entry_Len : constant N32 := 3 + Cert_Len + 2;
      List_Len  : constant N32 := Entry_Len;
      --  Body: context_len(1) + context(0) + list_len(3) + list
      Body_Len  : constant N32 := 1 + 3 + List_Len;
      Msg_Len   : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      if Msg_Len > N32 (Result'Length) then
         return;
      end if;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Body_Len));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      begin
         Buf_Arr := (others => 0);
         Initialize (Ctx, Buf);

         --  Empty certificate_request_context
         Set_Certificate_Request_Context_Length (Ctx, 0);
         Set_Certificate_Request_Context_Empty (Ctx);

         --  Certificate list with one entry
         Set_Certificate_List_Length
           (Ctx, RFLX.TLS_Handshake.Certificate_List_Length (List_Len));

         declare
            Entries_Ctx : RFLX.TLS_Handshake.Certificate_Entries.Context;
         begin
            Switch_To_Certificate_List (Ctx, Entries_Ctx);

            --  Build one certificate entry
            declare
               E_Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Entry_Len));
               E_Buf : RBT.Bytes_Ptr := E_Buf_Arr'Unrestricted_Access;
               E_Ctx : RFLX.TLS_Handshake.Certificate_Entry.Context;
            begin
               E_Buf_Arr := (others => 0);
               RFLX.TLS_Handshake.Certificate_Entry.Initialize (E_Ctx, E_Buf);
               RFLX.TLS_Handshake.Certificate_Entry.Set_Cert_Data_Length
                 (E_Ctx, RFLX.TLS_Handshake.Cert_Data_Length (Cert_Len));
               RFLX.TLS_Handshake.Certificate_Entry.Set_Cert_Data
                 (E_Ctx, To_RFLX (Cert_DER (0 .. Cert_Len - 1)));
               RFLX.TLS_Handshake.Certificate_Entry.Set_Extensions_Length
                 (E_Ctx, 0);
               RFLX.TLS_Handshake.Certificate_Entry.Set_Extensions_Empty
                 (E_Ctx);
               RFLX.TLS_Handshake.Certificate_Entries.Append_Element
                 (Entries_Ctx, E_Ctx);
               RFLX.TLS_Handshake.Certificate_Entry.Take_Buffer
                 (E_Ctx, E_Buf);
            end;

            Update_Certificate_List (Ctx, Entries_Ctx);
         end;

         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Certificate;
         Result (1) := Byte (Body_Len / 65536);
         Result (2) := Byte ((Body_Len / 256) mod 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
      end;

      Len := Msg_Len;
   end Build_Certificate;

   procedure Build_Certificate_Verify
     (Transcript_Hash : in     Byte_Seq;
      Signing_Key     : in     Bytes_64;
      Role            : in     TLS_Role;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Verify;

      --  RFC 8446 §4.4.3: context strings (both 34 chars)
      Context_Str : constant String :=
         (if Role = Role_Server
          then "TLS 1.3, server CertificateVerify"
          else "TLS 1.3, client CertificateVerify");
      H_Len       : constant N32 := N32 (Transcript_Hash'Length);
      Content_Len : constant N32 := 64 + N32 (Context_Str'Length) + 1 + H_Len;
      SM_Len      : constant N32 := 64 + Content_Len;
      Content     : Byte_Seq (0 .. Content_Len - 1);
      SM          : Byte_Seq (0 .. SM_Len - 1);
      SK          : SPARKNaCl.Sign.Signing_SK;

      --  Body: algorithm(2) + sig_len(2) + signature(64) = 68
      Body_Len : constant N32 := 68;
      Msg_Len  : constant N32 := 4 + Body_Len;
   begin
      Result := (others => 0);
      Len := 0;

      --  Build the content to sign (RFC 8446 Section 4.4.3)
      Content (0 .. 63) := (others => 16#20#);
      for I in Context_Str'Range loop
         Content (64 + N32 (I - Context_Str'First)) :=
            Byte (Character'Pos (Context_Str (I)));
      end loop;
      Content (64 + N32 (Context_Str'Length)) := 16#00#;
      Content (64 + N32 (Context_Str'Length) + 1 ..
               64 + N32 (Context_Str'Length) + H_Len) := Transcript_Hash;

      SPARKNaCl.Sign.Utils.Construct (Signing_Key, SK);
      SPARKNaCl.Sign.Sign (SM, Content, SK);

      if Msg_Len > N32 (Result'Length) then
         return;
      end if;

      declare
         Sig : constant Byte_Seq (0 .. 63) := SM (0 .. 63);
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Body_Len));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
         Ctx : Context;
      begin
         Buf_Arr := (others => 0);
         Initialize (Ctx, Buf);
         Set_Algorithm (Ctx, RFLX.Tls_Parameters.Ed25519_0807);
         Set_Signature_Length
           (Ctx, RFLX.TLS_Handshake.Signature_Length (64));
         Set_Signature (Ctx, To_RFLX (Sig));
         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Certificate_Verify;
         Result (1) := 16#00#;
         Result (2) := Byte (Body_Len / 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
      end;

      Len := Msg_Len;
   end Build_Certificate_Verify;

   --================================================================
   --  Build_Certificate_Request (mTLS)
   --  Uses RFLX Certificate_Request serializer.
   --================================================================
   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Request;
      use RFLX.Tls_Extensiontype_Values;

      --  signature_algorithms extension data:
      --    algo_list_length(2) + Ed25519(2) + P256-SHA256(2) + P384-SHA384(2) = 8
      Sig_Algo_Data : constant RBT.Bytes (1 .. 8) :=
        (1 => 0, 2 => 6,           --  algo list length = 6
         3 => 16#08#, 4 => 16#07#,  --  Ed25519
         5 => 16#04#, 6 => 16#03#,  --  ECDSA-P256-SHA256
         7 => 16#05#, 8 => 16#03#); --  ECDSA-P384-SHA384

      --  Extension: type(2) + data_len(2) + data(8) = 12
      Ext_Len   : constant N32 := 12;
      --  Body: context_len(1) + ext_list_len(2) + extension(12) = 15
      Body_Len  : constant N32 := 1 + 2 + Ext_Len;
      Msg_Len   : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      if Msg_Len > N32 (Result'Length) then
         return;
      end if;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Body_Len));
         Buf : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      begin
         Buf_Arr := (others => 0);
         Initialize (Ctx, Buf);

         --  Empty certificate_request_context
         Set_Certificate_Request_Context_Length (Ctx, 0);
         Set_Certificate_Request_Context_Empty (Ctx);

         --  Extensions
         Set_Extensions_Length
           (Ctx, RFLX.TLS_Handshake.Certificate_Request_Extensions_Length
                    (Ext_Len));

         declare
            Ext_Seq_Ctx : RFLX.TLS_Handshake.CR_Extensions.Context;
         begin
            Switch_To_Extensions (Ctx, Ext_Seq_Ctx);

            --  Build signature_algorithms extension
            declare
               E_Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Ext_Len));
               E_Buf : RBT.Bytes_Ptr := E_Buf_Arr'Unrestricted_Access;
               E_Ctx : RFLX.TLS_Handshake.CR_Extension.Context;
            begin
               E_Buf_Arr := (others => 0);
               RFLX.TLS_Handshake.CR_Extension.Initialize (E_Ctx, E_Buf);
               RFLX.TLS_Handshake.CR_Extension.Set_Tag
                 (E_Ctx, Signature_Algorithms);
               RFLX.TLS_Handshake.CR_Extension.Set_Data_Length
                 (E_Ctx, RFLX.TLS_Handshake.Data_Length
                            (Sig_Algo_Data'Length));
               RFLX.TLS_Handshake.CR_Extension.Set_Data
                 (E_Ctx, Sig_Algo_Data);
               RFLX.TLS_Handshake.CR_Extensions.Append_Element
                 (Ext_Seq_Ctx, E_Ctx);
               RFLX.TLS_Handshake.CR_Extension.Take_Buffer
                 (E_Ctx, E_Buf);
            end;

            Update_Extensions (Ctx, Ext_Seq_Ctx);
         end;

         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Certificate_Request;
         Result (1) := Byte (Body_Len / 65536);
         Result (2) := Byte ((Body_Len / 256) mod 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
      end;

      Len := Msg_Len;
   end Build_Certificate_Request;

end SPARKTLS.Handshake;
