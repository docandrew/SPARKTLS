with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Scalar;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKTLS.P256.ECDSA;
with SPARKTLS.P384.ECDSA;
with SPARKTLS.Key_Schedule;
with SPARKNaCl.HKDF;   use SPARKNaCl.HKDF;
with SPARKNaCl.MAC;    use SPARKNaCl.MAC;
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
with SPARKTLS.RSA;

package body SPARKTLS.Handshake with
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

      SK : SPARKNaCl.Cryptobox.Secret_Key;
      PK : SPARKNaCl.Cryptobox.Public_Key;

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
      Gen_Random (HC.Local_SK);
      SPARKNaCl.Cryptobox.Keypair (HC.Local_SK, PK, SK);

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

      PK_Bytes := SPARKNaCl.Cryptobox.Serialize (PK);

      --  Allocate buffer for ClientHello body
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ClientHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);  --  0x0303 per RFC 8446
      Set_Random (Ctx, To_RFLX (HC.Client_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
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
               (16#02#, 16#03#, 16#04#);  --  list_len=2, TLS 1.3
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
            use SPARKNaCl.Hashing.SHA256;
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

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (B + 4 .. Data'Last));
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
         if Suite_Val /= Suite_CHACHA20_POLY1305_SHA256 and
            Suite_Val /= Suite_AES_128_GCM_SHA256 and
            Suite_Val /= Suite_AES_256_GCM_SHA384
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
                        if Tag.Known and then
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
                              KS_Buf := new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
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
         HC.Shared_Secret (0 .. 31) :=
            SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
      end if;

      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

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

      if Data'Length < 4 or Data'Length > Max_Record_Plaintext then
         return;
      end if;

      declare
         Buf : RBT.Bytes_Ptr :=
            new RBT.Bytes'(1 .. RBT.Index (Data'Length) => 0);
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
            --  Validate known handshake type (TLS 1.2 + 1.3)
            if Msg_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                           16#0B# | 16#0C# | 16#0D# | 16#0E# |
                           16#0F# | 16#10# | 16#14#
            then
               OK := True;
            end if;
         end if;

         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
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
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
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
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Finished;

   procedure Parse_Client_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
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

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (B + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Extract client random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Client_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract legacy session ID
      declare
         SID_Len : constant N32 :=
            N32 (Get_Legacy_Session_ID_Length (Ctx));
      begin
         HC.Legacy_Session_ID := (others => 0);
         if SID_Len > 0 and SID_Len <= 32 then
            declare
               SID : RBT.Bytes (1 .. RBT.Index (SID_Len));
            begin
               Get_Legacy_Session_ID (Ctx, SID);
               HC.Legacy_Session_ID (0 .. SID_Len - 1) := To_NaCl (SID);
            end;
         end if;
      end;

      --  Iterate cipher suites to find one we support
      --  Store best TLS 1.3 suite and best TLS 1.2 suite separately.
      --  Version negotiation later picks the right one.
      S.Negotiated_Suite := 0;
      S.Negotiated_Suite_12 := 0;

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
                        --  TLS 1.3 suites (0x13xx)
                        if S.Negotiated_Suite = 0 and then
                           Val in Suite_AES_256_GCM_SHA384
                                | Suite_AES_128_GCM_SHA256
                                | Suite_CHACHA20_POLY1305_SHA256
                        then
                           S.Negotiated_Suite := Val;
                        end if;

                        --  TLS 1.2 suites (0xC0xx/0xCCxx)
                        if S.Negotiated_Suite_12 = 0 and then
                           Val in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                | Suite_ECDHE_RSA_AES256_GCM_SHA384
                                | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                                | Suite_ECDHE_RSA_CHACHA20_SHA256
                                | Suite_ECDHE_ECDSA_CHACHA20_SHA256
                        then
                           S.Negotiated_Suite_12 := Val;
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

      --  Need at least one matching suite (either TLS 1.3 or 1.2)
      if S.Negotiated_Suite = 0 and S.Negotiated_Suite_12 = 0 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
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
                              KS_Buf  : RBT.Bytes_Ptr;
                              KS_Ctx  : RFLX.TLS_Handshake
                                           .Key_Share_CH.Context;
                           begin
                              KS_Buf := new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
                              RFLX.TLS_Handshake.CH_Extension_TLS
                                .Get_Data (Ext_Ctx, KS_Buf.all);
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
                                                if Grp.Known then
                                                   if Grp.Enum =
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
                                                         HC.Peer_PK :=
                                                            To_NaCl (KB);
                                                         HC.Client_Has_X25519
                                                            := True;
                                                      end;
                                                   elsif Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .Secp256r1
                                                   then
                                                      declare
                                                         KLen : constant N32 :=
                                                            N32 (RFLX.TLS_Handshake
                                                               .Key_Share_Entry
                                                               .Get_Length
                                                                  (E_Ctx));
                                                         KB : RBT.Bytes
                                                                (1 .. RBT.Index (KLen));
                                                      begin
                                                         if KLen = 65 then
                                                            RFLX.TLS_Handshake
                                                              .Key_Share_Entry
                                                              .Get_Key_Exchange
                                                                (E_Ctx, KB);
                                                            for I in N32 range 0 .. 64 loop
                                                               HC.P256_Peer_PK (I) :=
                                                                  Byte (KB (RBT.Index (I + 1)));
                                                            end loop;
                                                            HC.Client_Has_P256
                                                               := True;
                                                         end if;
                                                      end;
                                                   elsif Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .Secp384r1
                                                   then
                                                      declare
                                                         KLen : constant N32 :=
                                                            N32 (RFLX.TLS_Handshake
                                                               .Key_Share_Entry
                                                               .Get_Length
                                                                  (E_Ctx));
                                                         KB : RBT.Bytes
                                                                (1 .. RBT.Index (KLen));
                                                      begin
                                                         if KLen = 97 then
                                                            RFLX.TLS_Handshake
                                                              .Key_Share_Entry
                                                              .Get_Key_Exchange
                                                                (E_Ctx, KB);
                                                            for I in N32 range 0 .. 96 loop
                                                               HC.P384_Peer_PK (I) :=
                                                                  Byte (KB (RBT.Index (I + 1)));
                                                            end loop;
                                                            HC.Client_Has_P384
                                                               := True;
                                                         end if;
                                                      end;
                                                   end if;
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
                              RFLX_Free (KS_Buf);
                           end;

                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values
                                 .Signature_Algorithms
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              SA_Data : RBT.Bytes
                                          (1 .. RBT.Index (DLen));
                              Pos : RBT.Index := 3;
                           begin
                              RFLX.TLS_Handshake.CH_Extension_TLS
                                .Get_Data (Ext_Ctx, SA_Data);
                              if DLen >= 4 then
                                 while Pos + 1 <= RBT.Index (DLen)
                                    and then HC.Peer_Sig_Algo_Count <
                                                Max_Sig_Algos
                                 loop
                                    HC.Peer_Sig_Algos
                                      (HC.Peer_Sig_Algo_Count) :=
                                       Unsigned_16 (SA_Data (Pos)) * 256 +
                                       Unsigned_16 (SA_Data (Pos + 1));
                                    HC.Peer_Sig_Algo_Count :=
                                       HC.Peer_Sig_Algo_Count + 1;
                                    Pos := Pos + 2;
                                 end loop;
                              end if;
                           end;

                        --  supported_groups extension (0x000A)
                        --  Used by TLS 1.2 to signal supported ECDHE curves
                        --  (TLS 1.3 also uses this alongside key_share)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Supported_Groups
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              SG_Data : RBT.Bytes
                                          (1 .. RBT.Index (DLen));
                              List_Len : N32;
                              Pos : N32;
                           begin
                              if DLen >= 4 then
                                 RFLX.TLS_Handshake.CH_Extension_TLS
                                   .Get_Data (Ext_Ctx, SG_Data);
                                 --  Format: list_len(2) || group(2) || ...
                                 List_Len := N32 (SG_Data (1)) * 256 +
                                             N32 (SG_Data (2));
                                 Pos := 3;
                                 while Pos + 1 <= N32 (DLen)
                                    and then Pos < 3 + List_Len
                                 loop
                                    declare
                                       Grp : constant Unsigned_16 :=
                                          Unsigned_16 (SG_Data (RBT.Index (Pos))) * 256 +
                                          Unsigned_16 (SG_Data (RBT.Index (Pos + 1)));
                                    begin
                                       if Grp = 16#001D# then
                                          HC.Client_Has_X25519 := True;
                                       elsif Grp = 16#0017# then
                                          HC.Client_Has_P256 := True;
                                       elsif Grp = 16#0018# then
                                          HC.Client_Has_P384 := True;
                                       end if;
                                    end;
                                    Pos := Pos + 2;
                                 end loop;
                              end if;
                           end;

                        --  pre_shared_key extension (0x0029)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Pre_Shared_Key
                        then
                           --  Parse PSK identities to find a ticket we recognize
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              Ext_Data : Byte_Seq (0 .. DLen - 1);
                           begin
                              if DLen >= 6 then
                                 declare
                                    ED : aliased RBT.Bytes
                                       (1 .. RBT.Index (DLen));
                                 begin
                                    RFLX.TLS_Handshake.CH_Extension_TLS
                                       .Get_Data (Ext_Ctx, ED);
                                    Ext_Data := To_NaCl (ED);
                                 end;

                                 --  identities_len(2) + first identity
                                 declare
                                    IDs_Len : constant N32 :=
                                       N32 (Ext_Data (0)) * 256 +
                                       N32 (Ext_Data (1));
                                    P : N32 := 2;
                                 begin
                                    if P + 2 <= DLen and then
                                       IDs_Len > 0
                                    then
                                       --  First identity: len(2) + ticket + age(4)
                                       declare
                                          Tick_Len : constant N32 :=
                                             N32 (Ext_Data (P)) * 256 +
                                             N32 (Ext_Data (P + 1));
                                       begin
                                          P := P + 2;
                                          if P + Tick_Len + 4 <= DLen
                                             and then Tick_Len = Ticket_ID_Len
                                          then
                                             HC.PSK_Ticket_ID :=
                                                Ext_Data (P .. P + Tick_Len - 1);
                                             HC.PSK_Offered := True;

                                             --  Skip to binders list
                                             --  (past all identities: 2 + IDs_Len)
                                             declare
                                                Binders_Start : constant N32 :=
                                                   2 + IDs_Len;
                                             begin
                                                if Binders_Start + 2 < DLen then
                                                   declare
                                                      Binders_Len : constant N32 :=
                                                         N32 (Ext_Data (Binders_Start)) * 256 +
                                                         N32 (Ext_Data (Binders_Start + 1));
                                                      B_Pos : constant N32 := Binders_Start + 2;
                                                   begin
                                                      if B_Pos < DLen then
                                                         declare
                                                            B_Len : constant N32 :=
                                                               N32 (Ext_Data (B_Pos));
                                                         begin
                                                            if B_Len in 32 | 48
                                                               and then B_Pos + 1 + B_Len <= DLen
                                                            then
                                                               for I in N32 range 0 .. B_Len - 1 loop
                                                                  HC.PSK_Binder (I) :=
                                                                     Ext_Data (B_Pos + 1 + I);
                                                               end loop;
                                                               HC.PSK_Binder_Len := B_Len;
                                                               --  Record binders offset relative
                                                               --  to the extension data start
                                                               HC.PSK_Binders_Offset := Binders_Start;
                                                            end if;
                                                         end;
                                                      end if;
                                                   end;
                                                end if;
                                             end;
                                          end if;
                                       end;
                                    end if;
                                 end;
                              end if;
                           end;

                        --  supported_versions extension (0x002B)
                        --  RFC 8446 §4.2.1: list_len(1) || version(2)...
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Supported_Versions
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              SV_Data : RBT.Bytes
                                          (1 .. RBT.Index (DLen));
                              List_Len : N32;
                              Pos : N32;
                           begin
                              if DLen >= 3 then
                                 RFLX.TLS_Handshake.CH_Extension_TLS
                                   .Get_Data (Ext_Ctx, SV_Data);
                                 List_Len := N32 (SV_Data (1));
                                 Pos := 2;
                                 while Pos + 1 <= N32 (DLen)
                                    and then Pos < 2 + List_Len
                                 loop
                                    if N32 (SV_Data (RBT.Index (Pos))) = 3
                                       and then N32 (SV_Data (RBT.Index (Pos + 1))) = 4
                                    then
                                       --  Found 0x0304 = TLS 1.3
                                       HC.Has_TLS_1_3 := True;
                                    end if;
                                    Pos := Pos + 2;
                                 end loop;
                              end if;
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
      RFLX_Free (Buf);

      --  Set version based on supported_versions parsing.
      --  If the client offered TLS 1.3 (0x0304), use it.
      --  Otherwise fall back to TLS 1.2.
      if HC.Has_TLS_1_3 then
         HC.Version := TLS_1_3;
      else
         HC.Version := TLS_1_2;
      end if;

      --  Shared secret computation deferred to Build_Server_Hello
      --  where we know which group to select.

      OK := True;
   end Parse_Client_Hello;

   --================================================================
   --  Server-side build procedures
   --================================================================

   procedure Build_Server_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      use RFLX.TLS_Common;

      SK : SPARKNaCl.Cryptobox.Secret_Key;
      PK : SPARKNaCl.Cryptobox.Public_Key;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

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

      SV_Data_Len : constant := 2;

      --  Key share data: varies by selected group
      KS_Raw     : Byte_Seq (0 .. 103) := (others => 0);  --  max P-384: 4+97
      KS_Raw_Len : N32 := 0;

      KS_Data_Len : N32;
      Ext_Total   : N32;
      SH_Body_Len : N32;
      SH_Msg_Len  : N32;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate server random
      Gen_Random (HC.Server_Random);

      --  Select key exchange group (prefer x25519 > P-256 > P-384)
      HC.Shared_Secret := (others => 0);
      if HC.Client_Has_X25519 then
         HC.Selected_Group := 16#001D#;
         declare
            PK_X : SPARKNaCl.Cryptobox.Public_Key;
         begin
            Gen_Random (HC.Local_SK);
            SPARKNaCl.Cryptobox.Keypair (HC.Local_SK, PK_X, SK);
            HC.Shared_Secret (0 .. 31) :=
               SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
            declare
               PK_Bytes : constant Bytes_32 :=
                  SPARKNaCl.Cryptobox.Serialize (PK_X);
            begin
               --  group(2) + key_len(2) + key(32) = 36
               KS_Raw (0) := 0; KS_Raw (1) := 16#1D#;  --  x25519
               KS_Raw (2) := 0; KS_Raw (3) := 32;
               for I in N32 range 0 .. 31 loop
                  KS_Raw (4 + I) := PK_Bytes (I);
               end loop;
               KS_Raw_Len := 36;
            end;
         end;

      elsif HC.Client_Has_P256 then
         HC.Selected_Group := 16#0017#;
         declare
            use SPARKTLS.P256.Point;
            PK_Jac  : P256_Jacobian;
            PK_Enc  : Byte_Seq (0 .. 64);
            Peer_Pt : P256_Jacobian;
            Valid   : SPARKNaCl.U32;
         begin
            Gen_Random (HC.P256_Local_SK);
            --  Our public key
            P256_Mulgen (PK_Jac, HC.P256_Local_SK, 32);
            P256_To_Affine (PK_Jac);
            P256_Encode (PK_Enc, PK_Jac);
            --  Shared secret: x-coord of [our_sk] * peer_pk
            P256_Decode (Peer_Pt, HC.P256_Peer_PK, Valid);
            if Valid = 0 then return; end if;
            P256_Mul (Peer_Pt, HC.P256_Local_SK, 32);
            P256_To_Affine (Peer_Pt);
            declare
               Enc : Byte_Seq (0 .. 64);
            begin
               P256_Encode (Enc, Peer_Pt);
               HC.Shared_Secret := (others => 0);
               HC.Shared_Secret (0 .. 31) := Enc (1 .. 32);
            end;
            --  group(2) + key_len(2) + key(65) = 69
            KS_Raw (0) := 0; KS_Raw (1) := 16#17#;
            KS_Raw (2) := 0; KS_Raw (3) := 65;
            for I in N32 range 0 .. 64 loop
               KS_Raw (4 + I) := PK_Enc (I);
            end loop;
            KS_Raw_Len := 69;
         end;

      elsif HC.Client_Has_P384 then
         HC.Selected_Group := 16#0018#;
         declare
            PK_Enc : Byte_Seq (0 .. 96);
            SS     : Bytes_48;
            SS_OK  : Boolean;
         begin
            Gen_Random (Byte_Seq (HC.P384_Local_SK));
            SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
            SPARKTLS.P384.Point.P384_ECDHE
              (Secret  => SS,
               OK      => SS_OK,
               SK      => HC.P384_Local_SK,
               Peer_PK => HC.P384_Peer_PK);
            if not SS_OK then return; end if;
            HC.Shared_Secret := SS;
            --  group(2) + key_len(2) + key(97) = 101
            KS_Raw (0) := 0; KS_Raw (1) := 16#18#;
            KS_Raw (2) := 0; KS_Raw (3) := 97;
            for I in N32 range 0 .. 96 loop
               KS_Raw (4 + I) := PK_Enc (I);
            end loop;
            KS_Raw_Len := 101;
         end;

      else
         --  No common key exchange group.
         --  Set Len = 0; caller will send handshake_failure alert.
         Len := 0;
         return;
      end if;

      KS_Data_Len := KS_Raw_Len;
      Ext_Total := (4 + KS_Data_Len) + (4 + SV_Data_Len);
      SH_Body_Len := 72 + Ext_Total;  --  version(2)+random(32)+sid_len(1)+sid(32)+suite(2)+comp(1)+ext_len(2)
      SH_Msg_Len := 4 + SH_Body_Len;

      --  Allocate buffer for ServerHello body
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ServerHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);
      Set_Random (Ctx, To_RFLX (HC.Server_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
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
         begin
            --  KS_Raw already populated with the selected group's key share

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + KS_Data_Len) => 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Key_Share);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (KS_Data_Len));
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (KS_Raw (0 .. KS_Raw_Len - 1)));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 2: supported_versions (0x002B)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
            SV_Raw  : Byte_Seq (0 .. SV_Data_Len - 1);
         begin
            SV_Raw (0) := 16#03#;
            SV_Raw (1) := 16#04#;  --  TLS 1.3

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SV_Data_Len) => 0);
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
            RFLX_Free (Ext_Buf);
         end;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if SH_Msg_Len > N32 (Result'Length) then
         RFLX_Free (Buf);
         return;
      end if;

      Result (0) := HT_Server_Hello;
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);
      Result (4 .. 4 + SH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (SH_Body_Len)));

      RFLX_Free (Buf);
      Len := SH_Msg_Len;

      --  If using PSK, append pre_shared_key extension to ServerHello.
      --  Format: tag(2) + data_len(2) + selected_identity(2) = 6 bytes.
      if HC.Using_PSK and then Len > 0 then
         declare
            PSK_Ext_Len : constant N32 := 6;
            New_Len     : constant N32 := Len + PSK_Ext_Len;
            --  Extension list length offset: after handshake header(4) +
            --  version(2) + random(32) + sid_len(1) + sid(32) + suite(2) +
            --  comp(1) = 74
            Ext_Len_Offset : constant N32 := 4 + 2 + 32 + 1 + 32 + 2 + 1;
            Old_Ext_Len : N32;
            P : N32;
         begin
            if New_Len <= N32 (Result'Length) then
               Old_Ext_Len := N32 (Result (Ext_Len_Offset)) * 256 +
                               N32 (Result (Ext_Len_Offset + 1));

               P := Len;
               --  pre_shared_key tag (0x0029)
               Result (P) := 0; Result (P + 1) := 16#29#;
               --  data_len (2)
               Result (P + 2) := 0; Result (P + 3) := 2;
               --  selected_identity (0 = first PSK)
               Result (P + 4) := 0; Result (P + 5) := 0;
               P := P + PSK_Ext_Len;

               --  Patch extensions length
               declare
                  New_Ext_Len : constant N32 := Old_Ext_Len + PSK_Ext_Len;
               begin
                  Result (Ext_Len_Offset) := Byte (New_Ext_Len / 256);
                  Result (Ext_Len_Offset + 1) := Byte (New_Ext_Len mod 256);
               end;

               --  Patch handshake body length
               declare
                  New_Body_Len : constant N32 := P - 4;
               begin
                  Result (1) := Byte (New_Body_Len / 65536);
                  Result (2) := Byte ((New_Body_Len / 256) mod 256);
                  Result (3) := Byte (New_Body_Len mod 256);
               end;

               Len := P;
            end if;
         end;
      end if;
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
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
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
         RFLX_Free (Buf);
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
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
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
               E_Buf : RBT.Bytes_Ptr :=
                  new RBT.Bytes'(1 .. RBT.Index (Entry_Len) => 0);
               E_Ctx : RFLX.TLS_Handshake.Certificate_Entry.Context;
            begin
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
               RFLX_Free (E_Buf);
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
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Certificate;

   procedure Build_Certificate_Chain
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      --  Build the Certificate message manually (simpler than RFLX
      --  for variable-count entries).
      --
      --  Format:
      --    handshake_header(4)
      --    certificate_request_context_length(1) = 0
      --    certificate_list_length(3)
      --    for each cert:
      --      cert_data_length(3) + cert_data + extensions_length(2) = 0

      Pos : N32 := 0;

      procedure Put_U8 (V : Byte) is
      begin
         if Pos <= Result'Last then
            Result (Pos) := V;
            Pos := Pos + 1;
         end if;
      end Put_U8;

      procedure Put_U24 (V : N32) is
      begin
         Put_U8 (Byte (V / 65536));
         Put_U8 (Byte ((V / 256) mod 256));
         Put_U8 (Byte (V mod 256));
      end Put_U24;

      procedure Put_Cert_Entry (DER : Byte_Seq; DER_Len : N32) is
      begin
         Put_U24 (DER_Len);              --  cert_data_length
         if Pos + DER_Len - 1 <= Result'Last then
            Result (Pos .. Pos + DER_Len - 1) := DER (0 .. DER_Len - 1);
            Pos := Pos + DER_Len;
         end if;
         Put_U8 (0); Put_U8 (0);         --  extensions_length = 0
      end Put_Cert_Entry;

      --  Compute total list length
      List_Len : N32 := 0;
   begin
      Result := (others => 0);
      Len := 0;

      if not Id.Has_Identity or Id.NaCl_Cert_Len = 0 then
         return;
      end if;

      --  Leaf entry: 3 + cert_len + 2
      List_Len := 3 + Id.NaCl_Cert_Len + 2;

      --  Intermediate entries
      for I in 0 .. Id.Int_Count - 1 loop
         if Id.Ints (I).Present then
            List_Len := List_Len + 3 + N32 (Id.Ints (I).DER_Len) + 2;
         end if;
      end loop;

      declare
         Body_Len : constant N32 := 1 + 3 + List_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         --  Handshake header
         Put_U8 (HT_Certificate);
         Put_U24 (Body_Len);

         --  certificate_request_context (empty)
         Put_U8 (0);

         --  certificate_list_length
         Put_U24 (List_Len);

         --  Leaf certificate entry
         Put_Cert_Entry (Id.NaCl_Cert_DER, Id.NaCl_Cert_Len);

         --  Intermediate certificate entries
         for I in 0 .. Id.Int_Count - 1 loop
            if Id.Ints (I).Present then
               declare
                  Int_DER : Byte_Seq (0 .. N32 (Id.Ints (I).DER_Len) - 1);
               begin
                  --  Convert X509.Byte_Seq to SPARKNaCl.Byte_Seq
                  for J in Int_DER'Range loop
                     Int_DER (J) := Byte (Id.Ints (I).DER (X509.N32 (J)));
                  end loop;
                  Put_Cert_Entry (Int_DER, N32 (Id.Ints (I).DER_Len));
               end;
            end if;
         end loop;

         Len := Pos;
      end;
   end Build_Certificate_Chain;

   procedure ECDSA_To_DER
     (R_Raw, S_Raw : in     Byte_Seq;
      Half_Len     : in     N32;
      DER_Out      :    out Byte_Seq;
      DER_Len      :    out N32)
   is
      procedure Write_Int
        (Src : Byte_Seq; Pos : in out N32)
      is
         Skip : N32 := 0;
         Pad  : Boolean;
      begin
         while Skip < N32 (Src'Length) - 1
            and then Src (Src'First + Skip) = 0
         loop
            Skip := Skip + 1;
         end loop;
         Pad := Src (Src'First + Skip) >= 16#80#;
         DER_Out (Pos) := 16#02#;
         DER_Out (Pos + 1) := Byte (N32 (Src'Length) - Skip
                                     + (if Pad then 1 else 0));
         Pos := Pos + 2;
         if Pad then
            DER_Out (Pos) := 0;
            Pos := Pos + 1;
         end if;
         for I in Skip .. N32 (Src'Length) - 1 loop
            DER_Out (Pos) := Src (Src'First + I);
            Pos := Pos + 1;
         end loop;
      end Write_Int;

      Pos : N32 := 2;
   begin
      DER_Out := (others => 0);
      DER_Len := 0;

      if Half_Len > 48 then
         return;
      end if;

      Write_Int (R_Raw, Pos);
      Write_Int (S_Raw, Pos);

      DER_Out (0) := 16#30#;
      DER_Out (1) := Byte (Pos - 2);
      DER_Len := Pos;
   end ECDSA_To_DER;

   procedure Build_Certificate_Verify
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Role            : in     TLS_Role;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Verify;

      Context_Str : constant String :=
         (if Role = Role_Server
          then "TLS 1.3, server CertificateVerify"
          else "TLS 1.3, client CertificateVerify");
      H_Len       : constant N32 := N32 (Transcript_Hash'Length);
      Content_Len : constant N32 := 64 + N32 (Context_Str'Length) + 1 + H_Len;
      Content     : Byte_Seq (0 .. Content_Len - 1);

      Sig     : Byte_Seq (0 .. 511) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean := False;

      Algo_Enum : RFLX.Tls_Parameters.TLS_SignatureScheme_Enum;
   begin
      Result := (others => 0);
      Len := 0;

      Content (0 .. 63) := (others => 16#20#);
      for I in Context_Str'Range loop
         Content (64 + N32 (I - Context_Str'First)) :=
            Byte (Character'Pos (Context_Str (I)));
      end loop;
      Content (64 + N32 (Context_Str'Length)) := 16#00#;
      Content (64 + N32 (Context_Str'Length) + 1 ..
               64 + N32 (Context_Str'Length) + H_Len) := Transcript_Hash;

      case Sig_Algo_Wire is
         when 16#0807# =>
            Algo_Enum := RFLX.Tls_Parameters.Ed25519_0807;
            Sig_Len := 64;
            declare
               SM_Len : constant N32 := 64 + Content_Len;
               SM     : Byte_Seq (0 .. SM_Len - 1);
               SK     : SPARKNaCl.Sign.Signing_SK;
            begin
               SPARKNaCl.Sign.Utils.Construct (Id.Ed25519_Key, SK);
               SPARKNaCl.Sign.Sign (SM, Content, SK);
               Sig (0 .. 63) := SM (0 .. 63);
               Sig_OK := True;
            end;

         when 16#0403# =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp256r1_Sha256;
            declare
               use SPARKNaCl.Hashing.SHA256;
               H : constant Digest := Hash (Content);
               K_Bytes : Bytes_32;
               R_Half, S_Half : SPARKTLS.P256.ECDSA.ECDSA_Sig_Half;
            begin
               Random.all (Byte_Seq (K_Bytes));
               SPARKTLS.P256.ECDSA.Sign
                 (Hash  => H,
                  D     => SPARKTLS.P256.ECDSA.ECDSA_Sig_Half
                             (Id.ECDSA_P256_Key),
                  K     => SPARKTLS.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER
                    (Byte_Seq (R_Half), Byte_Seq (S_Half), 32,
                     Sig, Sig_Len);
               end if;
            end;

         when 16#0503# =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp384r1_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H : constant Digest := Hash (Content);
               K_Bytes : Bytes_48;
               R_Half  : Byte_Seq (0 .. 47);
               S_Half  : Byte_Seq (0 .. 47);
            begin
               Random.all (Byte_Seq (K_Bytes));
               SPARKTLS.P384.ECDSA.Sign
                 (Hash  => H,
                  D     => Byte_Seq (Id.ECDSA_P384_Key),
                  K     => Byte_Seq (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER (R_Half, S_Half, 48, Sig, Sig_Len);
               end if;
            end;

         when 16#0804# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha256;
            declare
               use SPARKNaCl.Hashing.SHA256;
               H    : constant Digest := Hash (Content);
               Salt : Bytes_32;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLS.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 32,
                  Hash_Alg  => SPARKTLS.RSA.PSS_SHA256,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0805# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H    : constant Digest := Hash (Content);
               Salt : Bytes_48;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLS.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 48,
                  Hash_Alg  => SPARKTLS.RSA.PSS_SHA384,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0806# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha512;
            declare
               use SPARKNaCl.Hashing.SHA512;
               H    : constant Digest := Hash (Content);
               Salt : Bytes_64;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLS.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 64,
                  Hash_Alg  => SPARKTLS.RSA.PSS_SHA512,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when others =>
            return;
      end case;

      if not Sig_OK then
         return;
      end if;

      declare
         Body_Len : constant N32 := 4 + Sig_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
         Buf      : RBT.Bytes_Ptr;
         Ctx      : Context;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
         Initialize (Ctx, Buf);
         Set_Algorithm (Ctx, Algo_Enum);
         Set_Signature_Length
           (Ctx, RFLX.TLS_Handshake.Signature_Length (Sig_Len));
         Set_Signature (Ctx, To_RFLX (Sig (0 .. Sig_Len - 1)));
         Take_Buffer (Ctx, Buf);

         Result (0) := HT_Certificate_Verify;
         Result (1) := 16#00#;
         Result (2) := Byte (Body_Len / 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));

         RFLX_Free (Buf);
         Len := Msg_Len;
      end;
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
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
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
               E_Buf : RBT.Bytes_Ptr :=
                  new RBT.Bytes'(1 .. RBT.Index (Ext_Len) => 0);
               E_Ctx : RFLX.TLS_Handshake.CR_Extension.Context;
            begin
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
               RFLX_Free (E_Buf);
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
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Certificate_Request;

end SPARKTLS.Handshake;
