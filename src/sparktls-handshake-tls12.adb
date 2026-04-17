with Interfaces;                 use Interfaces;
with Ada.Unchecked_Deallocation;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Sign;
with SPARKTLS.P256.Point;
with SPARKTLS.P256.ECDSA;
with SPARKTLS.P384.Point;
with SPARKTLS.P384.ECDSA;
with SPARKTLS.RSA;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.RFLX_Bridge;      use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Common;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;

package body SPARKTLS.Handshake.TLS12 with
   SPARK_Mode => On
is
   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Bytes_Ptr;
   --  Helper: write a 3-byte big-endian length
   procedure Put24 (Buf : in out Byte_Seq; Pos : N32; Val : N32)
   with Pre => Pos + 2 <= Buf'Last and Val < 2**24
   is
   begin
      Buf (Pos)     := Byte (Val / 65536);
      Buf (Pos + 1) := Byte ((Val / 256) mod 256);
      Buf (Pos + 2) := Byte (Val mod 256);
   end Put24;

   --  Helper: write a 2-byte big-endian value
   procedure Put16 (Buf : in out Byte_Seq; Pos : N32; Val : Unsigned_16)
   with Pre => Pos + 1 <= Buf'Last
   is
   begin
      Buf (Pos)     := Byte (Val / 256);
      Buf (Pos + 1) := Byte (Val mod 256);
   end Put16;

   ------------------------------------------------------------------
   --  Build_Server_Hello_Done (RFC 5246 §7.4.5)
   --  Empty message: type(1)=0x0E || length(3)=0x000000
   ------------------------------------------------------------------

   procedure Build_Server_Hello_Done
     (Result :    out Byte_Seq;
      Len    :    out N32)
   is
   begin
      Result := (others => 0);
      Result (0) := HT_Server_Hello_Done;  --  0x0E
      Result (1) := 0;
      Result (2) := 0;
      Result (3) := 0;
      Len := Server_Hello_Done_Len;
   end Build_Server_Hello_Done;

   ------------------------------------------------------------------
   --  Build_Server_Key_Exchange (RFC 8422 §5.4, RFC 5246 §7.4.3)
   --
   --  Wire format:
   --    handshake_header: type(1)=0x0C || length(3)
   --    ec_params:
   --      curve_type(1)=0x03 || named_curve(2)
   --    ec_point:
   --      point_len(1) || point(N)
   --    signature:
   --      hash_alg(1) || sig_alg(1) || sig_len(2) || sig(M)
   --
   --  Signature input (RFC 5246 §7.4.3):
   --    client_random[32] || server_random[32] ||
   --    curve_type[1] || named_curve[2] || point_len[1] || point[N]
   ------------------------------------------------------------------

   procedure Build_Server_Key_Exchange
     (HC     : in     Handshake_Context;
      Id     : in     Identity;
      Random : in     Random_Bytes_Fn;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      --  EC params + point bytes (without handshake header)
      Params     : Byte_Seq (0 .. 3 + P384_Point_Len) := (others => 0);
      Params_Len : N32 := 0;

      --  Signature input: client_random || server_random || params
      Sig_Input     : Byte_Seq (0 .. 63 + 4 + P384_Point_Len) := (others => 0);
      Sig_Input_Len : N32;

      --  Signature output
      Sig     : Byte_Seq (0 .. 511) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean := False;

      Pt_Len : N32;
      P      : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Determine point length for selected group
      Pt_Len := Point_Len_For_Group (HC.Selected_Group);
      if Pt_Len = 0 then return; end if;

      --  Build EC params: curve_type(1) || named_curve(2) || point_len(1) || point(N)
      Params (0) := EC_Curve_Type_Named;  --  0x03
      Put16 (Params, 1, HC.Selected_Group);
      Params (3) := Byte (Pt_Len);

      --  Copy the server's ephemeral public key into params
      case HC.Selected_Group is
         when Group_X25519 =>
            declare
               PK   : SPARKNaCl.Cryptobox.Public_Key;
               PKB  : Bytes_32;
            begin
               declare
                  Dummy_SK : SPARKNaCl.Cryptobox.Secret_Key;
               begin
                  SPARKNaCl.Cryptobox.Keypair (HC.Local_SK, PK, Dummy_SK);
               end;
               PKB := SPARKNaCl.Cryptobox.Serialize (PK);
               Params (4 .. 4 + 31) := Byte_Seq (PKB);
            end;

         when Group_Secp256r1 =>
            --  P256_Peer_PK stores our pubkey in uncompressed form (0..64)
            --  Actually for SKE, we need the LOCAL public key, not peer
            declare
               PK_Jac : SPARKTLS.P256.Point.P256_Jacobian;
               PK_Enc : Byte_Seq (0 .. 64);
            begin
               SPARKTLS.P256.Point.P256_Mulgen
                 (PK_Jac, HC.P256_Local_SK, 32);
               SPARKTLS.P256.Point.P256_To_Affine (PK_Jac);
               SPARKTLS.P256.Point.P256_Encode (PK_Enc, PK_Jac);
               Params (4 .. 4 + 64) := PK_Enc;
            end;

         when Group_Secp384r1 =>
            declare
               PK_Enc : Byte_Seq (0 .. 96);
            begin
               SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
               Params (4 .. 4 + 96) := PK_Enc;
            end;

         when others =>
            return;
      end case;

      Params_Len := 4 + Pt_Len;

      --  RFC 5246 §7.4.3: Build signature input.
      --  MUST be: client_random[32] || server_random[32] || params
      --  Getting this wrong enables MITM attacks.
      Sig_Input (0 .. 31)  := Byte_Seq (HC.Client_Random);
      Sig_Input (32 .. 63) := Byte_Seq (HC.Server_Random);
      Sig_Input (64 .. 64 + Params_Len - 1) :=
         Params (0 .. Params_Len - 1);
      Sig_Input_Len := 64 + Params_Len;

      --  Sign using the negotiated signature algorithm
      --  The sig algo wire value is the 2-byte SignatureScheme from
      --  the client's signature_algorithms extension.
      declare
         Hash_Algo : Byte;
         Sig_Algo  : Byte;
      begin
         case HC.Negotiated_Sig_Algo is
            when 16#0804# =>  --  rsa_pss_rsae_sha256
               Hash_Algo := 8; Sig_Algo := 4;
               declare
                  H    : constant Digest := Hash
                    (Sig_Input (0 .. Sig_Input_Len - 1));
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

            when 16#0403# =>  --  ecdsa_secp256r1_sha256
               Hash_Algo := 4; Sig_Algo := 3;
               declare
                  H : constant Digest := Hash
                    (Sig_Input (0 .. Sig_Input_Len - 1));
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
                     Handshake.ECDSA_To_DER
                       (Byte_Seq (R_Half), Byte_Seq (S_Half), 32,
                        Sig, Sig_Len);
                  end if;
               end;

            when 16#0503# =>  --  ecdsa_secp384r1_sha384
               Hash_Algo := 5; Sig_Algo := 3;
               declare
                  H : constant SPARKNaCl.Hashing.SHA384.Digest :=
                     SPARKNaCl.Hashing.SHA384.Hash
                       (Sig_Input (0 .. Sig_Input_Len - 1));
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
                     Handshake.ECDSA_To_DER (R_Half, S_Half, 48, Sig, Sig_Len);
                  end if;
               end;

            when others =>
               return;
         end case;

         if not Sig_OK or Sig_Len = 0 then
            return;
         end if;

         --  Assemble into handshake message:
         --  header: type(1) || length(3)
         --  body:   params(Params_Len) ||
         --          hash_alg(1) || sig_alg(1) || sig_len(2) || sig(Sig_Len)
         declare
            Body_Len : constant N32 :=
               Params_Len + 2 + 2 + Sig_Len;  --  params + algo + len + sig
            Total    : constant N32 := 4 + Body_Len;
         begin
            if Total > Max_Server_Key_Exchange then
               return;
            end if;

            --  Handshake header
            Result (0) := HT_Server_Key_Exchange;
            Put24 (Result, 1, Body_Len);

            --  EC params + point
            P := 4;
            Result (P .. P + Params_Len - 1) :=
               Params (0 .. Params_Len - 1);
            P := P + Params_Len;

            --  Signature algorithm (TLS 1.2 split format)
            Result (P)     := Hash_Algo;
            Result (P + 1) := Sig_Algo;
            P := P + 2;

            --  Signature length + signature
            Put16 (Result, P, Unsigned_16 (Sig_Len));
            P := P + 2;
            Result (P .. P + Sig_Len - 1) := Sig (0 .. Sig_Len - 1);

            Len := Total;
         end;
      end;
   end Build_Server_Key_Exchange;

   ------------------------------------------------------------------
   --  Build_Client_Key_Exchange (RFC 8422 §5.7)
   --
   --  Wire format:
   --    handshake_header: type(1)=0x10 || length(3)
   --    body: point_len(1) || point(N)
   ------------------------------------------------------------------

   procedure Build_Client_Key_Exchange
     (HC     : in     Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      Pt_Len : constant N32 := Point_Len_For_Group (HC.Selected_Group);
   begin
      Result := (others => 0);
      Len := 0;

      if Pt_Len = 0 then return; end if;

      --  Handshake header: type || length
      --  Body = point_len(1) + point(Pt_Len)
      Result (0) := HT_Client_Key_Exchange;
      Put24 (Result, 1, 1 + Pt_Len);

      --  Point length prefix
      Result (4) := Byte (Pt_Len);

      --  Copy our public key
      case HC.Selected_Group is
         when Group_X25519 =>
            declare
               PK  : SPARKNaCl.Cryptobox.Public_Key;
               PKB : Bytes_32;
            begin
               declare
                  Dummy_SK : SPARKNaCl.Cryptobox.Secret_Key;
               begin
                  SPARKNaCl.Cryptobox.Keypair (HC.Local_SK, PK, Dummy_SK);
               end;
               PKB := SPARKNaCl.Cryptobox.Serialize (PK);
               Result (5 .. 5 + 31) := Byte_Seq (PKB);
            end;

         when Group_Secp256r1 =>
            declare
               PK_Jac : SPARKTLS.P256.Point.P256_Jacobian;
               PK_Enc : Byte_Seq (0 .. 64);
            begin
               SPARKTLS.P256.Point.P256_Mulgen
                 (PK_Jac, HC.P256_Local_SK, 32);
               SPARKTLS.P256.Point.P256_To_Affine (PK_Jac);
               SPARKTLS.P256.Point.P256_Encode (PK_Enc, PK_Jac);
               Result (5 .. 5 + 64) := PK_Enc;
            end;

         when Group_Secp384r1 =>
            declare
               PK_Enc : Byte_Seq (0 .. 96);
            begin
               SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
               Result (5 .. 5 + 96) := PK_Enc;
            end;

         when others =>
            return;
      end case;

      Len := 4 + 1 + Pt_Len;  --  header + point_len + point
   end Build_Client_Key_Exchange;

   ------------------------------------------------------------------
   --  Parse_Server_Key_Exchange (RFC 8422 §5.4)
   ------------------------------------------------------------------

   procedure Parse_Server_Key_Exchange
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
   begin
      OK := False;
      raise Program_Error with "Parse_Server_Key_Exchange not yet implemented";
   end Parse_Server_Key_Exchange;

   ------------------------------------------------------------------
   --  Parse_Client_Key_Exchange (RFC 8422 §5.7)
   --
   --  Extracts the client's ephemeral ECDHE public key.
   --  Data layout: point_len(1) || point(N)
   --  The curve is already set in HC.Selected_Group.
   ------------------------------------------------------------------

   procedure Parse_Client_Key_Exchange
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      Pt_Len : N32;
   begin
      OK := False;

      if Data'Length < 2 then return; end if;

      Pt_Len := N32 (Data (Data'First));

      --  Validate point length matches the negotiated group
      if Pt_Len /= Point_Len_For_Group (HC.Selected_Group) then
         return;
      end if;

      if N32 (Data'Length) < 1 + Pt_Len then return; end if;

      --  Store the peer's public key
      case HC.Selected_Group is
         when Group_X25519 =>
            for I in N32 range 0 .. 31 loop
               HC.Peer_PK (I) := Data (Data'First + 1 + I);
            end loop;

         when Group_Secp256r1 =>
            for I in N32 range 0 .. 64 loop
               HC.P256_Peer_PK (I) := Data (Data'First + 1 + I);
            end loop;
            HC.Use_P256_KE := True;

         when Group_Secp384r1 =>
            for I in N32 range 0 .. 96 loop
               HC.P384_Peer_PK (I) := Data (Data'First + 1 + I);
            end loop;
            HC.Use_P384_KE := True;

         when others =>
            return;
      end case;

      OK := True;
   end Parse_Client_Key_Exchange;

   ------------------------------------------------------------------
   --  Build_Finished_12 (RFC 5246 §7.4.9)
   ------------------------------------------------------------------

   procedure Build_Finished_12
     (Master          : in     Bytes_48;
      Label           : in     String;
      Transcript_Hash : in     Byte_Seq;
      Use_SHA384      : in     Boolean;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   is
      VD : Key_Schedule_12.Verify_Data_12;
   begin
      Result := (others => 0);

      --  Compute verify_data via PRF
      Key_Schedule_12.Compute_Finished_12
        (VD, Master, Label, Transcript_Hash, Use_SHA384);

      --  Build message: type(1) || length(3) || verify_data(12)
      Result (0) := HT_Finished;  --  0x14
      Result (1) := 0;
      Result (2) := 0;
      Result (3) := 12;           --  verify_data_length
      Result (4 .. 15) := Byte_Seq (VD);

      Len := Finished_12_Total_Len;
   end Build_Finished_12;

   ------------------------------------------------------------------
   --  Build_Certificate_Verify_12 (RFC 5246 §7.4.8)
   --
   --  TLS 1.2: signs Hash(handshake_messages) directly.
   --  No "TLS 1.3, server CertificateVerify\x00" context prefix.
   ------------------------------------------------------------------

   procedure Build_Certificate_Verify_12
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   is
      Sig     : Byte_Seq (0 .. 511) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean := False;
      Hash_Algo, Sig_Algo : Byte;
   begin
      Result := (others => 0);
      Len := 0;

      --  TLS 1.2: sign the transcript hash directly (no context prefix)
      case Sig_Algo_Wire is
         when 16#0804# =>  --  rsa_pss_rsae_sha256
            Hash_Algo := 8; Sig_Algo := 4;
            declare
               Salt : Bytes_32;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLS.RSA.Sign_PSS
                 (M_Hash    => Transcript_Hash (0 .. 31),
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

         when 16#0403# =>  --  ecdsa_secp256r1_sha256
            Hash_Algo := 4; Sig_Algo := 3;
            declare
               K_Bytes : Bytes_32;
               R_Half, S_Half : SPARKTLS.P256.ECDSA.ECDSA_Sig_Half;
            begin
               Random.all (Byte_Seq (K_Bytes));
               SPARKTLS.P256.ECDSA.Sign
                 (Hash  => Digest (Transcript_Hash (0 .. 31)),
                  D     => SPARKTLS.P256.ECDSA.ECDSA_Sig_Half
                             (Id.ECDSA_P256_Key),
                  K     => SPARKTLS.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  Handshake.ECDSA_To_DER
                    (Byte_Seq (R_Half), Byte_Seq (S_Half), 32,
                     Sig, Sig_Len);
               end if;
            end;

         when others =>
            return;
      end case;

      if not Sig_OK or Sig_Len = 0 then return; end if;

      --  Wire format: type(1)=0x0F || length(3) ||
      --               hash_alg(1) || sig_alg(1) || sig_len(2) || sig(N)
      declare
         Body_Len : constant N32 := 2 + 2 + Sig_Len;
         Total    : constant N32 := 4 + Body_Len;
      begin
         if Total > N32 (Result'Length) then return; end if;

         Result (0) := 16#0F#;  --  CertificateVerify type
         Put24 (Result, 1, Body_Len);
         Result (4) := Hash_Algo;
         Result (5) := Sig_Algo;
         Put16 (Result, 6, Unsigned_16 (Sig_Len));
         Result (8 .. 8 + Sig_Len - 1) := Sig (0 .. Sig_Len - 1);
         Len := Total;
      end;
   end Build_Certificate_Verify_12;

   ------------------------------------------------------------------
   --  Stubs for remaining procedures
   ------------------------------------------------------------------

   ------------------------------------------------------------------
   --  Build_Server_Hello_12 (RFC 5246 §7.4.1.2)
   --
   --  Uses RFLX Server_Hello context for structured serialization.
   --
   --  TLS 1.2 ServerHello:
   --    server_version = 0x0303 (real version)
   --    random[32]
   --    session_id_length[1] + session_id[0..32]
   --    cipher_suite[2] (TLS 1.2 ECDHE+AEAD suite)
   --    compression_method[1] = 0x00
   --    extensions:
   --      renegotiation_info (0xFF01) — empty for initial handshake
   --
   --  No supported_versions extension (that's TLS 1.3).
   --  No key_share extension (ECDHE is in ServerKeyExchange).
   ------------------------------------------------------------------

   procedure Build_Server_Hello_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      use RFLX.TLS_Common;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      --  Map TLS 1.2 wire values to RFLX cipher suite enum
      function To_Suite_Enum_12 (Val : Unsigned_16)
         return RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum
      is
      begin
         case Val is
            when Suite_ECDHE_RSA_AES128_GCM_SHA256 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
            when Suite_ECDHE_RSA_AES256_GCM_SHA384 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
            when Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
            when Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
            when Suite_ECDHE_RSA_CHACHA20_SHA256 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
            when Suite_ECDHE_ECDSA_CHACHA20_SHA256 =>
               return RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
            when others =>
               return RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
         end case;
      end To_Suite_Enum_12;

      --  RFLX free wrapper (SPARK_Mode On spec, Off body)
      procedure RFLX_Free_SH (Buf : in out RBT.Bytes_Ptr)
      with Post => Buf = null;

      procedure RFLX_Free_SH (Buf : in out RBT.Bytes_Ptr)
      with SPARK_Mode => Off
      is
         procedure Dealloc is new Ada.Unchecked_Deallocation
           (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      begin
         Dealloc (Buf);
      end RFLX_Free_SH;

      --  Renegotiation info (0xFF01): data = 1 byte (length=0)
      RI_Data_Len : constant := 1;

      --  Extended master secret (0x0017): no data (empty extension)
      --  RFC 7627: prevents triple handshake MITM
      EMS_Data_Len : constant := 0;

      --  Extensions total:
      --  reneg_info:  tag(2) + len(2) + data(1) = 5
      --  ext_master:  tag(2) + len(2) + data(0) = 4
      --  Total = 9
      Ext_Total   : constant N32 :=
         (4 + RI_Data_Len) + (4 + EMS_Data_Len);

      --  ServerHello body size:
      --  version(2) + random(32) + sid_len(1) + sid(32) + suite(2) + comp(1) + ext_len(2)
      --  = 72 + extensions
      SH_Body_Len : constant N32 := 72 + Ext_Total;
      SH_Msg_Len  : constant N32 := 4 + SH_Body_Len;

      Buf : RBT.Bytes_Ptr;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      --  Generate server random
      Gen_Random (HC.Server_Random);

      --  Generate session ID (32 bytes, random)
      Gen_Random (HC.Legacy_Session_ID);

      --  Allocate RFLX buffer and initialize context
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ServerHello fields via RFLX
      --  RFC 5246: version = 0x0303 (actual TLS 1.2)
      Set_Legacy_Version (Ctx, TLS_1_2);
      Set_Random (Ctx, To_RFLX (HC.Server_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
      Set_Cipher_Suite_TLS_Suite
        (Ctx, To_Suite_Enum_12 (S.Negotiated_Suite));
      Set_Legacy_Compression_Method (Ctx, 0);
      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Server_Hello_Extensions_Length (Ext_Total));

      --  Build extensions: renegotiation_info only
      declare
         Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  renegotiation_info (0xFF01)
         --  Data: renegotiated_connection length = 0 (1 byte)
         --  For initial handshake, the renegotiated_connection is empty.
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
            RI_Raw  : constant Byte_Seq (0 .. 0) := (0 => 0);
         begin
            Ext_Buf := new RBT.Bytes'
              (1 .. RBT.Index (4 + RI_Data_Len) => 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize
              (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx,
               RFLX.Tls_Extensiontype_Values.Renegotiation_Info);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx,
               RFLX.TLS_Handshake.Data_Length (RI_Data_Len));
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (RI_Raw));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free_SH (Ext_Buf);
         end;

         --  extended_master_secret (0x0017, RFC 7627)
         --  Empty extension — presence alone signals support.
         --  Prevents triple-handshake MITM attacks.
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
         begin
            Ext_Buf := new RBT.Bytes'(1 .. 4 => 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize
              (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx,
               RFLX.Tls_Extensiontype_Values.Extended_Master_Secret);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Empty
              (Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free_SH (Ext_Buf);
         end;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if SH_Msg_Len > N32 (Result'Length) then
         RFLX_Free_SH (Buf);
         return;
      end if;

      --  Handshake header: type(1) = 0x02 || length(3)
      Result (0) := 16#02#;  --  ServerHello
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);

      --  Copy RFLX-serialized body after header
      Result (4 .. 4 + SH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (SH_Body_Len)));

      RFLX_Free_SH (Buf);
      Len := SH_Msg_Len;
   end Build_Server_Hello_12;

   procedure Parse_Server_Hello_12
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
   begin
      OK := False;
      raise Program_Error with "Parse_Server_Hello_12 not yet implemented";
   end Parse_Server_Hello_12;

   ------------------------------------------------------------------
   --  Build_Certificate_Chain_12 (RFC 5246 §7.4.2)
   --
   --  TLS 1.2 Certificate:
   --    type(1)=0x0B || msg_length(3) ||
   --    cert_list_length(3) ||
   --    { cert_length(3) || cert_data[N] }*
   --
   --  No certificate_request_context (TLS 1.3 only).
   --  No per-certificate extensions (TLS 1.3 only).
   ------------------------------------------------------------------

   procedure Build_Certificate_Chain_12
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      P : N32 := 0;
      List_Start : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Handshake header placeholder (fill length later)
      Result (0) := 16#0B#;  --  Certificate
      P := 4;

      --  Certificate list length placeholder (fill later)
      List_Start := P;
      P := P + 3;

      --  Leaf certificate (use NaCl_Cert which is SPARKNaCl.Byte_Seq)
      if Id.NaCl_Cert_Len > 0 and then
         P + 3 + Id.NaCl_Cert_Len <= N32 (Result'Length)
      then
         Put24 (Result, P, Id.NaCl_Cert_Len);
         P := P + 3;
         Result (P .. P + Id.NaCl_Cert_Len - 1) :=
            Id.NaCl_Cert_DER (0 .. Id.NaCl_Cert_Len - 1);
         P := P + Id.NaCl_Cert_Len;
      else
         return;
      end if;

      --  Intermediate certificates
      --  TODO: add intermediate cert support for TLS 1.2

      --  Fill certificate list length
      declare
         List_Len : constant N32 := P - List_Start - 3;
      begin
         Put24 (Result, List_Start, List_Len);
      end;

      --  Fill handshake message length
      declare
         Msg_Body_Len : constant N32 := P - 4;
      begin
         Put24 (Result, 1, Msg_Body_Len);
      end;

      Len := P;
   end Build_Certificate_Chain_12;

   procedure Build_Client_Hello_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
   begin
      Result := (others => 0);
      Len := 0;
      raise Program_Error with "Build_Client_Hello_12 not yet implemented";
   end Build_Client_Hello_12;

end SPARKTLS.Handshake.TLS12;
