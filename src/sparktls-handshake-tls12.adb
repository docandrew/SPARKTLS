with Interfaces;                 use Interfaces;
with Ada.Unchecked_Deallocation;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Sign;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.Point;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.RSA;
use SPARKTLSCrypto;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.RFLX_Bridge;      use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Handshake.TLS_1_2_New_Session_Ticket;
with RFLX.TLS_Handshake.TLS_1_2_Server_Key_Exchange_ECDHE;
with RFLX.TLS_Handshake.TLS_1_2_Client_Key_Exchange_ECDHE;
with RFLX.TLS_Common;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;

package body SPARKTLS.Handshake.TLS12 with
   SPARK_Mode => On
is
   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Bytes_Ptr;
   use type RFLX.RFLX_Types.Base_Integer;

   Max_Sig : constant := 512;  --  max RSA-4096 signature
   --  Helper: write a 3-byte big-endian length
   procedure Put24 (Buf : in out Byte_Seq; Pos : N32; Val : N32)
   with Pre => Pos <= N32'Last - 2
               and then Pos >= Buf'First
               and then Pos + 2 <= Buf'Last
               and then Val < 2**24
   is
   begin
      Buf (Pos)     := Byte (Val / 65536);
      Buf (Pos + 1) := Byte ((Val / 256) mod 256);
      Buf (Pos + 2) := Byte (Val mod 256);
   end Put24;

   --  Helper: write a 2-byte big-endian value
   procedure Put16 (Buf : in out Byte_Seq; Pos : N32; Val : Unsigned_16)
   with Pre => Pos <= N32'Last - 1
               and then Pos >= Buf'First
               and then Pos + 1 <= Buf'Last
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
      Params_Len : N32;

      --  Signature input: client_random || server_random || params
      Sig_Input     : Byte_Seq (0 .. 63 + 4 + P384_Point_Len) := (others => 0);
      Sig_Input_Len : N32;

      --  Signature output
      Sig     : Byte_Seq (0 .. Max_Sig - 1) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean;

      Pt_Len : N32;
      Pos    : N32;
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
               PK_Jac : SPARKTLSCrypto.P256.Point.P256_Jacobian;
               PK_Enc : Byte_Seq (0 .. 64);
            begin
               SPARKTLSCrypto.P256.Point.P256_Mulgen
                 (PK_Jac, HC.P256_Local_SK, 32);
               SPARKTLSCrypto.P256.Point.P256_To_Affine (PK_Jac);
               SPARKTLSCrypto.P256.Point.P256_Encode (PK_Enc, PK_Jac);
               Params (4 .. 4 + 64) := PK_Enc;
            end;

         when Group_Secp384r1 =>
            declare
               PK_Enc : Byte_Seq (0 .. 96);
            begin
               SPARKTLSCrypto.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
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
         --  RFC 5246 §7.4.1.4.1 / RFC 8446 §4.2.3:
         --  SignatureAndHashAlgorithm wire form is just the high and
         --  low bytes of the SignatureScheme code. For modern schemes
         --  (rsa_pss_*, ed25519, rsa_pkcs1_*, ecdsa_*) this gives the
         --  correct on-wire encoding directly.
         Hash_Algo := Byte (Shift_Right (HC.Negotiated_Sig_Algo, 8));
         Sig_Algo  := Byte (HC.Negotiated_Sig_Algo and 16#FF#);
         case HC.Negotiated_Sig_Algo is
            when 16#0804# | 16#0805# | 16#0806# =>
               --  rsa_pss_rsae_sha{256,384,512}.
               if Id.RSA_Mod_Len < 64
                  or Id.RSA_Mod_Len > SPARKTLSCrypto.RSA.Max_RSA_Bytes
                  or Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
                  or Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               then return; end if;
               declare
                  --  Hash the SKE Sig_Input with the matching hash.
                  H256 : SPARKTLSCrypto.Hashing.SHA256.Digest;
                  H384 : SPARKNaCl.Hashing.SHA384.Digest;
                  H512 : SPARKNaCl.Hashing.SHA512.Digest;
                  Salt32 : Bytes_32; Salt48 : Bytes_48; Salt64 : Bytes_64;
               begin
                  case HC.Negotiated_Sig_Algo is
                     when 16#0804# =>
                        SPARKTLSCrypto.Hashing.SHA256.Hash
                          (H256, Sig_Input (0 .. Sig_Input_Len - 1));
                        Random.all (Byte_Seq (Salt32));
                        SPARKTLSCrypto.RSA.Sign_PSS
                          (M_Hash => Byte_Seq (H256), Hash_Len => 32,
                           Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Salt => Byte_Seq (Salt32),
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                     when 16#0805# =>
                        SPARKNaCl.Hashing.SHA384.Hash
                          (H384, Sig_Input (0 .. Sig_Input_Len - 1));
                        Random.all (Byte_Seq (Salt48));
                        SPARKTLSCrypto.RSA.Sign_PSS
                          (M_Hash => Byte_Seq (H384), Hash_Len => 48,
                           Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA384,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Salt => Byte_Seq (Salt48),
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                     when others =>  --  0x0806
                        SPARKNaCl.Hashing.SHA512.Hash
                          (H512, Sig_Input (0 .. Sig_Input_Len - 1));
                        Random.all (Byte_Seq (Salt64));
                        SPARKTLSCrypto.RSA.Sign_PSS
                          (M_Hash => Byte_Seq (H512), Hash_Len => 64,
                           Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA512,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Salt => Byte_Seq (Salt64),
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                  end case;
               end;

            when 16#0401# | 16#0501# | 16#0601# =>
               --  rsa_pkcs1_sha{256,384,512}. Hash_Algo/Sig_Algo
               --  already set above from scheme high/low bytes.
               if Id.RSA_Mod_Len < 64
                  or Id.RSA_Mod_Len > SPARKTLSCrypto.RSA.Max_RSA_Bytes
                  or Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
                  or Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               then return; end if;
               declare
                  H256 : SPARKTLSCrypto.Hashing.SHA256.Digest;
                  H384 : SPARKNaCl.Hashing.SHA384.Digest;
                  H512 : SPARKNaCl.Hashing.SHA512.Digest;
               begin
                  case HC.Negotiated_Sig_Algo is
                     when 16#0401# =>
                        SPARKTLSCrypto.Hashing.SHA256.Hash
                          (H256, Sig_Input (0 .. Sig_Input_Len - 1));
                        SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
                          (M_Hash => Byte_Seq (H256), Hash_Len => 32,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                     when 16#0501# =>
                        SPARKNaCl.Hashing.SHA384.Hash
                          (H384, Sig_Input (0 .. Sig_Input_Len - 1));
                        SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
                          (M_Hash => Byte_Seq (H384), Hash_Len => 48,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                     when others =>  --  0x0601
                        SPARKNaCl.Hashing.SHA512.Hash
                          (H512, Sig_Input (0 .. Sig_Input_Len - 1));
                        SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
                          (M_Hash => Byte_Seq (H512), Hash_Len => 64,
                           Modulus => Id.RSA_Modulus,
                           Mod_Len => Id.RSA_Mod_Len,
                           Priv_Exp => Id.RSA_Priv_Exp,
                           Signature => Sig, Sig_Len => Sig_Len,
                           OK => Sig_OK);
                  end case;
               end;

            when 16#0807# =>  --  ed25519
               --  Hash_Algo=0x08, Sig_Algo=0x07 already set above.
               --  Ed25519 signs the raw Sig_Input (no pre-hash; the
               --  underlying primitive does SHA-512 internally).
               declare
                  SM_Len : constant N32 := 64 + Sig_Input_Len;
                  SM     : Byte_Seq (0 .. SM_Len - 1);
                  SK     : Bytes_64;
               begin
                  SK := Id.Ed25519_Key;
                  SPARKTLSCrypto.Ed25519.Sign
                    (SM, Sig_Input (0 .. Sig_Input_Len - 1), SK);
                  Sig (0 .. 63) := SM (0 .. 63);
                  Sig_Len := 64;
                  Sig_OK := True;
               end;

            when 16#0403# =>  --  ecdsa_secp256r1_sha256
               Hash_Algo := 4; Sig_Algo := 3;
               declare
                  H : constant SPARKTLSCrypto.Hashing.SHA256.Digest :=
                    SPARKTLSCrypto.Hashing.SHA256.Hash
                      (Sig_Input (0 .. Sig_Input_Len - 1));
                  K_Bytes : Bytes_32;
                  K_OK    : Boolean;
                  R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
               begin
                  --  RFC 6979 deterministic nonce.
                  SPARKTLSCrypto.RFC6979.Derive_K_P256
                    (D => Bytes_32 (Id.ECDSA_P256_Key),
                     H => Bytes_32 (H),
                     K => K_Bytes,
                     OK => K_OK);
                  if not K_OK then
                     Sig_OK := False;
                     return;
                  end if;
                  SPARKTLSCrypto.P256.ECDSA.Sign
                    (Hash  => H,
                     D     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half
                                (Id.ECDSA_P256_Key),
                     K     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
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
                  K_OK    : Boolean;
                  R_Half  : Byte_Seq (0 .. 47);
                  S_Half  : Byte_Seq (0 .. 47);
               begin
                  --  RFC 6979 deterministic nonce (HMAC-SHA-384 DRBG).
                  SPARKTLSCrypto.RFC6979.Derive_K_P384
                    (D => Bytes_48 (Id.ECDSA_P384_Key),
                     H => Bytes_48 (H),
                     K => K_Bytes,
                     OK => K_OK);
                  if not K_OK then
                     Sig_OK := False;
                     return;
                  end if;
                  SPARKTLSCrypto.P384.ECDSA.Sign
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

         if not Sig_OK or Sig_Len = 0 or Sig_Len > Max_Sig then
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
            Pos := 4;
            Result (Pos .. Pos + Params_Len - 1) :=
               Params (0 .. Params_Len - 1);
            Pos := Pos + Params_Len;

            --  Signature algorithm (TLS 1.2 split format)
            Result (Pos)     := Hash_Algo;
            Result (Pos + 1) := Sig_Algo;
            Pos := Pos + 2;

            --  Signature length + signature
            Put16 (Result, Pos, Unsigned_16 (Sig_Len));
            Pos := Pos + 2;
            Result (Pos .. Pos + Sig_Len - 1) := Sig (0 .. Sig_Len - 1);

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
               PK_Jac : SPARKTLSCrypto.P256.Point.P256_Jacobian;
               PK_Enc : Byte_Seq (0 .. 64);
            begin
               SPARKTLSCrypto.P256.Point.P256_Mulgen
                 (PK_Jac, HC.P256_Local_SK, 32);
               SPARKTLSCrypto.P256.Point.P256_To_Affine (PK_Jac);
               SPARKTLSCrypto.P256.Point.P256_Encode (PK_Enc, PK_Jac);
               Result (5 .. 5 + 64) := PK_Enc;
            end;

         when Group_Secp384r1 =>
            declare
               PK_Enc : Byte_Seq (0 .. 96);
            begin
               SPARKTLSCrypto.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
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

   ------------------------------------------------------------------
   --  Parse_Server_Key_Exchange (RFC 8422 §5.4)
   --
   --  Data is the handshake body (after 4-byte HS header).
   --  Wire format:
   --    curve_type[1] = 0x03 (named_curve)
   --    named_curve[2]
   --    point_len[1]
   --    point[point_len]
   --    sig_hash_alg[1] || sig_alg[1] || sig_len[2] || sig[sig_len]
   --
   --  Extracts: group, server's ephemeral ECDHE pubkey.
   --  TODO: verify signature over client_random || server_random || params
   ------------------------------------------------------------------

   procedure Parse_Server_Key_Exchange
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      package SKE renames RFLX.TLS_Handshake.TLS_1_2_Server_Key_Exchange_ECDHE;
      procedure RFLX_Free_Local is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Buf : RBT.Bytes_Ptr := null;
      Ctx : SKE.Context;
   begin
      OK := False;

      --  Minimum body: curve_type(1) + curve(2) + pt_len(1) + pt(1) +
      --                algo(2) + sig_len(2) + sig(1) = 10
      if Data'Length < 10 then return; end if;
      pragma Assert (Data'First = 0);
      pragma Assert (Data'Last >= 9);

      --  RFLX parse. The TLS_1_2_Server_Key_Exchange_ECDHE message
      --  enforces curve_type = Named_Curve (rejects explicit-prime /
      --  explicit-char2 — those were never legal for modern TLS 1.2).
      declare
         Data_Len : constant N32 := Data'Last + 1;
      begin
         pragma Assert (Data_Len = Data'Length);
         Buf := new RBT.Bytes'(1 .. RBT.Index (Data_Len) => 0);
      end;
      Buf.all := To_RFLX (Data);
      SKE.Initialize
        (Ctx, Buf,
         Written_Last => RBT.Bit_Length (Buf'Length * 8));
      SKE.Verify_Message (Ctx);
      if not SKE.Well_Formed_Message (Ctx) then
         SKE.Take_Buffer (Ctx, Buf);
         RFLX_Free_Local (Buf);
         return;
      end if;

      declare
         NC : constant RFLX.Tls_Parameters.TLS_Supported_Groups :=
                SKE.Get_Named_Curve (Ctx);
         Curve : constant Unsigned_16 :=
            (if NC.Known then
               (case NC.Enum is
                  when RFLX.Tls_Parameters.Secp256r1 => Group_Secp256r1,
                  when RFLX.Tls_Parameters.Secp384r1 => Group_Secp384r1,
                  when RFLX.Tls_Parameters.X25519    => Group_X25519,
                  when others                        => 0)
             else 0);
         Pt_Len  : constant N32 := N32 (SKE.Get_Point_Length (Ctx));
         Sig_Len : constant N32 := N32 (SKE.Get_Signature_Length (Ctx));
      begin
         if Curve = 0
           or not Valid_ECDHE_Group (Curve)
           or Sig_Len = 0
           or Sig_Len > Max_Sig
         then
            SKE.Take_Buffer (Ctx, Buf);
            RFLX_Free_Local (Buf);
            return;
         end if;

         if Pt_Len /= Point_Len_For_Group (Curve) then
            HC.Ext_Parse_Err := Illegal_Parameter;
            SKE.Take_Buffer (Ctx, Buf);
            RFLX_Free_Local (Buf);
            return;
         end if;
         pragma Assert (Pt_Len = Point_Len_For_Group (Curve));
         pragma Assert (Pt_Len <= P384_Point_Len);
         pragma Assert (Sig_Len in 1 .. Max_Sig);
         HC.Selected_Group := Curve;

         --  Extract server's ephemeral public key.
         declare
            Pt_RFLX : RBT.Bytes (1 .. RBT.Index (Pt_Len));
         begin
            SKE.Get_Point (Ctx, Pt_RFLX);
            case Curve is
               when Group_X25519 =>
                  pragma Assert (Pt_Len = X25519_Point_Len);
                  for I in N32 range 0 .. 31 loop
                     HC.Peer_PK (I) :=
                        Byte (Pt_RFLX (RBT.Index (I + 1)));
                  end loop;

               when Group_Secp256r1 =>
                  pragma Assert (Pt_Len = P256_Point_Len);
                  if Byte (Pt_RFLX (1)) /= 16#04# then
                     HC.Ext_Parse_Err := Illegal_Parameter;
                     SKE.Take_Buffer (Ctx, Buf);
                     RFLX_Free_Local (Buf);
                     return;
                  end if;
                  for I in N32 range 0 .. 64 loop
                     HC.P256_Peer_PK (I) :=
                        Byte (Pt_RFLX (RBT.Index (I + 1)));
                  end loop;
                  HC.Use_P256_KE := True;

               when Group_Secp384r1 =>
                  pragma Assert (Pt_Len = P384_Point_Len);
                  if Byte (Pt_RFLX (1)) /= 16#04# then
                     HC.Ext_Parse_Err := Illegal_Parameter;
                     SKE.Take_Buffer (Ctx, Buf);
                     RFLX_Free_Local (Buf);
                     return;
                  end if;
                  for I in N32 range 0 .. 96 loop
                     HC.P384_Peer_PK (I) :=
                        Byte (Pt_RFLX (RBT.Index (I + 1)));
                  end loop;
                  HC.Use_P384_KE := True;

               when others =>
                  SKE.Take_Buffer (Ctx, Buf);
                  RFLX_Free_Local (Buf);
                  return;
            end case;
         end;

         if 4 + Pt_Len > Data'Length then
            SKE.Take_Buffer (Ctx, Buf);
            RFLX_Free_Local (Buf);
            return;
         end if;
         pragma Assert (4 + Pt_Len <= Data'Length);

         --  RFC 5246 §7.4.3: verify signature over
         --  client_random || server_random || params
         --  (params = curve_type(1) + named_curve(2) + point_len(1) + point).
         --  Not verifying allows MITM to substitute the ECDHE pubkey.
         declare
            Params_Len    : constant N32 := 4 + Pt_Len;
            Sig_Input_Len : constant N32 := 64 + Params_Len;
            Sig_Input     : Byte_Seq (0 .. Sig_Input_Len - 1) :=
                              (others => 0);
            Sig_Bytes     : Byte_Seq (0 .. Sig_Len - 1);
            Sig_RFLX      : RBT.Bytes
                              (1 .. RBT.Index (Sig_Len));
            Sig_OK        : Boolean;
            Alg_Value     : constant RFLX.RFLX_Types.Base_Integer :=
               RFLX.Tls_Parameters.To_Base_Integer
                 (SKE.Get_Algorithm (Ctx));
            Sig_Scheme    : Unsigned_16;
         begin
            if Params_Len > Data'Length
              or else Alg_Value > RFLX.RFLX_Types.Base_Integer (Unsigned_16'Last)
            then
               SKE.Take_Buffer (Ctx, Buf);
               RFLX_Free_Local (Buf);
               return;
            end if;
            pragma Assert (Params_Len <= Data'Length);
            pragma Assert (Data'First = 0);
            pragma Assert (Params_Len - 1 <= Data'Last);
            pragma Assert (Alg_Value <= RFLX.RFLX_Types.Base_Integer (Unsigned_16'Last));
            Sig_Scheme := Unsigned_16 (Alg_Value);

            Sig_Input (0 .. 31)  := Byte_Seq (HC.Client_Random);
            Sig_Input (32 .. 63) := Byte_Seq (HC.Server_Random);
            --  params is the first Params_Len bytes of the input
            --  (RFLX field order is curve_type then named_curve then
            --  point_length then point — matches RFC 8422 §5.4 wire).
            Sig_Input (64 .. 64 + Params_Len - 1) :=
               Data (0 .. Params_Len - 1);

            SKE.Get_Signature (Ctx, Sig_RFLX);
            for I in N32 range 0 .. Sig_Len - 1 loop
               Sig_Bytes (I) := Byte (Sig_RFLX (RBT.Index (I + 1)));
            end loop;

            if HC.Peer_Cert_Valid then
               Sig_OK := Cert_Verify.Verify_Signature_TLS12
                 (Data       => Sig_Input,
                  Sig        => Sig_Bytes,
                  Cert       => HC.Peer_Cert,
                  Sig_Scheme => Sig_Scheme);
            else
               Sig_OK := False;
            end if;

            if not Sig_OK then
               SKE.Take_Buffer (Ctx, Buf);
               RFLX_Free_Local (Buf);
               return;
            end if;
         end;
      end;

      SKE.Take_Buffer (Ctx, Buf);
      RFLX_Free_Local (Buf);
      OK := True;
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
      package CKE renames RFLX.TLS_Handshake.TLS_1_2_Client_Key_Exchange_ECDHE;
      procedure RFLX_Free_Local is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Buf : RBT.Bytes_Ptr;
      Ctx : CKE.Context;
   begin
      OK := False;

      --  Minimum: point_len(1) + point(1) = 2
      if Data'Length < 2 then
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      declare
         Data_Len : constant N32 := Data'Last - Data'First + 1;
      begin
         Buf := new RBT.Bytes'(1 .. RBT.Index (Data_Len) => 0);
      end;
      Buf.all := To_RFLX (Data);
      CKE.Initialize
        (Ctx, Buf,
         Written_Last => RBT.Bit_Length (Buf'Length * 8));
      CKE.Verify_Message (Ctx);
      if not CKE.Well_Formed_Message (Ctx) then
         CKE.Take_Buffer (Ctx, Buf);
         RFLX_Free_Local (Buf);
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      declare
         Pt_Len  : constant N32 := N32 (CKE.Get_Point_Length (Ctx));
         Pt_RFLX : RBT.Bytes (1 .. RBT.Index (Pt_Len));
      begin
         --  RFC 5246 §7.4.7: body ends exactly at 1 + Pt_Len bytes.
         --  Trailing bytes (BoGo TrailingMessageData-ClientKeyExchange)
         --  are a protocol error.
         if Data'Length /= 1 + Pt_Len then
            CKE.Take_Buffer (Ctx, Buf);
            RFLX_Free_Local (Buf);
            pragma Assert (Reasm_Building (HC));
            return;
         end if;

         if Pt_Len /= Point_Len_For_Group (HC.Selected_Group) then
            HC.Ext_Parse_Err := Illegal_Parameter;
            CKE.Take_Buffer (Ctx, Buf);
            RFLX_Free_Local (Buf);
            pragma Assert (Reasm_Building (HC));
            return;
         end if;

         CKE.Get_Point (Ctx, Pt_RFLX);
         case HC.Selected_Group is
            when Group_X25519 =>
               for I in N32 range 0 .. 31 loop
                  HC.Peer_PK (I) :=
                     Byte (Pt_RFLX (RBT.Index (I + 1)));
               end loop;

            when Group_Secp256r1 =>
               if Byte (Pt_RFLX (1)) /= 16#04# then
                  HC.Ext_Parse_Err := Illegal_Parameter;
                  CKE.Take_Buffer (Ctx, Buf);
                  RFLX_Free_Local (Buf);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;
               for I in N32 range 0 .. 64 loop
                  HC.P256_Peer_PK (I) :=
                     Byte (Pt_RFLX (RBT.Index (I + 1)));
               end loop;
               HC.Use_P256_KE := True;

            when Group_Secp384r1 =>
               if Byte (Pt_RFLX (1)) /= 16#04# then
                  HC.Ext_Parse_Err := Illegal_Parameter;
                  CKE.Take_Buffer (Ctx, Buf);
                  RFLX_Free_Local (Buf);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;
               for I in N32 range 0 .. 96 loop
                  HC.P384_Peer_PK (I) :=
                     Byte (Pt_RFLX (RBT.Index (I + 1)));
               end loop;
               HC.Use_P384_KE := True;

            when others =>
               CKE.Take_Buffer (Ctx, Buf);
               RFLX_Free_Local (Buf);
               pragma Assert (Reasm_Building (HC));
               return;
         end case;
      end;

      CKE.Take_Buffer (Ctx, Buf);
      RFLX_Free_Local (Buf);
      OK := True;
      pragma Assert (Reasm_Building (HC));
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
      Sig     : Byte_Seq (0 .. Max_Sig - 1) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean;
      Hash_Algo, Sig_Algo : Byte;
   begin
      Result := (others => 0);
      Len := 0;

      --  TLS 1.2: sign the transcript hash directly (no context prefix
      --  for hashed schemes; Ed25519 receives the raw transcript).
      --  Wire (Hash_Algo, Sig_Algo) = high/low bytes of scheme.
      Hash_Algo := Byte (Shift_Right (Sig_Algo_Wire, 8));
      Sig_Algo  := Byte (Sig_Algo_Wire and 16#FF#);
      case Sig_Algo_Wire is
         when 16#0804# =>  --  rsa_pss_rsae_sha256
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
            then return; end if;
            declare
               Salt : Bytes_32;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Transcript_Hash (0 .. 31),
                  Hash_Len  => 32,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0401# =>  --  rsa_pkcs1_sha256
            Hash_Algo := 4; Sig_Algo := 1;
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Transcript_Hash'Length /= 32
            then return; end if;
            SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
              (M_Hash    => Transcript_Hash (0 .. 31),
               Hash_Len  => 32,
               Modulus   => Id.RSA_Modulus,
               Mod_Len   => Id.RSA_Mod_Len,
               Priv_Exp  => Id.RSA_Priv_Exp,
               Signature => Sig,
               Sig_Len   => Sig_Len,
               OK        => Sig_OK);

         when 16#0501# =>  --  rsa_pkcs1_sha384
            Hash_Algo := 5; Sig_Algo := 1;
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Transcript_Hash'Length /= 48
            then return; end if;
            SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
              (M_Hash    => Transcript_Hash (0 .. 47),
               Hash_Len  => 48,
               Modulus   => Id.RSA_Modulus,
               Mod_Len   => Id.RSA_Mod_Len,
               Priv_Exp  => Id.RSA_Priv_Exp,
               Signature => Sig,
               Sig_Len   => Sig_Len,
               OK        => Sig_OK);

         when 16#0601# =>  --  rsa_pkcs1_sha512
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Transcript_Hash'Length /= 64
            then return; end if;
            SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
              (M_Hash    => Transcript_Hash (0 .. 63),
               Hash_Len  => 64,
               Modulus   => Id.RSA_Modulus,
               Mod_Len   => Id.RSA_Mod_Len,
               Priv_Exp  => Id.RSA_Priv_Exp,
               Signature => Sig,
               Sig_Len   => Sig_Len,
               OK        => Sig_OK);

         when 16#0805# =>  --  rsa_pss_rsae_sha384
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Transcript_Hash'Length /= 48
            then return; end if;
            declare
               Salt : Bytes_48;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Transcript_Hash (0 .. 47),
                  Hash_Len  => 48,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA384,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0806# =>  --  rsa_pss_rsae_sha512
            if Id.RSA_Mod_Len not in 64 .. SPARKTLSCrypto.RSA.Max_RSA_Bytes
               or else Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Sig'Last < N32 (Id.RSA_Mod_Len) - 1
               or else Transcript_Hash'Length /= 64
            then return; end if;
            declare
               Salt : Bytes_64;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Transcript_Hash (0 .. 63),
                  Hash_Len  => 64,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA512,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0503# =>  --  ecdsa_secp384r1_sha384 (mTLS w/ P-384 key)
            if Transcript_Hash'Length /= 48 then return; end if;
            declare
               K_Bytes : Bytes_48;
               K_OK    : Boolean;
               R_Half  : Byte_Seq (0 .. 47);
               S_Half  : Byte_Seq (0 .. 47);
            begin
               SPARKTLSCrypto.RFC6979.Derive_K_P384
                 (D => Bytes_48 (Id.ECDSA_P384_Key),
                  H => Bytes_48 (Transcript_Hash (0 .. 47)),
                  K => K_Bytes,
                  OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P384.ECDSA.Sign
                 (Hash  => Bytes_48 (Transcript_Hash (0 .. 47)),
                  D     => Byte_Seq (Id.ECDSA_P384_Key),
                  K     => Byte_Seq (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  Handshake.ECDSA_To_DER (R_Half, S_Half, 48, Sig, Sig_Len);
               end if;
            end;

         when 16#0807# =>  --  ed25519
            --  Ed25519 signs the raw transcript (the caller passed the
            --  raw transcript bytes rather than a pre-hash).
            declare
               SM_Len : constant N32 := 64 + Transcript_Hash'Length;
               SM     : Byte_Seq (0 .. SM_Len - 1);
               SK     : Bytes_64;
            begin
               SK := Id.Ed25519_Key;
               SPARKTLSCrypto.Ed25519.Sign (SM, Transcript_Hash, SK);
               Sig (0 .. 63) := SM (0 .. 63);
               Sig_Len := 64;
               Sig_OK := True;
            end;

         when 16#0403# =>  --  ecdsa_secp256r1_sha256
            Hash_Algo := 4; Sig_Algo := 3;
            declare
               K_Bytes : Bytes_32;
               K_OK    : Boolean;
               R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
            begin
               --  RFC 6979 deterministic nonce.
               SPARKTLSCrypto.RFC6979.Derive_K_P256
                 (D => Bytes_32 (Id.ECDSA_P256_Key),
                  H => Bytes_32 (Transcript_Hash (0 .. 31)),
                  K => K_Bytes,
                  OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P256.ECDSA.Sign
                 (Hash  => Bytes_32 (Transcript_Hash (0 .. 31)),
                  D     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half
                             (Id.ECDSA_P256_Key),
                  K     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
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
         if Total - 1 > Result'Last then return; end if;

         pragma Assert (Sig_Len <= Max_Sig);
         pragma Assert (Body_Len <= 4 + Max_Sig);
         pragma Assert (Total <= 8 + Max_Sig);

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
   --  Uses direct serialization. The TLS 1.2 ServerHello layout is
   --  fixed-size apart from a small extension list, and handwritten
   --  encoding keeps this path heap-free and straightforward to prove.
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
      subtype TLS12_SID_Len is N32 range 0 .. 32;
      subtype TLS12_ALPN_Data_Len is N32 range 0 .. 258;
      subtype TLS12_ALPN_Ext_Len is N32 range 0 .. 262;
      subtype TLS12_SH_Ext_Total is N32 range 0 .. 279;
      subtype TLS12_SH_Body_Len is N32 range 40 .. 351;
      subtype TLS12_SH_Msg_Len is N32 range 44 .. 355;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      --  Renegotiation info (0xFF01): data = 1 byte (length=0).
      --  Always emit. RFC 5746 §3.6 says only emit if the client
      --  offered (extension or SCSV); but most real clients always
      --  send the extension, and a few TLS-Anvil tests rely on us
      --  echoing it. Pragmatic: ALWAYS emit (no security risk —
      --  the empty initial-handshake form binds the connection).
      RI_Data_Len : constant := 1;
      --  RFC 5746 §3.6: server emits renegotiation_info only when
      --  the client signalled support — either by sending the
      --  extension itself or by including the TLS_EMPTY_RENEGOTIATION_
      --  INFO_SCSV (0x00FF) signaling cipher suite. BoGo
      --  Renegotiate-Server-NoExt verifies we DON'T echo it when
      --  neither signal is present.
      Emit_RI    : constant Boolean := HC.Saw_Reneg_Info;
      RI_Ext_Len : constant N32 := (if Emit_RI then 4 + RI_Data_Len else 0);

      --  Extended master secret (0x0017): no data (empty extension)
      EMS_Data_Len : constant := 0;

      --  Server name (0x0000): empty ack when the client sent SNI.
      SNI_Ext_Len : constant N32 := (if HC.Peer_SNI.Len > 0 then 4 else 0);

      --  ALPN (0x0010): if client offered and server configured
      --  Data: list_len(2) + proto_len(1) + proto(N)
      ALPN_Match : constant Boolean :=
         HC.Client_ALPN.Len > 0
         and then HC.Cfg.ALPN.Len > 0
         and then HC.Client_ALPN.Data (1 .. HC.Client_ALPN.Len) =
                  HC.Cfg.ALPN.Data (1 .. HC.Cfg.ALPN.Len);
      ALPN_Data_Len : constant TLS12_ALPN_Data_Len :=
         (if ALPN_Match then N32 (3 + HC.Cfg.ALPN.Len) else 0);
      ALPN_Ext_Len : constant TLS12_ALPN_Ext_Len :=
         (if ALPN_Match then 4 + ALPN_Data_Len else 0);

      --  EMS extension is only echoed in ServerHello when the
      --  client's ClientHello included it (RFC 7627 §5.1).
      EMS_Ext_Len : constant N32 :=
         (if HC.Use_EMS then 4 + EMS_Data_Len else 0);

      --  RFC 5077 §3.3: empty session_ticket ext in SH signals to the
      --  client that a NewSessionTicket message will follow. Echoed
      --  iff (a) client offered the extension and (b) we have ticket-
      --  encryption keys configured. The actual NST message is built
      --  by Process_Client_Finished_12 in the full-handshake path.
      Emit_ST_Ext : constant Boolean :=
         HC.TLS12_Ticket_Offered
         and then HC.Cfg.TLS12_Ticket_Keys /= null
         and then HC.Cfg.TLS12_Active_TEK_Idx < TLS12_Max_Keys
         and then HC.Cfg.TLS12_Ticket_Keys
                    (HC.Cfg.TLS12_Active_TEK_Idx).Valid;
      ST_Ext_Len : constant N32 := (if Emit_ST_Ext then 4 else 0);

      --  Extensions total
      Ext_Total   : constant TLS12_SH_Ext_Total :=
         RI_Ext_Len + EMS_Ext_Len + SNI_Ext_Len + ALPN_Ext_Len + ST_Ext_Len;

      --  ServerHello body size:
      --  version(2) + random(32) + sid_len(1) + sid(N) + suite(2)
      --  + comp(1) + ext_len(2) = 40 + N + extensions.
      SID_Out_Len : constant TLS12_SID_Len :=
         (if HC.TLS12_Resuming then HC.Legacy_Session_ID_Len else 32);
      SH_Body_Len : constant TLS12_SH_Body_Len :=
         40 + SID_Out_Len + Ext_Total;
      SH_Msg_Len  : constant TLS12_SH_Msg_Len := 4 + SH_Body_Len;

      Pos : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Generate server random + session ID (use temps to avoid SPARK aliasing)
      declare
         Tmp_SR  : Bytes_32;
         Tmp_SID : Bytes_32;
      begin
         Gen_Random (Byte_Seq (Tmp_SR));
         HC.Server_Random := Tmp_SR;
         --  RFC 5246 §7.4.1.3 / RFC 5077 §3.4: when resuming a session
         --  the server MUST echo the client's offered session_id in SH.
         --  HC.Legacy_Session_ID was populated from the client's CH; do
         --  NOT overwrite it on the resume path. For a fresh handshake
         --  generate a new SID as before.
         if not HC.TLS12_Resuming then
            Gen_Random (Byte_Seq (Tmp_SID));
            HC.Legacy_Session_ID := Tmp_SID;
            HC.Legacy_Session_ID_Len := 32;
         end if;
      end;

      if SH_Msg_Len - 1 > Result'Last then
         return;
      end if;

      pragma Assert (SH_Msg_Len <= Max_Server_Hello_12);

      --  Handshake header: type(1) = 0x02 || length(3)
      Result (0) := 16#02#;  --  ServerHello
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);

      Pos := 4;

      --  RFC 5246 §7.4.1.3: version = 0x0303 (actual TLS 1.2).
      pragma Assert (ServerHello_Legacy_Version_RFC_8446_4_1_3 (TLS_1_2));
      Result (Pos) := 16#03#;
      Result (Pos + 1) := 16#03#;
      Pos := Pos + 2;

      pragma Assert (Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random));
      Result (Pos .. Pos + 31) := Byte_Seq (HC.Server_Random);
      Pos := Pos + 32;

      pragma Assert (SID_Out_Len in 0 .. 32);
      Result (Pos) := Byte (SID_Out_Len);
      Pos := Pos + 1;
      if SID_Out_Len > 0 then
         Result (Pos .. Pos + SID_Out_Len - 1) :=
           Byte_Seq (HC.Legacy_Session_ID (0 .. SID_Out_Len - 1));
      end if;
      Pos := Pos + SID_Out_Len;

      Put16 (Result, Pos, S.Negotiated_Suite);
      Pos := Pos + 2;

      --  RFC 5246 §6.2.2 / §7.4.1.4: compression_method MUST be 0
      --  (null compression). CRIME-class attacks come from anything
      --  else; we never accept or emit non-zero here.
      pragma Assert (Compression_Method_None_RFC_5246_6_2_2 (0));
      Result (Pos) := 0;
      Pos := Pos + 1;

      Put16 (Result, Pos, Unsigned_16 (Ext_Total));
      Pos := Pos + 2;

      --  renegotiation_info (0xFF01). RFC 5746 §3.6: emit only when
      --  the client signalled support — via the extension itself or
      --  the TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) cipher
      --  suite. Both signals land in HC.Saw_Reneg_Info during CH
      --  parsing. BoGo Renegotiate-Server-NoExt verifies we DON'T
      --  echo it when the client offered neither.
      if Emit_RI then
         declare
            RI_Raw  : constant Byte_Seq (0 .. 0) := (0 => 0);
         begin
            pragma Assert (RI_Empty_Initial_RFC_5746_3_5 (RI_Raw));
            Put16 (Result, Pos, 16#FF01#);
            Put16 (Result, Pos + 2, Unsigned_16 (RI_Data_Len));
            Result (Pos + 4) := RI_Raw (0);
            Pos := Pos + RI_Ext_Len;
         end;
      end if;

      --  extended_master_secret (0x0017, RFC 7627). RFC 7627 §5.1:
      --  echo the extension only if the client offered it.
      if HC.Use_EMS then
         pragma Assert (EMS_Extension_Empty_Body_RFC_7627_5_1 (0));
         Put16 (Result, Pos, 16#0017#);
         Put16 (Result, Pos + 2, 0);
         Pos := Pos + EMS_Ext_Len;
      end if;

      --  RFC 6066 §3 server_name acknowledgement: empty body.
      if HC.Peer_SNI.Len > 0 then
         Put16 (Result, Pos, 16#0000#);
         Put16 (Result, Pos + 2, 0);
         Pos := Pos + SNI_Ext_Len;
      end if;

      --  RFC 5077 §3.3 session_ticket (0x0023) — empty body.
      if Emit_ST_Ext then
         Put16 (Result, Pos, 16#0023#);
         Put16 (Result, Pos + 2, 0);
         Pos := Pos + ST_Ext_Len;
      end if;

      --  ALPN (0x0010) — if client offered and server matches.
      if ALPN_Match then
         declare
            Proto_Len : constant Natural := HC.Cfg.ALPN.Len;
         begin
            Put16 (Result, Pos, 16#0010#);
            Put16 (Result, Pos + 2, Unsigned_16 (ALPN_Data_Len));
            Result (Pos + 4) := Byte ((Proto_Len + 1) / 256);
            Result (Pos + 5) := Byte ((Proto_Len + 1) mod 256);
            Result (Pos + 6) := Byte (Proto_Len);
            for I in 1 .. Proto_Len loop
               pragma Loop_Invariant (I in 1 .. Proto_Len);
               Result (Pos + N32 (6 + I)) :=
                  Byte (Character'Pos (HC.Cfg.ALPN.Data (I)));
            end loop;
            Pos := Pos + ALPN_Ext_Len;

            --  Store negotiated ALPN in session.
            S.Negotiated_ALPN := HC.Cfg.ALPN;
         end;
      end if;

      pragma Assert (Pos = SH_Msg_Len);
      Len := SH_Msg_Len;
   end Build_Server_Hello_12;

   ------------------------------------------------------------------
   --  Parse_Server_Hello_12: Manual TLS 1.2 ServerHello parser.
   --
   --  Wire format (after 4-byte HS header):
   --    version[2] + random[32] + session_id_len[1] +
   --    session_id[0..32] + cipher_suite[2] + compression[1] +
   --    extensions_length[2] + extensions[...]
   --
   --  Handles empty session_id (length=0), which RFLX parser rejects.
   ------------------------------------------------------------------

   procedure Parse_Server_Hello_12
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      B   : constant N32 := Data'First;
      Pos : N32;
      SID_Len : N32;
   begin
      OK := False;

      --  Minimum: type(1) + len(3) + version(2) + random(32) +
      --  sid_len(1) + suite(2) + comp(1) = 42
      if Data'Length < 42 then return; end if;

      --  Check handshake type
      if Data (B) /= 16#02# then return; end if;

      --  Skip 4-byte header
      Pos := B + 4;

      --  Version: must be 0x0303
      if Data (Pos) /= 3 or Data (Pos + 1) /= 3 then return; end if;
      Pos := Pos + 2;

      --  Random (32 bytes)
      for I in N32 range 0 .. 31 loop
         pragma Loop_Invariant (Reasm_Coherent (HC));
         pragma Loop_Invariant
           (HC.Reasm_Len = HC.Reasm_Len'Loop_Entry);
         pragma Loop_Invariant
           (HC.Reasm_Need = HC.Reasm_Need'Loop_Entry);
         pragma Loop_Invariant
           (HC.Reasm_Hdr_Pending = HC.Reasm_Hdr_Pending'Loop_Entry);
         HC.Server_Random (I) := Data (Pos + I);
      end loop;
      Pos := Pos + 32;

      --  RFC 8446 §4.1.3 downgrade protection. If this client offered
      --  TLS 1.3 but the server negotiated TLS 1.2 and set either the
      --  standard downgrade marker or the JDK 11 compatibility marker,
      --  abort. A TLS_1_2_Only client accepts the JDK 11 marker because
      --  it did not offer TLS 1.3 in the first place.
      if HC.Cfg.Versions /= TLS_1_2_Only then
         declare
            type Sentinel_T is array (N32 range 0 .. 7) of Byte;
            S13 : constant Sentinel_T :=
              (16#44#, 16#4F#, 16#57#, 16#4E#,
               16#47#, 16#52#, 16#44#, 16#01#);
            S12 : constant Sentinel_T :=
              (16#44#, 16#4F#, 16#57#, 16#4E#,
               16#47#, 16#52#, 16#44#, 16#00#);
            S_JDK : constant Sentinel_T :=
              (16#ED#, 16#BF#, 16#B4#, 16#A8#,
               16#C2#, 16#47#, 16#10#, 16#FF#);
            M13, M12, MJ : Boolean := True;
         begin
            for I in N32 range 0 .. 7 loop
               pragma Loop_Invariant (Reasm_Coherent (HC));
               pragma Loop_Invariant
                 (HC.Reasm_Len = HC.Reasm_Len'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Reasm_Need = HC.Reasm_Need'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Reasm_Hdr_Pending =
                    HC.Reasm_Hdr_Pending'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Transcript_Len = HC.Transcript_Len'Loop_Entry
                  and then HC.HRR_Cookie_Len =
                    HC.HRR_Cookie_Len'Loop_Entry);
               if HC.Server_Random (24 + I) /= S13 (I) then
                  M13 := False;
               end if;
               if HC.Server_Random (24 + I) /= S12 (I) then
                  M12 := False;
               end if;
               if HC.Server_Random (24 + I) /= S_JDK (I) then
                  MJ  := False;
               end if;
            end loop;

            if M13 or else M12 or else MJ then
               S.Last_Error := Illegal_Parameter;
               return;
            end if;
         end;
      end if;

      --  Session ID length
      SID_Len := N32 (Data (Pos));
      Pos := Pos + 1;
      if SID_Len > 32 or else Pos + SID_Len + 2 > Data'Last then
         return;
      end if;

      --  Session ID (may be empty)
      HC.Legacy_Session_ID := (others => 0);
      for I in N32 range 0 .. SID_Len - 1 loop
         pragma Loop_Invariant
           (HC.Transcript_Len = HC.Transcript_Len'Loop_Entry
            and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Loop_Entry
            and then Reasm_Coherent (HC)
            and then HC.Reasm_Len = HC.Reasm_Len'Loop_Entry
            and then HC.Reasm_Need = HC.Reasm_Need'Loop_Entry
            and then HC.Reasm_Hdr_Pending =
              HC.Reasm_Hdr_Pending'Loop_Entry);
         HC.Legacy_Session_ID (I) := Data (Pos + I);
      end loop;
      Pos := Pos + SID_Len;

      --  Cipher suite (2 bytes)
      declare
         Suite_Val : constant Unsigned_16 :=
            Unsigned_16 (Data (Pos)) * 256 + Unsigned_16 (Data (Pos + 1));
      begin
         if Suite_Val not in Suite_ECDHE_RSA_AES128_GCM_SHA256
                           | Suite_ECDHE_RSA_AES256_GCM_SHA384
                           | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                           | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                           | Suite_ECDHE_RSA_CHACHA20_SHA256
                           | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then
            return;
         end if;
         S.Negotiated_Suite := Suite_Val;
      end;
      Pos := Pos + 2;

      --  RFC 5246 §6.2.2 / §7.4.1.4: server's chosen compression
      --  method MUST be null (0x00). BoGo InvalidCompressionMethod
      --  expects illegal_parameter (not handshake_failure).
      if Data (Pos) /= 0 then
         S.Last_Error := Illegal_Parameter;
         return;
      end if;
      Pos := Pos + 1;

      --  Extension parsing (policy + ALPN extraction) was already
      --  done by Pre_Scan_SH_Extensions in the caller's
      --  Parse_Server_Hello pass. Walk only to extract HC.Use_EMS —
      --  the one piece of state this fallback owns. RFC 7627 §5.1:
      --  EMS in SH means the server agreed to derive the master
      --  secret via the EMS PRF.
      HC.Use_EMS := False;
      if Pos + 1 <= Data'Last then
         declare
            Ext_Len : constant N32 :=
               N32 (Data (Pos)) * 256 + N32 (Data (Pos + 1));
            Available_End : constant N32 := Data'Last + 1;
            Ext_End       : constant N32 :=
               (if Ext_Len <= N32'Last - Pos - 2
                then N32'Min (Pos + 2 + Ext_Len, Available_End)
                else Available_End);
            Ext_Pos : N32 := Pos + 2;
         begin
            while Ext_Pos + 3 <= Data'Last
              and then Ext_Pos + 4 <= Ext_End
            loop
               pragma Loop_Invariant (Reasm_Coherent (HC));
               pragma Loop_Invariant
                 (HC.Reasm_Len = HC.Reasm_Len'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Reasm_Need = HC.Reasm_Need'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Reasm_Hdr_Pending =
                    HC.Reasm_Hdr_Pending'Loop_Entry);
               declare
                  Ext_Type : constant Unsigned_16 :=
                     Unsigned_16 (Data (Ext_Pos)) * 256 +
                     Unsigned_16 (Data (Ext_Pos + 1));
                  Ext_DLen : constant N32 :=
                     N32 (Data (Ext_Pos + 2)) * 256
                     + N32 (Data (Ext_Pos + 3));
               begin
                  if Ext_Type = 16#0017# then
                     HC.Use_EMS := True;
                  end if;
                  --  RFC 5077 §3.3 session_ticket (0x0023): empty
                  --  body in SH signals the server will send a
                  --  NewSessionTicket later in the flight. We
                  --  record the flag; the actual receive happens
                  --  in the post-Finished / abbreviated flow.
                  if Ext_Type = 16#0023# and Ext_DLen = 0 then
                     HC.TLS12_Server_Will_Issue := True;
                  end if;
                  Ext_Pos := Ext_Pos + 4 + Ext_DLen;
               end;
            end loop;
         end;
      end if;

      --  No supported_versions → TLS 1.2
      HC.Has_TLS_1_3 := False;
      HC.Version := TLS_1_2;

      --  RFC 8446 §4.2.1: enforce our Cfg.Versions policy. If the
      --  user constrained us to TLS_1_3_Only via `-min-version 0x0304`
      --  or `-no-tls12`, refuse to negotiate TLS 1.2 here. BoGo's
      --  MinimumVersion-{Client,Client2}-TLS13-TLS12 + the runner's
      --  NegotiateVersion bug force a TLS 1.2 SH on our shim despite
      --  our offer; this guard fires so we reject rather than accept.
      if HC.Cfg.Versions = TLS_1_3_Only then
         S.Last_Error := Protocol_Version;
         OK := False;
         return;
      end if;

      OK := True;
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
      Pos : N32;
      List_Start : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Handshake header placeholder (fill length later)
      Result (0) := 16#0B#;  --  Certificate
      Pos := 4;

      --  Certificate list length placeholder (fill later)
      List_Start := Pos;
      Pos := Pos + 3;

      --  Leaf certificate (use NaCl_Cert which is SPARKNaCl.Byte_Seq)
      --  Need space for: cert_len(3) + cert_data(NaCl_Cert_Len)
      if Id.NaCl_Cert_Len > 0
         and then Id.NaCl_Cert_Len <= Max_Cert_DER_Len
         and then Pos <= Result'Last - 3 - Id.NaCl_Cert_Len + 1
      then
         Put24 (Result, Pos, Id.NaCl_Cert_Len);
         Pos := Pos + 3;
         Result (Pos .. Pos + Id.NaCl_Cert_Len - 1) :=
            Id.NaCl_Cert_DER (0 .. Id.NaCl_Cert_Len - 1);
         Pos := Pos + Id.NaCl_Cert_Len;
      else
         return;
      end if;

      --  Intermediate certificates
      --  TODO: add intermediate cert support for TLS 1.2

      --  Fill certificate list length
      declare
         List_Len : constant N32 := Pos - List_Start - 3;
      begin
         Put24 (Result, List_Start, List_Len);
      end;

      --  Fill handshake message length
      declare
         Msg_Body_Len : constant N32 := Pos - 4;
      begin
         Put24 (Result, 1, Msg_Body_Len);
      end;

      Len := Pos;
   end Build_Certificate_Chain_12;

   ------------------------------------------------------------------
   --  RFC 5077 §3.3 TLS 1.2 NewSessionTicket build/parse via RFLX
   ------------------------------------------------------------------

   procedure Build_New_Session_Ticket_12
     (Lifetime_Hint : in     Interfaces.Unsigned_32;
      Ticket        : in     Byte_Seq;
      Result        :    out Byte_Seq;
      Len           :    out N32)
   is
      package NST renames RFLX.TLS_Handshake.TLS_1_2_New_Session_Ticket;
      procedure RFLX_Free_Local is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Ticket_Len : constant N32 := Ticket'Last + 1;
      Body_Len   : constant N32 := 4 + 2 + Ticket_Len;
      Total_Len  : constant N32 := 4 + Body_Len;
      Buf        : RBT.Bytes_Ptr;
      Ctx        : NST.Context;
   begin
      Result := (others => 0);
      Len := 0;

      if Total_Len - 1 > Result'Last then
         return;
      end if;

      --  Build the body via RFLX.
      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      NST.Initialize (Ctx, Buf);
      NST.Set_Ticket_Lifetime_Hint
        (Ctx, RFLX.TLS_Handshake.Ticket_Lifetime (Lifetime_Hint));
      NST.Set_Ticket_Length
        (Ctx, RFLX.TLS_Handshake.TLS_1_2_NST_Ticket_Length (Ticket_Len));
      if Ticket_Len > 0 then
         NST.Set_Ticket (Ctx, To_RFLX (Ticket));
      else
         NST.Set_Ticket_Empty (Ctx);
      end if;
      NST.Take_Buffer (Ctx, Buf);

      --  Prepend HS header (type=0x04, 3-byte body length).
      Result (0) := 16#04#;
      Result (1) := Byte (Body_Len / 65536);
      Result (2) := Byte ((Body_Len / 256) mod 256);
      Result (3) := Byte (Body_Len mod 256);
      Result (4 .. 4 + Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));

      RFLX_Free_Local (Buf);
      Len := Total_Len;
   end Build_New_Session_Ticket_12;

   procedure Parse_New_Session_Ticket_12
     (NST_Body      : in     Byte_Seq;
      Lifetime_Hint :    out Interfaces.Unsigned_32;
      Ticket_Len    :    out N32;
      OK            :    out Boolean)
   is
      package NST renames RFLX.TLS_Handshake.TLS_1_2_New_Session_Ticket;
      procedure RFLX_Free_Local is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Buf : RBT.Bytes_Ptr;
      Ctx : NST.Context;
   begin
      Lifetime_Hint := 0;
      Ticket_Len    := 0;
      OK            := False;

      --  Smallest body = lifetime(4) + ticket_len(2) = 6 bytes.
      if N32 (NST_Body'Length) < 6 then
         return;
      end if;

      Buf := new RBT.Bytes'(1 .. RBT.Index (NST_Body'Length) => 0);
      Buf.all := To_RFLX (NST_Body);
      NST.Initialize
        (Ctx, Buf,
         Written_Last => RBT.Bit_Length (NST_Body'Length * 8));
      NST.Verify_Message (Ctx);
      if not NST.Well_Formed_Message (Ctx) then
         NST.Take_Buffer (Ctx, Buf);
         RFLX_Free_Local (Buf);
         return;
      end if;

      Lifetime_Hint := Interfaces.Unsigned_32
                        (NST.Get_Ticket_Lifetime_Hint (Ctx));
      Ticket_Len    := N32 (NST.Get_Ticket_Length (Ctx));

      NST.Take_Buffer (Ctx, Buf);
      RFLX_Free_Local (Buf);

      --  Final structural sanity: declared sizes match wire length.
      if Ticket_Len + 6 /= N32 (NST_Body'Length) then
         Ticket_Len := 0;
         return;
      end if;

      OK := True;
   end Parse_New_Session_Ticket_12;

end SPARKTLS.Handshake.TLS12;
