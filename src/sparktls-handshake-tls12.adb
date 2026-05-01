with Interfaces;                 use Interfaces;
with Ada.Unchecked_Deallocation;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Sign;
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
with RFLX.TLS_Common;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;

package body SPARKTLS.Handshake.TLS12 with
   SPARK_Mode => On
is
   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Bytes_Ptr;

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
         case HC.Negotiated_Sig_Algo is
            when 16#0804# =>  --  rsa_pss_rsae_sha256
               Hash_Algo := 8; Sig_Algo := 4;
               --  RSA key size must satisfy Sign_PSS preconditions
               if Id.RSA_Mod_Len < 64
                  or Id.RSA_Mod_Len > SPARKTLSCrypto.RSA.Max_RSA_Bytes
                  or Id.RSA_Modulus'Last < N32 (Id.RSA_Mod_Len) - 1
                  or Id.RSA_Priv_Exp'Last < N32 (Id.RSA_Mod_Len) - 1
               then return; end if;
               declare
                  H    : constant SPARKTLSCrypto.Hashing.SHA256.Digest :=
                    SPARKTLSCrypto.Hashing.SHA256.Hash
                      (Sig_Input (0 .. Sig_Input_Len - 1));
                  Salt : Bytes_32;
               begin
                  Random.all (Byte_Seq (Salt));
                  SPARKTLSCrypto.RSA.Sign_PSS
                    (M_Hash    => Byte_Seq (H),
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

            when 16#0403# =>  --  ecdsa_secp256r1_sha256
               Hash_Algo := 4; Sig_Algo := 3;
               declare
                  H : constant SPARKTLSCrypto.Hashing.SHA256.Digest :=
                    SPARKTLSCrypto.Hashing.SHA256.Hash
                      (Sig_Input (0 .. Sig_Input_Len - 1));
                  K_Bytes : Bytes_32;
                  R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
               begin
                  --  RFC 6979 deterministic nonce.
                  SPARKTLSCrypto.RFC6979.Derive_K_P256
                    (D => Bytes_32 (Id.ECDSA_P256_Key),
                     H => Bytes_32 (H),
                     K => K_Bytes);
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
                  R_Half  : Byte_Seq (0 .. 47);
                  S_Half  : Byte_Seq (0 .. 47);
               begin
                  --  RFC 6979 deterministic nonce (HMAC-SHA-384 DRBG).
                  SPARKTLSCrypto.RFC6979.Derive_K_P384
                    (D => Bytes_48 (Id.ECDSA_P384_Key),
                     H => Bytes_48 (H),
                     K => K_Bytes);
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
      B   : constant N32 := Data'First;
      Pos : N32 := B;
      Curve : Unsigned_16;
      Pt_Len : N32;
   begin
      OK := False;

      --  Minimum: curve_type(1) + curve(2) + pt_len(1) + pt(1) +
      --           sig_hash(1) + sig_alg(1) + sig_len(2) = 9
      if Data'Length < 9 then return; end if;

      --  curve_type must be 0x03 (named_curve)
      if Data (Pos) /= EC_Curve_Type_Named then return; end if;
      Pos := Pos + 1;

      --  named_curve (2 bytes)
      Curve := Unsigned_16 (Data (Pos)) * 256 +
               Unsigned_16 (Data (Pos + 1));
      Pos := Pos + 2;

      --  Validate curve is one we support
      if not Valid_ECDHE_Group (Curve) then return; end if;
      HC.Selected_Group := Curve;

      --  point_len
      Pt_Len := N32 (Data (Pos));
      Pos := Pos + 1;

      --  Validate point_len matches expected for this curve
      if Pt_Len /= Point_Len_For_Group (Curve) then return; end if;

      --  Check we have enough data for point + signature header
      if Pos + Pt_Len + 3 > Data'Last then return; end if;

      --  Extract server's ephemeral public key
      case Curve is
         when Group_X25519 =>
            for I in N32 range 0 .. 31 loop
               HC.Peer_PK (I) := Data (Pos + I);
            end loop;

         when Group_Secp256r1 =>
            for I in N32 range 0 .. 64 loop
               HC.P256_Peer_PK (I) := Data (Pos + I);
            end loop;
            HC.Use_P256_KE := True;

         when Group_Secp384r1 =>
            for I in N32 range 0 .. 96 loop
               HC.P384_Peer_PK (I) := Data (Pos + I);
            end loop;
            HC.Use_P384_KE := True;

         when others =>
            return;
      end case;

      Pos := Pos + Pt_Len;

      --  Parse signature: hash_alg[1] || sig_alg[1] || sig_len[2] || sig[N]
      --  We store the sig algo for reference but skip full verification
      --  for now (TODO: verify signature over client_random || server_random || params)
      --  Verify signature over client_random || server_random || params
      --  RFC 5246 §7.4.3: This prevents MITM substitution of the ECDHE pubkey.
      declare
         Sig_Hash_Alg : constant Byte := Data (Pos);
         Sig_Sig_Alg  : constant Byte := Data (Pos + 1);
         Sig_Len      : constant N32 :=
            N32 (Data (Pos + 2)) * 256 + N32 (Data (Pos + 3));

         --  params = curve_type(1) + named_curve(2) + point_len(1) + point(N)
         Params_Len : constant N32 := 4 + Pt_Len;

         --  signed_data = client_random[32] || server_random[32] || params
         Sig_Input_Len : constant N32 := 64 + Params_Len;
         Sig_Input : Byte_Seq (0 .. Sig_Input_Len - 1) := (others => 0);

         Sig_OK : Boolean;
      begin
         Pos := Pos + 4;

         --  Verify we have enough data for the signature
         if Sig_Len = 0
            or else Pos + Sig_Len - 1 > Data'Last
         then
            return;
         end if;

         --  Build signed data: client_random || server_random || params
         Sig_Input (0 .. 31)  := Byte_Seq (HC.Client_Random);
         Sig_Input (32 .. 63) := Byte_Seq (HC.Server_Random);
         --  params starts at Data(B) = curve_type
         Sig_Input (64 .. 64 + Params_Len - 1) :=
            Data (B .. B + Params_Len - 1);

         --  Verify the signature using the server's certificate public key.
         --  RFC 5246 §7.4.3: The signature covers
         --    client_random || server_random || params
         --  Not verifying allows MITM to substitute the ECDHE pubkey.
         --
         --  Map TLS 1.2 split hash/sig algorithm to SignatureScheme:
         --    hash=4(SHA256), sig=1(RSA) → 0x0401 (rsa_pkcs1_sha256)
         --    hash=4(SHA256), sig=3(ECDSA) → 0x0403 (ecdsa_secp256r1_sha256)
         --    hash=8, sig=4 → 0x0804 (rsa_pss_rsae_sha256)
         --    hash=5(SHA384), sig=3(ECDSA) → 0x0503 (ecdsa_secp384r1_sha384)
         declare
            Scheme : constant Unsigned_16 :=
               Unsigned_16 (Sig_Hash_Alg) * 256 +
               Unsigned_16 (Sig_Sig_Alg);
            Sig_Bytes : Byte_Seq (0 .. Sig_Len - 1);
         begin
            for I in N32 range 0 .. Sig_Len - 1 loop
               Sig_Bytes (I) := Data (Pos + I);
            end loop;

            if HC.Peer_Cert_Valid then
               Sig_OK := Cert_Verify.Verify_Signature
                 (Data       => Sig_Input,
                  Sig        => Sig_Bytes,
                  Cert       => HC.Peer_Cert,
                  Sig_Scheme => Scheme);
            else
               Sig_OK := HC.Cfg.Skip_Verify;
            end if;
         end;

         if not Sig_OK and not HC.Cfg.Skip_Verify then
            return;
         end if;
      end;

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
      Pt_Len : N32;
   begin
      OK := False;

      if Data'Last < 1 then return; end if;  --  need at least 2 bytes

      Pt_Len := N32 (Data (0));

      --  Validate point length matches the negotiated group
      if Pt_Len /= Point_Len_For_Group (HC.Selected_Group) then
         return;
      end if;

      if Data'Last < Pt_Len then return; end if;  --  need 1 + Pt_Len bytes

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
      Sig     : Byte_Seq (0 .. Max_Sig - 1) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean;
      Hash_Algo, Sig_Algo : Byte;
   begin
      Result := (others => 0);
      Len := 0;

      --  TLS 1.2: sign the transcript hash directly (no context prefix)
      case Sig_Algo_Wire is
         when 16#0804# =>  --  rsa_pss_rsae_sha256
            Hash_Algo := 8; Sig_Algo := 4;
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

         when 16#0403# =>  --  ecdsa_secp256r1_sha256
            Hash_Algo := 4; Sig_Algo := 3;
            declare
               K_Bytes : Bytes_32;
               R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
            begin
               --  RFC 6979 deterministic nonce.
               SPARKTLSCrypto.RFC6979.Derive_K_P256
                 (D => Bytes_32 (Id.ECDSA_P256_Key),
                  H => Bytes_32 (Transcript_Hash (0 .. 31)),
                  K => K_Bytes);
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
      EMS_Data_Len : constant := 0;

      --  ALPN (0x0010): if client offered and server configured
      --  Data: list_len(2) + proto_len(1) + proto(N)
      ALPN_Match : constant Boolean :=
         HC.Client_ALPN.Len > 0
         and then HC.Cfg.ALPN.Len > 0
         and then HC.Client_ALPN.Data (1 .. HC.Client_ALPN.Len) =
                  HC.Cfg.ALPN.Data (1 .. HC.Cfg.ALPN.Len);
      ALPN_Data_Len : constant N32 :=
         (if ALPN_Match then N32 (3 + HC.Cfg.ALPN.Len) else 0);
      ALPN_Ext_Len : constant N32 :=
         (if ALPN_Match then 4 + ALPN_Data_Len else 0);

      --  Extensions total
      Ext_Total   : constant N32 :=
         (4 + RI_Data_Len) + (4 + EMS_Data_Len) + ALPN_Ext_Len;

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

      --  Generate server random + session ID (use temps to avoid SPARK aliasing)
      declare
         Tmp_SR  : Bytes_32;
         Tmp_SID : Bytes_32;
      begin
         Gen_Random (Byte_Seq (Tmp_SR));
         HC.Server_Random := Tmp_SR;
         Gen_Random (Byte_Seq (Tmp_SID));
         HC.Legacy_Session_ID := Tmp_SID;
      end;

      --  Allocate RFLX buffer and initialize context
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Help the prover: buffer is 17000 bytes, ServerHello is << 256.
      pragma Assert (Has_Buffer (Ctx));

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

         --  ALPN (0x0010) — if client offered and server matches
         if ALPN_Match then
            declare
               Ext_Buf : RBT.Bytes_Ptr;
               Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
               ALPN_Raw : Byte_Seq (0 .. ALPN_Data_Len - 1)
                             := (others => 0);
               Proto_Len : constant Natural := HC.Cfg.ALPN.Len;
            begin
               --  list_len(2) + proto_len(1) + proto(N)
               ALPN_Raw (0) := Byte ((Proto_Len + 1) / 256);
               ALPN_Raw (1) := Byte ((Proto_Len + 1) mod 256);
               ALPN_Raw (2) := Byte (Proto_Len);
               for I in 1 .. Proto_Len loop
                  ALPN_Raw (N32 (2 + I)) :=
                     Byte (Character'Pos (HC.Cfg.ALPN.Data (I)));
               end loop;

               Ext_Buf := new RBT.Bytes'
                  (1 .. RBT.Index (4 + ALPN_Data_Len) => 0);
               RFLX.TLS_Handshake.SH_Extension_TLS.Initialize
                  (Ext_Ctx, Ext_Buf);
               RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
                  (Ext_Ctx,
                   RFLX.Tls_Extensiontype_Values
                     .Application_Layer_Protocol_Negotiation);
               RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
                  (Ext_Ctx,
                   RFLX.TLS_Handshake.Data_Length (ALPN_Data_Len));
               RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
                  (Ext_Ctx, To_RFLX (ALPN_Raw));
               RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
                  (Exts_Ctx, Ext_Ctx);
               RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
                  (Ext_Ctx, Ext_Buf);
               RFLX_Free_SH (Ext_Buf);

               --  Store negotiated ALPN in session
               S.Negotiated_ALPN := HC.Cfg.ALPN;
            end;
         end if;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if SH_Msg_Len - 1 > Result'Last then
         RFLX_Free_SH (Buf);
         return;
      end if;

      --  Handshake header: type(1) = 0x02 || length(3)
      Result (0) := 16#02#;  --  ServerHello
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);

      --  Copy RFLX-serialized body after header
      pragma Assert (SH_Body_Len >= 1);
      pragma Assert (SH_Body_Len <= RFLX_Main_Size);
      Result (4 .. 4 + SH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (SH_Body_Len)));

      RFLX_Free_SH (Buf);
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
         HC.Server_Random (I) := Data (Pos + I);
      end loop;
      Pos := Pos + 32;

      --  Session ID length
      SID_Len := N32 (Data (Pos));
      Pos := Pos + 1;
      if SID_Len > 32 or else Pos + SID_Len + 2 > Data'Last then
         return;
      end if;

      --  Session ID (may be empty)
      HC.Legacy_Session_ID := (others => 0);
      for I in N32 range 0 .. SID_Len - 1 loop
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

      --  Compression method (must be 0)
      if Data (Pos) /= 0 then return; end if;
      Pos := Pos + 1;

      --  Parse extensions (look for extended_master_secret = 0x0017)
      HC.Use_EMS := False;
      if Pos + 1 <= Data'Last then
         declare
            Ext_Len : constant N32 :=
               N32 (Data (Pos)) * 256 + N32 (Data (Pos + 1));
            --  Bound Ext_End to Data'Last to prevent out-of-bounds
            Ext_End : constant N32 :=
               N32'Min (Pos + 2 + Ext_Len, Data'Last + 1);
            Ext_Pos : N32 := Pos + 2;
         begin
            while Ext_Pos + 3 <= Data'Last and then Ext_Pos + 4 <= Ext_End loop
               declare
                  Ext_Type : constant Unsigned_16 :=
                     Unsigned_16 (Data (Ext_Pos)) * 256 +
                     Unsigned_16 (Data (Ext_Pos + 1));
                  Ext_DLen : constant N32 :=
                     N32 (Data (Ext_Pos + 2)) * 256 + N32 (Data (Ext_Pos + 3));
               begin
                  if Ext_Type = 16#0017# then
                     --  extended_master_secret (RFC 7627)
                     HC.Use_EMS := True;

                  elsif Ext_Type = 16#0010# and then Ext_DLen >= 4
                     and then Ext_Pos + 6 <= Data'Last
                  then
                     --  ALPN (RFC 7301)
                     --  Format: list_len(2) + proto_len(1) + proto(N)
                     declare
                        Proto_Len : constant Natural :=
                           Natural (Data (Ext_Pos + 6));
                     begin
                        if Proto_Len > 0 and then Proto_Len <= Max_Hostname_Len
                           and then N32 (Proto_Len + 3) <= Ext_DLen
                           and then Ext_Pos + N32 (7 + Proto_Len) - 1 <= Data'Last
                        then
                           S.Negotiated_ALPN.Len := Proto_Len;
                           for I in 1 .. Proto_Len loop
                              S.Negotiated_ALPN.Data (I) :=
                                 Character'Val (Data (Ext_Pos + N32 (6 + I)));
                           end loop;
                        end if;
                     end;
                  end if;
                  Ext_Pos := Ext_Pos + 4 + Ext_DLen;
               end;
            end loop;
         end;
      end if;

      --  No supported_versions → TLS 1.2
      HC.Has_TLS_1_3 := False;
      HC.Version := TLS_1_2;

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

end SPARKTLS.Handshake.TLS12;
