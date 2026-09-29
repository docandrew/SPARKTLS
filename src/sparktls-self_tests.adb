with Interfaces;                   use Interfaces;
with SPARKNaCl;                    use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA512;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.P384.Point;
with SPARKTLSCrypto.RSA;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Self_Tests.Vectors;
with MLKEM;
with MLKEM.ML_KEM_768;

package body SPARKTLS.Self_Tests
  with SPARK_Mode => On
is
   package V renames SPARKTLS.Self_Tests.Vectors;

   --  Blinding inputs for the blinded scalar multiplications. Any value
   --  gives the same result; fixed ones keep the tests deterministic.
   Blind_P256 : constant Byte_Seq (0 .. 39) := (others => 16#A5#);
   Blind_P384 : constant Byte_Seq (0 .. SPARKTLSCrypto.P384.Point.Blind_Len - 1) :=
     (others => 16#A5#);
   Blind_RSA  : constant Bytes_16 := (others => 16#A5#);

   ----------------------------------------------------------------------------
   --  Hashes and MACs
   ----------------------------------------------------------------------------

   procedure HMAC_SHA256 (OK : out Boolean) is
      D : SPARKTLSCrypto.Hashing.SHA256.Digest;
   begin
      SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, V.HMAC_Msg, V.HMAC_Key);
      OK := Byte_Seq (D) = V.HMAC_SHA256;
   end HMAC_SHA256;

   procedure HMAC_SHA384_KAT (OK : out Boolean) is
      D : SPARKTLSCrypto.HMAC384.Digest_384;
   begin
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384 (D, V.HMAC_Msg, V.HMAC_Key);
      OK := Byte_Seq (D) = V.HMAC_SHA384;
   end HMAC_SHA384_KAT;

   procedure SHA512_KAT (OK : out Boolean) is
      D : SPARKTLSCrypto.Hashing.SHA512.Digest;
   begin
      SPARKTLSCrypto.Hashing.SHA512.Hash (D, V.SHA512_Msg);
      OK := Byte_Seq (D) = V.SHA512_MD;
   end SHA512_KAT;

   ----------------------------------------------------------------------------
   --  AES-GCM
   ----------------------------------------------------------------------------

   procedure GCM_KAT (OK : out Boolean) is
      use SPARKTLSCrypto.AES_GCM;
      C128 : Byte_Seq (V.GCM128_Enc_PT'Range);
      C256 : Byte_Seq (V.GCM256_Enc_PT'Range);
      M128 : Byte_Seq (V.GCM128_Dec_CT'Range);
      M256 : Byte_Seq (V.GCM256_Dec_CT'Range);
      Tag  : Bytes_16;
   begin
      Encrypt (C128, Tag, V.GCM128_Enc_PT, V.GCM128_Enc_IV,
               SPARKNaCl.AES.Construct (V.GCM128_Enc_Key), V.GCM128_Enc_AAD);
      if C128 /= V.GCM128_Enc_CT or else Tag /= V.GCM128_Enc_Tag then
         OK := False;
         return;
      end if;
      Encrypt_256 (C256, Tag, V.GCM256_Enc_PT, V.GCM256_Enc_IV,
                   SPARKNaCl.AES.Construct (V.GCM256_Enc_Key), V.GCM256_Enc_AAD);
      if C256 /= V.GCM256_Enc_CT or else Tag /= V.GCM256_Enc_Tag then
         OK := False;
         return;
      end if;
      Decrypt (M128, OK, V.GCM128_Dec_Tag, V.GCM128_Dec_CT, V.GCM128_Dec_IV,
               SPARKNaCl.AES.Construct (V.GCM128_Dec_Key), V.GCM128_Dec_AAD);
      if not OK or else M128 /= V.GCM128_Dec_PT then
         OK := False;
         return;
      end if;
      Decrypt_256 (M256, OK, V.GCM256_Dec_Tag, V.GCM256_Dec_CT, V.GCM256_Dec_IV,
                   SPARKNaCl.AES.Construct (V.GCM256_Dec_Key), V.GCM256_Dec_AAD);
      OK := OK and then M256 = V.GCM256_Dec_PT;
   end GCM_KAT;

   ----------------------------------------------------------------------------
   --  Key derivation
   ----------------------------------------------------------------------------

   procedure HKDF_KAT (OK : out Boolean) is
      use SPARKTLSCrypto.HKDF;
      PRK : SPARKTLSCrypto.Hashing.SHA256.Digest;
      OKM : OKM_Seq (0 .. V.HKDF_OKM'Length - 1);
   begin
      Extract (PRK, V.HKDF_IKM, V.HKDF_Salt);
      Expand (OKM, PRK, V.HKDF_Info);
      OK := (for all I in OKM'Range => OKM (I) = V.HKDF_OKM (I));
   end HKDF_KAT;

   procedure TLS12_PRF_KAT (OK : out Boolean) is
      Master : Byte_Seq (V.TLS12_Master'Range);
   begin
      SPARKTLS.Key_Schedule_12.PRF_SHA256
        (Master, V.TLS12_PMS, "extended master secret", V.TLS12_Session_Hash);
      OK := Master = V.TLS12_Master;
   end TLS12_PRF_KAT;

   procedure TLS13_KDF_KAT (OK : out Boolean) is
      OKM : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. V.TLS13_Derived'Length - 1);
   begin
      SPARKTLS.Key_Schedule.Expand_Label (OKM, V.TLS13_Secret, "derived", V.TLS13_Context);
      OK := (for all I in OKM'Range => OKM (I) = V.TLS13_Derived (I));
   end TLS13_KDF_KAT;

   ----------------------------------------------------------------------------
   --  Elliptic curves
   ----------------------------------------------------------------------------

   procedure ECDSA_KAT (OK : out Boolean) is
      R256, S256 : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
      R384, S384 : Byte_Seq (0 .. 47);
   begin
      SPARKTLSCrypto.P256.ECDSA.Sign
        (V.P256_Hash, V.P256_D, V.P256_K, Blind_P256, R256, S256, OK);
      if not OK or else R256 /= V.P256_R or else S256 /= V.P256_S
        or else not SPARKTLSCrypto.P256.ECDSA.Verify
                      (V.P256_Hash, V.P256_Qx, V.P256_Qy, V.P256_R, V.P256_S)
      then
         OK := False;
         return;
      end if;
      SPARKTLSCrypto.P384.ECDSA.Sign
        (V.P384_Hash, V.P384_D, V.P384_K, Blind_P384, R384, S384, OK);
      OK := OK and then R384 = V.P384_R and then S384 = V.P384_S
        and then SPARKTLSCrypto.P384.ECDSA.Verify
                   (V.P384_Hash, V.P384_Qx, V.P384_Qy, V.P384_R, V.P384_S);
   end ECDSA_KAT;

   procedure ECDH_KAT (OK : out Boolean) is
      use SPARKTLSCrypto.P256.Point;
      Peer  : P256_Jacobian;
      Valid : U32;
      Enc   : Byte_Seq (0 .. 64);
      Z384  : Bytes_48;
   begin
      P256_Decode (Peer, V.P256_ECDH_Peer, Valid);
      if Valid = 0 then
         OK := False;
         return;
      end if;
      P256_Mul_Blinded (Peer, V.P256_ECDH_SK, Blind_P256);
      P256_To_Affine (Peer);
      P256_Encode (Enc, Peer);
      if Enc (1 .. 32) /= V.P256_ECDH_Z then
         OK := False;
         return;
      end if;
      SPARKTLSCrypto.P384.Point.P384_ECDHE_Blinded
        (Z384, OK, V.P384_ECDH_SK, V.P384_ECDH_Peer, Blind_P384);
      OK := OK and then Byte_Seq (Z384) = V.P384_ECDH_Z;
   end ECDH_KAT;

   ----------------------------------------------------------------------------
   --  RSA
   ----------------------------------------------------------------------------

   procedure RSA_KAT (OK : out Boolean) is
      use SPARKTLSCrypto.RSA;
      CRT     : CRT_Params;
      Sig     : Byte_Seq (0 .. V.RSA_N'Length - 1);
      Sig_Len : N32;
   begin
      CRT.Valid := True;
      CRT.Prime_Len := V.RSA_P'Length;
      CRT.P (0 .. V.RSA_P'Length - 1) := V.RSA_P;
      CRT.Q (0 .. V.RSA_Q'Length - 1) := V.RSA_Q;
      CRT.DP (0 .. V.RSA_DP'Length - 1) := V.RSA_DP;
      CRT.DQ (0 .. V.RSA_DQ'Length - 1) := V.RSA_DQ;
      CRT.QInv (0 .. V.RSA_QInv'Length - 1) := V.RSA_QInv;
      Sign_PKCS1_v1_5
        (M_Hash    => V.RSA_Hash,
         Hash_Len  => 32,
         Modulus   => V.RSA_N,
         Mod_Len   => V.RSA_N'Length,
         Priv_Exp  => V.RSA_D,
         Signature => Sig,
         Sig_Len   => Sig_Len,
         OK        => OK,
         Blind     => Blind_RSA,
         Pub_Exp   => V.RSA_E,
         CRT       => CRT);
      OK := OK and then Sig_Len = V.RSA_Sig'Length and then Sig = V.RSA_Sig
        and then Verify_PKCS1_v1_5_SHA256
                   (V.RSA_Hash, V.RSA_N, V.RSA_N'Length, V.RSA_E, V.RSA_Sig, V.RSA_Sig'Length);
   end RSA_KAT;

   ----------------------------------------------------------------------------
   --  Ed25519
   ----------------------------------------------------------------------------

   procedure Ed25519_KAT (OK : out Boolean) is
      SK      : constant Bytes_64 := V.Ed25519_Seed & V.Ed25519_PK;
      SM      : Byte_Seq (0 .. 64 + V.Ed25519_Msg'Length - 1);
      Opened  : Byte_Seq (SM'Range);
      Valid   : Boolean;
      Msg_Len : I32;
   begin
      SPARKTLSCrypto.Ed25519.Sign (SM, V.Ed25519_Msg, SK);
      if SM (0 .. 63) /= V.Ed25519_Sig then
         OK := False;
         return;
      end if;
      SPARKTLSCrypto.Ed25519.Open (Opened, Valid, Msg_Len, SM, V.Ed25519_PK);
      OK := Valid;
   end Ed25519_KAT;

   ----------------------------------------------------------------------------
   --  ML-KEM-768 (the crate has its own byte types)
   ----------------------------------------------------------------------------

   function To_KEM (B : Byte_Seq) return MLKEM.Byte_Seq
   with Pre  => B'First = 0 and then B'Length <= 4096,
        Post => To_KEM'Result'First = 0 and then To_KEM'Result'Length = B'Length
   is
      R : MLKEM.Byte_Seq (0 .. MLKEM.N32 (B'Length) - 1) := (others => 0);
   begin
      for I in R'Range loop
         R (I) := MLKEM.Byte (B (N32 (I)));
      end loop;
      return R;
   end To_KEM;

   function SHA256_Of (B : MLKEM.Byte_Seq) return Byte_Seq
   with Pre => B'First = 0 and then B'Length <= 4096
   is
      C : Byte_Seq (0 .. N32 (B'Length) - 1) := (others => 0);
   begin
      for I in C'Range loop
         C (I) := Byte (B (MLKEM.N32 (I)));
      end loop;
      return Byte_Seq (SPARKTLSCrypto.Hashing.SHA256.Hash (C));
   end SHA256_Of;

   function From_KEM_32 (B : MLKEM.Bytes_32) return Byte_Seq is
      R : Byte_Seq (0 .. 31) := (others => 0);
   begin
      for I in R'Range loop
         R (I) := Byte (B (MLKEM.N32 (I)));
      end loop;
      return R;
   end From_KEM_32;

   procedure MLKEM_KAT (OK : out Boolean) is
      use MLKEM.ML_KEM_768;
      Key : MLKEM_Key;
      EK  : constant MLKEM_Encapsulation_Key := To_KEM (V.MLKEM_Enc_EK);
      DK  : constant MLKEM_Decapsulation_Key := To_KEM (V.MLKEM_Dec_DK);
      C   : constant Ciphertext := To_KEM (V.MLKEM_Dec_C);
      Bad : Ciphertext := C;
      Ct  : Ciphertext;
      K   : MLKEM.Bytes_32;
   begin
      --  Key generation from fixed seeds (d, z).
      MLKEM_KeyGen (To_KEM (V.MLKEM_KG_D), To_KEM (V.MLKEM_KG_Z), Key);
      if SHA256_Of (Key.EK) /= V.MLKEM_KG_EK_SHA256
        or else SHA256_Of (Key.DK) /= V.MLKEM_KG_DK_SHA256
      then
         OK := False;
         return;
      end if;
      --  Encapsulation with fixed randomness m.
      if not EK_Valid_For_Encaps (EK) then
         OK := False;
         return;
      end if;
      MLKEM_Encaps (EK, To_KEM (V.MLKEM_Enc_M), K, Ct);
      if From_KEM_32 (K) /= V.MLKEM_Enc_K or else SHA256_Of (Ct) /= V.MLKEM_Enc_C_SHA256 then
         OK := False;
         return;
      end if;
      --  Decapsulation, then implicit rejection of a modified ciphertext
      --  (IG 10.3.A note 21: both paths).
      if not DK_Valid_For_Decaps (DK) then
         OK := False;
         return;
      end if;
      MLKEM_Decaps (C, DK, K);
      if From_KEM_32 (K) /= V.MLKEM_Dec_K then
         OK := False;
         return;
      end if;
      Bad (0) := Bad (0) xor 1;
      MLKEM_Decaps (Bad, DK, K);
      OK := From_KEM_32 (K) = V.MLKEM_Reject_K;
   end MLKEM_KAT;

   ----------------------------------------------------------------------------

   procedure Remaining (OK : out Boolean) is
   begin
      HMAC_SHA384_KAT (OK);
      if OK then SHA512_KAT (OK);    end if;
      if OK then GCM_KAT (OK);       end if;
      if OK then HKDF_KAT (OK);      end if;
      if OK then TLS12_PRF_KAT (OK); end if;
      if OK then TLS13_KDF_KAT (OK); end if;
      if OK then ECDSA_KAT (OK);     end if;
      if OK then ECDH_KAT (OK);      end if;
      if OK then RSA_KAT (OK);       end if;
      if OK then Ed25519_KAT (OK);   end if;
      if OK then MLKEM_KAT (OK);     end if;
   end Remaining;

end SPARKTLS.Self_Tests;
