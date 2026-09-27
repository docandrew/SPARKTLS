--  ACVP module wrapper for the SPARKTLS cryptographic module.
--
--  Speaks BoringSSL's acvptool wrapper protocol over stdin/stdout
--  (util/fipstools/acvp/ACVP.md): a request is a count of byte strings, the
--  length of each, then the strings, all counts and lengths 32-bit
--  little-endian; the first string names the command. A reply has the same
--  shape without the command. Every command calls the module's own
--  implementation, the code a TLS session runs.
--
--  Commands implemented (the deterministic ACVP tests the lane runs):
--    getConfig
--    SHA2-256 SHA2-384 SHA2-512 and their /MCT forms
--    HMAC-SHA2-256 HMAC-SHA2-384
--    AES-GCM/seal AES-GCM/open               (96-bit IV, 128-bit tag)
--    HKDF/<H> HKDFExtract/<H> HKDFExpandLabel/<H>  (H = SHA2-256, SHA2-384)
--    TLSKDF/1.2/<H>
--    hmacDRBG/SHA2-256 hmacDRBG-reseed/SHA2-256
--    ECDH/P-256 ECDH/P-384                   (with a given private key)
--    ECDSA/sigVer  RSA/sigVer/<H>/{pkcs1v1.5,pss}  EDDSA/sigVer
--    ML-KEM-768/{keyGen,encap,decap,encapKeyCheck,decapKeyCheck}
--
--  A test program, not part of the library: it uses the Ada runtime freely.

with Ada.Unchecked_Deallocation;
with GNAT.OS_Lib;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HMAC_DRBG;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA512;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.P384.Point;
with SPARKTLSCrypto.RSA;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Schedule_12;
with MLKEM;
with MLKEM.ML_KEM_768;

procedure ACVP_Wrapper is

   type Seq_Access is access Byte_Seq;
   procedure Free is new Ada.Unchecked_Deallocation (Byte_Seq, Seq_Access);

   Max_Args : constant := 16;
   type Arg_Array is array (1 .. Max_Args) of Seq_Access;

   Protocol_Error : exception;

   ----------------------------------------------------------------------------
   --  I/O
   ----------------------------------------------------------------------------

   Empty : constant Byte_Seq (0 .. -1) := (others => 0);

   --  Read exactly Len bytes from stdin; False at end of input.
   function Read_Bytes (Len : Natural; Buf : out Seq_Access) return Boolean is
      Got : Natural := 0;
      N   : Integer;
   begin
      Buf := new Byte_Seq (0 .. N32 (Len) - 1);
      while Got < Len loop
         N := GNAT.OS_Lib.Read (GNAT.OS_Lib.Standin, Buf (N32 (Got))'Address, Len - Got);
         if N <= 0 then
            return False;
         end if;
         Got := Got + N;
      end loop;
      return True;
   end Read_Bytes;

   function To_U32 (B : Byte_Seq) return Unsigned_32 is
     (Unsigned_32 (B (B'First))
      or Shift_Left (Unsigned_32 (B (B'First + 1)), 8)
      or Shift_Left (Unsigned_32 (B (B'First + 2)), 16)
      or Shift_Left (Unsigned_32 (B (B'First + 3)), 24));

   function LE32 (V : Unsigned_32) return Byte_Seq is
     (0 => Byte (V and 16#FF#),
      1 => Byte (Shift_Right (V, 8) and 16#FF#),
      2 => Byte (Shift_Right (V, 16) and 16#FF#),
      3 => Byte (Shift_Right (V, 24) and 16#FF#));

   procedure Write_All (B : Byte_Seq) is
      Done : Natural := 0;
      N    : Integer;
   begin
      while Done < B'Length loop
         N := GNAT.OS_Lib.Write
           (GNAT.OS_Lib.Standout, B (B'First + N32 (Done))'Address, B'Length - Done);
         if N <= 0 then
            raise Protocol_Error;
         end if;
         Done := Done + N;
      end loop;
   end Write_All;

   --  Reply with the given byte strings (each passed as an access so the
   --  list can mix lengths).
   type Reply_List is array (Positive range <>) of Seq_Access;

   procedure Reply (Parts : Reply_List) is
   begin
      Write_All (LE32 (Unsigned_32 (Parts'Length)));
      for P of Parts loop
         Write_All (LE32 (Unsigned_32 (P'Length)));
      end loop;
      for P of Parts loop
         if P'Length > 0 then
            Write_All (P.all);
         end if;
      end loop;
   end Reply;

   function Box (B : Byte_Seq) return Seq_Access is
      R : constant Seq_Access := new Byte_Seq (0 .. B'Length - 1);
   begin
      R.all := B;
      return R;
   end Box;

   procedure Reply1 (A : Byte_Seq) is
      P : Seq_Access := Box (A);
   begin
      Reply ((1 => P));
      Free (P);
   end Reply1;

   procedure Reply2 (A, B : Byte_Seq) is
      P : Seq_Access := Box (A);
      Q : Seq_Access := Box (B);
   begin
      Reply ((P, Q));
      Free (P);
      Free (Q);
   end Reply2;

   procedure Reply3 (A, B, C : Byte_Seq) is
      P : Seq_Access := Box (A);
      Q : Seq_Access := Box (B);
      R : Seq_Access := Box (C);
   begin
      Reply ((P, Q, R));
      Free (P);
      Free (Q);
      Free (R);
   end Reply3;

   function Flag (B : Boolean) return Byte_Seq is (0 => (if B then 1 else 0));

   function To_String (B : Byte_Seq) return String is
      S : String (1 .. B'Length);
   begin
      for I in S'Range loop
         S (I) := Character'Val (B (B'First + N32 (I - 1)));
      end loop;
      return S;
   end To_String;

   --  Left-pad (or keep the low-order end of) a big-endian integer to Len
   --  bytes.
   function Fit (B : Byte_Seq; Len : N32) return Byte_Seq is
      R : Byte_Seq (0 .. Len - 1) := (others => 0);
   begin
      if B'Length >= Len then
         R := B (B'Last - Len + 1 .. B'Last);
      else
         R (Len - B'Length .. Len - 1) := B;
      end if;
      return R;
   end Fit;

   ----------------------------------------------------------------------------
   --  Algorithms
   ----------------------------------------------------------------------------

   function Hash (Name : String; M : Byte_Seq) return Byte_Seq is
   begin
      if Name = "SHA2-256" then
         return Byte_Seq (SPARKTLSCrypto.Hashing.SHA256.Hash (M));
      elsif Name = "SHA2-384" then
         return Byte_Seq (SPARKTLSCrypto.Hashing.SHA384.Hash (M));
      elsif Name = "SHA2-512" then
         return Byte_Seq (SPARKTLSCrypto.Hashing.SHA512.Hash (M));
      end if;
      raise Protocol_Error with "hash " & Name;
   end Hash;

   --  ACVP SHA-2 Monte Carlo inner loop: 1000 iterations over the last
   --  three digests, starting from three copies of the seed.
   function Hash_MCT (Name : String; Seed : Byte_Seq) return Byte_Seq is
      L   : constant N32 := Seed'Length;
      Buf : Byte_Seq (0 .. 3 * L - 1);
   begin
      Buf (0 .. L - 1) := Seed;
      Buf (L .. 2 * L - 1) := Seed;
      Buf (2 * L .. 3 * L - 1) := Seed;
      for I in 1 .. 1000 loop
         declare
            D : constant Byte_Seq := Hash (Name, Buf);
         begin
            Buf (0 .. 2 * L - 1) := Buf (L .. 3 * L - 1);
            Buf (2 * L .. 3 * L - 1) := D;
         end;
      end loop;
      return Buf (2 * L .. 3 * L - 1);
   end Hash_MCT;

   function HMAC (Name : String; M, K : Byte_Seq) return Byte_Seq is
      Msg : constant Byte_Seq (0 .. M'Length - 1) := M;
      Key : constant Byte_Seq (0 .. K'Length - 1) := K;
   begin
      if Name = "SHA2-256" then
         declare
            D : SPARKTLSCrypto.Hashing.SHA256.Digest;
         begin
            SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, Msg, Key);
            return Byte_Seq (D);
         end;
      elsif Name = "SHA2-384" then
         declare
            D : SPARKTLSCrypto.HMAC384.Digest_384;
         begin
            SPARKTLSCrypto.HMAC384.HMAC_SHA_384 (D, Msg, Key);
            return Byte_Seq (D);
         end;
      end if;
      raise Protocol_Error with "hmac " & Name;
   end HMAC;

   --  AES-GCM seal: ciphertext || tag.
   function GCM_Seal (Key, PT, Nonce, AAD : Byte_Seq) return Byte_Seq is
      use SPARKTLSCrypto.AES_GCM;
      M : constant Byte_Seq (0 .. PT'Length - 1) := PT;
      A : constant Byte_Seq (0 .. AAD'Length - 1) := AAD;
      N : constant Bytes_12 := Nonce;
      C : Byte_Seq (0 .. PT'Length - 1);
      T : Bytes_16;
   begin
      if Key'Length = 16 then
         Encrypt (C, T, M, N, SPARKNaCl.AES.Construct (Bytes_16 (Key)), A);
      else
         Encrypt_256 (C, T, M, N, SPARKNaCl.AES.Construct (Bytes_32 (Key)), A);
      end if;
      return C & Byte_Seq (T);
   end GCM_Seal;

   procedure GCM_Open (Key, CT_Tag, Nonce, AAD : Byte_Seq) is
      use SPARKTLSCrypto.AES_GCM;
      Len : constant N32 := CT_Tag'Length - 16;
      C   : constant Byte_Seq (0 .. Len - 1) := CT_Tag (CT_Tag'First .. CT_Tag'First + Len - 1);
      T   : constant Bytes_16 := CT_Tag (CT_Tag'Last - 15 .. CT_Tag'Last);
      A   : constant Byte_Seq (0 .. AAD'Length - 1) := AAD;
      N   : constant Bytes_12 := Nonce;
      M   : Byte_Seq (0 .. Len - 1);
      OK  : Boolean;
   begin
      if Len = 0 then
         --  Empty ciphertext: the tag is recomputed and compared.
         declare
            Want : constant Byte_Seq := GCM_Seal (Key, Empty, Nonce, AAD);
         begin
            OK := Want = Byte_Seq (T);
         end;
      elsif Key'Length = 16 then
         Decrypt (M, OK, T, C, N, SPARKNaCl.AES.Construct (Bytes_16 (Key)), A);
      else
         Decrypt_256 (M, OK, T, C, N, SPARKNaCl.AES.Construct (Bytes_32 (Key)), A);
      end if;
      if OK then
         Reply2 (Flag (True), M);
      else
         Reply2 (Flag (False), Empty);
      end if;
   end GCM_Open;

   function HKDF_Extract (Name : String; Secret, Salt : Byte_Seq) return Byte_Seq is
      IKM : constant Byte_Seq (0 .. Secret'Length - 1) := Secret;
      S   : constant Byte_Seq (0 .. Salt'Length - 1) := Salt;
   begin
      if IKM'Length = 0 then
         --  HKDF-Extract is HMAC(salt, IKM); the proven Extract requires a
         --  non-empty IKM, which TLS always has.
         return HMAC (Name, IKM, S);
      elsif Name = "SHA2-256" then
         declare
            PRK : SPARKTLSCrypto.Hashing.SHA256.Digest;
         begin
            SPARKTLSCrypto.HKDF.Extract (PRK, IKM, S);
            return Byte_Seq (PRK);
         end;
      else
         declare
            PRK : SPARKTLSCrypto.HKDF384.Digest_384;
         begin
            SPARKTLSCrypto.HKDF384.Extract (PRK, IKM, S);
            return Byte_Seq (PRK);
         end;
      end if;
   end HKDF_Extract;

   function HKDF_Expand (Name : String; PRK, Info : Byte_Seq; Len : N32) return Byte_Seq is
      I : constant Byte_Seq (0 .. Info'Length - 1) := Info;
      R : Byte_Seq (0 .. Len - 1);
   begin
      if Name = "SHA2-256" then
         declare
            use SPARKTLSCrypto.HKDF;
            O : OKM_Seq (0 .. Len - 1);
         begin
            Expand (O, SPARKTLSCrypto.Hashing.SHA256.Digest (PRK), I);
            for J in R'Range loop R (J) := O (J); end loop;
         end;
      else
         declare
            use SPARKTLSCrypto.HKDF384;
            O : OKM384_Seq (0 .. Len - 1);
         begin
            Expand (O, Digest_384 (PRK), I);
            for J in R'Range loop R (J) := O (J); end loop;
         end;
      end if;
      return R;
   end HKDF_Expand;

   function Expand_Label (Name : String; Len : N32; Secret, Label, Context : Byte_Seq)
     return Byte_Seq
   is
      Ctx : constant Byte_Seq (0 .. Context'Length - 1) := Context;
      L   : constant String := To_String (Label);
      R   : Byte_Seq (0 .. Len - 1);
   begin
      if Name = "SHA2-256" then
         declare
            O : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. Len - 1);
         begin
            SPARKTLS.Key_Schedule.Expand_Label
              (O, SPARKTLSCrypto.Hashing.SHA256.Digest (Secret), L, Ctx);
            for J in R'Range loop R (J) := O (J); end loop;
         end;
      else
         declare
            O : SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. Len - 1);
         begin
            SPARKTLS.Key_Schedule.Expand_Label_384
              (O, SPARKTLS.Key_Schedule.Digest_384 (Secret), L, Ctx);
            for J in R'Range loop R (J) := O (J); end loop;
         end;
      end if;
      return R;
   end Expand_Label;

   function TLS12_PRF (Name : String; Len : N32; Secret, Label, Seed1, Seed2 : Byte_Seq)
     return Byte_Seq
   is
      S    : constant Byte_Seq (0 .. Secret'Length - 1) := Secret;
      Seed : constant Byte_Seq (0 .. Seed1'Length + Seed2'Length - 1) := Seed1 & Seed2;
      R    : Byte_Seq (0 .. Len - 1);
   begin
      if Name = "SHA2-256" then
         SPARKTLS.Key_Schedule_12.PRF_SHA256 (R, S, To_String (Label), Seed);
      else
         SPARKTLS.Key_Schedule_12.PRF_SHA384 (R, S, To_String (Label), Seed);
      end if;
      return R;
   end TLS12_PRF;

   --  SP 800-90A test: instantiate, optionally reseed, generate twice and
   --  return the second output.
   function DRBG (Len : N32; Entropy, Perso, Reseed_AD, Reseed_Entropy, AD1, AD2, Nonce : Byte_Seq;
                  With_Reseed : Boolean) return Byte_Seq
   is
      use SPARKTLSCrypto.HMAC_DRBG;
      E  : constant Byte_Seq (0 .. Entropy'Length - 1) := Entropy;
      P  : constant Byte_Seq (0 .. Perso'Length - 1) := Perso;
      N  : constant Byte_Seq (0 .. Nonce'Length - 1) := Nonce;
      RA : constant Byte_Seq (0 .. Reseed_AD'Length - 1) := Reseed_AD;
      RE : constant Byte_Seq (0 .. Reseed_Entropy'Length - 1) := Reseed_Entropy;
      A1 : constant Byte_Seq (0 .. AD1'Length - 1) := AD1;
      A2 : constant Byte_Seq (0 .. AD2'Length - 1) := AD2;
      S  : State;
      R  : Byte_Seq (0 .. Len - 1);
      OK : Boolean;
   begin
      Instantiate (S, E, N, P);
      if With_Reseed then
         Reseed (S, RE, RA);
      end if;
      Generate (S, A1, R, OK);
      Generate (S, A2, R, OK);
      Sanitize (S);
      return R;
   end DRBG;

   --  ECDH with a given private key: (our X, our Y, shared X).
   procedure ECDH (Curve : String; X, Y, Priv : Byte_Seq) is
   begin
      if Curve = "P-256" then
         declare
            use SPARKTLSCrypto.P256.Point;
            SK   : constant Byte_Seq (0 .. 31) := Fit (Priv, 32);
            Pub  : P256_Jacobian;
            Peer : P256_Jacobian;
            Enc  : Byte_Seq (0 .. 64);
            Sh   : Byte_Seq (0 .. 64);
            V    : U32;
         begin
            P256_Mulgen (Pub, SK, 32);
            P256_To_Affine (Pub);
            P256_Encode (Enc, Pub);
            P256_Decode (Peer, Byte_Seq'(0 => 4) & Fit (X, 32) & Fit (Y, 32), V);
            if V = 0 then
               raise Protocol_Error with "bad P-256 peer point";
            end if;
            P256_Mul (Peer, SK, 32);
            P256_To_Affine (Peer);
            P256_Encode (Sh, Peer);
            Reply3 (Enc (1 .. 32), Enc (33 .. 64), Sh (1 .. 32));
         end;
      elsif Curve = "P-384" then
         declare
            use SPARKTLSCrypto.P384.Point;
            SK  : constant Byte_Seq (0 .. 47) := Fit (Priv, 48);
            Pub : Byte_Seq (0 .. 96);
            Sh  : Bytes_48;
            OK  : Boolean;
         begin
            P384_Mulgen (Pub, SK);
            P384_ECDHE (Sh, OK, SK, Byte_Seq'(0 => 4) & Fit (X, 48) & Fit (Y, 48));
            if not OK then
               raise Protocol_Error with "bad P-384 peer point";
            end if;
            Reply3 (Pub (1 .. 48), Pub (49 .. 96), Byte_Seq (Sh));
         end;
      else
         raise Protocol_Error with "ECDH curve " & Curve;
      end if;
   end ECDH;

   --  FIPS 186-5 6.4.1: the leftmost bits of the digest, as an integer the
   --  width of the curve order.
   function Digest_For (Width : N32; H : Byte_Seq) return Byte_Seq is
     (if H'Length >= Width then H (H'First .. H'First + Width - 1) else Fit (H, Width));

   function ECDSA_Verify (Curve, Hash_Name : String; Msg, X, Y, R, S : Byte_Seq) return Boolean is
      H : constant Byte_Seq := Hash (Hash_Name, Msg);
   begin
      if Curve = "P-256" then
         return SPARKTLSCrypto.P256.ECDSA.Verify
           (Bytes_32 (Digest_For (32, H)), Fit (X, 32), Fit (Y, 32), Fit (R, 32), Fit (S, 32));
      elsif Curve = "P-384" then
         return SPARKTLSCrypto.P384.ECDSA.Verify
           (Bytes_48 (Digest_For (48, H)), Fit (X, 48), Fit (Y, 48), Fit (R, 48), Fit (S, 48));
      end if;
      raise Protocol_Error with "ECDSA curve " & Curve;
   end ECDSA_Verify;

   function RSA_Verify (Hash_Name : String; PSS : Boolean; N, E, Msg, Sig : Byte_Seq) return Boolean is
      use SPARKTLSCrypto.RSA;
      Len : constant N32 := N'Length;
      Mo  : constant Byte_Seq (0 .. Len - 1) := N;
      Sg  : constant Byte_Seq (0 .. Len - 1) := Fit (Sig, Len);
      Ex  : Unsigned_32 := 0;
      H   : constant Byte_Seq := Hash (Hash_Name, Msg);
   begin
      if E'Length > 4 then
         raise Protocol_Error with "RSA exponent wider than 32 bits";
      end if;
      for B of E loop
         Ex := Shift_Left (Ex, 8) or Unsigned_32 (B);
      end loop;
      if Hash_Name = "SHA2-256" then
         return (if PSS then Verify_PSS_SHA256 (Bytes_32 (H), Mo, Len, Ex, Sg, Len)
                 else Verify_PKCS1_v1_5_SHA256 (Bytes_32 (H), Mo, Len, Ex, Sg, Len));
      elsif Hash_Name = "SHA2-384" then
         return (if PSS then Verify_PSS_SHA384 (Bytes_48 (H), Mo, Len, Ex, Sg, Len)
                 else Verify_PKCS1_v1_5_SHA384 (Bytes_48 (H), Mo, Len, Ex, Sg, Len));
      else
         return (if PSS then Verify_PSS_SHA512 (Bytes_64 (H), Mo, Len, Ex, Sg, Len)
                 else Verify_PKCS1_v1_5_SHA512 (Bytes_64 (H), Mo, Len, Ex, Sg, Len));
      end if;
   end RSA_Verify;

   function Ed25519_Verify (Msg, Q, Sig : Byte_Seq) return Boolean is
      SM : constant Byte_Seq (0 .. 64 + Msg'Length - 1) := Sig & Msg;
      M  : Byte_Seq (0 .. SM'Last);
      OK : Boolean;
      L  : I32;
   begin
      if Sig'Length /= 64 or else Q'Length /= 32 then
         return False;
      end if;
      SPARKTLSCrypto.Ed25519.Open (M, OK, L, SM, Bytes_32 (Q));
      return OK;
   end Ed25519_Verify;

   --  ML-KEM-768. The crate has its own byte types.
   function To_KEM (B : Byte_Seq) return MLKEM.Byte_Seq is
      R : MLKEM.Byte_Seq (0 .. MLKEM.N32 (B'Length) - 1);
   begin
      for I in R'Range loop
         R (I) := MLKEM.Byte (B (B'First + N32 (I)));
      end loop;
      return R;
   end To_KEM;

   function From_KEM (B : MLKEM.Byte_Seq) return Byte_Seq is
      R : Byte_Seq (0 .. N32 (B'Length) - 1);
   begin
      for I in R'Range loop
         R (I) := Byte (B (B'First + MLKEM.N32 (I)));
      end loop;
      return R;
   end From_KEM;

   procedure ML_KEM (Op : String; Args : Arg_Array) is
      use MLKEM.ML_KEM_768;
   begin
      if Op = "keyGen" then
         declare
            Seed : constant MLKEM.Byte_Seq := To_KEM (Args (2).all);
            Key  : MLKEM_Key;
         begin
            MLKEM_KeyGen (MLKEM.Bytes_32 (Seed (0 .. 31)), MLKEM.Bytes_32 (Seed (32 .. 63)), Key);
            Reply2 (From_KEM (Key.EK), From_KEM (Key.DK));
         end;
      elsif Op = "encap" then
         declare
            EK : constant MLKEM_Encapsulation_Key := To_KEM (Args (2).all);
            M  : constant MLKEM.Bytes_32 := To_KEM (Args (3).all);
            K  : MLKEM.Bytes_32;
            C  : Ciphertext;
         begin
            MLKEM_Encaps (EK, M, K, C);
            Reply2 (From_KEM (C), From_KEM (K));
         end;
      elsif Op = "decap" then
         declare
            DK : constant MLKEM_Decapsulation_Key := To_KEM (Args (2).all);
            C  : constant Ciphertext := To_KEM (Args (3).all);
            K  : MLKEM.Bytes_32;
         begin
            MLKEM_Decaps (C, DK, K);
            Reply1 (From_KEM (K));
         end;
      elsif Op = "encapKeyCheck" then
         Reply1 (Flag (Args (2)'Length = 1184
                       and then EK_Valid_For_Encaps (To_KEM (Args (2).all))));
      elsif Op = "decapKeyCheck" then
         Reply1 (Flag (Args (2)'Length = 2400
                       and then DK_Valid_For_Decaps (To_KEM (Args (2).all))));
      else
         raise Protocol_Error with "ML-KEM op " & Op;
      end if;
   end ML_KEM;

   ----------------------------------------------------------------------------
   --  getConfig: the algorithms acvptool may send (offline it only needs the
   --  names; an online registration would carry the full capabilities).
   ----------------------------------------------------------------------------

   Config : constant String :=
     "[" &
     "{""algorithm"":""SHA2-256"",""revision"":""1.0""}," &
     "{""algorithm"":""SHA2-384"",""revision"":""1.0""}," &
     "{""algorithm"":""SHA2-512"",""revision"":""1.0""}," &
     "{""algorithm"":""HMAC-SHA2-256"",""revision"":""1.0""}," &
     "{""algorithm"":""HMAC-SHA2-384"",""revision"":""1.0""}," &
     "{""algorithm"":""ACVP-AES-GCM"",""revision"":""1.0""}," &
     "{""algorithm"":""KDA"",""mode"":""HKDF"",""revision"":""Sp800-56Cr2""}," &
     "{""algorithm"":""TLS-v1.2"",""mode"":""KDF"",""revision"":""RFC7627""}," &
     "{""algorithm"":""TLS-v1.3"",""mode"":""KDF"",""revision"":""RFC8446""}," &
     "{""algorithm"":""hmacDRBG"",""revision"":""1.0""}," &
     "{""algorithm"":""KAS-ECC-SSC"",""revision"":""Sp800-56Ar3""}," &
     "{""algorithm"":""ECDSA"",""mode"":""sigVer"",""revision"":""FIPS186-5""}," &
     "{""algorithm"":""RSA"",""mode"":""sigVer"",""revision"":""FIPS186-5""}," &
     "{""algorithm"":""EDDSA"",""mode"":""sigVer"",""revision"":""1.0""}," &
     "{""algorithm"":""ML-KEM"",""mode"":""keyGen"",""revision"":""FIPS203""}," &
     "{""algorithm"":""ML-KEM"",""mode"":""encapDecap"",""revision"":""FIPS203""}" &
     "]";

   ----------------------------------------------------------------------------
   --  Dispatch
   ----------------------------------------------------------------------------

   function Starts (S, Prefix : String) return Boolean is
     (S'Length >= Prefix'Length and then S (S'First .. S'First + Prefix'Length - 1) = Prefix);

   function After (S, Prefix : String) return String is (S (S'First + Prefix'Length .. S'Last));

   procedure Dispatch (Args : Arg_Array; Count : Positive) is
      Cmd : constant String := To_String (Args (1).all);
      function A (I : Positive) return Byte_Seq is (Args (I).all);
   begin
      if Cmd = "getConfig" then
         declare
            C : Byte_Seq (0 .. Config'Length - 1);
         begin
            for I in C'Range loop
               C (I) := Character'Pos (Config (Config'First + Integer (I)));
            end loop;
            Reply1 (C);
         end;
      elsif Cmd in "SHA2-256" | "SHA2-384" | "SHA2-512" then
         Reply1 (Hash (Cmd, A (2)));
      elsif Cmd in "SHA2-256/MCT" | "SHA2-384/MCT" | "SHA2-512/MCT" then
         Reply1 (Hash_MCT (Cmd (Cmd'First .. Cmd'Last - 4), A (2)));
      elsif Starts (Cmd, "HMAC-") then
         Reply1 (HMAC (After (Cmd, "HMAC-"), A (2), A (3)));
      elsif Cmd = "AES-GCM/seal" then
         if To_U32 (A (2)) /= 16 or else A (5)'Length /= 12 then
            raise Protocol_Error with "GCM tag/IV length";
         end if;
         Reply1 (GCM_Seal (A (3), A (4), A (5), A (6)));
      elsif Cmd = "AES-GCM/open" then
         if To_U32 (A (2)) /= 16 or else A (5)'Length /= 12 then
            raise Protocol_Error with "GCM tag/IV length";
         end if;
         GCM_Open (A (3), A (4), A (5), A (6));
      elsif Starts (Cmd, "HKDFExtract/") then
         Reply1 (HKDF_Extract (After (Cmd, "HKDFExtract/"), A (2), A (3)));
      elsif Starts (Cmd, "HKDFExpandLabel/") then
         Reply1 (Expand_Label (After (Cmd, "HKDFExpandLabel/"), N32 (To_U32 (A (2))), A (3), A (4), A (5)));
      elsif Starts (Cmd, "HKDF/") then
         declare
            Name : constant String := After (Cmd, "HKDF/");
         begin
            Reply1 (HKDF_Expand (Name, HKDF_Extract (Name, A (2), A (3)), A (4), N32 (To_U32 (A (5)))));
         end;
      elsif Starts (Cmd, "TLSKDF/1.2/") then
         Reply1 (TLS12_PRF (After (Cmd, "TLSKDF/1.2/"), N32 (To_U32 (A (2))), A (3), A (4), A (5), A (6)));
      elsif Cmd = "hmacDRBG/SHA2-256" then
         Reply1 (DRBG (N32 (To_U32 (A (2))), A (3), A (4), Empty, Empty, A (5), A (6), A (7), False));
      elsif Cmd = "hmacDRBG-reseed/SHA2-256" then
         Reply1 (DRBG (N32 (To_U32 (A (2))), A (3), A (4), A (5), A (6), A (7), A (8), A (9), True));
      elsif Starts (Cmd, "ECDH/") then
         ECDH (After (Cmd, "ECDH/"), A (2), A (3), A (4));
      elsif Cmd = "ECDSA/sigVer" then
         Reply1 (Flag (ECDSA_Verify (To_String (A (2)), To_String (A (3)), A (4), A (5), A (6), A (7), A (8))));
      elsif Starts (Cmd, "RSA/sigVer/") then
         declare
            Rest : constant String := After (Cmd, "RSA/sigVer/");
            Slash : Natural := Rest'First;
         begin
            while Rest (Slash) /= '/' loop Slash := Slash + 1; end loop;
            Reply1 (Flag (RSA_Verify (Rest (Rest'First .. Slash - 1), Rest (Slash + 1 .. Rest'Last) = "pss",
                                      A (2), A (3), A (4), A (5))));
         end;
      elsif Cmd = "EDDSA/sigVer" then
         Reply1 (Flag (To_String (A (2)) = "ED-25519" and then A (6) (0) = 0
                       and then Ed25519_Verify (A (3), A (4), A (5))));
      elsif Starts (Cmd, "ML-KEM-768/") then
         ML_KEM (After (Cmd, "ML-KEM-768/"), Args);
      else
         raise Protocol_Error with "unsupported command " & Cmd;
      end if;
      pragma Unreferenced (Count);
   end Dispatch;

   Args  : Arg_Array := (others => null);
   Head  : Seq_Access;
   Count : Natural;
begin
   loop
      exit when not Read_Bytes (4, Head);
      Count := Natural (To_U32 (Head.all));
      Free (Head);
      if Count = 0 or else Count > Max_Args then
         raise Protocol_Error with "bad argument count";
      end if;
      declare
         Lens : array (1 .. Count) of Natural;
      begin
         for I in 1 .. Count loop
            if not Read_Bytes (4, Head) then
               raise Protocol_Error with "truncated request";
            end if;
            Lens (I) := Natural (To_U32 (Head.all));
            Free (Head);
         end loop;
         for I in 1 .. Count loop
            if not Read_Bytes (Lens (I), Args (I)) then
               raise Protocol_Error with "truncated request";
            end if;
         end loop;
      end;
      if To_String (Args (1).all) /= "flush" then
         Dispatch (Args, Count);
      end if;
      for I in 1 .. Count loop
         Free (Args (I));
      end loop;
   end loop;
end ACVP_Wrapper;
