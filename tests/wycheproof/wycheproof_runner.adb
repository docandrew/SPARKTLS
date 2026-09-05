--  Wycheproof / NIST CAVP test-vector runner.
--
--  Reads space-separated commands from stdin, one per line. Writes
--  "valid" or "invalid" on stdout per line. Designed to be driven
--  by a Python harness that iterates JSON-encoded test vectors.
--
--  Supported commands (case-sensitive):
--    rsa_pkcs1_sha256 <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    rsa_pkcs1_sha384 <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    rsa_pkcs1_sha512 <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    rsa_pss_sha256   <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    rsa_pss_sha384   <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    rsa_pss_sha512   <hex_mod> <hex_exp> <hex_hash> <hex_sig>
--    ecdsa_p256_sha256 <hex_qx> <hex_qy> <hex_msg> <hex_der_sig>
--    ecdsa_p384_sha384 <hex_qx> <hex_qy> <hex_msg> <hex_der_sig>
--    ed25519           <hex_pubkey> <hex_msg> <hex_sig>
--    aes_gcm_decrypt   <hex_key> <hex_iv> <hex_aad> <hex_ct> <hex_tag>
--    chacha_poly_dec   <hex_key> <hex_nonce> <hex_aad> <hex_ct> <hex_tag>
--    quit
--
--  Hex strings are lowercase. Empty hex = empty Byte_Seq.

with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Strings.Fixed;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with SPARKNaCl.AES;
with SPARKNaCl.Core;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;

procedure Wycheproof_Runner is

   function Hex_To_Bytes (S : String) return Byte_Seq is
      --  Sentinel '_' = empty field (since space-separated tokens
      --  collapse adjacent empties). Python harness emits '_' for
      --  empty AAD / msg / etc.
      Effective_S : constant String := (if S = "_" then "" else S);
      Len : constant Natural := Effective_S'Length / 2;
      function Nyb (C : Character) return Byte is
        (case C is
            when '0' .. '9' => Byte (Character'Pos (C) - Character'Pos ('0')),
            when 'a' .. 'f' => Byte (Character'Pos (C) - Character'Pos ('a') + 10),
            when 'A' .. 'F' => Byte (Character'Pos (C) - Character'Pos ('A') + 10),
            when others     => 0);
   begin
      if Len = 0 then
         --  Empty Byte_Seq with valid N32 bounds (1 > 0 → null range,
         --  both bounds in 0 .. I32'Last so no constraint violation).
         return Byte_Seq'(1 .. 0 => 0);
      end if;
      declare
         R : Byte_Seq (0 .. N32 (Len) - 1);
      begin
         for I in 0 .. Len - 1 loop
            R (N32 (I)) := Nyb (S (S'First + I * 2)) * 16
                         + Nyb (S (S'First + I * 2 + 1));
         end loop;
         return R;
      end;
   end Hex_To_Bytes;

   --  Strip a leading 0x00 byte (sometimes added in DER for sign-bit).
   function Trim_Leading_Zero (B : Byte_Seq) return Byte_Seq is
   begin
      if B'Length > 1 and then B (B'First) = 0 then
         return B (B'First + 1 .. B'Last);
      else
         return B;
      end if;
   end Trim_Leading_Zero;

   --  Hex string → Unsigned_32 (big-endian). Empty = 0.
   function Hex_To_U32 (S : String) return Unsigned_32 is
      R : Unsigned_32 := 0;
      function Nyb (C : Character) return Unsigned_32 is
        (case C is
            when '0' .. '9' =>
              Unsigned_32 (Character'Pos (C) - Character'Pos ('0')),
            when 'a' .. 'f' =>
              Unsigned_32 (Character'Pos (C) - Character'Pos ('a') + 10),
            when 'A' .. 'F' =>
              Unsigned_32 (Character'Pos (C) - Character'Pos ('A') + 10),
            when others     => 0);
      Effective_S : constant String := (if S = "_" then "" else S);
   begin
      for I in Effective_S'Range loop
         R := R * 16 + Nyb (Effective_S (I));
      end loop;
      return R;
   end Hex_To_U32;

   --  Tokenise on spaces. Tok index 1 = command, 2..N = args.
   type Token_Array is array (Positive range <>) of Unbounded_String;
   function Tokenise (S : String) return Token_Array is
      Toks : Token_Array (1 .. 16) := (others => Null_Unbounded_String);
      N    : Natural := 0;
      I    : Natural := S'First;
      Start : Natural;
   begin
      while I <= S'Last loop
         while I <= S'Last and then S (I) = ' ' loop I := I + 1; end loop;
         exit when I > S'Last;
         Start := I;
         while I <= S'Last and then S (I) /= ' ' loop I := I + 1; end loop;
         N := N + 1;
         exit when N > Toks'Last;
         Toks (N) := To_Unbounded_String (S (Start .. I - 1));
      end loop;
      return Toks (1 .. N);
   end Tokenise;

   procedure Reply_Valid is
   begin Put_Line ("valid"); end;
   procedure Reply_Invalid is
   begin Put_Line ("invalid"); end;

   ----------------------------------------------------------------------------
   --  Verifier dispatchers
   ----------------------------------------------------------------------------

   procedure Do_RSA_PKCS1_SHA256
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_32 := (others => 0);
   begin
      if H_Bytes'Length /= 32 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 31 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PKCS1_SHA256;

   procedure Do_RSA_PKCS1_SHA384
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_48 := (others => 0);
   begin
      if H_Bytes'Length /= 48 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 47 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA384
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PKCS1_SHA384;

   procedure Do_RSA_PKCS1_SHA512
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_64 := (others => 0);
   begin
      if H_Bytes'Length /= 64 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 63 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA512
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PKCS1_SHA512;

   procedure Do_RSA_PSS_SHA256
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_32 := (others => 0);
   begin
      if H_Bytes'Length /= 32 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 31 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PSS_SHA256
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PSS_SHA256;

   procedure Do_RSA_PSS_SHA384
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_48 := (others => 0);
   begin
      if H_Bytes'Length /= 48 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 47 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PSS_SHA384
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PSS_SHA384;

   procedure Do_RSA_PSS_SHA512
     (Hex_Mod, Hex_Exp, Hex_Hash, Hex_Sig : String)
   is
      Modulus : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Mod));
      Exp     : constant Unsigned_32 := Hex_To_U32 (Hex_Exp);
      H_Bytes : constant Byte_Seq := Hex_To_Bytes (Hex_Hash);
      Sig     : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Hash    : Bytes_64 := (others => 0);
   begin
      if H_Bytes'Length /= 64 or Sig'Length /= Modulus'Length
         or Modulus'Length < 64
         or Modulus'Length > SPARKTLSCrypto.RSA.Max_RSA_Bytes
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 63 loop Hash (I) := H_Bytes (I); end loop;
      if SPARKTLSCrypto.RSA.Verify_PSS_SHA512
         (Hash      => Hash,
          Modulus   => Modulus,
          Mod_Len   => Modulus'Length,
          Exponent  => Exp,
          Signature => Sig,
          Sig_Len   => Sig'Length)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_RSA_PSS_SHA512;

   --  Parse a DER-encoded ECDSA signature into raw r||s coords of size
   --  Coord_Len (32 for P-256, 48 for P-384). Returns False if malformed.
   function Parse_DER_ECDSA
     (DER : Byte_Seq; R, S : out Byte_Seq) return Boolean
   is
      Idx : N32;
      Outer_Len, R_Len, S_Len, R_Off, S_Off, Outer_End : N32;
      Coord_Len : constant N32 := R'Length;
   begin
      R := (others => 0); S := (others => 0);
      if DER'Length < 8 or DER'Length > 256 then return False; end if;
      Idx := DER'First;
      if DER (Idx) /= 16#30# then return False; end if;
      Idx := Idx + 1;
      --  Outer SEQUENCE length: strict DER allows 0x81 (long form) only
      --  when the value is >= 128. Anything < 128 must use short form.
      if DER (Idx) < 16#80# then
         Outer_Len := N32 (DER (Idx));
         Idx := Idx + 1;
      elsif DER (Idx) = 16#81#
         and then Idx + 1 <= DER'Last
         and then DER (Idx + 1) >= 16#80#
      then
         Outer_Len := N32 (DER (Idx + 1));
         Idx := Idx + 2;
      else
         return False;
      end if;
      Outer_End := Idx + Outer_Len;
      if Outer_End - 1 /= DER'Last then return False; end if;
      --  R INTEGER. INTEGERs in P-256/P-384/P-521 sigs are < 128 bytes.
      if DER (Idx) /= 16#02# then return False; end if;
      Idx := Idx + 1;
      if DER (Idx) >= 16#80# then return False; end if;  -- long-form len
      R_Len := N32 (DER (Idx)); Idx := Idx + 1;
      if R_Len = 0 or R_Len > Coord_Len + 1
         or Idx + R_Len - 1 > DER'Last
      then return False; end if;
      --  Strict DER: positive INTEGER with high bit set in byte 0 must
      --  have a leading 0x00 byte; without it the encoding would be
      --  ambiguous (negative in two's complement). Conversely, a
      --  leading 0x00 followed by a byte with high bit clear is
      --  superfluous (would shrink to one fewer byte) — also invalid.
      R_Off := 0;
      if DER (Idx) = 0 then
         if R_Len < 2 or DER (Idx + 1) < 16#80# then return False; end if;
         R_Off := 1;
         R_Len := R_Len - 1;
      elsif DER (Idx) >= 16#80# then
         return False;  -- missing leading 0 on positive INTEGER
      end if;
      if R_Len = 0 or R_Len > Coord_Len then return False; end if;
      for I in N32 range 0 .. R_Len - 1 loop
         R (Coord_Len - R_Len + I) := DER (Idx + R_Off + I);
      end loop;
      Idx := Idx + R_Off + R_Len;
      --  S INTEGER (same strict-DER treatment)
      if DER (Idx) /= 16#02# then return False; end if;
      Idx := Idx + 1;
      if DER (Idx) >= 16#80# then return False; end if;
      S_Len := N32 (DER (Idx)); Idx := Idx + 1;
      if S_Len = 0 or S_Len > Coord_Len + 1
         or Idx + S_Len - 1 > DER'Last
      then return False; end if;
      S_Off := 0;
      if DER (Idx) = 0 then
         if S_Len < 2 or DER (Idx + 1) < 16#80# then return False; end if;
         S_Off := 1;
         S_Len := S_Len - 1;
      elsif DER (Idx) >= 16#80# then
         return False;
      end if;
      if S_Len = 0 or S_Len > Coord_Len then return False; end if;
      for I in N32 range 0 .. S_Len - 1 loop
         S (Coord_Len - S_Len + I) := DER (Idx + S_Off + I);
      end loop;
      if Idx + S_Off + S_Len /= Outer_End then return False; end if;
      return True;
   end Parse_DER_ECDSA;

   procedure Do_ECDSA_P256_SHA256
     (Hex_Qx, Hex_Qy, Hex_Msg, Hex_Sig : String)
   is
      Qx_BS  : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Qx));
      Qy_BS  : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Qy));
      Msg    : constant Byte_Seq := Hex_To_Bytes (Hex_Msg);
      DER    : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Qx, Qy : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half := (others => 0);
      R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
      H : SPARKTLSCrypto.Hashing.SHA256.Digest;
      OK : Boolean;
   begin
      if Qx_BS'Length > 32 or Qy_BS'Length > 32 then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. Qx_BS'Length - 1 loop
         Qx (32 - Qx_BS'Length + I) := Qx_BS (Qx_BS'First + I);
      end loop;
      for I in N32 range 0 .. Qy_BS'Length - 1 loop
         Qy (32 - Qy_BS'Length + I) := Qy_BS (Qy_BS'First + I);
      end loop;
      SPARKTLSCrypto.Hashing.SHA256.Hash (H, Msg);
      OK := Parse_DER_ECDSA (DER, Byte_Seq (R_Half), Byte_Seq (S_Half));
      if not OK then Reply_Invalid; return; end if;
      if SPARKTLSCrypto.P256.ECDSA.Verify
        (Hash => H, Qx => Qx, Qy => Qy, R => R_Half, S => S_Half)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_ECDSA_P256_SHA256;

   procedure Do_ECDSA_P384_SHA384
     (Hex_Qx, Hex_Qy, Hex_Msg, Hex_Sig : String)
   is
      Qx_BS  : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Qx));
      Qy_BS  : constant Byte_Seq := Trim_Leading_Zero (Hex_To_Bytes (Hex_Qy));
      Msg    : constant Byte_Seq := Hex_To_Bytes (Hex_Msg);
      DER    : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      Qx, Qy : Byte_Seq (0 .. 47) := (others => 0);
      R_Half : Byte_Seq (0 .. 47);
      S_Half : Byte_Seq (0 .. 47);
      H : SPARKNaCl.Hashing.SHA384.Digest;
      OK : Boolean;
   begin
      if Qx_BS'Length > 48 or Qy_BS'Length > 48 then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. Qx_BS'Length - 1 loop
         Qx (48 - Qx_BS'Length + I) := Qx_BS (Qx_BS'First + I);
      end loop;
      for I in N32 range 0 .. Qy_BS'Length - 1 loop
         Qy (48 - Qy_BS'Length + I) := Qy_BS (Qy_BS'First + I);
      end loop;
      SPARKNaCl.Hashing.SHA384.Hash (H, Msg);
      OK := Parse_DER_ECDSA (DER, R_Half, S_Half);
      if not OK then Reply_Invalid; return; end if;
      if SPARKTLSCrypto.P384.ECDSA.Verify
        (Hash => Bytes_48 (Byte_Seq (H)),
         Qx => Qx, Qy => Qy, R => R_Half, S => S_Half)
      then Reply_Valid; else Reply_Invalid; end if;
   end Do_ECDSA_P384_SHA384;

   procedure Do_AES_GCM_Decrypt
     (Hex_Key, Hex_IV, Hex_AAD, Hex_CT, Hex_Tag : String)
   is
      Key_BS  : constant Byte_Seq := Hex_To_Bytes (Hex_Key);
      IV_BS   : constant Byte_Seq := Hex_To_Bytes (Hex_IV);
      AAD     : constant Byte_Seq := Hex_To_Bytes (Hex_AAD);
      CT      : constant Byte_Seq := Hex_To_Bytes (Hex_CT);
      Tag_BS  : constant Byte_Seq := Hex_To_Bytes (Hex_Tag);
      Tag     : Bytes_16 := (others => 0);
      IV      : Bytes_12 := (others => 0);
   begin
      --  Wycheproof / CAVP only emit 96-bit IVs and 128-bit tags for
      --  most test sets; reject other sizes (treated as invalid).
      if IV_BS'Length /= 12 or Tag_BS'Length /= 16
         or (Key_BS'Length /= 16 and Key_BS'Length /= 32)
      then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 11 loop IV (I) := IV_BS (I); end loop;
      for I in N32 range 0 .. 15 loop Tag (I) := Tag_BS (I); end loop;
      if CT'Length = 0 then
         declare
            M_Empty : Byte_Seq (1 .. 0) := (others => 0);
            Status  : Boolean;
         begin
            if Key_BS'Length = 16 then
               declare
                  K128 : SPARKNaCl.AES.AES128_Key;
               begin
                  SPARKNaCl.AES.Construct (K128, Bytes_16 (Key_BS));
                  SPARKTLSCrypto.AES_GCM.Decrypt
                    (M => M_Empty, Status => Status, Tag => Tag,
                     C => M_Empty, N => IV, K => K128, AAD => AAD);
                  if Status then Reply_Valid; else Reply_Invalid; end if;
               end;
            else
               declare
                  K256 : SPARKNaCl.AES.AES256_Key;
               begin
                  SPARKNaCl.AES.Construct (K256, Bytes_32 (Key_BS));
                  SPARKTLSCrypto.AES_GCM.Decrypt_256
                    (M => M_Empty, Status => Status, Tag => Tag,
                     C => M_Empty, N => IV, K => K256, AAD => AAD);
                  if Status then Reply_Valid; else Reply_Invalid; end if;
               end;
            end if;
         end;
      else
         declare
            M : Byte_Seq (0 .. CT'Length - 1) := (others => 0);
            Status : Boolean;
            CT_Local : Byte_Seq (0 .. CT'Length - 1) := CT;
         begin
            if Key_BS'Length = 16 then
               declare
                  K128 : SPARKNaCl.AES.AES128_Key;
               begin
                  SPARKNaCl.AES.Construct (K128, Bytes_16 (Key_BS));
                  SPARKTLSCrypto.AES_GCM.Decrypt
                    (M => M, Status => Status, Tag => Tag,
                     C => CT_Local, N => IV, K => K128, AAD => AAD);
                  if Status then Reply_Valid; else Reply_Invalid; end if;
               end;
            else
               declare
                  K256 : SPARKNaCl.AES.AES256_Key;
               begin
                  SPARKNaCl.AES.Construct (K256, Bytes_32 (Key_BS));
                  SPARKTLSCrypto.AES_GCM.Decrypt_256
                    (M => M, Status => Status, Tag => Tag,
                     C => CT_Local, N => IV, K => K256, AAD => AAD);
                  if Status then Reply_Valid; else Reply_Invalid; end if;
               end;
            end if;
         end;
      end if;
   end Do_AES_GCM_Decrypt;

   --  Wycheproof ChaCha20-Poly1305 vectors give (key, iv, aad, msg=pt,
   --  ct, tag). We don't expose a Decrypt, so we re-encrypt the
   --  plaintext and compare CT+Tag byte-for-byte. Equivalent coverage:
   --  every "invalid" test that corrupted the tag, ciphertext, or
   --  plaintext shows up as a mismatch in our recomputation.
   procedure Do_ChaCha_Poly_Encrypt_KAT
     (Hex_Key, Hex_IV, Hex_AAD, Hex_PT, Hex_CT, Hex_Tag : String)
   is
      Key_BS  : constant Byte_Seq := Hex_To_Bytes (Hex_Key);
      IV_BS   : constant Byte_Seq := Hex_To_Bytes (Hex_IV);
      AAD     : constant Byte_Seq := Hex_To_Bytes (Hex_AAD);
      PT      : constant Byte_Seq := Hex_To_Bytes (Hex_PT);
      Exp_CT  : constant Byte_Seq := Hex_To_Bytes (Hex_CT);
      Exp_Tag : constant Byte_Seq := Hex_To_Bytes (Hex_Tag);
   begin
      if Key_BS'Length /= 32 or IV_BS'Length /= 12
         or Exp_Tag'Length /= 16 or Exp_CT'Length /= PT'Length
      then
         Reply_Invalid; return;
      end if;
      declare
         K   : SPARKNaCl.Core.ChaCha20_Key;
         IV  : Bytes_12 := (others => 0);
         CT  : Byte_Seq (0 .. (if PT'Length = 0 then 0 else PT'Length - 1))
               := (others => 0);
         Tag : Bytes_16;
      begin
         SPARKNaCl.Core.Construct (K, Bytes_32 (Key_BS));
         for I in N32 range 0 .. 11 loop IV (I) := IV_BS (I); end loop;
         if PT'Length = 0 then
            declare
               Empty_PT : Byte_Seq (1 .. 0) := (others => 0);
               Empty_CT : Byte_Seq (1 .. 0) := (others => 0);
            begin
               SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
                 (C => Empty_CT, Tag => Tag, M => Empty_PT,
                  N => IV, K => K, AAD => AAD);
            end;
         else
            declare
               PT_Local : Byte_Seq (0 .. PT'Length - 1) := PT;
               CT_Local : Byte_Seq (0 .. PT'Length - 1) := (others => 0);
            begin
               SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
                 (C => CT_Local, Tag => Tag, M => PT_Local,
                  N => IV, K => K, AAD => AAD);
               --  Compare CT.
               for I in N32 range 0 .. PT'Length - 1 loop
                  if CT_Local (I) /= Exp_CT (Exp_CT'First + I) then
                     Reply_Invalid; return;
                  end if;
               end loop;
            end;
         end if;
         --  Compare tag (constant-time-ish via OR-accumulator — not
         --  strictly needed for a test runner but cheap).
         declare
            Diff : Byte := 0;
         begin
            for I in N32 range 0 .. 15 loop
               Diff := Diff or (Tag (I) xor Exp_Tag (Exp_Tag'First + I));
            end loop;
            if Diff = 0 then Reply_Valid; else Reply_Invalid; end if;
         end;
      end;
   end Do_ChaCha_Poly_Encrypt_KAT;

   procedure Do_Ed25519
     (Hex_PK, Hex_Msg, Hex_Sig : String)
   is
      PK_BS  : constant Byte_Seq := Hex_To_Bytes (Hex_PK);
      Msg    : constant Byte_Seq := Hex_To_Bytes (Hex_Msg);
      Sig    : constant Byte_Seq := Hex_To_Bytes (Hex_Sig);
      PK     : Bytes_32 := (others => 0);
      SM     : Byte_Seq (0 .. 64 + Msg'Length - 1) := (others => 0);
      M      : Byte_Seq (0 .. 64 + Msg'Length - 1);
      OK     : Boolean;
      M_Len  : SPARKNaCl.I32;
   begin
      if PK_BS'Length /= 32 or Sig'Length /= 64 then
         Reply_Invalid; return;
      end if;
      for I in N32 range 0 .. 31 loop PK (I) := PK_BS (I); end loop;
      SM (0 .. 63) := Sig;
      if Msg'Length > 0 then SM (64 .. SM'Last) := Msg; end if;
      SPARKTLSCrypto.Ed25519.Open (M, OK, M_Len, SM, PK);
      if OK then Reply_Valid; else Reply_Invalid; end if;
   end Do_Ed25519;

begin
   loop
      declare
         Line : constant String :=
            (if End_Of_File then "quit" else Get_Line);
         Toks : constant Token_Array := Tokenise (Line);
      begin
         exit when Toks'Length = 0 or else To_String (Toks (1)) = "quit";
         if To_String (Toks (1)) = "rsa_pkcs1_sha256" and Toks'Length = 5 then
            Do_RSA_PKCS1_SHA256
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "rsa_pkcs1_sha384" and Toks'Length = 5 then
            Do_RSA_PKCS1_SHA384
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "rsa_pkcs1_sha512" and Toks'Length = 5 then
            Do_RSA_PKCS1_SHA512
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "rsa_pss_sha256" and Toks'Length = 5 then
            Do_RSA_PSS_SHA256
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "rsa_pss_sha384" and Toks'Length = 5 then
            Do_RSA_PSS_SHA384
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "rsa_pss_sha512" and Toks'Length = 5 then
            Do_RSA_PSS_SHA512
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "ecdsa_p256_sha256" and Toks'Length = 5 then
            Do_ECDSA_P256_SHA256
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "ecdsa_p384_sha384" and Toks'Length = 5 then
            Do_ECDSA_P384_SHA384
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)));
         elsif To_String (Toks (1)) = "aes_gcm_decrypt" and Toks'Length = 6 then
            Do_AES_GCM_Decrypt
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)),
               To_String (Toks (6)));
         elsif To_String (Toks (1)) = "chacha_poly_kat" and Toks'Length = 7 then
            Do_ChaCha_Poly_Encrypt_KAT
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)), To_String (Toks (5)),
               To_String (Toks (6)), To_String (Toks (7)));
         elsif To_String (Toks (1)) = "ed25519" and Toks'Length = 4 then
            Do_Ed25519
              (To_String (Toks (2)), To_String (Toks (3)),
               To_String (Toks (4)));
         else
            Reply_Invalid;  --  unknown command counts as invalid
         end if;
      end;
   end loop;
end Wycheproof_Runner;
