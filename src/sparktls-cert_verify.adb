with Interfaces; use Interfaces;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Sign;
with SPARKTLS.RSA;
with SPARKTLS.P256.ECDSA;
with SPARKTLS.P384.ECDSA;

package body SPARKTLS.Cert_Verify with
   SPARK_Mode => On
is
   use type X509.N32;
   use type X509.Algorithm_ID;

   --  NOTE: This package copies bytes between X509.Byte_Seq and
   --  SPARKNaCl.Byte_Seq because they are distinct Ada types despite
   --  identical layouts (both are Unsigned_8 arrays).  X509 uses
   --  Unsigned_32 indices; SPARKNaCl uses Integer_32 range 0..2^31-1.
   --  Unifying them causes 30+ overflow proof failures in x509.adb
   --  because the prover can't guarantee arithmetic stays in the
   --  smaller signed range.  Unchecked_Conversion isn't SPARK-legal.
   --  So we copy.  Sorry.

   --================================================================
   --  DER ECDSA Signature Parser
   --  Parses: SEQUENCE { INTEGER r, INTEGER s }
   --  Outputs r and s as fixed-length big-endian byte arrays,
   --  right-aligned and zero-padded.
   --================================================================

   procedure Parse_DER_ECDSA_Sig
     (Sig       : in  X509.Byte_Seq;
      R_Out     : out Byte_Seq;
      S_Out     : out Byte_Seq;
      OK        : out Boolean)
   with Pre => R_Out'First = 0 and S_Out'First = 0
               and R_Out'Length = S_Out'Length
               and R_Out'Length > 0
               and R_Out'Last < N32'Last
   is
      Coord_Len : constant N32 := R_Out'Last + 1;
      Idx       : X509.N32 := Sig'First;
      R_Len     : X509.N32;
      S_Len     : X509.N32;
      R_Off     : X509.N32;
      S_Off     : X509.N32;
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      --  SEQUENCE tag.  DER ECDSA sigs are always < 200 bytes;
      --  bound Sig'Last to prevent overflow in index arithmetic.
      if Sig'Length < 8 or else Sig'Last > 512 or else Sig (Idx) /= 16#30# then
         return;
      end if;
      Idx := Idx + 2;  --  skip tag + length

      --  First INTEGER (r)
      if Idx > Sig'Last or else Sig (Idx) /= 16#02# then
         return;
      end if;
      Idx := Idx + 1;
      if Idx > Sig'Last then return; end if;
      R_Len := X509.N32 (Sig (Idx));
      Idx := Idx + 1;

      --  Skip leading zero byte
      R_Off := 0;
      if R_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) = 0 then
         R_Off := 1;
         R_Len := R_Len - 1;
      end if;

      --  Copy r, right-aligned
      if R_Len > 0 and then R_Len <= X509.N32 (Coord_Len)
         and then R_Len <= X509.N32 (N32'Last)
         and then Idx + R_Off + R_Len - 1 <= Sig'Last
      then
         for I in X509.N32 range 0 .. R_Len - 1 loop
            R_Out (Coord_Len - N32 (R_Len) + N32 (I)) :=
               Byte (Sig (Idx + R_Off + I));
         end loop;
      else
         return;
      end if;
      if Idx > Sig'Last - R_Off - R_Len then return; end if;
      Idx := Idx + R_Off + R_Len;

      --  Second INTEGER (s)
      if Idx > Sig'Last or else Sig (Idx) /= 16#02# then
         return;
      end if;
      Idx := Idx + 1;
      if Idx > Sig'Last then return; end if;
      S_Len := X509.N32 (Sig (Idx));
      Idx := Idx + 1;

      S_Off := 0;
      if S_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) = 0 then
         S_Off := 1;
         S_Len := S_Len - 1;
      end if;

      if S_Len > 0 and then S_Len <= X509.N32 (Coord_Len)
         and then S_Len <= X509.N32 (N32'Last)
         and then Idx + S_Off + S_Len - 1 <= Sig'Last
      then
         for I in X509.N32 range 0 .. S_Len - 1 loop
            S_Out (Coord_Len - N32 (S_Len) + N32 (I)) :=
               Byte (Sig (Idx + S_Off + I));
         end loop;
      else
         return;
      end if;

      OK := True;
   end Parse_DER_ECDSA_Sig;

   --================================================================
   --  Verify Certificate Signature
   --================================================================

   function Verify_Cert_Signature
     (Cert_DER : Byte_Seq;
      Cert     : X509.Certificate;
      Issuer   : X509.Certificate) return Boolean
   is
      Sig_Algo : constant X509.Algorithm_ID := X509.Sig_Algorithm (Cert);
      TBS_Span : constant X509.Span := X509.TBS (Cert);
   begin
      if not TBS_Span.Present or else X509.Sig_Length (Cert) = 0 then
         return False;
      end if;

      if X509.PK_Length (Issuer) = 0 then
         return False;
      end if;

      --  Guard TBS span fits in SPARKNaCl N32 range and in Cert_DER
      if TBS_Span.Last > X509.N32 (N32'Last)
         or else TBS_Span.First > X509.N32 (N32'Last)
      then
         return False;
      end if;
      if N32 (TBS_Span.Last) > Cert_DER'Last then
         return False;
      end if;

      --  Guard PK/Sig lengths fit preconditions and N32 range
      if X509.Sig_Length (Cert) > X509.Max_Sig_Bytes
         or else X509.PK_Length (Issuer) > X509.Max_PK_Bytes
      then
         return False;
      end if;
      if X509.Sig_Length (Cert) > X509.N32 (N32'Last)
         or else X509.PK_Length (Issuer) > X509.N32 (N32'Last)
      then
         return False;
      end if;

      declare
         TBS_Bytes : constant Byte_Seq :=
            Cert_DER (N32 (TBS_Span.First) .. N32 (TBS_Span.Last));
         Sig_Data  : constant X509.Byte_Seq := X509.Sig_Data (Cert);
         Sig_Len   : constant X509.N32 := X509.Sig_Length (Cert);
         PK_Data   : constant X509.Byte_Seq := X509.PK_Data (Issuer);
         PK_Len    : constant X509.N32 := X509.PK_Length (Issuer);
      begin
         case Sig_Algo is

            --  RSA-PSS / RSA PKCS#1 with SHA-256
            when X509.Algo_RSA_PKCS1_SHA256 | X509.Algo_RSA_PSS =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                  or else PK_Len < 64 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA256.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1) := (others => 0);
               begin
                  SPARKNaCl.Hashing.SHA256.Hash (H, TBS_Bytes);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  for I in N32 range 0 .. N32 (Sig_Len) - 1 loop
                     Sig_Bytes (I) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  return RSA.Verify_PSS_SHA256
                    (Hash      => Bytes_32 (Byte_Seq (H)),
                     Modulus   => Mod_Bytes,
                     Mod_Len   => N32 (PK_Len),
                     Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                     Signature => Sig_Bytes,
                     Sig_Len   => N32 (Sig_Len));
               end;

            --  RSA PKCS#1 with SHA-384
            when X509.Algo_RSA_PKCS1_SHA384 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                  or else PK_Len < 64 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA384.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1) := (others => 0);
               begin
                  SPARKNaCl.Hashing.SHA384.Hash (H, TBS_Bytes);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  for I in N32 range 0 .. N32 (Sig_Len) - 1 loop
                     Sig_Bytes (I) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  return RSA.Verify_PSS_SHA384
                    (Hash      => Bytes_48 (Byte_Seq (H)),
                     Modulus   => Mod_Bytes,
                     Mod_Len   => N32 (PK_Len),
                     Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                     Signature => Sig_Bytes,
                     Sig_Len   => N32 (Sig_Len));
               end;

            --  RSA PKCS#1 with SHA-512
            when X509.Algo_RSA_PKCS1_SHA512 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                  or else PK_Len < 64 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA512.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1) := (others => 0);
               begin
                  SPARKNaCl.Hashing.SHA512.Hash (H, TBS_Bytes);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  for I in N32 range 0 .. N32 (Sig_Len) - 1 loop
                     Sig_Bytes (I) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  return RSA.Verify_PSS_SHA512
                    (Hash      => Bytes_64 (Byte_Seq (H)),
                     Modulus   => Mod_Bytes,
                     Mod_Len   => N32 (PK_Len),
                     Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                     Signature => Sig_Bytes,
                     Sig_Len   => N32 (Sig_Len));
               end;

            --  ECDSA P-384 with SHA-384
            when X509.Algo_ECDSA_P384_SHA384 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_EC_P384
                  or else PK_Len /= 97
               then
                  return False;
               end if;
               declare
                  H     : Bytes_48;
                  Qx    : Byte_Seq (0 .. 47) := (others => 0);
                  Qy    : Byte_Seq (0 .. 47) := (others => 0);
                  R_Val : Byte_Seq (0 .. 47) := (others => 0);
                  S_Val : Byte_Seq (0 .. 47) := (others => 0);
                  Sig_OK : Boolean;
               begin
                  SPARKNaCl.Hashing.SHA384.Hash (H, TBS_Bytes);

                  for I in 0 .. 47 loop
                     Qx (N32 (I)) := Byte (PK_Data (X509.N32 (1 + I)));
                     Qy (N32 (I)) := Byte (PK_Data (X509.N32 (49 + I)));
                  end loop;

                  Parse_DER_ECDSA_Sig (Sig_Data, R_Val, S_Val, Sig_OK);
                  if not Sig_OK then return False; end if;

                  return P384.ECDSA.Verify
                    (Hash => H, Qx => Qx, Qy => Qy, R => R_Val, S => S_Val);
               end;

            --  ECDSA P-256 with SHA-256
            when X509.Algo_ECDSA_P256_SHA256 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_EC_P256
                  or else PK_Len /= 65
               then
                  return False;
               end if;
               declare
                  H     : Bytes_32;
                  Qx    : Byte_Seq (0 .. 31) := (others => 0);
                  Qy    : Byte_Seq (0 .. 31) := (others => 0);
                  R_Val : Byte_Seq (0 .. 31) := (others => 0);
                  S_Val : Byte_Seq (0 .. 31) := (others => 0);
                  Sig_OK : Boolean;
               begin
                  SPARKNaCl.Hashing.SHA256.Hash (H, TBS_Bytes);

                  for I in 0 .. 31 loop
                     Qx (N32 (I)) := Byte (PK_Data (X509.N32 (1 + I)));
                     Qy (N32 (I)) := Byte (PK_Data (X509.N32 (33 + I)));
                  end loop;

                  Parse_DER_ECDSA_Sig (Sig_Data, R_Val, S_Val, Sig_OK);
                  if not Sig_OK then return False; end if;

                  return P256.ECDSA.Verify
                    (Hash => H, Qx => Qx, Qy => Qy, R => R_Val, S => S_Val);
               end;

            --  Ed25519
            when X509.Algo_Ed25519 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_EC_Ed25519
                  or else PK_Len /= 32
               then
                  return False;
               end if;
               if TBS_Bytes'Length > N32'Last - 64 then
                  return False;
               end if;
               declare
                  --  Ed25519 sig = 64 bytes, verify via Sign.Open
                  SM_Len : constant N32 := 64 + N32 (TBS_Bytes'Length);
                  SM     : Byte_Seq (0 .. SM_Len - 1) := (others => 0);
                  M      : Byte_Seq (0 .. SM_Len - 1) := (others => 0);
                  PK_B   : Bytes_32 := (others => 0);
                  CV_PK  : SPARKNaCl.Sign.Signing_PK;
                  Verify_OK : Boolean;
                  Verify_Len : I32;
               begin
                  if Sig_Len /= 64 then return False; end if;

                  --  Build signed message: sig(64) || message
                  for I in 0 .. 63 loop
                     SM (N32 (I)) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  SM (64 .. SM_Len - 1) := TBS_Bytes;

                  --  Extract public key
                  for I in 0 .. 31 loop
                     PK_B (N32 (I)) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  SPARKNaCl.Sign.PK_From_Bytes (PK_B, CV_PK);

                  SPARKNaCl.Sign.Open
                    (M      => M,
                     Status => Verify_OK,
                     MLen   => Verify_Len,
                     SM     => SM,
                     PK     => CV_PK);

                  return Verify_OK;
               end;

            --  SHA-1 with RSA (legacy, needed for PKITS tests)
            when X509.Algo_RSA_PKCS1_SHA1 =>
               --  We don't support SHA-1 verification (insecure)
               return False;

            when others =>
               return False;
         end case;
      end;
   end Verify_Cert_Signature;

   --================================================================
   --  Validate a trust anchor (root CA)
   --================================================================

   function Validate_Root
     (Root : X509.Certificate;
      Now  : X509.Date_Time;
      Mode : Validation_Mode := Mode_WebPKI) return Validation_Result
   is
   begin
      --  RFC 5280 §6.1: Full structural validation of trust anchor
      if not X509.Is_Structurally_Valid (Root, Now) then
         if not X509.Is_Valid (Root) then
            return Err_Parse_Failed;
         elsif not X509.Is_Date_Valid (Root, Now) then
            return Err_Expired;
         elsif X509.Has_Unknown_Critical_Extension (Root) then
            return Err_Unknown_Critical;
         else
            return Err_Parse_Failed;
         end if;
      end if;

      --  RFC 5280 §4.2.1.9: Trust anchors must be CAs
      if not X509.Is_CA (Root) then
         return Err_Not_CA;
      end if;

      --  RFC 5280 §4.2.1.9: CA certs MUST mark BC as critical
      if not X509.Is_Basic_Constraints_Critical (Root) then
         return Err_Not_CA;
      end if;

      if Mode = Mode_WebPKI then
         --  CABF: roots must not have EKU extension
         if X509.Has_EKU (Root) then
            return Err_Forbidden_EKU;
         end if;

         --  CABF 7.1.2.1.3: root AKI must not have
         --  authorityCertIssuer or authorityCertSerialNumber
         if X509.AKID_Serial (Root).Present then
            return Err_Missing_AKI;
         end if;

         --  CABF 6.1.5: RSA keys must be >= 2048 bits and divisible by 8
         if X509.PK_Algorithm (Root) = X509.Algo_RSA then
            if X509.PK_Length (Root) < 256
               or else (X509.PK_Length (Root) mod 8) /= 0
            then
               return Err_Weak_Key;
            end if;
         end if;
      end if;

      return Valid;
   end Validate_Root;

   --================================================================
   --  Verify Certificate Signature (X509.Byte_Seq overload)
   --  Copies DER to SPARKNaCl.Byte_Seq and delegates.
   --================================================================

   function Verify_Cert_Signature
     (Cert_DER : X509.Byte_Seq;
      Cert     : X509.Certificate;
      Issuer   : X509.Certificate) return Boolean
   is
   begin
      --  Guard: X509 uses Unsigned_32 indices, SPARKNaCl uses Integer_32.
      --  Reject DER that exceeds SPARKNaCl's index range.
      if Cert_DER'Last >= X509.N32 (N32'Last) then
         return False;
      end if;
      declare
         NaCl_DER : Byte_Seq (0 .. N32 (Cert_DER'Last)) := (others => 0);
      begin
         for I in Cert_DER'Range loop
            NaCl_DER (N32 (I)) := Byte (Cert_DER (I));
         end loop;
         return Verify_Cert_Signature (NaCl_DER, Cert, Issuer);
      end;
   end Verify_Cert_Signature;

   --================================================================
   --  Validate one link in the chain
   --================================================================

   function Validate_Link
     (Cert_DER         : X509.Byte_Seq;
      Cert             : X509.Certificate;
      Issuer_DER       : X509.Byte_Seq;
      Issuer           : X509.Certificate;
      Now              : X509.Date_Time;
      Must_Be_CA       : Boolean;
      CAs_Below_Issuer : Natural;
      Mode             : Validation_Mode := Mode_WebPKI) return Validation_Result
   is
   begin
      --  1. Full structural validation (parse, dates, extensions, encoding)
      if not X509.Is_Structurally_Valid (Cert, Now) then
         if not X509.Is_Valid (Cert) then
            return Err_Parse_Failed;
         elsif not X509.Is_Date_Valid (Cert, Now) then
            return Err_Expired;
         elsif X509.Has_Unknown_Critical_Extension (Cert) then
            return Err_Unknown_Critical;
         else
            return Err_Structural;
         end if;
      end if;

      --  2. CA constraint
      if Must_Be_CA and then not X509.Is_CA (Cert) then
         return Err_Not_CA;
      end if;

      --  3. RFC 5280 §4.2.1.1: non-root certs MUST have AKI
      if not X509.Authority_Key_ID (Cert).Present then
         return Err_Missing_AKI;
      end if;

      --  4. Issuer DN must match
      if not X509.Issuer_Matches (Cert, Cert_DER, Issuer, Issuer_DER) then
         return Err_Issuer_Mismatch;
      end if;

      --  5. Issuer Key Usage must allow cert signing
      if not X509.Issuer_May_Sign (Issuer) then
         return Err_Signature_Invalid;
      end if;

      --  6. Issuer EKU must allow signing (if present)
      if not X509.Issuer_EKU_Allows_Signing (Issuer) then
         return Err_Forbidden_EKU;
      end if;

      --  7. Name constraints
      if not X509.Satisfies_Name_Constraints
        (Cert, Cert_DER, Issuer, Issuer_DER)
      then
         return Err_Name_Constraint;
      end if;

      --  8. Path length constraint on the issuer
      if X509.Has_Path_Len_Constraint (Issuer)
         and then CAs_Below_Issuer > X509.Path_Len_Constraint (Issuer)
      then
         return Err_Path_Length_Exceeded;
      end if;

      --  9. Cryptographic signature verification
      if not Verify_Cert_Signature (Cert_DER, Cert, Issuer) then
         return Err_Signature_Invalid;
      end if;

      --  10. WebPKI: RSA key must be >= 2048 bits and divisible by 8
      if Mode = Mode_WebPKI
         and then X509.PK_Algorithm (Cert) = X509.Algo_RSA
      then
         if X509.PK_Length (Cert) < 256
            or else (X509.PK_Length (Cert) mod 8) /= 0
         then
            return Err_Weak_Key;
         end if;
      end if;

      return Valid;
   end Validate_Link;

   --================================================================
   --  Validate leaf-specific policy
   --================================================================

   function Validate_Leaf_Policy
     (Leaf     : X509.Certificate;
      Leaf_DER : X509.Byte_Seq;
      Hostname : String;
      Purpose  : Validation_Purpose := Purpose_Server;
      Mode     : Validation_Mode := Mode_WebPKI) return Validation_Result
   is
   begin
      --  1. EKU check: if present, must match purpose (RFC 5280)
      if X509.Has_EKU (Leaf) then
         case Purpose is
            when Purpose_Server =>
               if not X509.Has_EKU_Server_Auth (Leaf) then
                  return Err_Wrong_EKU;
               end if;
            when Purpose_Client | Purpose_Any =>
               null;  --  TODO: client auth EKU check
         end case;
      end if;

      --  2. WebPKI mode (CABF Baseline Requirements)
      if Mode = Mode_WebPKI then
         --  Leaf must have EKU with serverAuth
         if Purpose = Purpose_Server and then not X509.Has_EKU (Leaf) then
            return Err_Wrong_EKU;
         end if;

         --  CABF 7.1.2.7.10: anyExtendedKeyUsage forbidden on leaf
         if X509.Has_EKU_Any_Purpose (Leaf) then
            return Err_Wrong_EKU;
         end if;

         --  EKU must not be critical on leaf
         if X509.Is_EKU_Critical (Leaf) then
            return Err_Wrong_EKU;
         end if;

         --  Leaf must have SAN (DNS or IP)
         if X509.SAN_Count (Leaf) = 0
            and then X509.IP_SAN_Count (Leaf) = 0
         then
            return Err_Missing_SAN;
         end if;

         --  Leaf must not be a CA
         if X509.Is_CA (Leaf) then
            return Err_Not_CA;
         end if;

         --  CABF 6.1.5: RSA keys must be >= 2048 bits and divisible by 8
         if X509.PK_Algorithm (Leaf) = X509.Algo_RSA then
            if X509.PK_Length (Leaf) < 256
               or else (X509.PK_Length (Leaf) mod 8) /= 0
            then
               return Err_Weak_Key;
            end if;
         end if;

      end if;

      --  3. Hostname matching
      if Hostname'Length > 0 then
         if not X509.Matches_Hostname (Leaf, Leaf_DER, Hostname) then
            return Err_Hostname_Mismatch;
         end if;
      end if;

      return Valid;
   end Validate_Leaf_Policy;

   --================================================================
   --  Trust Store helpers
   --================================================================

   --  Internal: parse DER and add to a pool at a given index.
   procedure Add_To_Pool
     (Pool  : in out Cert_Pool;
      Index : Natural;
      DER   : X509.Byte_Seq;
      OK    : out Boolean)
   is
      C    : X509.Certificate;
      P_OK : Boolean;
   begin
      OK := False;
      if DER'Length = 0
         or else X509.N32 (DER'Length) > X509.N32 (Max_Cert_DER)
         or else Index > Pool'Last
      then
         return;
      end if;

      X509.Parse (DER, C, P_OK);
      if not P_OK or else not X509.Is_Valid (C) then
         return;
      end if;

      Pool (Index).Cert := C;
      Pool (Index).DER (0 .. X509.N32 (DER'Length) - 1) := DER;
      Pool (Index).DER_Len := X509.N32 (DER'Length);
      Pool (Index).Present := True;
      OK := True;
   end Add_To_Pool;

   procedure Add_Root
     (Store : in out Trust_Store;
      DER   : X509.Byte_Seq;
      OK    : out Boolean)
   is
      C    : X509.Certificate;
      P_OK : Boolean;
      Idx  : Natural;
   begin
      OK := False;
      if Store.Root_Count >= Max_Root_Pool_Size then
         return;
      end if;
      if DER'Length = 0
         or else X509.N32 (DER'Length) > X509.N32 (Max_Cert_DER)
      then
         return;
      end if;

      X509.Parse (DER, C, P_OK);
      if not P_OK or else not X509.Is_Valid (C) then
         return;
      end if;

      Idx := Store.Root_Count;
      Store.Roots (Idx).Cert := C;
      Store.Roots (Idx).DER (0 .. X509.N32 (DER'Length) - 1) := DER;
      Store.Roots (Idx).DER_Len := X509.N32 (DER'Length);
      Store.Roots (Idx).Present := True;
      Store.Root_Count := Store.Root_Count + 1;
      OK := True;
   end Add_Root;

   procedure Load_Roots
     (Store  : out Trust_Store;
      DER    : X509.Byte_Seq;
      Loaded : out Natural;
      OK     : out Boolean)
   is
      use type X509.N32;
      Pos : X509.N32 := DER'First;
   begin
      Store := (Roots => <>, Root_Count => 0);
      Loaded := 0;
      OK := True;

      while Pos <= DER'Last and Store.Root_Count < Max_Root_Pool_Size loop
         --  Each cert starts with SEQUENCE tag (0x30)
         if DER (Pos) /= 16#30# then
            OK := Loaded > 0;
            return;
         end if;

         --  Parse DER length to find the end of this certificate
         declare
            Len_Pos : X509.N32 := Pos + 1;
            Cert_Len : X509.N32;
            Hdr_Len  : X509.N32;
         begin
            if Len_Pos > DER'Last then
               OK := Loaded > 0;
               return;
            end if;

            if DER (Len_Pos) < 16#80# then
               --  Short form length
               Cert_Len := X509.N32 (DER (Len_Pos));
               Hdr_Len := 2;
            elsif DER (Len_Pos) = 16#81# then
               --  Long form, 1 byte
               if Len_Pos + 1 > DER'Last then
                  OK := Loaded > 0; return;
               end if;
               Cert_Len := X509.N32 (DER (Len_Pos + 1));
               Hdr_Len := 3;
            elsif DER (Len_Pos) = 16#82# then
               --  Long form, 2 bytes
               if Len_Pos + 2 > DER'Last then
                  OK := Loaded > 0; return;
               end if;
               Cert_Len := X509.N32 (DER (Len_Pos + 1)) * 256
                         + X509.N32 (DER (Len_Pos + 2));
               Hdr_Len := 4;
            elsif DER (Len_Pos) = 16#83# then
               --  Long form, 3 bytes
               if Len_Pos + 3 > DER'Last then
                  OK := Loaded > 0; return;
               end if;
               Cert_Len := X509.N32 (DER (Len_Pos + 1)) * 65536
                         + X509.N32 (DER (Len_Pos + 2)) * 256
                         + X509.N32 (DER (Len_Pos + 3));
               Hdr_Len := 5;
            else
               OK := Loaded > 0;
               return;
            end if;

            declare
               Total : constant X509.N32 := Hdr_Len + Cert_Len;
            begin
               if Total > X509.N32 (Max_Cert_DER)
                  or else Pos + Total - 1 > DER'Last
               then
                  OK := Loaded > 0;
                  return;
               end if;

               declare
                  One_OK : Boolean;
               begin
                  Add_Root (Store, DER (Pos .. Pos + Total - 1), One_OK);
                  if One_OK then
                     Loaded := Loaded + 1;
                  end if;
               end;

               Pos := Pos + Total;
            end;
         end;
      end loop;
   end Load_Roots;

   --================================================================
   --  Identity helpers
   --================================================================

   procedure Set_Identity
     (Id       : out Identity;
      Cert_DER : X509.Byte_Seq;
      Key      : Byte_Seq;
      OK       : out Boolean)
   is
      C    : X509.Certificate;
      P_OK : Boolean;
   begin
      Id := (others => <>);
      OK := False;

      if Cert_DER'Length = 0 then
         return;
      end if;

      X509.Parse (Cert_DER, C, P_OK);
      if not P_OK or else not X509.Is_Valid (C) then
         return;
      end if;

      --  Infer signing algorithm from certificate's public key
      case X509.PK_Algorithm (C) is
         when X509.Algo_EC_Ed25519 | X509.Algo_Ed25519 =>
            if Key'Length /= 64 then return; end if;
            Id.Sign_Algo := Sign_Ed25519;
            for I in N32 range 0 .. 63 loop
               Id.Ed25519_Key (I) := Key (Key'First + I);
            end loop;

         when X509.Algo_EC_P256 =>
            if Key'Length /= 32 then return; end if;
            Id.Sign_Algo := Sign_ECDSA_P256;
            for I in N32 range 0 .. 31 loop
               Id.ECDSA_P256_Key (I) := Key (Key'First + I);
            end loop;

         when X509.Algo_EC_P384 =>
            if Key'Length /= 48 then return; end if;
            Id.Sign_Algo := Sign_ECDSA_P384;
            for I in N32 range 0 .. 47 loop
               Id.ECDSA_P384_Key (I) := Key (Key'First + I);
            end loop;

         when others =>
            return;
      end case;

      Id.Cert := C;
      Id.Cert_DER (0 .. X509.N32 (Cert_DER'Length) - 1) := Cert_DER;
      Id.Cert_DER_Len := X509.N32 (Cert_DER'Length);

      --  Also store SPARKNaCl copy for handshake message building
      if Cert_DER'Length <= N32'Last then
         Id.NaCl_Cert_Len := N32 (Cert_DER'Length);
         for I in X509.N32 range 0 .. X509.N32 (Cert_DER'Length) - 1 loop
            Id.NaCl_Cert_DER (N32 (I)) := Byte (Cert_DER (I));
         end loop;
      end if;

      Id.Cert_Valid := True;
      Id.Has_Identity := True;
      OK := True;
   end Set_Identity;

   procedure Add_Intermediate
     (Id  : in out Identity;
      DER : X509.Byte_Seq;
      OK  : out Boolean)
   is
   begin
      OK := False;
      if Id.Int_Count >= Max_Pool_Size then
         return;
      end if;
      Add_To_Pool (Id.Ints, Id.Int_Count, DER, OK);
      if OK then
         Id.Int_Count := Id.Int_Count + 1;
      end if;
   end Add_Intermediate;

   --================================================================
   --  Chain building and validation
   --================================================================

   function Validate_Chain
     (Leaf_DER   : X509.Byte_Seq;
      Leaf       : X509.Certificate;
      Ints       : Cert_Pool;
      Int_Count  : Natural;
      Roots      : Root_Pool;
      Root_Count : Natural;
      Now        : X509.Date_Time;
      Hostname   : String;
      Purpose    : Validation_Purpose := Purpose_Server;
      Mode       : Validation_Mode := Mode_WebPKI) return Validation_Result
   is
      --  Recursive DFS: try to chain Cert to a trust anchor.
      --  Depth = number of intermediates between this cert and the leaf.
      --  Used tracks which intermediates are already in the chain.
      --  Returns Valid if a chain to a root was found and all links valid.
      --  Budget is passed in-out to satisfy SPARK (no mutable globals).
      procedure Try_Build
        (Cert_DER : X509.Byte_Seq;
         Cert     : X509.Certificate;
         Used     : Used_Set;
         Depth    : Natural;
         Budget   : in out Natural;
         Result   : out Validation_Result)
      with Pre => Cert_DER'First = 0 and Cert_DER'Last < X509.N32'Last,
           Subprogram_Variant => (Decreases => Budget),
           Post => Budget <= Budget'Old
      is
         R : Validation_Result;
         Saved_Budget : Natural with Ghost;
      begin
         Result := Err_No_Trust_Anchor;

         if Budget = 0 then
            Saved_Budget := 0;
            return;
         end if;
         Budget := Budget - 1;
         Saved_Budget := Budget;

         if Depth > Max_Chain_Depth then
            Result := Err_Path_Length_Exceeded;
            return;
         end if;

         --  1. Try each root as the issuer of Cert
         for Ri in 0 .. Root_Count - 1 loop
            pragma Loop_Invariant (Budget = Saved_Budget);
            if Ri <= Roots'Last
               and then Roots (Ri).Present
               and then Roots (Ri).DER_Len > 0
               and then Roots (Ri).DER_Len <= X509.N32 (Max_Cert_DER)
            then
               declare
                  VR : constant Validation_Result :=
                     Validate_Root (Roots (Ri).Cert, Now, Mode);
               begin
                  if VR = Valid then
                     R := Validate_Link
                       (Cert_DER         => Cert_DER,
                        Cert             => Cert,
                        Issuer_DER       =>
                           Roots (Ri).DER (0 .. Roots (Ri).DER_Len - 1),
                        Issuer           => Roots (Ri).Cert,
                        Now              => Now,
                        Must_Be_CA       => Depth > 0,
                        CAs_Below_Issuer => Depth,
                        Mode             => Mode);
                     if R = Valid then
                        Result := Valid;
                        return;
                     end if;
                  end if;
               end;
            end if;
         end loop;

         --  2. Try each unused intermediate as the issuer of Cert
         for Ii in 0 .. Int_Count - 1 loop
            pragma Loop_Invariant (Budget <= Saved_Budget);
            if Ii <= Ints'Last
               and then not Used (Ii)
               and then Ints (Ii).Present
               and then Ints (Ii).DER_Len > 0
               and then Ints (Ii).DER_Len <= X509.N32 (Max_Cert_DER)
            then
               R := Validate_Link
                 (Cert_DER         => Cert_DER,
                  Cert             => Cert,
                  Issuer_DER       =>
                     Ints (Ii).DER (0 .. Ints (Ii).DER_Len - 1),
                  Issuer           => Ints (Ii).Cert,
                  Now              => Now,
                  Must_Be_CA       => Depth > 0,
                  CAs_Below_Issuer => Depth,
                  Mode             => Mode);
               if R = Valid then
                  --  This intermediate is a valid issuer; recurse
                  declare
                     Next_Used : Used_Set := Used;
                  begin
                     Next_Used (Ii) := True;
                     Try_Build
                       (Ints (Ii).DER (0 .. Ints (Ii).DER_Len - 1),
                        Ints (Ii).Cert,
                        Next_Used, Depth + 1, Budget, R);
                     if R = Valid then
                        Result := Valid;
                        return;
                     end if;
                     --  Backtrack: try next intermediate
                  end;
               end if;
            end if;
         end loop;
      end Try_Build;

      R      : Validation_Result;
      Budget : Natural := Max_Build_Calls;
   begin
      --  Build chain from leaf upward
      Try_Build
        (Leaf_DER, Leaf,
         Used   => (others => False),
         Depth  => 0,
         Budget => Budget,
         Result => R);

      if R /= Valid then
         return R;
      end if;

      --  Chain is valid; check leaf policy
      return Validate_Leaf_Policy
        (Leaf     => Leaf,
         Leaf_DER => Leaf_DER,
         Hostname => Hostname,
         Purpose  => Purpose,
         Mode     => Mode);
   end Validate_Chain;

end SPARKTLS.Cert_Verify;
