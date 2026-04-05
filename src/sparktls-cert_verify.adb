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
   is
      Coord_Len : constant N32 := N32 (R_Out'Length);
      Idx       : X509.N32 := Sig'First;
      R_Len     : X509.N32;
      S_Len     : X509.N32;
      R_Off     : X509.N32;
      S_Off     : X509.N32;
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      --  SEQUENCE tag
      if Sig'Length < 8 or else Sig (Idx) /= 16#30# then
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
         and then Idx + R_Off + R_Len - 1 <= Sig'Last
      then
         for I in X509.N32 range 0 .. R_Len - 1 loop
            R_Out (Coord_Len - N32 (R_Len) + N32 (I)) :=
               Byte (Sig (Idx + R_Off + I));
         end loop;
      else
         return;
      end if;
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

      if N32 (TBS_Span.Last) > Cert_DER'Last then
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
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA256.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1);
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
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA384.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1);
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
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA then
                  return False;
               end if;
               declare
                  H : SPARKNaCl.Hashing.SHA512.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1);
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
                  Qx    : Byte_Seq (0 .. 47);
                  Qy    : Byte_Seq (0 .. 47);
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
                  Qx    : Byte_Seq (0 .. 31);
                  Qy    : Byte_Seq (0 .. 31);
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
               declare
                  --  Ed25519 sig = 64 bytes, verify via Sign.Open
                  SM_Len : constant N32 := 64 + N32 (TBS_Bytes'Length);
                  SM     : Byte_Seq (0 .. SM_Len - 1);
                  M      : Byte_Seq (0 .. SM_Len - 1);
                  PK_B   : Bytes_32;
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
      Now  : X509.Date_Time) return Validation_Result
   is
   begin
      --  RFC 5280 §6.1: Full structural validation of trust anchor
      if not X509.Is_Structurally_Valid (Root, Now) then
         --  Return a specific error for the most common cases
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

      return Valid;
   end Validate_Root;

   --================================================================
   --  Validate a certificate against its issuer
   --================================================================

   function Validate_Cert
     (Cert_DER    : Byte_Seq;
      Cert        : X509.Certificate;
      Issuer      : X509.Certificate;
      Now         : X509.Date_Time;
      Must_Be_CA  : Boolean;
      Chain_Depth : Natural := 0) return Validation_Result
   is
   begin
      --  1. Must have parsed OK
      if not X509.Is_Valid (Cert) then
         return Err_Parse_Failed;
      end if;

      --  2. Must not have unknown critical extensions
      if X509.Has_Unknown_Critical_Extension (Cert) then
         return Err_Unknown_Critical;
      end if;

      --  3. Must be within validity period
      if not X509.Is_Date_Valid (Cert, Now) then
         return Err_Expired;
      end if;

      --  4. Must have known algorithms
      if X509.Sig_Algorithm (Cert) = X509.Algo_Unknown or else
         X509.PK_Algorithm (Cert) = X509.Algo_Unknown
      then
         return Err_Unknown_Algorithm;
      end if;

      --  5. If this cert is an intermediate (not end-entity),
      --     it must have Basic Constraints CA=True
      if Must_Be_CA and then not X509.Is_CA (Cert) then
         return Err_Not_CA;
      end if;

      --  6. Check path length constraint on the ISSUER
      --     If the issuer has pathLenConstraint = N, then
      --     Chain_Depth (certs below the issuer) must be <= N.
      if X509.Is_CA (Issuer) and then
         X509.Has_Path_Len_Constraint (Issuer) and then
         Chain_Depth > X509.Path_Len_Constraint (Issuer)
      then
         return Err_Path_Length_Exceeded;
      end if;

      --  7. Verify signature against issuer's public key
      if not Verify_Cert_Signature (Cert_DER, Cert, Issuer) then
         return Err_Signature_Invalid;
      end if;

      return Valid;
   end Validate_Cert;

end SPARKTLS.Cert_Verify;
