with Interfaces; use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;

package body SPARKTLS.Cert_Verify
  with SPARK_Mode => On
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

   ----------------------------------------------------------------------------
   --  DER ECDSA Signature Parser
   --  Parses: SEQUENCE { INTEGER r, INTEGER s }
   --  Outputs r and s as fixed-length big-endian byte arrays,
   --  right-aligned and zero-padded.
   ----------------------------------------------------------------------------

   procedure Parse_DER_ECDSA_Sig
     (Sig : in X509.Byte_Seq; R_Out : out Byte_Seq; S_Out : out Byte_Seq; OK : out Boolean)
   with
     Pre =>
       R_Out'First = 0
       and S_Out'First = 0
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
      Outer_Len : X509.N32;
      Outer_End : X509.N32;
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      --  SEQUENCE tag.  DER ECDSA sigs are always < 200 bytes;
      --  bound Sig'Last to prevent overflow in index arithmetic.
      if Sig'Length < 8 or else Sig'Last > 512 or else Sig (Idx) /= 16#30# then
         return;
      end if;
      Idx := Idx + 1;  --  skip SEQUENCE tag

      --  Parse SEQUENCE length. Supports short-form (single byte 0..127)
      --  and long-form 0x81 (one length byte 128..255). Reject 0x82+
      --  (longer payloads)  DER ECDSA sigs for P-256/P-384/P-521 fit
      --  in <= 200 bytes, so any longer encoding is malformed.
      if Idx > Sig'Last then
         return;
      end if;
      --  Strict DER: 0x81 long-form is permitted only when the value
      --  is >= 128. Anything < 128 must use short form (a single byte).
      if Sig (Idx) < 16#80# then
         Outer_Len := X509.N32 (Sig (Idx));
         Idx := Idx + 1;
      elsif Sig (Idx) = 16#81# and then Idx + 1 <= Sig'Last and then Sig (Idx + 1) >= 16#80# then
         Outer_Len := X509.N32 (Sig (Idx + 1));
         Idx := Idx + 2;
      else
         return;
      end if;
      if Outer_Len = 0 or else Outer_Len > X509.N32 (Sig'Last - Idx + 1) then
         return;
      end if;
      Outer_End := Idx + Outer_Len;
      --  Strict-DER: outer SEQUENCE must consume the full input. No
      --  trailing data after (r, s).
      if Outer_End - 1 /= Sig'Last then
         return;
      end if;

      --  First INTEGER (r). Length is short-form; INTEGERs in
      --  P-256/P-384/P-521 sigs are at most 66 bytes (< 128).
      if Idx > Sig'Last or else Sig (Idx) /= 16#02# then
         return;
      end if;
      Idx := Idx + 1;
      if Idx > Sig'Last then
         return;
      end if;
      if Sig (Idx) >= 16#80# then
         return;
      end if;  -- reject long-form
      R_Len := X509.N32 (Sig (Idx));
      Idx := Idx + 1;

      --  Strict DER for the INTEGER value:
      --   - byte 0 with high bit set requires a leading 0x00 (otherwise
      --     the encoding would denote a negative value)
      --   - leading 0x00 followed by byte < 0x80 is superfluous (would
      --     shrink to one fewer byte)  also non-canonical
      R_Off := 0;
      if R_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) = 0 then
         if R_Len < 2 or else Idx + 1 > Sig'Last or else Sig (Idx + 1) < 16#80# then
            return;
         end if;
         R_Off := 1;
         R_Len := R_Len - 1;
      elsif R_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) >= 16#80# then
         return;  -- positive INTEGER missing required leading 0x00
      end if;

      --  Copy r, right-aligned
      if R_Len > 0
        and then R_Len <= X509.N32 (Coord_Len)
        and then R_Len <= X509.N32 (N32'Last)
        and then Idx + R_Off + R_Len - 1 <= Sig'Last
      then
         for I in X509.N32 range 0 .. R_Len - 1 loop
            R_Out (Coord_Len - N32 (R_Len) + N32 (I)) := Byte (Sig (Idx + R_Off + I));
         end loop;
      else
         return;
      end if;
      if Idx > Sig'Last - R_Off - R_Len then
         return;
      end if;
      Idx := Idx + R_Off + R_Len;

      --  Second INTEGER (s)
      if Idx > Sig'Last or else Sig (Idx) /= 16#02# then
         return;
      end if;
      Idx := Idx + 1;
      if Idx > Sig'Last then
         return;
      end if;
      if Sig (Idx) >= 16#80# then
         return;
      end if;  -- reject long-form
      S_Len := X509.N32 (Sig (Idx));
      Idx := Idx + 1;

      S_Off := 0;
      if S_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) = 0 then
         if S_Len < 2 or else Idx + 1 > Sig'Last or else Sig (Idx + 1) < 16#80# then
            return;
         end if;
         S_Off := 1;
         S_Len := S_Len - 1;
      elsif S_Len > 0 and then Idx <= Sig'Last and then Sig (Idx) >= 16#80# then
         return;  -- positive INTEGER missing required leading 0x00
      end if;

      if S_Len > 0
        and then S_Len <= X509.N32 (Coord_Len)
        and then S_Len <= X509.N32 (N32'Last)
        and then Idx + S_Off + S_Len - 1 <= Sig'Last
      then
         for I in X509.N32 range 0 .. S_Len - 1 loop
            S_Out (Coord_Len - N32 (S_Len) + N32 (I)) := Byte (Sig (Idx + S_Off + I));
         end loop;
      else
         return;
      end if;

      --  Strict-DER: after consuming s, the cursor must land exactly
      --  on the SEQUENCE end (no trailing bytes inside the SEQUENCE).
      if Idx + S_Off + S_Len /= Outer_End then
         return;
      end if;

      OK := True;
   end Parse_DER_ECDSA_Sig;

   ----------------------------------------------------------------------------
   --  Verify Certificate Signature
   ----------------------------------------------------------------------------

   function Verify_Cert_Signature
     (Cert_DER : Byte_Seq; Cert : X509.Certificate; Issuer : X509.Certificate) return Boolean
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
      if TBS_Span.Last > X509.N32 (N32'Last) or else TBS_Span.First > X509.N32 (N32'Last) then
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
         TBS_Bytes : constant Byte_Seq := Cert_DER (N32 (TBS_Span.First) .. N32 (TBS_Span.Last));
         Sig_Data  : constant X509.Byte_Seq := X509.Sig_Data (Cert);
         Sig_Len   : constant X509.N32 := X509.Sig_Length (Cert);
         PK_Data   : constant X509.Byte_Seq := X509.PK_Data (Issuer);
         PK_Len    : constant X509.N32 := X509.PK_Length (Issuer);
      begin
         case Sig_Algo is

            --  RSA PKCS#1 v1.5 with SHA-256, or RSA-PSS with SHA-256.
            --  NB: sparkx509 currently exposes a single Algo_RSA_PSS
            --  (no per-hash variant) so PSS in cert chains is treated
            --  as PSS-SHA256 here. Real-world PSS-SHA384/512 chain
            --  certs are rare; lift this restriction by extending
            --  X509.Algorithm_ID to carry the PSS hash variant.

            when X509.Algo_RSA_PKCS1_SHA256 | X509.Algo_RSA_PSS =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                 or else PK_Len < 64
                 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H         : SPARKTLSCrypto.Hashing.SHA256.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. N32 (Sig_Len) - 1) := (others => 0);
               begin
                  SPARKTLSCrypto.Hashing.SHA256.Hash (H, TBS_Bytes);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  for I in N32 range 0 .. N32 (Sig_Len) - 1 loop
                     Sig_Bytes (I) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  if Sig_Algo = X509.Algo_RSA_PSS then
                     return
                       RSA.Verify_PSS_SHA256
                         (Hash      => Bytes_32 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                          Signature => Sig_Bytes,
                          Sig_Len   => N32 (Sig_Len));
                  else
                     return
                       RSA.Verify_PKCS1_v1_5_SHA256
                         (Hash      => Bytes_32 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                          Signature => Sig_Bytes,
                          Sig_Len   => N32 (Sig_Len));
                  end if;
               end;

               --  RSA PKCS#1 v1.5 with SHA-384

            when X509.Algo_RSA_PKCS1_SHA384 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                 or else PK_Len < 64
                 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H         : SPARKNaCl.Hashing.SHA384.Digest;
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
                  return
                    RSA.Verify_PKCS1_v1_5_SHA384
                      (Hash      => Bytes_48 (Byte_Seq (H)),
                       Modulus   => Mod_Bytes,
                       Mod_Len   => N32 (PK_Len),
                       Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                       Signature => Sig_Bytes,
                       Sig_Len   => N32 (Sig_Len));
               end;

               --  RSA PKCS#1 v1.5 with SHA-512

            when X509.Algo_RSA_PKCS1_SHA512 =>
               if X509.PK_Algorithm (Issuer) /= X509.Algo_RSA
                 or else PK_Len < 64
                 or else PK_Len /= Sig_Len
               then
                  return False;
               end if;
               declare
                  H         : SPARKNaCl.Hashing.SHA512.Digest;
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
                  return
                    RSA.Verify_PKCS1_v1_5_SHA512
                      (Hash      => Bytes_64 (Byte_Seq (H)),
                       Modulus   => Mod_Bytes,
                       Mod_Len   => N32 (PK_Len),
                       Exponent  => Unsigned_32 (X509.RSA_Exponent (Issuer)),
                       Signature => Sig_Bytes,
                       Sig_Len   => N32 (Sig_Len));
               end;

               --  ECDSA with SHA-384 or SHA-256
               --  The sig algo determines the hash; the issuer's PK determines the curve.

            when X509.Algo_ECDSA_P384_SHA384 | X509.Algo_ECDSA_P256_SHA256 =>
               --  P-384 key
               if X509.PK_Algorithm (Issuer) = X509.Algo_EC_P384 and then PK_Len = 97 then
                  declare
                     H      : Bytes_48;
                     H32    : Bytes_32;
                     Qx     : Byte_Seq (0 .. 47) := (others => 0);
                     Qy     : Byte_Seq (0 .. 47) := (others => 0);
                     R_Val  : Byte_Seq (0 .. 47);
                     S_Val  : Byte_Seq (0 .. 47);
                     Sig_OK : Boolean;
                  begin
                     --  Hash with the algorithm specified by the signature
                     if Sig_Algo = X509.Algo_ECDSA_P384_SHA384 then
                        SPARKNaCl.Hashing.SHA384.Hash (H, TBS_Bytes);
                     else
                        --  SHA-256 hash, zero-pad to 48 bytes for P-384
                        SPARKTLSCrypto.Hashing.SHA256.Hash (H32, TBS_Bytes);
                        H := (others => 0);
                        for I in N32 range 0 .. 31 loop
                           H (I) := H32 (I);
                        end loop;
                     end if;

                     for I in 0 .. 47 loop
                        Qx (N32 (I)) := Byte (PK_Data (X509.N32 (1 + I)));
                        Qy (N32 (I)) := Byte (PK_Data (X509.N32 (49 + I)));
                     end loop;

                     Parse_DER_ECDSA_Sig (Sig_Data, R_Val, S_Val, Sig_OK);
                     if not Sig_OK then
                        return False;
                     end if;

                     return
                       P384.ECDSA.Verify (Hash => H, Qx => Qx, Qy => Qy, R => R_Val, S => S_Val);
                  end;

                  --  P-256 key
               elsif X509.PK_Algorithm (Issuer) = X509.Algo_EC_P256 and then PK_Len = 65 then
                  declare
                     H      : Bytes_32;
                     H384   : SPARKNaCl.Hashing.SHA384.Digest;
                     Qx     : Byte_Seq (0 .. 31) := (others => 0);
                     Qy     : Byte_Seq (0 .. 31) := (others => 0);
                     R_Val  : Byte_Seq (0 .. 31);
                     S_Val  : Byte_Seq (0 .. 31);
                     Sig_OK : Boolean;
                  begin
                     if Sig_Algo = X509.Algo_ECDSA_P384_SHA384 then
                        SPARKNaCl.Hashing.SHA384.Hash (H384, TBS_Bytes);
                        for I in N32 range 0 .. 31 loop
                           H (I) := Byte_Seq (H384) (I);
                        end loop;
                     else
                        SPARKTLSCrypto.Hashing.SHA256.Hash (H, TBS_Bytes);
                     end if;

                     for I in 0 .. 31 loop
                        Qx (N32 (I)) := Byte (PK_Data (X509.N32 (1 + I)));
                        Qy (N32 (I)) := Byte (PK_Data (X509.N32 (33 + I)));
                     end loop;

                     Parse_DER_ECDSA_Sig (Sig_Data, R_Val, S_Val, Sig_OK);
                     if not Sig_OK then
                        return False;
                     end if;

                     return
                       P256.ECDSA.Verify (Hash => H, Qx => Qx, Qy => Qy, R => R_Val, S => S_Val);
                  end;

               else
                  --  Unknown EC key type for ECDSA
                  return False;
               end if;

               --  Ed25519

            when X509.Algo_Ed25519 =>
               if X509.PK_Algorithm (Issuer) not in X509.Algo_Ed25519 | X509.Algo_EC_Ed25519
                 or else PK_Len /= 32
               then
                  return False;
               end if;
               if TBS_Bytes'Length > N32'Last - 64 then
                  return False;
               end if;
               declare
                  --  Ed25519 sig = 64 bytes, verify via Sign.Open
                  SM_Len             : constant N32 := 64 + N32 (TBS_Bytes'Length);
                  SM                 : Byte_Seq (0 .. SM_Len - 1) := (others => 0);
                  Ignored_M          : Byte_Seq (0 .. SM_Len - 1);
                  PK_B               : Bytes_32 := (others => 0);
                  Verify_OK          : Boolean;
                  Ignored_Verify_Len : I32;
               begin
                  if Sig_Len /= 64 then
                     return False;
                  end if;

                  --  Build signed message: sig(64) || message
                  for I in 0 .. 63 loop
                     SM (N32 (I)) := Byte (Sig_Data (X509.N32 (I)));
                  end loop;
                  SM (64 .. SM_Len - 1) := TBS_Bytes;

                  --  Extract public key
                  for I in 0 .. 31 loop
                     PK_B (N32 (I)) := Byte (PK_Data (X509.N32 (I)));
                  end loop;

                  SPARKTLSCrypto.Ed25519.Open
                    (M       => Ignored_M,
                     Valid   => Verify_OK,
                     Msg_Len => Ignored_Verify_Len,
                     SM      => SM,
                     PK      => PK_B);

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

   ----------------------------------------------------------------------------
   --  Validate a trust anchor (root CA)
   ----------------------------------------------------------------------------

   function Validate_Root
     (Root     : X509.Certificate;
      Root_DER : X509.Byte_Seq;
      Now      : X509.Date_Time;
      Mode     : Validation_Mode := Mode_WebPKI) return Validation_Result is
   begin
      --  RFC 5280 6.1: Structural validation of trust anchor.
      --  Trust anchors are trusted by definition (RFC 5280 6.1.1),
      --  but we validate structure to catch obviously broken certs.
      --  Exception: we tolerate Bad_Serial because legacy roots
      --  (Starfield G2, serial=0) violate RFC 5280 4.1.2.2 but
      --  are in every major trust store.
      if not X509.Is_Structurally_Valid (Root, Now) then
         --  Retry without serial: if serial is the only problem,
         --  the cert passes all other individual checks.
         if not (X509.Is_Valid (Root)
                 and then X509.Is_Date_Valid (Root, Now)
                 and then not X509.Has_Unknown_Critical_Extension (Root)
                 and then not X509.Has_Duplicate_Extension (Root)
                 and then not X509.Has_Bad_Extension_Criticality (Root)
                 and then not X509.Has_Bad_Time_Format (Root)
                 and then not X509.Has_Bad_SAN (Root)
                 and then not X509.Has_Empty_Key_Usage_Value (Root)
                 and then not X509.Has_Key_Cert_Sign_Without_CA (Root)
                 and then X509.TBS (Root).Present)
         then
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
         --  Only Bad_Serial  tolerate for trust anchors

      end if;

      --  RFC 5280 4.2.1.9: Trust anchors must be CAs
      if not X509.Is_CA (Root) then
         return Err_Not_CA;
      end if;

      --  RFC 5280 4.2.1.9: CA certs MUST mark BC as critical
      if not X509.Is_Basic_Constraints_Critical (Root) then
         return Err_Not_CA;
      end if;

      --  RFC 5280 4.2.1.2: CA certs MUST have SKI
      if X509.CA_Missing_Subject_Key_ID (Root) then
         return Err_Structural;
      end if;

      --  RFC 5280 4.2.1.1: non-self-issued certs MUST have AKI
      if not X509.Is_Self_Issued (Root, Root_DER) and then not X509.Authority_Key_ID (Root).Present
      then
         return Err_Missing_AKI;
      end if;

      if Mode = Mode_WebPKI then
         --  CABF: roots must not have EKU extension
         if X509.Has_EKU (Root) then
            return Err_Forbidden_EKU;
         end if;

         --  CABF 7.1.2.1.3: root AKI constraints
         --  Must not have authorityCertIssuer/Serial
         if X509.AKID_Serial (Root).Present then
            return Err_Missing_AKI;
         end if;
         if X509.Has_AKID_Issuer (Root) then
            return Err_Missing_AKI;
         end if;
         --  If AKI present, must have keyIdentifier
         if X509.Has_AKID_Missing_Key_ID (Root) then
            return Err_Missing_AKI;
         end if;
         --  CABF 7.1.2.1.3: AKI keyIdentifier must match SKI
         if not X509.AKI_Matches_SKI (Root, Root_DER) then
            return Err_Missing_AKI;
         end if;

         --  CABF 6.1.5: RSA keys must be >= 2048 bits and divisible by 8
         if X509.PK_Algorithm (Root) = X509.Algo_RSA then
            if X509.PK_Length (Root) < 256 or else (X509.PK_Length (Root) mod 8) /= 0 then
               return Err_Weak_Key;
            end if;
         end if;
      end if;

      return Valid;
   end Validate_Root;

   ----------------------------------------------------------------------------
   --  Verify Certificate Signature (X509.Byte_Seq overload)
   --  Copies DER to SPARKNaCl.Byte_Seq and delegates.
   ----------------------------------------------------------------------------

   function Verify_Cert_Signature
     (Cert_DER : X509.Byte_Seq; Cert : X509.Certificate; Issuer : X509.Certificate) return Boolean
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

   ----------------------------------------------------------------------------
   --  Validate one link in the chain
   ----------------------------------------------------------------------------

   function Validate_Link
     (Cert_DER         : X509.Byte_Seq;
      Cert             : X509.Certificate;
      Issuer_DER       : X509.Byte_Seq;
      Issuer           : X509.Certificate;
      Now              : X509.Date_Time;
      Must_Be_CA       : Boolean;
      CAs_Below_Issuer : Natural;
      Mode             : Validation_Mode := Mode_WebPKI) return Validation_Result is
   begin
      --  1. Full structural validation (parse, dates, extensions, encoding).
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

      --  3. RFC 5280 4.2.1.1: non-root certs MUST have AKI
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
      --  RFC 5280 4.2.1.10: NC MUST be critical.
      --  CABF BRs explicitly allow non-critical NC for legacy compat.
      if Mode = Mode_RFC5280 and then X509.Has_NC_Noncritical (Issuer) then
         return Err_Name_Constraint;
      end if;
      --  RFC 5280 4.2.1.10: NC do not apply to self-issued intermediates
      --  (but always apply to the leaf, i.e. when Must_Be_CA = False)
      if not (Must_Be_CA and then X509.Is_Self_Issued (Cert, Cert_DER)) then
         if not X509.Satisfies_Name_Constraints (Cert, Cert_DER, Issuer, Issuer_DER) then
            return Err_Name_Constraint;
         end if;
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
      if Mode = Mode_WebPKI and then X509.PK_Algorithm (Cert) = X509.Algo_RSA then
         if X509.PK_Length (Cert) < 256 or else (X509.PK_Length (Cert) mod 8) /= 0 then
            return Err_Weak_Key;
         end if;
      end if;

      return Valid;
   end Validate_Link;

   ----------------------------------------------------------------------------
   --  Validate leaf-specific policy
   ----------------------------------------------------------------------------

   function Validate_Leaf_Policy
     (Leaf     : X509.Certificate;
      Leaf_DER : X509.Byte_Seq;
      Hostname : String;
      Purpose  : Validation_Purpose := Purpose_Server;
      Mode     : Validation_Mode := Mode_WebPKI) return Validation_Result is
   begin
      --  1. EKU check: if present, must match purpose (RFC 5280)
      if X509.Has_EKU (Leaf) then
         case Purpose is
            when Purpose_Server =>
               if not X509.Has_EKU_Server_Auth (Leaf) then
                  return Err_Wrong_EKU;
               end if;

            when Purpose_Client =>
               if not X509.Has_EKU_Client_Auth (Leaf) then
                  return Err_Wrong_EKU;
               end if;

            when Purpose_Any =>
               null;
         end case;
      end if;

      --  2. WebPKI mode (CABF Baseline Requirements)
      if Mode = Mode_WebPKI then
         --  CABF BRs: leaf must have EKU with serverAuth.
         --  RFC 5280: EKU is optional. Mode_WebPKI enforces CABF.
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
         if X509.SAN_Count (Leaf) = 0 and then X509.IP_SAN_Count (Leaf) = 0 then
            return Err_Missing_SAN;
         end if;

         --  Note: CABF BR 7.1.4.3 requires CN to match a SAN entry,
         --  but this is a CA issuance requirement. Validators do not
         --  enforce this  it would reject many valid certificates
         --  already in the wild.

         --  CABF BRs: leaf must not be a CA.
         --  RFC 5280: allows CA in leaf position.
         if X509.Is_CA (Leaf) then
            return Err_Not_CA;
         end if;

         --  CABF 6.1.5: RSA keys must be >= 2048 bits and divisible by 8
         if X509.PK_Algorithm (Leaf) = X509.Algo_RSA then
            if X509.PK_Length (Leaf) < 256 or else (X509.PK_Length (Leaf) mod 8) /= 0 then
               return Err_Weak_Key;
            end if;
         end if;

      end if;

      --  RFC 8446 4.4.2.2 + RFC 5246 7.4.2 + RFC 5280 4.2.1.3:
      --  when the leaf's keyUsage extension is present, it MUST allow
      --  digitalSignature for the negotiated certificate role. Server
      --  certs sign ServerKeyExchange/CertificateVerify; client certs
      --  sign CertificateVerify.
      if Purpose in Purpose_Server | Purpose_Client
        and then X509.Has_Key_Usage (Leaf)
        and then not X509.KU_Digital_Signature (Leaf)
      then
         return Err_Wrong_EKU;
      end if;

      --  3. Hostname matching
      if Hostname'Length > 0 then
         if not X509.Matches_Hostname (Leaf, Leaf_DER, Hostname) then
            return Err_Hostname_Mismatch;
         end if;
      end if;

      return Valid;
   end Validate_Leaf_Policy;

   ----------------------------------------------------------------------------
   --  Trust Store helpers
   ----------------------------------------------------------------------------

   --  Internal: parse DER and add to a pool at a given index.
   procedure Add_To_Pool
     (Pool : in out Cert_Pool; Index : Natural; DER : X509.Byte_Seq; OK : out Boolean)
   with Pre => DER'First = 0 and DER'Last < X509.N32'Last;

   procedure Add_To_Pool
     (Pool : in out Cert_Pool; Index : Natural; DER : X509.Byte_Seq; OK : out Boolean)
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

      Pool (Index).Present := False;
      Pool (Index).Cert := C;
      Pool (Index).DER (0 .. X509.N32 (DER'Length) - 1) := DER;
      Pool (Index).DER_Len := X509.N32 (DER'Length);
      pragma Assert (Pool (Index).DER_Len - 1 = DER'Last);
      Pool (Index).Present := True;
      OK := True;
   end Add_To_Pool;

   procedure Add_Root (Store : in out Trust_Store; DER : X509.Byte_Seq; OK : out Boolean) is
      C    : X509.Certificate;
      P_OK : Boolean;
      Idx  : Natural;
   begin
      OK := False;
      if Store.Root_Count >= Max_Root_Pool_Size then
         return;
      end if;
      if DER'Length = 0 or else X509.N32 (DER'Length) > X509.N32 (Max_Cert_DER) then
         return;
      end if;

      X509.Parse (DER, C, P_OK);
      if not P_OK or else not X509.Is_Valid (C) then
         return;
      end if;

      Idx := Store.Root_Count;
      --  Clear Present first so partial-update predicate checks are vacuous.
      Store.Roots (Idx).Present := False;
      Store.Roots (Idx).Cert := C;
      Store.Roots (Idx).DER (0 .. X509.N32 (DER'Length) - 1) := DER;
      Store.Roots (Idx).DER_Len := X509.N32 (DER'Length);
      pragma Assert (Store.Roots (Idx).DER_Len - 1 = DER'Last);
      Store.Roots (Idx).Present := True;
      Store.Root_Count := Store.Root_Count + 1;
      OK := True;
   end Add_Root;

   procedure Load_Roots
     (Store : out Trust_Store; DER : X509.Byte_Seq; Loaded : out Natural; OK : out Boolean)
   is
      use type X509.N32;
      Pos : X509.N32 := DER'First;
   begin
      --  Fully initialize Store so 'Initialized holds on every path.
      Store.Roots := (others => <>);
      Store.Root_Count := 0;
      Loaded := 0;
      OK := True;

      while Pos <= DER'Last and Store.Root_Count < Max_Root_Pool_Size loop
         pragma Loop_Invariant (Loaded <= Store.Root_Count);
         pragma Loop_Invariant (Store.Root_Count <= Max_Root_Pool_Size);
         --  Each cert starts with SEQUENCE tag (0x30)
         if DER (Pos) /= 16#30# then
            OK := Loaded > 0;
            return;
         end if;

         --  Parse DER length to find the end of this certificate
         declare
            Len_Pos  : constant X509.N32 := Pos + 1;
            Cert_Len : X509.N32;
            Hdr_Len  : X509.N32;
         begin
            if Pos >= DER'Last then
               OK := Loaded > 0;
               return;
            end if;
            --  Now Len_Pos <= DER'Last (Pos < DER'Last so Pos + 1 <= DER'Last).

            if DER (Len_Pos) < 16#80# then
               --  Short form length
               Cert_Len := X509.N32 (DER (Len_Pos));
               Hdr_Len := 2;
            elsif DER (Len_Pos) = 16#81# then
               --  Long form, 1 byte
               if DER'Last - Len_Pos < 1 then
                  OK := Loaded > 0;
                  return;
               end if;
               Cert_Len := X509.N32 (DER (Len_Pos + 1));
               Hdr_Len := 3;
            elsif DER (Len_Pos) = 16#82# then
               --  Long form, 2 bytes
               if DER'Last - Len_Pos < 2 then
                  OK := Loaded > 0;
                  return;
               end if;
               Cert_Len := X509.N32 (DER (Len_Pos + 1)) * 256 + X509.N32 (DER (Len_Pos + 2));
               Hdr_Len := 4;
            elsif DER (Len_Pos) = 16#83# then
               --  Long form, 3 bytes
               if DER'Last - Len_Pos < 3 then
                  OK := Loaded > 0;
                  return;
               end if;
               Cert_Len :=
                 X509.N32 (DER (Len_Pos + 1)) * 65536 + X509.N32 (DER (Len_Pos + 2)) * 256
                 + X509.N32 (DER (Len_Pos + 3));
               Hdr_Len := 5;
            else
               OK := Loaded > 0;
               return;
            end if;

            declare
               Total : constant X509.N32 := Hdr_Len + Cert_Len;
            begin
               if Total = 0
                 or else Total > X509.N32 (Max_Cert_DER)
                 or else DER'Last - Pos < Total - 1
               then
                  OK := Loaded > 0;
                  return;
               end if;

               declare
                  One_DER : X509.Byte_Seq (0 .. Total - 1);
                  One_OK  : Boolean;
               begin
                  --  Copy to 0-indexed slice (Add_Root requires DER'First = 0)
                  for I in X509.N32 range 0 .. Total - 1 loop
                     One_DER (I) := DER (Pos + I);
                  end loop;
                  Add_Root (Store, One_DER, One_OK);
                  if One_OK then
                     Loaded := Loaded + 1;
                  end if;
               end;

               Pos := Pos + Total;
            end;
         end;
      end loop;
   end Load_Roots;

   ----------------------------------------------------------------------------
   --  Identity helpers
   ----------------------------------------------------------------------------

   procedure Set_Identity
     (Id : out Identity; Cert_DER : X509.Byte_Seq; Key : Byte_Seq; OK : out Boolean)
   is
      C    : X509.Certificate;
      P_OK : Boolean;
   begin
      OK := False;
      --  Initialize all Id fields explicitly so SPARK flow analysis
      --  sees a fully-set 'out' parameter on every return path.
      Id.Int_Count := 0;
      Id.Ints := (others => <>);
      Id.Cert_DER := (others => 0);
      Id.Cert_DER_Len := 0;
      Id.Cert := C;  --  defaults
      Id.Cert_Valid := False;
      Id.NaCl_Cert_DER := (others => 0);
      Id.NaCl_Cert_Len := 0;
      Id.Sign_Algo := Sign_None;
      Id.Ed25519_Key := (others => 0);
      Id.ECDSA_P256_Key := (others => 0);
      Id.ECDSA_P384_Key := (others => 0);
      Id.RSA_Modulus := (others => 0);
      Id.RSA_Mod_Len := 0;
      Id.RSA_Priv_Exp := (others => 0);
      Id.RSA_Pub_Exp := 0;
      Id.Has_Identity := False;

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
            if Key'Length /= 64 then
               return;
            end if;
            Id.Sign_Algo := Sign_Ed25519;
            for I in N32 range 0 .. 63 loop
               Id.Ed25519_Key (I) := Key (Key'First + I);
            end loop;

         when X509.Algo_EC_P256 =>
            if Key'Length /= 32 then
               return;
            end if;
            Id.Sign_Algo := Sign_ECDSA_P256;
            for I in N32 range 0 .. 31 loop
               Id.ECDSA_P256_Key (I) := Key (Key'First + I);
            end loop;

         when X509.Algo_EC_P384 =>
            if Key'Length /= 48 then
               return;
            end if;
            Id.Sign_Algo := Sign_ECDSA_P384;
            for I in N32 range 0 .. 47 loop
               Id.ECDSA_P384_Key (I) := Key (Key'First + I);
            end loop;

         when X509.Algo_RSA =>
            --  Key is packed: n_len(2) || n || d_len(2) || d || e(4)
            if Key'Length < 8 then
               return;
            end if;
            declare
               KF    : constant N32 := Key'First;
               N_Len : constant N32 := N32 (Key (KF)) * 256 + N32 (Key (KF + 1));
               D_Off : N32;
               D_Len : N32;
               E_Off : N32;
            begin
               if N_Len < 64 or N_Len > Max_RSA_Key_Bytes then
                  return;
               end if;
               if KF + 2 + N_Len + 5 > Key'Last then
                  return;
               end if;

               D_Off := KF + 2 + N_Len;
               D_Len := N32 (Key (D_Off)) * 256 + N32 (Key (D_Off + 1));
               if D_Len < 64 or D_Len > Max_RSA_Key_Bytes then
                  return;
               end if;
               if D_Len > N_Len then
                  return;
               end if;
               if D_Off + 2 + D_Len + 3 > Key'Last then
                  return;
               end if;

               E_Off := D_Off + 2 + D_Len;

               Id.Sign_Algo := Sign_RSA_PSS;
               Id.RSA_Mod_Len := N_Len;

               Id.RSA_Modulus := (others => 0);
               for I in N32 range 0 .. N_Len - 1 loop
                  Id.RSA_Modulus (I) := Key (KF + 2 + I);
               end loop;

               Id.RSA_Priv_Exp := (others => 0);
               for I in N32 range 0 .. D_Len - 1 loop
                  Id.RSA_Priv_Exp (N_Len - D_Len + I) := Key (D_Off + 2 + I);
               end loop;

               Id.RSA_Pub_Exp :=
                 Unsigned_32 (Key (E_Off)) * 2 ** 24 + Unsigned_32 (Key (E_Off + 1)) * 2 ** 16
                 + Unsigned_32 (Key (E_Off + 2)) * 2 ** 8
                 + Unsigned_32 (Key (E_Off + 3));
            end;

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

   procedure Add_Intermediate (Id : in out Identity; DER : X509.Byte_Seq; OK : out Boolean) is
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

   ----------------------------------------------------------------------------
   --  Chain building and validation
   ----------------------------------------------------------------------------

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
         PL_Depth : Natural;
         --  non-self-issued CA count for pathlen
         Budget   : in out Natural;
         Result   : out Validation_Result)
      with
        Pre =>
          Cert_DER'First = 0
          and Cert_DER'Last < X509.N32'Last - 256
          and PL_Depth <= Max_Chain_Depth
          and X509.Spans_Valid (Cert, Cert_DER'Last),
        Subprogram_Variant => (Decreases => Budget),
        Post => Budget <= Budget'Old
      is
         R            : Validation_Result;
         Saved_Budget : Natural
         with Ghost;
      begin
         Result := Err_No_Trust_Anchor;

         if Budget = 0 then
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
                    Validate_Root
                      (Roots (Ri).Cert, Roots (Ri).DER (0 .. Roots (Ri).DER_Len - 1), Now, Mode);
               begin
                  if VR = Valid then
                     pragma
                       Assert  --  PROBE-T8
                         (X509.Spans_Valid (Cert, Cert_DER'Last)
                            and then X509.Spans_Valid (Roots (Ri).Cert, Roots (Ri).DER_Len - 1));
                     R :=
                       Validate_Link
                         (Cert_DER         => Cert_DER,
                          Cert             => Cert,
                          Issuer_DER       => Roots (Ri).DER (0 .. Roots (Ri).DER_Len - 1),
                          Issuer           => Roots (Ri).Cert,
                          Now              => Now,
                          Must_Be_CA       => Depth > 0,
                          CAs_Below_Issuer => PL_Depth,
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
               pragma
                 Assert  --  PROBE-T8
                   (X509.Spans_Valid (Cert, Cert_DER'Last)
                      and then X509.Spans_Valid (Ints (Ii).Cert, Ints (Ii).DER_Len - 1));
               R :=
                 Validate_Link
                   (Cert_DER         => Cert_DER,
                    Cert             => Cert,
                    Issuer_DER       => Ints (Ii).DER (0 .. Ints (Ii).DER_Len - 1),
                    Issuer           => Ints (Ii).Cert,
                    Now              => Now,
                    Must_Be_CA       => Depth > 0,
                    CAs_Below_Issuer => PL_Depth,
                    Mode             => Mode);
               if R = Valid then
                  --  This intermediate is a valid issuer; recurse.
                  --  RFC 5280 4.2.1.9: self-issued certs don't count
                  --  toward pathLenConstraint.
                  declare
                     Next_Used : Used_Set := Used;
                     Next_PL   : constant Natural :=
                       (if X509.Is_Self_Issued
                             (Ints (Ii).Cert, Ints (Ii).DER (0 .. Ints (Ii).DER_Len - 1))
                        then PL_Depth
                        elsif PL_Depth >= Max_Chain_Depth
                        then Max_Chain_Depth  --  saturate; outer Depth
                        --  guard rejects in any case
                        else PL_Depth + 1);
                  begin
                     Next_Used (Ii) := True;
                     Try_Build
                       (Ints (Ii).DER (0 .. Ints (Ii).DER_Len - 1),
                        Ints (Ii).Cert,
                        Next_Used,
                        Depth + 1,
                        Next_PL,
                        Budget,
                        R);
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

      R              : Validation_Result;
      Ignored_Budget : Natural := Max_Build_Calls;
   begin
      --  Build chain from leaf upward
      Try_Build
        (Leaf_DER,
         Leaf,
         Used     => (others => False),
         Depth    => 0,
         PL_Depth => 0,
         Budget   => Ignored_Budget,
         Result   => R);

      if R /= Valid then
         return R;
      end if;

      --  Chain is valid; check leaf policy
      return
        Validate_Leaf_Policy
          (Leaf     => Leaf,
           Leaf_DER => Leaf_DER,
           Hostname => Hostname,
           Purpose  => Purpose,
           Mode     => Mode);
   end Validate_Chain;

   ------------------------------------------------------------------
   --  Verify_Signature: verify a raw signature against a cert's pubkey.
   --
   --  1. Hash the Data with the algorithm implied by Sig_Scheme
   --  2. Extract the public key from Cert
   --  3. Verify using RSA-PSS, ECDSA, or Ed25519
   ------------------------------------------------------------------

   function Verify_Signature_Hashed
     (H256_In    : Bytes_32;
      H384_In    : Bytes_48;
      H512_In    : Bytes_64;
      Sig        : Byte_Seq;
      Cert       : X509.Certificate;
      Sig_Scheme : Unsigned_16) return Boolean
   is
      PK_Algo : constant X509.Algorithm_ID := X509.PK_Algorithm (Cert);
      PK_Len  : constant X509.N32 := X509.PK_Length (Cert);
      Sig_Len : constant N32 := N32 (Sig'Length);
   begin
      if PK_Len = 0 or PK_Len > X509.N32 (X509.Max_PK_Bytes) then
         return False;
      end if;
      declare
         PK_Data : constant X509.Byte_Seq := X509.PK_Data (Cert);
      begin

         case Sig_Scheme is

            --  RSA-PSS-SHA256 (0x0804) or RSA-PKCS1-SHA256 (0x0401).
            --  Both schemes are accepted at this layer; the TLS 1.3
            --  caller is responsible for rejecting rsa_pkcs1_* per
            --  RFC 8446 4.2.3 before reaching here.

            when 16#0804# | 16#0401# =>
               if PK_Algo /= X509.Algo_RSA then
                  return False;
               end if;
               if PK_Len < 64 or PK_Len > X509.N32 (RSA.Max_RSA_Bytes) then
                  return False;
               end if;
               if Sig_Len /= N32 (PK_Len) then
                  return False;
               end if;
               declare
                  H         : SPARKTLSCrypto.Hashing.SHA256.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. Sig_Len - 1);
               begin
                  H := SPARKTLSCrypto.Hashing.SHA256.Digest (H256_In);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  Sig_Bytes := Sig;
                  if Sig_Scheme = 16#0804# then
                     return
                       RSA.Verify_PSS_SHA256
                         (Hash      => Bytes_32 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  else
                     return
                       RSA.Verify_PKCS1_v1_5_SHA256
                         (Hash      => Bytes_32 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  end if;
               end;

               --  RSA-PSS-SHA384 (0x0805) or RSA-PKCS1-SHA384 (0x0501)

            when 16#0805# | 16#0501# =>
               if PK_Algo /= X509.Algo_RSA then
                  return False;
               end if;
               if PK_Len < 64 or PK_Len > X509.N32 (RSA.Max_RSA_Bytes) then
                  return False;
               end if;
               if Sig_Len /= N32 (PK_Len) then
                  return False;
               end if;
               declare
                  H         : SPARKNaCl.Hashing.SHA384.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. Sig_Len - 1);
               begin
                  H := SPARKNaCl.Hashing.SHA384.Digest (H384_In);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  Sig_Bytes := Sig;
                  if Sig_Scheme = 16#0805# then
                     return
                       RSA.Verify_PSS_SHA384
                         (Hash      => Bytes_48 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  else
                     return
                       RSA.Verify_PKCS1_v1_5_SHA384
                         (Hash      => Bytes_48 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  end if;
               end;

               --  RSA-PSS-SHA512 (0x0806) or RSA-PKCS1-SHA512 (0x0601)

            when 16#0806# | 16#0601# =>
               if PK_Algo /= X509.Algo_RSA then
                  return False;
               end if;
               if PK_Len < 64 or PK_Len > X509.N32 (RSA.Max_RSA_Bytes) then
                  return False;
               end if;
               if Sig_Len /= N32 (PK_Len) then
                  return False;
               end if;
               declare
                  H         : SPARKNaCl.Hashing.SHA512.Digest;
                  Mod_Bytes : Byte_Seq (0 .. N32 (PK_Len) - 1) := (others => 0);
                  Sig_Bytes : Byte_Seq (0 .. Sig_Len - 1);
               begin
                  H := SPARKNaCl.Hashing.SHA512.Digest (H512_In);
                  for I in N32 range 0 .. N32 (PK_Len) - 1 loop
                     Mod_Bytes (I) := Byte (PK_Data (X509.N32 (I)));
                  end loop;
                  Sig_Bytes := Sig;
                  if Sig_Scheme = 16#0806# then
                     return
                       RSA.Verify_PSS_SHA512
                         (Hash      => Bytes_64 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  else
                     return
                       RSA.Verify_PKCS1_v1_5_SHA512
                         (Hash      => Bytes_64 (Byte_Seq (H)),
                          Modulus   => Mod_Bytes,
                          Mod_Len   => N32 (PK_Len),
                          Exponent  => Unsigned_32 (X509.RSA_Exponent (Cert)),
                          Signature => Sig_Bytes,
                          Sig_Len   => Sig_Len);
                  end if;
               end;

               --  ECDSA-P256-SHA256 (0x0403)

            when 16#0403# =>
               if PK_Algo /= X509.Algo_EC_P256 then
                  return False;
               end if;
               if PK_Len /= 65 then
                  return False;
               end if;
               declare
                  H      : SPARKTLSCrypto.Hashing.SHA256.Digest;
                  Qx     : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
                  Qy     : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
                  R_Val  : P256.ECDSA.ECDSA_Sig_Half;
                  S_Val  : P256.ECDSA.ECDSA_Sig_Half;
                  DER_OK : Boolean;
               begin
                  H := SPARKTLSCrypto.Hashing.SHA256.Digest (H256_In);
                  --  Extract public key (skip 0x04 uncompressed prefix)
                  for I in 0 .. 31 loop
                     Qx (N32 (I)) := Byte (PK_Data (X509.N32 (I + 1)));
                     Qy (N32 (I)) := Byte (PK_Data (X509.N32 (I + 33)));
                  end loop;
                  --  Parse DER signature into r, s
                  declare
                     X_Sig : X509.Byte_Seq (0 .. X509.N32 (Sig_Len) - 1) := (others => 0);
                  begin
                     for I in N32 range 0 .. Sig_Len - 1 loop
                        X_Sig (X509.N32 (I)) := X509.Byte (Sig (I));
                     end loop;
                     Parse_DER_ECDSA_Sig (X_Sig, Byte_Seq (R_Val), Byte_Seq (S_Val), DER_OK);
                  end;
                  if not DER_OK then
                     return False;
                  end if;
                  return
                    P256.ECDSA.Verify
                      (Hash => H,
                       Qx   => P256.ECDSA.ECDSA_Sig_Half (Qx),
                       Qy   => P256.ECDSA.ECDSA_Sig_Half (Qy),
                       R    => R_Val,
                       S    => S_Val);
               end;

               --  ECDSA-P384-SHA384 (0x0503)

            when 16#0503# =>
               if PK_Algo /= X509.Algo_EC_P384 then
                  return False;
               end if;
               if PK_Len /= 97 then
                  return False;
               end if;
               declare
                  H      : SPARKNaCl.Hashing.SHA384.Digest;
                  Qx     : Byte_Seq (0 .. 47) := (others => 0);
                  Qy     : Byte_Seq (0 .. 47) := (others => 0);
                  R_Val  : Byte_Seq (0 .. 47);
                  S_Val  : Byte_Seq (0 .. 47);
                  DER_OK : Boolean;
               begin
                  H := SPARKNaCl.Hashing.SHA384.Digest (H384_In);
                  for I in 0 .. 47 loop
                     Qx (N32 (I)) := Byte (PK_Data (X509.N32 (I + 1)));
                     Qy (N32 (I)) := Byte (PK_Data (X509.N32 (I + 49)));
                  end loop;
                  declare
                     X_Sig : X509.Byte_Seq (0 .. X509.N32 (Sig_Len) - 1) := (others => 0);
                  begin
                     for I in N32 range 0 .. Sig_Len - 1 loop
                        X_Sig (X509.N32 (I)) := X509.Byte (Sig (I));
                     end loop;
                     Parse_DER_ECDSA_Sig (X_Sig, R_Val, S_Val, DER_OK);
                  end;
                  if not DER_OK then
                     return False;
                  end if;
                  return
                    P384.ECDSA.Verify
                      (Hash => Bytes_48 (Byte_Seq (H)), Qx => Qx, Qy => Qy, R => R_Val, S => S_Val);
               end;

               --  Ed25519 (0x0807): PureEdDSA signs the raw message, which
               --  no digest can stand in for.  Digest-based callers (TLS 1.2
               --  CertificateVerify over the streamed transcript) therefore
               --  cannot accept it; the raw-data entry points still do.

            when 16#0807# =>
               return False;

            when others =>
               return False;

         end case;
      end;
   end Verify_Signature_Hashed;

   function Verify_Signature
     (Data : Byte_Seq; Sig : Byte_Seq; Cert : X509.Certificate; Sig_Scheme : Unsigned_16)
      return Boolean
   is
      PK_Algo : constant X509.Algorithm_ID := X509.PK_Algorithm (Cert);
      PK_Len  : constant X509.N32 := X509.PK_Length (Cert);
      Sig_Len : constant N32 := N32 (Sig'Length);
   begin
      if PK_Len = 0 or PK_Len > X509.N32 (X509.Max_PK_Bytes) then
         return False;
      end if;

      --  Ed25519 verifies over the raw message and so cannot delegate
      --  to the digest core.
      if Sig_Scheme = 16#0807# then
         declare
            PK_Data : constant X509.Byte_Seq := X509.PK_Data (Cert);
         begin
            case Sig_Scheme is
               --  Ed25519 (0x0807)

               when 16#0807# =>
                  if PK_Algo not in X509.Algo_Ed25519 | X509.Algo_EC_Ed25519 then
                     return False;
                  end if;
                  if PK_Len /= 32 or Sig_Len /= 64 then
                     return False;
                  end if;
                  declare
                     SM_Len      : constant N32 := 64 + N32 (Data'Length);
                     SM          : Byte_Seq (0 .. SM_Len - 1) := (others => 0);
                     Ignored_M   : Byte_Seq (0 .. SM_Len - 1);
                     PK_Bytes    : Bytes_32 := (others => 0);
                     OK          : Boolean;
                     Ignored_Len : I32;
                  begin
                     SM (0 .. 63) := Sig;
                     SM (64 .. SM_Len - 1) := Data;
                     for I in 0 .. 31 loop
                        PK_Bytes (N32 (I)) := Byte (PK_Data (X509.N32 (I)));
                     end loop;
                     SPARKTLSCrypto.Ed25519.Open (Ignored_M, OK, Ignored_Len, SM, PK_Bytes);
                     return OK;
                  end;

               when others =>
                  return False;
            end case;
         end;
      end if;

      declare
         H2 : SPARKTLSCrypto.Hashing.SHA256.Digest;
         H3 : SPARKNaCl.Hashing.SHA384.Digest;
         H5 : SPARKNaCl.Hashing.SHA512.Digest;
      begin
         SPARKTLSCrypto.Hashing.SHA256.Hash (H2, Data);
         SPARKNaCl.Hashing.SHA384.Hash (H3, Data);
         SPARKNaCl.Hashing.SHA512.Hash (H5, Data);
         return
           Verify_Signature_Hashed
             (H256_In    => Bytes_32 (Byte_Seq (H2)),
              H384_In    => Bytes_48 (Byte_Seq (H3)),
              H512_In    => Bytes_64 (Byte_Seq (H5)),
              Sig        => Sig,
              Cert       => Cert,
              Sig_Scheme => Sig_Scheme);
      end;
   end Verify_Signature;

   function Verify_Signature_TLS12
     (Data : Byte_Seq; Sig : Byte_Seq; Cert : X509.Certificate; Sig_Scheme : Unsigned_16)
      return Boolean
   is
      PK_Algo : constant X509.Algorithm_ID := X509.PK_Algorithm (Cert);
      PK_Len  : constant X509.N32 := X509.PK_Length (Cert);
   begin
      if Sig_Scheme = 16#0503# and then PK_Algo = X509.Algo_EC_P256 then
         if PK_Len /= 65 then
            return False;
         end if;

         declare
            H384    : SPARKNaCl.Hashing.SHA384.Digest;
            H256    : Bytes_32;
            PK_Data : constant X509.Byte_Seq := X509.PK_Data (Cert);
            Qx      : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
            Qy      : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
            R_Val   : P256.ECDSA.ECDSA_Sig_Half;
            S_Val   : P256.ECDSA.ECDSA_Sig_Half;
            DER_OK  : Boolean;
         begin
            SPARKNaCl.Hashing.SHA384.Hash (H384, Data);
            for I in N32 range 0 .. 31 loop
               H256 (I) := Byte_Seq (H384) (I);
            end loop;

            for I in 0 .. 31 loop
               Qx (N32 (I)) := Byte (PK_Data (X509.N32 (I + 1)));
               Qy (N32 (I)) := Byte (PK_Data (X509.N32 (I + 33)));
            end loop;

            declare
               X_Sig : X509.Byte_Seq (0 .. X509.N32 (Sig'Length) - 1) := (others => 0);
            begin
               for I in N32 range 0 .. N32 (Sig'Length) - 1 loop
                  X_Sig (X509.N32 (I)) := X509.Byte (Sig (I));
               end loop;
               Parse_DER_ECDSA_Sig (X_Sig, Byte_Seq (R_Val), Byte_Seq (S_Val), DER_OK);
            end;

            if not DER_OK then
               return False;
            end if;

            return
              P256.ECDSA.Verify
                (Hash => H256,
                 Qx   => P256.ECDSA.ECDSA_Sig_Half (Qx),
                 Qy   => P256.ECDSA.ECDSA_Sig_Half (Qy),
                 R    => R_Val,
                 S    => S_Val);
         end;
      end if;

      return Verify_Signature (Data => Data, Sig => Sig, Cert => Cert, Sig_Scheme => Sig_Scheme);
   end Verify_Signature_TLS12;

   function Verify_Signature_TLS12_Hashed
     (H256_In    : Bytes_32;
      H384_In    : Bytes_48;
      H512_In    : Bytes_64;
      Sig        : Byte_Seq;
      Cert       : X509.Certificate;
      Sig_Scheme : Unsigned_16) return Boolean
   is
      PK_Algo : constant X509.Algorithm_ID := X509.PK_Algorithm (Cert);
      PK_Len  : constant X509.N32 := X509.PK_Length (Cert);
   begin
      --  TLS 1.2 (sha384, ecdsa) with a P-256 key: the curve does not
      --  bind the hash; verify over the truncated SHA-384 digest.
      if Sig_Scheme = 16#0503# and then PK_Algo = X509.Algo_EC_P256 then
         if PK_Len /= 65 then
            return False;
         end if;

         declare
            H256    : Bytes_32;
            PK_Data : constant X509.Byte_Seq := X509.PK_Data (Cert);
            Qx      : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
            Qy      : P256.ECDSA.ECDSA_Sig_Half := (others => 0);
            R_Val   : P256.ECDSA.ECDSA_Sig_Half;
            S_Val   : P256.ECDSA.ECDSA_Sig_Half;
            DER_OK  : Boolean;
         begin
            for I in N32 range 0 .. 31 loop
               H256 (I) := H384_In (I);
            end loop;

            for I in 0 .. 31 loop
               Qx (N32 (I)) := Byte (PK_Data (X509.N32 (I + 1)));
               Qy (N32 (I)) := Byte (PK_Data (X509.N32 (I + 33)));
            end loop;

            declare
               X_Sig : X509.Byte_Seq (0 .. X509.N32 (Sig'Length) - 1) := (others => 0);
            begin
               for I in N32 range 0 .. N32 (Sig'Length) - 1 loop
                  X_Sig (X509.N32 (I)) := X509.Byte (Sig (I));
               end loop;
               Parse_DER_ECDSA_Sig (X_Sig, Byte_Seq (R_Val), Byte_Seq (S_Val), DER_OK);
            end;

            if not DER_OK then
               return False;
            end if;

            return
              P256.ECDSA.Verify
                (Hash => H256,
                 Qx   => P256.ECDSA.ECDSA_Sig_Half (Qx),
                 Qy   => P256.ECDSA.ECDSA_Sig_Half (Qy),
                 R    => R_Val,
                 S    => S_Val);
         end;
      end if;

      return
        Verify_Signature_Hashed
          (H256_In    => H256_In,
           H384_In    => H384_In,
           H512_In    => H512_In,
           Sig        => Sig,
           Cert       => Cert,
           Sig_Scheme => Sig_Scheme);
   end Verify_Signature_TLS12_Hashed;

end SPARKTLS.Cert_Verify;
