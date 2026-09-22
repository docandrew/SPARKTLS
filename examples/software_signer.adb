with Interfaces; use Interfaces;
with SPARKTLS.Credentials;
with Entropy_Random;
with SPARKTLS.External_Signing;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.Ed25519;
with Entropy_Random;

package body Software_Signer is

   Key_Id : aliased Identity;
   Loaded : Boolean := False;

   procedure Init (Cert_Path, Key_Path : String; OK : out Boolean) is
   begin
      Credentials.Load_Identity (Key_Id, Cert_Path, Key_Path, Entropy_Random.Random'Access, OK);
      Loaded := OK;
   end Init;

   procedure Sign
     (Id      : in     Identity;
      Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status)
   is
      pragma Unreferenced (Id);   --  one key here; a multi-identity signer would match Id.Cert
      OK : Boolean := False;
   begin
      Sig := (others => 0);
      Sig_Len := 0;
      Status := Failed;
      if not Loaded or else Refuse then
         return;
      end if;

      case Scheme is
         when Sig_Ed25519 =>
            --  PureEdDSA: the message, never a digest. An empty message is
            --  never a TLS input; refuse rather than sign it.
            declare
               SM : Byte_Seq (0 .. Message'Length + 63);
               M  : constant Byte_Seq (0 .. Message'Length - 1) := Message;
            begin
               if Sig'Length < 64 or else Message'Length = 0 then
                  return;
               end if;
               SPARKTLSCrypto.Ed25519.Sign (SM, M, Key_Id.Ed25519_Key);
               Sig (Sig'First .. Sig'First + 63) := SM (0 .. 63);
               Sig_Len := 64;
               OK := True;
            end;

         when Sig_ECDSA_P256_SHA256 =>
            declare
               H     : Bytes_32;
               K     : Bytes_32;
               Blind : Byte_Seq (0 .. 39);
               R, S  : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
               Raw   : Byte_Seq (0 .. 63);
               DER   : Byte_Seq (0 .. External_Signing.Max_ECDSA_DER_Len - 1);
               D_Len : N32;
               K_OK, S_OK, D_OK : Boolean;
            begin
               if Digest'Length /= 32 or else Sig'Length < External_Signing.Max_ECDSA_DER_Len then
                  return;
               end if;
               H := Bytes_32 (Digest);
               SPARKTLSCrypto.RFC6979.Derive_K_P256 (Key_Id.ECDSA_P256_Key, H, K, K_OK);
               if not K_OK then
                  return;
               end if;
               Entropy_Random.Random (Blind);
               SPARKTLSCrypto.P256.ECDSA.Sign
                 (Hash => H, D => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (Key_Id.ECDSA_P256_Key),
                  K => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K), Blind => Blind,
                  R_Out => R, S_Out => S, OK => S_OK);
               if not S_OK then
                  return;
               end if;
               --  Hardware returns r || s; convert as a real signer would.
               Raw (0 .. 31) := Byte_Seq (R);
               Raw (32 .. 63) := Byte_Seq (S);
               External_Signing.ECDSA_Raw_To_DER (Raw, 32, DER, D_Len, D_OK);
               if not D_OK then
                  return;
               end if;
               Sig (Sig'First .. Sig'First + D_Len - 1) := DER (0 .. D_Len - 1);
               Sig_Len := D_Len;
               OK := True;
            end;

         when Sig_ECDSA_P384_SHA384 =>
            declare
               H     : SPARKNaCl.Bytes_48;
               K     : SPARKNaCl.Bytes_48;
               R, S  : Byte_Seq (0 .. 47);
               Raw   : Byte_Seq (0 .. 95);
               DER   : Byte_Seq (0 .. External_Signing.Max_ECDSA_DER_Len - 1);
               D_Len : N32;
               K_OK, S_OK, D_OK : Boolean;
               Blind : Byte_Seq (0 .. 55);   --  scalar/coordinate blinding
            begin
               if Digest'Length /= 48 or else Sig'Length < External_Signing.Max_ECDSA_DER_Len then
                  return;
               end if;
               H := SPARKNaCl.Bytes_48 (Digest);
               SPARKTLSCrypto.RFC6979.Derive_K_P384 (Key_Id.ECDSA_P384_Key, H, K, K_OK);
               if not K_OK then
                  return;
               end if;
               Entropy_Random.Random (Blind);
               SPARKTLSCrypto.P384.ECDSA.Sign
                 (Hash => H, D => Byte_Seq (Key_Id.ECDSA_P384_Key), K => Byte_Seq (K),
                  Blind => Blind, R_Out => R, S_Out => S, OK => S_OK);
               if not S_OK then
                  return;
               end if;
               Raw (0 .. 47) := R;
               Raw (48 .. 95) := S;
               External_Signing.ECDSA_Raw_To_DER (Raw, 48, DER, D_Len, D_OK);
               if not D_OK then
                  return;
               end if;
               Sig (Sig'First .. Sig'First + D_Len - 1) := DER (0 .. D_Len - 1);
               Sig_Len := D_Len;
               OK := True;
            end;

         when Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512 =>
            declare
               H_Len : constant N32 := Digest'Length;
               Alg   : constant SPARKTLSCrypto.RSA.PSS_Hash :=
                 (case Scheme is
                    when Sig_RSA_PSS_SHA256 => SPARKTLSCrypto.RSA.PSS_SHA256,
                    when Sig_RSA_PSS_SHA384 => SPARKTLSCrypto.RSA.PSS_SHA384,
                    when others             => SPARKTLSCrypto.RSA.PSS_SHA512);
               M_Hash : Byte_Seq (0 .. 63) := (others => 0);
               Salt   : Byte_Seq (0 .. 63) := (others => 0);
               Blind  : Bytes_16;
               Out_S  : Byte_Seq (0 .. 1023) := (others => 0);
               O_Len  : N32;
            begin
               if H_Len not in 32 | 48 | 64 or else Key_Id.RSA_Mod_Len < 64
                 or else Sig'Length < Key_Id.RSA_Mod_Len
               then
                  return;
               end if;
               M_Hash (0 .. H_Len - 1) := Digest;
               Entropy_Random.Random (Salt (0 .. H_Len - 1));
               Entropy_Random.Random (Byte_Seq (Blind));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash => M_Hash (0 .. H_Len - 1), Hash_Len => H_Len, Hash_Alg => Alg,
                  Modulus => Key_Id.RSA_Modulus, Mod_Len => Key_Id.RSA_Mod_Len,
                  Priv_Exp => Key_Id.RSA_Priv_Exp, Salt => Salt (0 .. H_Len - 1),
                  Signature => Out_S, Sig_Len => O_Len, OK => OK,
                  Blind => Blind, Pub_Exp => Key_Id.RSA_Pub_Exp, CRT => Key_Id.RSA_CRT);
               if OK then
                  Sig (Sig'First .. Sig'First + O_Len - 1) := Out_S (0 .. O_Len - 1);
                  Sig_Len := O_Len;
               end if;
            end;

         when Sig_RSA_PKCS1_SHA256 | Sig_RSA_PKCS1_SHA384 | Sig_RSA_PKCS1_SHA512 =>
            declare
               H_Len  : constant N32 := Digest'Length;
               M_Hash : Byte_Seq (0 .. 63) := (others => 0);
               Blind  : Bytes_16;
               Out_S  : Byte_Seq (0 .. 1023) := (others => 0);
               O_Len  : N32;
            begin
               if H_Len not in 32 | 48 | 64 or else Key_Id.RSA_Mod_Len < 64
                 or else Sig'Length < Key_Id.RSA_Mod_Len
               then
                  return;
               end if;
               M_Hash (0 .. H_Len - 1) := Digest;
               Entropy_Random.Random (Byte_Seq (Blind));
               SPARKTLSCrypto.RSA.Sign_PKCS1_v1_5
                 (M_Hash => M_Hash (0 .. H_Len - 1), Hash_Len => H_Len,
                  Modulus => Key_Id.RSA_Modulus, Mod_Len => Key_Id.RSA_Mod_Len,
                  Priv_Exp => Key_Id.RSA_Priv_Exp,
                  Signature => Out_S, Sig_Len => O_Len, OK => OK,
                  Blind => Blind, Pub_Exp => Key_Id.RSA_Pub_Exp, CRT => Key_Id.RSA_CRT);
               if OK then
                  Sig (Sig'First .. Sig'First + O_Len - 1) := Out_S (0 .. O_Len - 1);
                  Sig_Len := O_Len;
               end if;
            end;

         when others =>
            return;
      end case;

      if OK then
         if Corrupt_Output and then Sig_Len > 0 then
            --  Flip the LAST byte: still well-formed (DER tag/length and
            --  RSA range untouched), so what fails is the verification
            --  itself, not a parser or range check in front of it.
            Sig (Sig'First + Sig_Len - 1) := Sig (Sig'First + Sig_Len - 1) xor 16#01#;
         end if;
         Status := Signed;
      end if;
   end Sign;

end Software_Signer;
