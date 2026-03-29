--  SPARKTLS RSA-PSS-RSAE Signature Verification
--  Uses SPARK-proven BigNat library for modular exponentiation.

with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLS.BigNat;
with Interfaces; use Interfaces;

package body SPARKTLS.RSA with
   SPARK_Mode => On
is
   --================================================================
   --  Forward declarations
   --================================================================

   procedure RSA_Public
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Unsigned_32;
      OK      :    out Boolean)
   with Always_Terminates,
        Pre => X'First = 0 and X'Last < N32'Last
               and Modulus'First = 0 and Modulus'Last < N32'Last
               and Mod_Len <= Max_RSA_Bytes
               and (Mod_Len = 0 or else N32 (Mod_Len) - 1 <= Modulus'Last)
               and (X_Len = 0 or else N32 (X_Len) - 1 <= X'Last);

   procedure PSS_Verify
     (EM       : in out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      N_Bitlen : in     Natural;
      Valid    :    out Boolean)
   with Always_Terminates;

   --================================================================
   --  Constant-time primitives
   --================================================================

   function CT_Eq0 (X : Unsigned_32) return Unsigned_32 is
     (Shift_Right (Shift_Right (X, 1) or (X and 1), 31) xor 1);
   --  1 if X=0, 0 otherwise (constant time)

   function Bit_Length_Word (X : Unsigned_32) return Unsigned_32 is
      function CT_Neq (A, B : Unsigned_32) return Unsigned_32 is
         (Shift_Right ((A xor B) or (-(A xor B)), 31));
      function CT_GT (A, B : Unsigned_32) return Unsigned_32 is
         (Shift_Right ((B - A) xor ((A xor B) and ((A xor (B - A)))), 31));
      function CT_Mux (Ctl, A, B : Unsigned_32) return Unsigned_32 is
        (B xor ((-Ctl) and (A xor B)));
      V : Unsigned_32 := X;
      K : Unsigned_32;
      C : Unsigned_32;
   begin
      K := CT_Neq (V, 0);
      C := CT_GT (V, 16#FFFF#);
      V := CT_Mux (C, Shift_Right (V, 16), V);
      K := K + Shift_Left (C, 4);
      C := CT_GT (V, 16#FF#);
      V := CT_Mux (C, Shift_Right (V, 8), V);
      K := K + Shift_Left (C, 3);
      C := CT_GT (V, 16#F#);
      V := CT_Mux (C, Shift_Right (V, 4), V);
      K := K + Shift_Left (C, 2);
      C := CT_GT (V, 16#3#);
      V := CT_Mux (C, Shift_Right (V, 2), V);
      K := K + Shift_Left (C, 1);
      K := K + CT_GT (V, 16#1#);
      return K;
   end Bit_Length_Word;

   --================================================================
   --  RSA public key operation using SPARK-proven BigNat
   --================================================================

   procedure RSA_Public
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Unsigned_32;
      OK      :    out Boolean)
   is
      use BigNat;
      M     : Big_Nat;
      A     : Big_Nat;
      M0I   : Word;
      E     : Byte_Seq (0 .. 3) := (others => 0);
   begin
      OK := False;

      if Mod_Len = 0 or else X_Len /= Mod_Len
         or else Mod_Len > Max_RSA_Bytes
      then
         return;
      end if;

      --  Copy to 0-indexed buffers for BigNat (requires First=0)
      declare
         Mod_Buf : Byte_Seq (0 .. N32 (Mod_Len) - 1);
         X_Buf   : Byte_Seq (0 .. N32 (X_Len) - 1);
      begin
         Mod_Buf := Modulus (Modulus'First .. Modulus'First + N32 (Mod_Len) - 1);
         X_Buf   := X (X'First .. X'First + N32 (X_Len) - 1);

         Decode (M, Mod_Buf);

         if M.Len = 0 or else (M.W (0) and 1) = 0 then
            return;
         end if;

         M0I := Ninv32 (M.W (0));

         Decode (A, X_Buf);

         if A.Len < M.Len then
            A.Len := M.Len;
         elsif A.Len > M.Len then
            return;
         end if;

         E (0) := Byte (Shift_Right (Exp, 24) and 16#FF#);
         E (1) := Byte (Shift_Right (Exp, 16) and 16#FF#);
         E (2) := Byte (Shift_Right (Exp, 8) and 16#FF#);
         E (3) := Byte (Exp and 16#FF#);

         declare
            Result : Big_Nat;
         begin
            Modpow (Result, A, E, M, M0I);
            Encode (X_Buf, Result);
         end;

         X (X'First .. X'First + N32 (X_Len) - 1) := X_Buf;
      end;

      OK := True;
   end RSA_Public;

   --================================================================
   --  Hash computation
   --================================================================

   procedure Compute_Hash
     (Alg     : in     PSS_Hash;
      Input   : in     Byte_Seq;
      Output  :    out Byte_Seq;
      Out_Len : in     Natural)
   with Pre => Input'First = 0 and Output'First = 0
               and Output'Last < N32'Last
               and (Out_Len = 0 or else N32 (Out_Len) - 1 <= Output'Last)
               and Out_Len <= 64
               and Input'Last < N32'Last
   is
   begin
      Output := (others => 0);
      case Alg is
         when PSS_SHA256 =>
            declare
               D : SPARKNaCl.Hashing.SHA256.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 32);
            begin
               SPARKNaCl.Hashing.SHA256.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA384 =>
            declare
               D : SPARKNaCl.Hashing.SHA384.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 48);
            begin
               SPARKNaCl.Hashing.SHA384.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA512 =>
            declare
               D : SPARKNaCl.Hashing.SHA512.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 64);
            begin
               SPARKNaCl.Hashing.SHA512.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
      end case;
   end Compute_Hash;

   --================================================================
   --  MGF1
   --================================================================

   procedure MGF1_XOR
     (Alg       : in     PSS_Hash;
      Hash_Len  : in     Natural;
      Data      : in out Byte_Seq;
      Data_Len  : in     Natural;
      Seed      : in     Byte_Seq;
      Seed_Len  : in     Natural)
   with Pre => Hash_Len in 32 | 48 | 64
               and Data'First = 0
               and Data'Last < Max_RSA_Bytes
               and (Data_Len = 0 or else N32 (Data_Len) - 1 <= Data'Last)
               and Data_Len <= Max_RSA_Bytes
               and Seed'First = 0
               and Seed'Last < 1000
               and (Seed_Len = 0 or else N32 (Seed_Len) - 1 <= Seed'Last)
               and Seed_Len <= 500
   is
      Counter : Unsigned_32 := 0;
      Pos     : Natural := 0;
   begin
      while Pos < Data_Len loop
         pragma Loop_Invariant (Pos <= Data_Len and Pos <= Max_RSA_Bytes);
         declare
            Input_Len : constant N32 := N32 (Seed_Len) + 4;
            Input     : Byte_Seq (0 .. Input_Len - 1) := (others => 0);
            H_Out     : Byte_Seq (0 .. N32 (Hash_Len) - 1) := (others => 0);
         begin
            Input (0 .. N32 (Seed_Len) - 1) :=
               Seed (0 .. N32 (Seed_Len) - 1);
            Input (N32 (Seed_Len))     :=
               Byte (Shift_Right (Counter, 24) and 16#FF#);
            Input (N32 (Seed_Len) + 1) :=
               Byte (Shift_Right (Counter, 16) and 16#FF#);
            Input (N32 (Seed_Len) + 2) :=
               Byte (Shift_Right (Counter, 8) and 16#FF#);
            Input (N32 (Seed_Len) + 3) :=
               Byte (Counter and 16#FF#);

            Compute_Hash (Alg, Input, H_Out, Hash_Len);

            for I in 0 .. Hash_Len - 1 loop
               exit when Pos + I >= Data_Len;
               Data (N32 (Pos + I)) :=
                  Data (N32 (Pos + I)) xor H_Out (N32 (I));
            end loop;
         end;

         Pos := Pos + Hash_Len;
         Counter := Counter + 1;
      end loop;
   end MGF1_XOR;

   --================================================================
   --  PSS Verify (RFC 8017 Section 9.1.2)
   --================================================================

   procedure PSS_Verify
     (EM       : in out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      N_Bitlen : in     Natural;
      Valid    :    out Boolean)
   with SPARK_Mode => Off  --  Data/Seed aliasing in MGF1_XOR call
   is
      Salt_Len  : constant Natural := Hash_Len;
      R         : Unsigned_32 := 0;
      EM_Bits   : constant Natural := N_Bitlen - 1;
      XLen      : constant Natural := (EM_Bits + 7) / 8;
      DB_Len    : Natural;
      Seed_Off  : Natural;
      Salt_Off  : Natural;
      Pad_Len   : Natural;
   begin
      Valid := False;

      if XLen < Hash_Len + Salt_Len + 2 then
         return;
      end if;

      if (EM_Bits mod 8) /= 0 then
         R := R or (Unsigned_32 (EM (EM'First)) and
                    Unsigned_32 (Shift_Left (Unsigned_8 (16#FF#),
                                             Natural (EM_Bits mod 8))));
      end if;

      R := R or (Unsigned_32 (EM (EM'First + N32 (XLen) - 1)) xor 16#BC#);

      DB_Len   := XLen - Hash_Len - 1;
      Seed_Off := DB_Len;

      MGF1_XOR
        (Alg      => Hash_Alg,
         Hash_Len => Hash_Len,
         Data     => EM (EM'First .. EM'First + N32 (DB_Len) - 1),
         Data_Len => DB_Len,
         Seed     => EM (EM'First + N32 (Seed_Off) ..
                         EM'First + N32 (Seed_Off) + N32 (Hash_Len) - 1),
         Seed_Len => Hash_Len);

      if (EM_Bits mod 8) /= 0 then
         EM (EM'First) := EM (EM'First) and
            Byte (Shift_Right (Unsigned_8 (16#FF#),
                               8 - Natural (EM_Bits mod 8)));
      end if;

      Pad_Len := DB_Len - Salt_Len - 1;
      for I in 0 .. Pad_Len - 1 loop
         R := R or Unsigned_32 (EM (EM'First + N32 (I)));
      end loop;
      R := R or (Unsigned_32 (EM (EM'First + N32 (Pad_Len))) xor 16#01#);

      Salt_Off := Pad_Len + 1;

      declare
         M_Buf_Len : constant N32 := 8 + N32 (Hash_Len) + N32 (Salt_Len);
         M_Buf     : Byte_Seq (0 .. M_Buf_Len - 1);
         H_Out     : Byte_Seq (0 .. N32 (Hash_Len) - 1);
      begin
         M_Buf (0 .. 7) := (others => 0);
         M_Buf (8 .. 8 + N32 (Hash_Len) - 1) :=
            M_Hash (M_Hash'First .. M_Hash'First + N32 (Hash_Len) - 1);
         for I in 0 .. Salt_Len - 1 loop
            M_Buf (8 + N32 (Hash_Len) + N32 (I)) :=
               EM (EM'First + N32 (Salt_Off) + N32 (I));
         end loop;

         Compute_Hash (Hash_Alg, M_Buf, H_Out, Hash_Len);

         for I in 0 .. Hash_Len - 1 loop
            R := R or (Unsigned_32 (H_Out (N32 (I))) xor
                       Unsigned_32 (EM (EM'First + N32 (Seed_Off) + N32 (I))));
         end loop;
      end;

      Valid := CT_Eq0 (R) = 1;
   end PSS_Verify;

   --================================================================
   --  Top-level Verify_PSS
   --================================================================

   function Verify_PSS
     (M_Hash    : in Byte_Seq;
      Hash_Len  : in N32;
      Hash_Alg  : in PSS_Hash;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
      X  : Byte_Seq (0 .. N32 (Sig_Len) - 1);
      OK : Boolean;
   begin
      X := Signature (Signature'First .. Signature'First + N32 (Sig_Len) - 1);

      RSA_Public
        (X       => X,
         X_Len   => Natural (Sig_Len),
         Modulus => Modulus,
         Mod_Len => Natural (Mod_Len),
         Exp     => Exponent,
         OK      => OK);

      if not OK then
         return False;
      end if;

      declare
         N_Bitlen : Natural := Natural (Mod_Len) * 8;
         Skip     : Natural := 0;
         PSS_OK   : Boolean;
      begin
         while Skip < Natural (Mod_Len) and then
               Modulus (Modulus'First + N32 (Skip)) = 0
         loop
            pragma Loop_Invariant (Skip < Natural (Mod_Len));
            pragma Loop_Variant (Increases => Skip);
            Skip := Skip + 1;
         end loop;
         if Skip < Natural (Mod_Len) then
            N_Bitlen := (Natural (Mod_Len) - Skip - 1) * 8 +
               Natural (Bit_Length_Word (
                  Unsigned_32 (Modulus (Modulus'First + N32 (Skip)))));
         end if;

         PSS_Verify
           (EM       => X,
            EM_Len   => Natural (Sig_Len),
            M_Hash   => M_Hash,
            Hash_Len => Natural (Hash_Len),
            Hash_Alg => Hash_Alg,
            N_Bitlen => N_Bitlen,
            Valid    => PSS_OK);

         return PSS_OK;
      end;
   end Verify_PSS;

   --================================================================
   --  Convenience wrappers
   --================================================================

   function Verify_PSS_SHA256
     (Hash      : in Bytes_32;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 32,
         Hash_Alg  => PSS_SHA256,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA256;

   function Verify_PSS_SHA384
     (Hash      : in Bytes_48;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 48,
         Hash_Alg  => PSS_SHA384,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA384;

   function Verify_PSS_SHA512
     (Hash      : in Bytes_64;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 64,
         Hash_Alg  => PSS_SHA512,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA512;

end SPARKTLS.RSA;
