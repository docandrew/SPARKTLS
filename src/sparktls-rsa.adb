--  SPARKTLS RSA-PSS-RSAE Signature Verification
--  Ported from BearSSL i32 implementation (Thomas Pornin, MIT license)

with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with Interfaces; use Interfaces;

package body SPARKTLS.RSA with
   SPARK_Mode => Off
is
   --================================================================
   --  Constant-time primitives (from BearSSL inner.h)
   --================================================================

   function CT_Not (Ctl : Unsigned_32) return Unsigned_32 is
     (Ctl xor 1) with Inline;

   function CT_Mux
     (Ctl, X, Y : Unsigned_32) return Unsigned_32 is
     (Y xor ((-Ctl) and (X xor Y))) with Inline;

   function CT_Eq
     (X, Y : Unsigned_32) return Unsigned_32
   is
      Q : constant Unsigned_32 := X xor Y;
   begin
      return CT_Not (Shift_Right (Q or (-Q), 31));
   end CT_Eq;

   function CT_Neq
     (X, Y : Unsigned_32) return Unsigned_32
   is
      Q : constant Unsigned_32 := X xor Y;
   begin
      return Shift_Right (Q or (-Q), 31);
   end CT_Neq;

   function CT_GT
     (X, Y : Unsigned_32) return Unsigned_32
   is
      Z : constant Unsigned_32 := Y - X;
   begin
      return Shift_Right (Z xor ((X xor Y) and (X xor Z)), 31);
   end CT_GT;

   function CT_Eq0 (X : Unsigned_32) return Unsigned_32 is
   begin
      return CT_Not (Shift_Right (X or (-X), 31));
   end CT_Eq0;

   function CT_CMP (X, Y : Unsigned_32) return Unsigned_32 is
      GT_Val : constant Unsigned_32 := CT_GT (X, Y);
      LT_Val : constant Unsigned_32 := CT_GT (Y, X);
   begin
      return GT_Val or (-LT_Val);
   end CT_CMP;

   --  Constant-time conditional copy: if Ctl=1, copy Src to Dst
   procedure CT_Copy
     (Ctl : in     Unsigned_32;
      Dst : in out Big_Int;
      Src : in     Big_Int;
      Len : in     Natural)
   is
      Mask : constant Unsigned_32 := -Ctl;
   begin
      for I in 0 .. Len loop
         Dst (I) := Dst (I) xor (Mask and (Dst (I) xor Src (I)));
      end loop;
   end CT_Copy;

   --================================================================
   --  Bit length computation (constant-time, from BearSSL)
   --================================================================

   function Bit_Length_Word (X : Unsigned_32) return Unsigned_32 is
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

   function I32_Bit_Length
     (X    : Big_Int;
      From : Natural;
      XLen : Natural) return Unsigned_32
   is
      TW  : Unsigned_32 := 0;
      TWK : Unsigned_32 := 0;
   begin
      for I in reverse 0 .. XLen - 1 loop
         declare
            C : constant Unsigned_32 := CT_Eq (TW, 0);
            W : constant Unsigned_32 := X (From + I);
         begin
            TW  := CT_Mux (C, W, TW);
            TWK := CT_Mux (C, Unsigned_32 (I), TWK);
         end;
      end loop;
      return Shift_Left (TWK, 5) + Bit_Length_Word (TW);
   end I32_Bit_Length;

   --================================================================
   --  Big integer decode (big-endian bytes -> i32 format)
   --  x[0] = bit length, x[1..] = value words (little-endian)
   --================================================================

   procedure I32_Decode
     (X   : out Big_Int;
      Src : in  Byte_Seq;
      Len : in  Natural)
   is
      U : Natural := Len;
      V : Natural := 1;
   begin
      X := (others => 0);
      while U >= 4 loop
         U := U - 4;
         X (V) := Shift_Left (Unsigned_32 (Src (Src'First + N32 (U))), 24) or
                  Shift_Left (Unsigned_32 (Src (Src'First + N32 (U) + 1)), 16) or
                  Shift_Left (Unsigned_32 (Src (Src'First + N32 (U) + 2)), 8) or
                  Unsigned_32 (Src (Src'First + N32 (U) + 3));
         V := V + 1;
      end loop;
      if U > 0 then
         declare
            W : Unsigned_32 := 0;
         begin
            for I in 0 .. U - 1 loop
               W := Shift_Left (W, 8) or
                    Unsigned_32 (Src (Src'First + N32 (I)));
            end loop;
            X (V) := W;
            V := V + 1;
         end;
      end if;
      X (0) := I32_Bit_Length (X, 1, V - 1);
   end I32_Decode;

   --================================================================
   --  Big integer encode (i32 format -> big-endian bytes)
   --================================================================

   procedure I32_Encode
     (Dst : in out Byte_Seq;
      Len : in     Natural;
      X   : in     Big_Int)
   is
      K     : Natural;
      Pos   : Natural := 0;
      B_Len : constant Natural := Natural ((X (0) + 7) / 8);
   begin
      while Pos < Len and then Pos < Len - B_Len loop
         Dst (Dst'First + N32 (Pos)) := 0;
         Pos := Pos + 1;
      end loop;

      declare
         Remaining : constant Natural := Len - Pos;
      begin
         K := (Remaining + 3) / 4;
         declare
            Partial : constant Natural := Remaining mod 4;
         begin
            if Partial > 0 and then K > 0 then
               declare
                  W : constant Unsigned_32 := X (K);
               begin
                  if Partial >= 3 then
                     Dst (Dst'First + N32 (Pos)) :=
                        Byte (Shift_Right (W, 16) and 16#FF#);
                     Pos := Pos + 1;
                  end if;
                  if Partial >= 2 then
                     Dst (Dst'First + N32 (Pos)) :=
                        Byte (Shift_Right (W, 8) and 16#FF#);
                     Pos := Pos + 1;
                  end if;
                  Dst (Dst'First + N32 (Pos)) :=
                     Byte (W and 16#FF#);
                  Pos := Pos + 1;
               end;
               K := K - 1;
            end if;
         end;

         while K > 0 loop
            declare
               W : constant Unsigned_32 := X (K);
            begin
               Dst (Dst'First + N32 (Pos))     :=
                  Byte (Shift_Right (W, 24) and 16#FF#);
               Dst (Dst'First + N32 (Pos) + 1) :=
                  Byte (Shift_Right (W, 16) and 16#FF#);
               Dst (Dst'First + N32 (Pos) + 2) :=
                  Byte (Shift_Right (W, 8) and 16#FF#);
               Dst (Dst'First + N32 (Pos) + 3) :=
                  Byte (W and 16#FF#);
            end;
            Pos := Pos + 4;
            K := K - 1;
         end loop;
      end;
   end I32_Encode;

   --================================================================
   --  Compute -1/m[1] mod 2^32 (Newton's method)
   --================================================================

   function I32_Ninv32 (M1 : Unsigned_32) return Unsigned_32 is
      Y : Unsigned_32;
   begin
      Y := 2 - M1;
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      return CT_Mux (M1 and 1, -Y, 0);
   end I32_Ninv32;

   --================================================================
   --  Initialize big int to zero with given bit length
   --================================================================

   procedure I32_Zero (X : out Big_Int; Bit_Len : Unsigned_32) is
   begin
      X := (others => 0);
      X (0) := Bit_Len;
   end I32_Zero;

   --================================================================
   --  Subtraction: always compute a-b and borrow, but conditionally
   --  write the result (only if Ctl=1).
   --  Returns the final borrow (0 or 1).
   --  This matches BearSSL's br_i32_sub semantics exactly.
   --================================================================

   function I32_Sub
     (A   : in out Big_Int;
      B   : in     Big_Int;
      Ctl : in     Unsigned_32) return Unsigned_32
   is
      Len : constant Natural := Natural ((A (0) + 31) / 32);
      CC  : Unsigned_64 := 0;
   begin
      for I in 1 .. Len loop
         declare
            Aw : constant Unsigned_32 := A (I);
            Bw : constant Unsigned_32 := B (I);
         begin
            CC := Unsigned_64 (Aw) - Unsigned_64 (Bw) - CC;
            --  Conditionally write: store new value only if Ctl=1
            A (I) := CT_Mux (Ctl, Unsigned_32 (CC and 16#FFFFFFFF#), Aw);
            --  Extract borrow from bit 63 (sign bit of wrapped result)
            CC := Shift_Right (CC, 63) and 1;
         end;
      end loop;
      return Unsigned_32 (CC);
   end I32_Sub;

   --================================================================
   --  Addition: if Ctl=1, compute a := a + b.
   --  Returns the final carry (0 or 1).
   --================================================================

   function I32_Add
     (A   : in out Big_Int;
      B   : in     Big_Int;
      Ctl : in     Unsigned_32) return Unsigned_32
   is
      Len : constant Natural := Natural ((A (0) + 31) / 32);
      CC  : Unsigned_64 := 0;
   begin
      for I in 1 .. Len loop
         declare
            Aw : constant Unsigned_32 := A (I);
            Bw : constant Unsigned_32 := B (I);
         begin
            CC := Unsigned_64 (Aw) + Unsigned_64 (Bw) + CC;
            A (I) := CT_Mux (Ctl, Unsigned_32 (CC and 16#FFFFFFFF#), Aw);
            CC := Shift_Right (CC, 32);
         end;
      end loop;
      return Unsigned_32 (CC);
   end I32_Add;

   --================================================================
   --  Decode with modular reduction (value must be < m)
   --  Returns 1 if value < m, 0 otherwise.
   --================================================================

   function I32_Decode_Mod
     (X   : out Big_Int;
      Src : in  Byte_Seq;
      Len : in  Natural;
      M   : in  Big_Int) return Unsigned_32
   is
      MLen : constant Natural := Natural ((M (0) + 7) / 8);
      R    : Unsigned_32 := 0;
      UMax : constant Natural := (if MLen > Len then MLen else Len);
   begin
      I32_Zero (X, M (0));

      for U in reverse 1 .. UMax loop
         declare
            V  : constant Natural := U - 1;
            MB : Unsigned_32;
            XB : Unsigned_32;
         begin
            if V >= MLen then
               MB := 0;
            else
               MB := Shift_Right (M (1 + V / 4),
                                  Natural ((V mod 4) * 8)) and 16#FF#;
            end if;
            if V >= Len then
               XB := 0;
            else
               XB := Unsigned_32 (Src (Src'First + N32 (Len - U)));
            end if;
            R := CT_Mux (CT_Eq (R, 0), CT_CMP (XB, MB), R);
         end;
      end loop;

      R := Shift_Right (R, 24);

      declare
         UCopy : constant Natural := (if MLen > Len then Len else MLen);
      begin
         for U in reverse 1 .. UCopy loop
            declare
               XB : constant Unsigned_32 :=
                  Unsigned_32 (Src (Src'First + N32 (Len - U)))
                  and R;
               Idx : constant Natural := (U - 1) / 4 + 1;
               Shift_Amt : constant Natural := ((U - 1) mod 4) * 8;
            begin
               X (Idx) := X (Idx) or Shift_Left (XB, Shift_Amt);
            end;
         end loop;
      end;

      return Shift_Right (R, 7);
   end I32_Decode_Mod;

   --================================================================
   --  Convert to Montgomery representation: x := x * 2^(32*len) mod m
   --  Uses repeated doubling: for each of 32*len bits,
   --  x := 2*x mod m.
   --================================================================

   procedure I32_To_Monty (X : in out Big_Int; M : in Big_Int) is
      Len        : constant Natural := Natural ((M (0) + 31) / 32);
      Total_Bits : constant Natural := Len * 32;
   begin
      for Bit in 1 .. Total_Bits loop
         declare
            Carry    : Unsigned_32 := 0;
            Discard  : Unsigned_32;
         begin
            --  X := X * 2 (shift left by 1 bit)
            for J in 1 .. Len loop
               declare
                  W   : constant Unsigned_32 := X (J);
                  New_Carry : constant Unsigned_32 := Shift_Right (W, 31);
               begin
                  X (J) := Shift_Left (W, 1) or Carry;
                  Carry := New_Carry;
               end;
            end loop;
            --  If carry set or X >= M, subtract M.
            --  I32_Sub with Ctl=0 tests X >= M without modifying X,
            --  and returns borrow=0 if X >= M, borrow=1 if X < M.
            Discard := I32_Sub (X, M,
               CT_Neq (Carry, 0) or CT_Not (I32_Sub (X, M, 0)));
         end;
      end loop;
   end I32_To_Monty;

   --================================================================
   --  Montgomery multiplication: d = (x * y) / 2^(32*len) mod m
   --  Direct port of BearSSL i32_montmul.c
   --================================================================

   procedure I32_Monty_Mul
     (D   : out    Big_Int;
      X   : in     Big_Int;
      Y   : in     Big_Int;
      M   : in     Big_Int;
      M0I : in     Unsigned_32)
   is
      Len : constant Natural := Natural ((M (0) + 31) / 32);
      DH  : Unsigned_64 := 0;
   begin
      I32_Zero (D, M (0));

      for U in 1 .. Len loop
         declare
            XU : constant Unsigned_32 := X (U);
            F  : constant Unsigned_32 :=
               (D (1) + XU * Y (1)) * M0I;
            R1 : Unsigned_64 := 0;
            R2 : Unsigned_64 := 0;
         begin
            for V in 1 .. Len loop
               declare
                  Z : Unsigned_64;
                  T : Unsigned_32;
               begin
                  Z := Unsigned_64 (D (V)) +
                       Unsigned_64 (XU) * Unsigned_64 (Y (V)) + R1;
                  R1 := Shift_Right (Z, 32);
                  T := Unsigned_32 (Z and 16#FFFFFFFF#);
                  Z := Unsigned_64 (T) +
                       Unsigned_64 (F) * Unsigned_64 (M (V)) + R2;
                  R2 := Shift_Right (Z, 32);
                  if V > 1 then
                     D (V - 1) := Unsigned_32 (Z and 16#FFFFFFFF#);
                  end if;
               end;
            end loop;
            declare
               ZH : constant Unsigned_64 := DH + R1 + R2;
            begin
               D (Len) := Unsigned_32 (ZH and 16#FFFFFFFF#);
               DH := Shift_Right (ZH, 32);
            end;
         end;
      end loop;

      --  Final reduction: d may still be >= m
      declare
         Discard : Unsigned_32;
      begin
         Discard := I32_Sub (D, M,
            CT_Neq (Unsigned_32 (DH), 0) or
            CT_Not (I32_Sub (D, M, 0)));
      end;
   end I32_Monty_Mul;

   --================================================================
   --  Modular exponentiation: x := x^e mod m
   --  Uses Montgomery multiplication (BearSSL i32_modpow.c)
   --================================================================

   procedure I32_Modpow
     (X   : in out Big_Int;
      E   : in     Byte_Seq;
      M   : in     Big_Int;
      M0I : in     Unsigned_32)
   is
      MLen : constant Natural := Natural ((M (0) + 63) / 32);
      T1   : Big_Int;
      T2   : Big_Int;
   begin
      --  T1 = x in Montgomery form
      T1 := X;
      I32_To_Monty (T1, M);

      --  X = 1 (accumulator, normal form)
      I32_Zero (X, M (0));
      X (1) := 1;

      --  Right-to-left binary exponentiation
      for K in 0 .. N32 (E'Length) * 8 - 1 loop
         declare
            Byte_Idx : constant N32 := E'Last - K / 8;
            Bit_Idx  : constant Natural := Natural (K mod 8);
            Ctl      : constant Unsigned_32 :=
               Shift_Right (Unsigned_32 (E (Byte_Idx)), Bit_Idx) and 1;
         begin
            --  T2 = X * T1 (Montgomery multiply)
            I32_Monty_Mul (T2, X, T1, M, M0I);
            --  If bit is set, X = T2 (conditionally copy)
            CT_Copy (Ctl, X, T2, MLen);
            --  T2 = T1 * T1 (square T1)
            I32_Monty_Mul (T2, T1, T1, M, M0I);
            --  T1 = T2
            T1 (0 .. MLen) := T2 (0 .. MLen);
         end;
      end loop;
   end I32_Modpow;

   --================================================================
   --  RSA public key operation: x := x^e mod n
   --  (in-place on big-endian byte array)
   --================================================================

   function RSA_Public
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Unsigned_32) return Boolean
   is
      M   : Big_Int;
      A   : Big_Int;
      M0I : Unsigned_32;
      R   : Unsigned_32;
      E   : Byte_Seq (0 .. 3);
   begin
      if Mod_Len = 0 or else X_Len /= Mod_Len
         or else Mod_Len > Max_RSA_Bytes
      then
         return False;
      end if;

      --  Strip leading zeros from modulus and decode
      declare
         Skip : Natural := 0;
      begin
         while Skip < Mod_Len and then
               Modulus (Modulus'First + N32 (Skip)) = 0
         loop
            Skip := Skip + 1;
         end loop;
         if Skip = Mod_Len then
            return False;
         end if;
         I32_Decode (M,
                     Modulus (Modulus'First + N32 (Skip) ..
                              Modulus'First + N32 (Mod_Len) - 1),
                     Mod_Len - Skip);
      end;

      M0I := I32_Ninv32 (M (1));

      --  M must be odd
      R := M0I and 1;
      if R = 0 then
         return False;
      end if;

      --  Decode x mod m
      R := R and I32_Decode_Mod (A, X (X'First .. X'First + N32 (X_Len) - 1),
                                  X_Len, M);
      if R = 0 then
         return False;
      end if;

      --  Encode exponent as 4 bytes big-endian
      E (0) := Byte (Shift_Right (Exp, 24) and 16#FF#);
      E (1) := Byte (Shift_Right (Exp, 16) and 16#FF#);
      E (2) := Byte (Shift_Right (Exp, 8) and 16#FF#);
      E (3) := Byte (Exp and 16#FF#);

      --  Compute modular exponentiation
      I32_Modpow (A, E, M, M0I);

      --  Encode result back to X
      I32_Encode (X (X'First .. X'First + N32 (X_Len) - 1), X_Len, A);

      return True;
   end RSA_Public;

   --================================================================
   --  Compute hash using selected algorithm into a max-size buffer.
   --  Returns the first Hash_Len bytes of the hash.
   --================================================================

   procedure Compute_Hash
     (Alg     : in     PSS_Hash;
      Input   : in     Byte_Seq;
      Output  :    out Byte_Seq;
      Out_Len : in     Natural)
   is
   begin
      Output := (others => 0);
      case Alg is
         when PSS_SHA256 =>
            declare
               D : SPARKNaCl.Hashing.SHA256.Digest;
            begin
               SPARKNaCl.Hashing.SHA256.Hash (D, Input);
               for I in 0 .. Out_Len - 1 loop
                  Output (Output'First + N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA384 =>
            declare
               D : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               SPARKNaCl.Hashing.SHA384.Hash (D, Input);
               for I in 0 .. Out_Len - 1 loop
                  Output (Output'First + N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA512 =>
            declare
               D : SPARKNaCl.Hashing.SHA512.Digest;
            begin
               SPARKNaCl.Hashing.SHA512.Hash (D, Input);
               for I in 0 .. Out_Len - 1 loop
                  Output (Output'First + N32 (I)) := D (N32 (I));
               end loop;
            end;
      end case;
   end Compute_Hash;

   --================================================================
   --  MGF1: XOR mask into buffer using selected hash
   --================================================================

   procedure MGF1_XOR
     (Alg       : in     PSS_Hash;
      Hash_Len  : in     Natural;
      Data      : in out Byte_Seq;
      Data_Len  : in     Natural;
      Seed      : in     Byte_Seq;
      Seed_Len  : in     Natural)
   is
      Counter : Unsigned_32 := 0;
      Pos     : Natural := 0;
   begin
      while Pos < Data_Len loop
         declare
            Input_Len : constant N32 := N32 (Seed_Len) + 4;
            Input     : Byte_Seq (0 .. Input_Len - 1);
            H_Out     : Byte_Seq (0 .. N32 (Hash_Len) - 1);
         begin
            Input (0 .. N32 (Seed_Len) - 1) :=
               Seed (Seed'First .. Seed'First + N32 (Seed_Len) - 1);
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
               Data (Data'First + N32 (Pos + I)) :=
                  Data (Data'First + N32 (Pos + I)) xor
                  H_Out (N32 (I));
            end loop;
         end;

         Pos := Pos + Hash_Len;
         Counter := Counter + 1;
      end loop;
   end MGF1_XOR;

   --================================================================
   --  PSS Signature Unpadding (RFC 8017 Section 9.1.2)
   --  Generalized for SHA-256/384/512.
   --  salt_len = hash_len per TLS 1.3 (RFC 8446 Section 4.2.3).
   --================================================================

   function PSS_Verify
     (EM       : in out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      N_Bitlen : in     Natural) return Boolean
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
      if XLen < Hash_Len + Salt_Len + 2 then
         return False;
      end if;

      --  Check leading bits are zero
      if (EM_Bits mod 8) /= 0 then
         R := R or (Unsigned_32 (EM (EM'First)) and
                    Unsigned_32 (Shift_Left (Unsigned_8 (16#FF#),
                                             Natural (EM_Bits mod 8))));
      end if;

      --  Check rightmost byte is 0xBC
      R := R or (Unsigned_32 (EM (EM'First + N32 (XLen) - 1)) xor 16#BC#);

      DB_Len   := XLen - Hash_Len - 1;
      Seed_Off := DB_Len;

      --  Unmask DB using MGF1(H, dbLen)
      MGF1_XOR
        (Alg      => Hash_Alg,
         Hash_Len => Hash_Len,
         Data     => EM (EM'First .. EM'First + N32 (DB_Len) - 1),
         Data_Len => DB_Len,
         Seed     => EM (EM'First + N32 (Seed_Off) ..
                         EM'First + N32 (Seed_Off) + N32 (Hash_Len) - 1),
         Seed_Len => Hash_Len);

      --  Clear leading bits of DB
      if (EM_Bits mod 8) /= 0 then
         EM (EM'First) := EM (EM'First) and
            Byte (Shift_Right (Unsigned_8 (16#FF#),
                               8 - Natural (EM_Bits mod 8)));
      end if;

      --  Check padding: DB should be 00...00 || 01 || salt
      Pad_Len := DB_Len - Salt_Len - 1;
      for I in 0 .. Pad_Len - 1 loop
         R := R or Unsigned_32 (EM (EM'First + N32 (I)));
      end loop;
      R := R or (Unsigned_32 (EM (EM'First + N32 (Pad_Len))) xor 16#01#);

      Salt_Off := Pad_Len + 1;

      --  Recompute H' = Hash(00..00 || mHash || salt)
      declare
         --  8 zero bytes + hash_len + salt_len
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

      return CT_Eq0 (R) = 1;
   end PSS_Verify;

   --================================================================
   --  Generic RSA-PSS Verify (all hash variants)
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
      X : Byte_Seq (0 .. N32 (Sig_Len) - 1);
   begin
      X := Signature (Signature'First .. Signature'First + N32 (Sig_Len) - 1);

      if not RSA_Public
        (X       => X,
         X_Len   => Natural (Sig_Len),
         Modulus => Modulus,
         Mod_Len => Natural (Mod_Len),
         Exp     => Exponent)
      then
         return False;
      end if;

      declare
         N_Bitlen : Natural := Natural (Mod_Len) * 8;
         Skip     : Natural := 0;
      begin
         while Skip < Natural (Mod_Len) and then
               Modulus (Modulus'First + N32 (Skip)) = 0
         loop
            Skip := Skip + 1;
         end loop;
         if Skip < Natural (Mod_Len) then
            N_Bitlen := (Natural (Mod_Len) - Skip - 1) * 8 +
               Natural (Bit_Length_Word (
                  Unsigned_32 (Modulus (Modulus'First + N32 (Skip)))));
         end if;

         return PSS_Verify
           (EM       => X,
            EM_Len   => Natural (Sig_Len),
            M_Hash   => M_Hash,
            Hash_Len => Natural (Hash_Len),
            Hash_Alg => Hash_Alg,
            N_Bitlen => N_Bitlen);
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
