with Interfaces; use Interfaces;

package body SPARKTLS.BigNat with
   SPARK_Mode => On
is

   --================================================================
   --  Constant-time primitives
   --================================================================

   function CT_Not (X : Word) return Word is
     (X xor 1);

   function CT_Mux (Ctl, X, Y : Word) return Word is
     (Y xor ((-Ctl) and (X xor Y)));

   function CT_Eq (X, Y : Word) return Word is
      Q : constant Word := X xor Y;
   begin
      return CT_Not (Shift_Right (Q or (-Q), 31));
   end CT_Eq;

   function CT_Neq (X, Y : Word) return Word is
      Q : constant Word := X xor Y;
   begin
      return Shift_Right (Q or (-Q), 31);
   end CT_Neq;

   --================================================================
   --  Ninv32: compute -M^(-1) mod 2^32 by Newton's method
   --================================================================

   function Ninv32 (M0 : Word) return Word is
      Y : Word;
   begin
      Y := 2 - M0;
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      return CT_Mux (M0 and 1, -Y, 0);
   end Ninv32;

   --================================================================
   --  Zero
   --================================================================

   procedure Zero
     (Result : out Big_Nat;
      Len    : in  Word_Count)
   is
   begin
      Result.Len := Len;
      Result.W   := (others => 0);
   end Zero;

   --================================================================
   --  CT_Sub: constant-time conditional subtraction
   --  Returns (A - B, borrow) if Ctl=1, (A, 0) if Ctl=0
   --================================================================

   function CT_Sub
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   is
      R  : Big_Nat;
      CC : DWord := 0;
   begin
      R.Len := A.Len;
      R.W   := (others => 0);

      for I in 0 .. A.Len - 1 loop
         pragma Loop_Invariant (R.Len = A.Len);
         declare
            Aw  : constant Word := A.W (I);
            Bw  : constant Word := B.W (I);
            Diff : DWord;
         begin
            Diff := DWord (Aw) - DWord (Bw) - CC;
            R.W (I) := CT_Mux (Ctl, Word (Diff and 16#FFFFFFFF#), Aw);
            CC := Shift_Right (Diff, 63) and 1;
         end;
      end loop;

      return (Value => R, Carry => Word (CC));
   end CT_Sub;

   --================================================================
   --  CT_Add: constant-time conditional addition
   --================================================================

   function CT_Add
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   is
      R  : Big_Nat;
      CC : DWord := 0;
   begin
      R.Len := A.Len;
      R.W   := (others => 0);

      for I in 0 .. A.Len - 1 loop
         pragma Loop_Invariant (R.Len = A.Len);
         declare
            Aw : constant Word := A.W (I);
            Bw : constant Word := B.W (I);
            Sum : DWord;
         begin
            Sum := DWord (Aw) + DWord (Bw) + CC;
            R.W (I) := CT_Mux (Ctl, Word (Sum and 16#FFFFFFFF#), Aw);
            CC := Shift_Right (Sum, 32);
         end;
      end loop;

      return (Value => R, Carry => Word (CC));
   end CT_Add;

   --================================================================
   --  Decode: big-endian bytes -> Big_Nat (little-endian words)
   --================================================================

   procedure Decode
     (Result : out Big_Nat;
      Src    : in  Byte_Seq)
   is
      U   : Natural := Natural (Src'Length);
      Idx : Natural := 0;
   begin
      Result.Len := 0;
      Result.W   := (others => 0);

      --  Process 4 bytes at a time from the end
      while U >= 4 and Idx < Max_Words loop
         pragma Loop_Invariant (Idx < Max_Words and U >= 4
                                and N32 (U) - 1 <= Src'Last);
         U := U - 4;
         Result.W (Idx) :=
            Shift_Left (Word (Src (N32 (U))), 24) or
            Shift_Left (Word (Src (N32 (U) + 1)), 16) or
            Shift_Left (Word (Src (N32 (U) + 2)), 8) or
            Word (Src (N32 (U) + 3));
         Idx := Idx + 1;
      end loop;

      --  Process remaining 1-3 bytes
      if U > 0 and Idx < Max_Words then
         declare
            W : Word := 0;
         begin
            for I in 0 .. U - 1 loop
               pragma Loop_Invariant (I < U);
               W := Shift_Left (W, 8) or Word (Src (N32 (I)));
            end loop;
            Result.W (Idx) := W;
            Idx := Idx + 1;
         end;
      end if;

      Result.Len := Idx;
   end Decode;

   --================================================================
   --  Encode: Big_Nat (little-endian words) -> big-endian bytes
   --================================================================

   procedure Encode
     (Dst : out Byte_Seq;
      A   : in  Big_Nat)
   is
      Pos : Natural := 0;
      K   : Natural;
      Dst_Len : constant Natural := Natural (Dst'Length);
      Byte_Len : constant Natural :=
         (if A.Len = 0 then 0 else A.Len * 4);
   begin
      Dst := (others => 0);

      --  Leading zero padding
      while Pos < Dst_Len and then Pos + Byte_Len < Dst_Len loop
         pragma Loop_Invariant (Pos < Dst_Len);
         Dst (N32 (Pos)) := 0;
         Pos := Pos + 1;
      end loop;

      --  Write words in big-endian from most significant
      if A.Len > 0 then
         K := A.Len;
         while K > 0 and then Pos + 3 < Dst_Len loop
            pragma Loop_Invariant (K > 0 and K <= A.Len
                                   and Pos + 3 < Dst_Len
                                   and N32 (Pos) + 3 <= Dst'Last);
            K := K - 1;
            declare
               W : constant Word := A.W (K);
            begin
               Dst (N32 (Pos))     := Byte (Shift_Right (W, 24) and 16#FF#);
               Dst (N32 (Pos) + 1) := Byte (Shift_Right (W, 16) and 16#FF#);
               Dst (N32 (Pos) + 2) := Byte (Shift_Right (W, 8) and 16#FF#);
               Dst (N32 (Pos) + 3) := Byte (W and 16#FF#);
               Pos := Pos + 4;
            end;
         end loop;
      end if;
   end Encode;

   --================================================================
   --  To_Monty: convert A to Montgomery domain
   --  A := A * R mod M, where R = 2^(32*Len)
   --  Uses repeated doubling.
   --================================================================

   procedure To_Monty
     (A   : in out Big_Nat;
      M   : in     Big_Nat;
      M0I : in     Word)
   is
      pragma Unreferenced (M0I);
      Total_Bits : constant Natural := M.Len * 32;
   begin
      for Bit in 1 .. Total_Bits loop
         pragma Loop_Invariant (A.Len = M.Len);
         declare
            Carry : Word := 0;
            Trial : Arith_Result;
            Final : Arith_Result;
         begin
            --  A := A * 2 (shift left by 1 bit)
            for J in 0 .. A.Len - 1 loop
               pragma Loop_Invariant (A.Len = M.Len);
               declare
                  W         : constant Word := A.W (J);
                  New_Carry : constant Word := Shift_Right (W, 31);
               begin
                  A.W (J) := Shift_Left (W, 1) or Carry;
                  Carry := New_Carry;
               end;
            end loop;

            --  Trial subtraction: check if A >= M
            Trial := CT_Sub (A, M, 0);
            --  Real subtraction: if carry or no borrow
            Final := CT_Sub (A, M,
               CT_Neq (Carry, 0) or CT_Not (Trial.Carry));
            A := Final.Value;
         end;
      end loop;
   end To_Monty;

   --================================================================
   --  Montgomery multiplication: Result = A * B * R^(-1) mod M
   --================================================================

   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len : constant Word_Count := M.Len;
      DH  : DWord := 0;
   begin
      Zero (Result, Len);

      for U in 0 .. Len - 1 loop
         pragma Loop_Invariant (Result.Len = Len);
         declare
            AU : constant Word := A.W (U);
            F  : constant Word :=
               (Result.W (0) + AU * B.W (0)) * M0I;
            R1 : DWord := 0;
            R2 : DWord := 0;
         begin
            for V in 0 .. Len - 1 loop
               pragma Loop_Invariant (Result.Len = Len);
               declare
                  Z : DWord;
                  T : Word;
               begin
                  Z := DWord (Result.W (V)) +
                       DWord (AU) * DWord (B.W (V)) + R1;
                  R1 := Shift_Right (Z, 32);
                  T := Word (Z and 16#FFFFFFFF#);
                  Z := DWord (T) +
                       DWord (F) * DWord (M.W (V)) + R2;
                  R2 := Shift_Right (Z, 32);
                  if V > 0 then
                     Result.W (V - 1) := Word (Z and 16#FFFFFFFF#);
                  end if;
               end;
            end loop;

            declare
               ZH : constant DWord := DH + R1 + R2;
            begin
               Result.W (Len - 1) := Word (ZH and 16#FFFFFFFF#);
               DH := Shift_Right (ZH, 32);
            end;
         end;
      end loop;

      --  Final reduction: if DH or Result >= M, subtract M
      declare
         Trial : constant Arith_Result := CT_Sub (Result, M, 0);
         Final : constant Arith_Result := CT_Sub (Result, M,
            CT_Neq (Word (DH and 16#FFFFFFFF#), 0) or
            CT_Not (Trial.Carry));
      begin
         Result := Final.Value;
      end;
   end Monty_Mul;

   --================================================================
   --  Modular exponentiation: Result = Base^Exp mod M
   --  Right-to-left binary method with Montgomery multiplication.
   --================================================================

   procedure Modpow
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      T1      : Big_Nat;  --  Base in Montgomery form
      T2      : Big_Nat;
      Ctl     : Word;
      Mask    : Word;
   begin
      --  T1 = base in Montgomery form
      T1 := Base;
      To_Monty (T1, M, M0I);
      pragma Assert (T1.Len = M.Len);

      --  Result = 1 (accumulator, normal form — NOT in Montgomery)
      Zero (Result, M.Len);
      if M.Len > 0 then
         Result.W (0) := 1;
      end if;

      --  Right-to-left binary exponentiation
      declare
         Total_Bits : constant N32 := N32 (Exp'Length) * 8;
      begin
         for K in N32 range 0 .. Total_Bits - 1 loop
            pragma Loop_Invariant (Result.Len = M.Len and T1.Len = M.Len);
         declare
            Byte_Idx : constant N32 := Exp'Last - K / 8;
            Bit_Idx  : constant Natural := Natural (K mod 8);
         begin
            Ctl := Shift_Right (Word (Exp (Byte_Idx)), Bit_Idx) and 1;

            --  T2 = Result * T1 (Montgomery multiply)
            Monty_Mul (T2, Result, T1, M, M0I);

            --  If bit is set, Result = T2 (constant-time conditional copy)
            Mask := -Ctl;
            for I in 0 .. M.Len - 1 loop
               pragma Loop_Invariant (Result.Len = M.Len);
               Result.W (I) := Result.W (I) xor
                  (Mask and (Result.W (I) xor T2.W (I)));
            end loop;

            --  T2 = T1^2 (square)
            Monty_Mul (T2, T1, T1, M, M0I);

            --  T1 = T2
            T1 := T2;
         end;
      end loop;
      end;
   end Modpow;

end SPARKTLS.BigNat;
