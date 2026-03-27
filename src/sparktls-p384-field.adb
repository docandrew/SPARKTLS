--  SPARKTLS P-384 Field Arithmetic (body)
--
--  Montgomery-based arithmetic mod p384 using RSA Big_Int.
--  Shared by P384.ECDSA and P384.Point.

with Interfaces; use Interfaces;

package body SPARKTLS.P384.Field with
   SPARK_Mode => Off
is
   --================================================================
   --  Constant-time primitives
   --================================================================

   function CT_Neq (A, B : Unsigned_32) return Unsigned_32 is
      (Shift_Right ((A xor B) or (-(A xor B)), 31)) with Inline;

   function CT_Not (C : Unsigned_32) return Unsigned_32 is
      (C xor 1) with Inline;

   function CT_Mux (C, X, Y : Unsigned_32) return Unsigned_32 is
      (Y xor ((-C) and (X xor Y))) with Inline;

   --================================================================
   --  Big_Int helpers
   --================================================================

   function Ninv32 (M1 : Unsigned_32) return Unsigned_32 is
      Y : Unsigned_32;
   begin
      Y := 2 - M1;
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      Y := Y * (2 - Y * M1);
      return CT_Mux (M1 and 1, -Y, 0);
   end Ninv32;

   function Sub
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
            A (I) := CT_Mux (Ctl, Unsigned_32 (CC and 16#FFFFFFFF#), Aw);
            CC := Shift_Right (CC, 63) and 1;
         end;
      end loop;
      return Unsigned_32 (CC);
   end Sub;

   function Add
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
   end Add;

   procedure To_Monty (X : in out Big_Int; M : Big_Int) is
      Len : constant Natural := Natural ((M (0) + 31) / 32);
   begin
      for Bit in 1 .. Len * 32 loop
         declare
            Carry   : Unsigned_32 := 0;
            Discard : Unsigned_32;
         begin
            for J in 1 .. Len loop
               declare
                  W  : constant Unsigned_32 := X (J);
                  NC : constant Unsigned_32 := Shift_Right (W, 31);
               begin
                  X (J) := Shift_Left (W, 1) or Carry;
                  Carry := NC;
               end;
            end loop;
            Discard := Sub (X, M,
               CT_Neq (Carry, 0) or CT_Not (Sub (X, M, 0)));
         end;
      end loop;
   end To_Monty;

   procedure Monty_Mul
     (D   : out    Big_Int;
      X   : in     Big_Int;
      Y   : in     Big_Int;
      M   : in     Big_Int;
      M0I : in     Unsigned_32)
   is
      Len : constant Natural := Natural ((M (0) + 31) / 32);
      DH  : Unsigned_64 := 0;
   begin
      Zero (D, M (0));
      for U in 1 .. Len loop
         declare
            XU : constant Unsigned_32 := X (U);
            F  : constant Unsigned_32 := (D (1) + XU * Y (1)) * M0I;
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
      declare
         Discard : Unsigned_32;
      begin
         Discard := Sub (D, M,
            CT_Neq (Unsigned_32 (DH), 0) or CT_Not (Sub (D, M, 0)));
      end;
   end Monty_Mul;

   procedure Modpow
     (X   : in out Big_Int;
      E   : in     Byte_Seq;
      M   : in     Big_Int;
      M0I : in     Unsigned_32)
   is
      MLen : constant Natural := Natural ((M (0) + 63) / 32);
      T1   : Big_Int;
      T2   : Big_Int;
   begin
      T1 := X;
      To_Monty (T1, M);
      Zero (X, M (0));
      X (1) := 1;
      for K in 0 .. N32 (E'Length) * 8 - 1 loop
         declare
            Byte_Idx : constant N32 := E'Last - K / 8;
            Bit_Idx  : constant Natural := Natural (K mod 8);
            Ctl      : constant Unsigned_32 :=
               Shift_Right (Unsigned_32 (E (Byte_Idx)), Bit_Idx) and 1;
         begin
            Monty_Mul (T2, X, T1, M, M0I);
            for I in 0 .. MLen loop
               X (I) := X (I) xor ((-Ctl) and (X (I) xor T2 (I)));
            end loop;
            Monty_Mul (T2, T1, T1, M, M0I);
            T1 (0 .. MLen) := T2 (0 .. MLen);
         end;
      end loop;
   end Modpow;

   --================================================================
   --  Field state
   --================================================================

   P_Inited : Boolean := False;

   --================================================================
   --  Public implementations
   --================================================================

   procedure Init_Field is
   begin
      if not P_Inited then
         Decode (P, P384_P, 48);
         P_M0I := Ninv32 (P (1));
         P_Inited := True;
      end if;
   end Init_Field;

   procedure Decode (X : out Big_Int; Src : Byte_Seq; Len : Natural) is
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
      declare
         BL : Unsigned_32 := 0;
         Found : Boolean := False;
      begin
         for I in reverse 1 .. V - 1 loop
            if not Found and then X (I) /= 0 then
               Found := True;
               declare
                  W : Unsigned_32 := X (I);
                  Bits : Unsigned_32 := 0;
               begin
                  while W /= 0 loop
                     Bits := Bits + 1;
                     W := Shift_Right (W, 1);
                  end loop;
                  BL := Unsigned_32 (I - 1) * 32 + Bits;
               end;
            end if;
         end loop;
         X (0) := BL;
      end;
   end Decode;

   procedure Encode (Dst : out Byte_Seq; Len : Natural; X : Big_Int) is
   begin
      Dst := (others => 0);
      for I in 0 .. Len - 1 loop
         declare
            Word_Idx : constant Natural := I / 4 + 1;
            Byte_Pos : constant Natural := (I mod 4) * 8;
         begin
            if Word_Idx <= Big_Int_Index'Last then
               Dst (Dst'First + N32 (Len - 1 - I)) :=
                  Byte (Shift_Right (X (Word_Idx), Byte_Pos) and 16#FF#);
            end if;
         end;
      end loop;
   end Encode;

   procedure Zero (X : out Big_Int; BL : Unsigned_32) is
   begin
      X := (others => 0);
      X (0) := BL;
   end Zero;

   procedure FE_Add (D : out Big_Int; A, B : Big_Int) is
      Tmp : Big_Int;
      Carry, Discard : Unsigned_32;
   begin
      Tmp := A;
      Carry := Add (Tmp, B, 1);
      Discard := Sub (Tmp, P,
         CT_Neq (Carry, 0) or CT_Not (Sub (Tmp, P, 0)));
      D := Tmp;
   end FE_Add;

   procedure FE_Sub (D : out Big_Int; A, B : Big_Int) is
      Tmp : Big_Int;
      Borrow : Unsigned_32;
   begin
      Tmp := A;
      Borrow := Sub (Tmp, B, 1);
      Borrow := Add (Tmp, P, Borrow);
      D := Tmp;
   end FE_Sub;

   procedure FE_Mul (D : out Big_Int; A, B : Big_Int) is
      Tmp : Big_Int;
   begin
      Monty_Mul (Tmp, A, B, P, P_M0I);
      D := Tmp;
   end FE_Mul;

   procedure FE_Sqr (D : out Big_Int; A : Big_Int) is
      Tmp : Big_Int;
   begin
      Monty_Mul (Tmp, A, A, P, P_M0I);
      D := Tmp;
   end FE_Sqr;

   procedure FE_To_Monty (X : in out Big_Int) is
   begin
      To_Monty (X, P);
   end FE_To_Monty;

   procedure FE_From_Monty (D : out Big_Int; A : Big_Int) is
      One, Tmp : Big_Int;
   begin
      Zero (One, P (0));
      One (1) := 1;
      Monty_Mul (Tmp, A, One, P, P_M0I);
      D := Tmp;
   end FE_From_Monty;

   procedure FE_Inv (D : out Big_Int; A : Big_Int) is
      PM2 : Byte_Seq (0 .. 47) := P384_P;
      Tmp : Big_Int;
   begin
      PM2 (47) := PM2 (47) - 2;
      FE_From_Monty (Tmp, A);
      Modpow (Tmp, PM2, P, P_M0I);
      FE_To_Monty (Tmp);
      D := Tmp;
   end FE_Inv;

   function FE_Is_Zero (A : Big_Int) return Boolean is
      R : Unsigned_32 := 0;
   begin
      for I in 1 .. W384 loop
         R := R or A (I);
      end loop;
      return R = 0;
   end FE_Is_Zero;

   --================================================================
   --  Point operations
   --================================================================

   procedure Point_Double (Q : in out Jacobian) is
      Delta_V, Gamma, Beta, Alpha, T1, T2 : Big_Int;
   begin
      FE_Sqr (Delta_V, Q.Z);
      FE_Sqr (Gamma, Q.Y);
      FE_Mul (Beta, Q.X, Gamma);
      FE_Sub (T1, Q.X, Delta_V);
      FE_Add (T2, Q.X, Delta_V);
      FE_Mul (Alpha, T1, T2);
      FE_Add (T1, Alpha, Alpha);
      FE_Add (Alpha, T1, Alpha);
      FE_Sqr (Q.X, Alpha);
      FE_Add (T1, Beta, Beta);
      FE_Add (T1, T1, T1);
      FE_Add (T2, T1, T1);
      FE_Sub (Q.X, Q.X, T2);
      FE_Add (T2, Q.Y, Q.Z);
      FE_Sqr (Q.Z, T2);
      FE_Sub (Q.Z, Q.Z, Gamma);
      FE_Sub (Q.Z, Q.Z, Delta_V);
      FE_Sub (T2, T1, Q.X);
      FE_Mul (Q.Y, Alpha, T2);
      FE_Sqr (T1, Gamma);
      FE_Add (T2, T1, T1);
      FE_Add (T2, T2, T2);
      FE_Add (T2, T2, T2);
      FE_Sub (Q.Y, Q.Y, T2);
   end Point_Double;

   procedure Point_Add (P1 : in out Jacobian; P2 : Jacobian) is
      Z1SQ, Z2SQ, U1, U2, S1, S2, H, I_V, J, R_V, V, T1 : Big_Int;
   begin
      if FE_Is_Zero (P2.Z) then
         return;
      end if;
      if FE_Is_Zero (P1.Z) then
         P1 := P2;
         return;
      end if;

      FE_Sqr (Z1SQ, P1.Z);
      FE_Sqr (Z2SQ, P2.Z);
      FE_Mul (U1, P1.X, Z2SQ);
      FE_Mul (U2, P2.X, Z1SQ);
      FE_Mul (T1, P2.Z, Z2SQ);
      FE_Mul (S1, P1.Y, T1);
      FE_Mul (T1, P1.Z, Z1SQ);
      FE_Mul (S2, P2.Y, T1);

      FE_Sub (H, U2, U1);
      FE_Sub (R_V, S2, S1);

      if FE_Is_Zero (H) then
         if FE_Is_Zero (R_V) then
            Point_Double (P1);
         else
            P1.X := (others => 0);
            P1.X (0) := P (0);
            P1.Y := P1.X;
            P1.Y (1) := 1;
            P1.Z := (others => 0);
            P1.Z (0) := P (0);
         end if;
         return;
      end if;

      FE_Add (I_V, H, H);
      FE_Sqr (I_V, I_V);
      FE_Mul (J, H, I_V);
      FE_Mul (V, U1, I_V);
      FE_Add (R_V, R_V, R_V);
      FE_Sqr (P1.X, R_V);
      FE_Sub (P1.X, P1.X, J);
      FE_Sub (P1.X, P1.X, V);
      FE_Sub (P1.X, P1.X, V);
      FE_Sub (T1, V, P1.X);
      FE_Mul (P1.Y, R_V, T1);
      FE_Mul (T1, S1, J);
      FE_Add (T1, T1, T1);
      FE_Sub (P1.Y, P1.Y, T1);
      FE_Add (T1, P1.Z, P2.Z);
      FE_Sqr (T1, T1);
      FE_Sub (T1, T1, Z1SQ);
      FE_Sub (T1, T1, Z2SQ);
      FE_Mul (P1.Z, T1, H);
   end Point_Add;

   procedure Scalar_Mul (P_Pt : in out Jacobian; K : Byte_Seq) is
      R0, R1 : Jacobian;
   begin
      Zero (R0.X, P (0));
      Zero (R0.Y, P (0));
      R0.Y (1) := 1;
      FE_To_Monty (R0.Y);
      Zero (R0.Z, P (0));
      R1 := P_Pt;

      for Byte_Idx in K'Range loop
         for Bit in reverse 0 .. 7 loop
            declare
               B : constant Natural :=
                  Natural (Shift_Right (Unsigned_32 (K (Byte_Idx)), Bit) and 1);
            begin
               if B = 1 then
                  Point_Add (R0, R1);
                  Point_Double (R1);
               else
                  Point_Add (R1, R0);
                  Point_Double (R0);
               end if;
            end;
         end loop;
      end loop;

      P_Pt := R0;
   end Scalar_Mul;

   procedure To_Affine (Pt : in out Jacobian) is
      Z_Inv, Z_Inv2, Z_Inv3 : Big_Int;
   begin
      if FE_Is_Zero (Pt.Z) then
         return;
      end if;
      FE_Inv (Z_Inv, Pt.Z);
      FE_Sqr (Z_Inv2, Z_Inv);
      FE_Mul (Z_Inv3, Z_Inv2, Z_Inv);
      FE_Mul (Pt.X, Pt.X, Z_Inv2);
      FE_Mul (Pt.Y, Pt.Y, Z_Inv3);
      Zero (Pt.Z, P (0));
      Pt.Z (1) := 1;
      FE_To_Monty (Pt.Z);
   end To_Affine;

   procedure Make_Generator (G : out Jacobian) is
   begin
      Init_Field;
      Decode (G.X, P384_GX, 48);
      FE_To_Monty (G.X);
      Decode (G.Y, P384_GY, 48);
      FE_To_Monty (G.Y);
      Zero (G.Z, P (0));
      G.Z (1) := 1;
      FE_To_Monty (G.Z);
   end Make_Generator;

   procedure Make_Point (Pt : out Jacobian; Qx, Qy : Byte_Seq) is
   begin
      Init_Field;
      Decode (Pt.X, Qx, 48);
      FE_To_Monty (Pt.X);
      Decode (Pt.Y, Qy, 48);
      FE_To_Monty (Pt.Y);
      Zero (Pt.Z, P (0));
      Pt.Z (1) := 1;
      FE_To_Monty (Pt.Z);
   end Make_Point;

end SPARKTLS.P384.Field;
