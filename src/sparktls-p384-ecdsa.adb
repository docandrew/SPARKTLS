--  SPARKTLS ECDSA P-384 Signature Verification
--  Uses shared P384.Field for field/point arithmetic.

with Interfaces; use Interfaces;
with SPARKTLS.RSA; use SPARKTLS.RSA;
with SPARKTLS.P384.Field; use SPARKTLS.P384.Field;

package body SPARKTLS.P384.ECDSA with
   SPARK_Mode => Off
is
   --================================================================
   --  Group order arithmetic mod n
   --================================================================

   N : Big_Int;
   N_M0I : Unsigned_32;
   N_Inited : Boolean := False;

   --  Constant-time primitives (needed for group order ops)
   function CT_Neq (A, B : Unsigned_32) return Unsigned_32 is
      (Shift_Right ((A xor B) or (-(A xor B)), 31)) with Inline;

   function CT_Not (C : Unsigned_32) return Unsigned_32 is
      (C xor 1) with Inline;

   function CT_Mux (C, X, Y : Unsigned_32) return Unsigned_32 is
      (Y xor ((-C) and (X xor Y))) with Inline;

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

   function Sub_N
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
   end Sub_N;

   procedure To_Monty_N (X : in out Big_Int; M : Big_Int) is
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
            Discard := Sub_N (X, M,
               CT_Neq (Carry, 0) or CT_Not (Sub_N (X, M, 0)));
         end;
      end loop;
   end To_Monty_N;

   procedure Monty_Mul_N
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
         Discard := Sub_N (D, M,
            CT_Neq (Unsigned_32 (DH), 0) or CT_Not (Sub_N (D, M, 0)));
      end;
   end Monty_Mul_N;

   procedure Modpow_N
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
      To_Monty_N (T1, M);
      Zero (X, M (0));
      X (1) := 1;
      for K in 0 .. N32 (E'Length) * 8 - 1 loop
         declare
            Byte_Idx : constant N32 := E'Last - K / 8;
            Bit_Idx  : constant Natural := Natural (K mod 8);
            Ctl      : constant Unsigned_32 :=
               Shift_Right (Unsigned_32 (E (Byte_Idx)), Bit_Idx) and 1;
         begin
            Monty_Mul_N (T2, X, T1, M, M0I);
            for I in 0 .. MLen loop
               X (I) := X (I) xor ((-Ctl) and (X (I) xor T2 (I)));
            end loop;
            Monty_Mul_N (T2, T1, T1, M, M0I);
            T1 (0 .. MLen) := T2 (0 .. MLen);
         end;
      end loop;
   end Modpow_N;

   procedure Init_Order is
   begin
      if not N_Inited then
         Decode (N, P384_N, 48);
         N_M0I := Ninv32 (N (1));
         N_Inited := True;
      end if;
   end Init_Order;

   procedure Mul_Mod_N (D : out Big_Int; A, B : Big_Int) is
      Tmp : Big_Int;
   begin
      Monty_Mul_N (Tmp, A, B, N, N_M0I);
      D := Tmp;
   end Mul_Mod_N;

   procedure Inv_Mod_N (D : out Big_Int; A : Big_Int) is
      NM2 : Byte_Seq (0 .. 47) := P384_N;
   begin
      NM2 (47) := NM2 (47) - 2;
      D := A;
      Modpow_N (D, NM2, N, N_M0I);
   end Inv_Mod_N;

   function Is_Zero_384 (A : Big_Int) return Boolean is
      R : Unsigned_32 := 0;
   begin
      for I in 1 .. W384 loop
         R := R or A (I);
      end loop;
      return R = 0;
   end Is_Zero_384;

   function In_Range (V : Big_Int) return Boolean is
      T : Big_Int := V;
      Borrow : Unsigned_32;
   begin
      if Is_Zero_384 (V) then
         return False;
      end if;
      T (0) := N (0);
      Borrow := Sub_N (T, N, 0);
      return Borrow = 1;
   end In_Range;

   --================================================================
   --  ECDSA Verify
   --================================================================

   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   is
      R_Int, S_Int, H_Int : Big_Int;
      W, U1, U2 : Big_Int;
      G_Pt, Q_Pt : Jacobian;
      T1, T2 : Big_Int;
      RX_Bytes : Byte_Seq (0 .. 47);
      RX_Int : Big_Int;
   begin
      Init_Field;
      Init_Order;

      --  Decode r, s and check they're in [1, n-1]
      Decode (R_Int, R, 48);
      Decode (S_Int, S, 48);
      if not In_Range (R_Int) or not In_Range (S_Int) then
         return False;
      end if;

      --  Decode hash
      Decode (H_Int, Byte_Seq (Hash), 48);

      --  w = s^(-1) mod n
      Inv_Mod_N (W, S_Int);

      --  u1 = hash * w mod n
      T1 := H_Int;
      To_Monty_N (T1, N);
      T2 := W;
      To_Monty_N (T2, N);
      Mul_Mod_N (U1, T1, T2);
      declare
         One : Big_Int;
      begin
         Zero (One, N (0));
         One (1) := 1;
         Mul_Mod_N (T1, U1, One);
         U1 := T1;
      end;

      --  u2 = r * w mod n
      T1 := R_Int;
      To_Monty_N (T1, N);
      T2 := W;
      To_Monty_N (T2, N);
      Mul_Mod_N (U2, T1, T2);
      declare
         One : Big_Int;
      begin
         Zero (One, N (0));
         One (1) := 1;
         Mul_Mod_N (T1, U2, One);
         U2 := T1;
      end;

      --  Compute u1*G + u2*Q
      declare
         U1_Bytes, U2_Bytes : Byte_Seq (0 .. 47);
      begin
         Encode (U1_Bytes, 48, U1);
         Encode (U2_Bytes, 48, U2);

         Make_Generator (G_Pt);
         Make_Point (Q_Pt, Qx, Qy);

         Scalar_Mul (G_Pt, U1_Bytes);
         Scalar_Mul (Q_Pt, U2_Bytes);
         Point_Add (G_Pt, Q_Pt);

         To_Affine (G_Pt);
      end;

      --  Get x-coordinate back to normal form
      FE_From_Monty (T1, G_Pt.X);

      --  Encode x, reduce mod n, compare with r
      Encode (RX_Bytes, 48, T1);
      Decode (RX_Int, RX_Bytes, 48);

      RX_Int (0) := N (0);
      declare
         Discard : Unsigned_32;
      begin
         Discard := Sub_N (RX_Int, N, CT_Not (Sub_N (RX_Int, N, 0)));
      end;

      declare
         Diff : Unsigned_32 := 0;
      begin
         for I in 1 .. W384 loop
            Diff := Diff or (RX_Int (I) xor R_Int (I));
         end loop;
         return Diff = 0;
      end;
   end Verify;

end SPARKTLS.P384.ECDSA;
