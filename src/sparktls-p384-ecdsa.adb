--  SPARKTLS ECDSA P-384 Signature Verification
--  Uses shared P384.Field for field/point arithmetic,
--  and SPARK-proven BigNat for group order arithmetic.

with Interfaces;           use Interfaces;
with SPARKTLS.BigNat;      use SPARKTLS.BigNat;
with SPARKTLS.P384.Field;  use SPARKTLS.P384.Field;

package body SPARKTLS.P384.ECDSA with
   SPARK_Mode => On
is
   --================================================================
   --  Group order state
   --================================================================

   N        : Big_Nat;
   N_M0I    : Word;
   N_Inited : Boolean := False;

   procedure Init_Order
   with Post => N.Len = W384
   is
   begin
      if not N_Inited then
         Decode (N, P384_N);
         N_M0I := Ninv32 (N.W (0));
         N_Inited := True;
      end if;
      N.Len := W384;
   end Init_Order;

   --  Group order field operations (using BigNat directly)
   procedure Mul_Mod_N (D : out Big_Nat; A, B : Big_Nat) is
   begin
      Monty_Mul (D, A, B, N, N_M0I);
   end Mul_Mod_N;

   procedure Inv_Mod_N (D : out Big_Nat; A : Big_Nat) is
      NM2    : Byte_Seq (0 .. 47) := P384_N;
      Result : Big_Nat;
   begin
      NM2 (47) := NM2 (47) - 2;
      Modpow (Result, A, NM2, N, N_M0I);
      D := Result;
   end Inv_Mod_N;

   function Is_Zero_384 (A : Big_Nat) return Boolean is
      R : Word := 0;
   begin
      for I in 0 .. W384 - 1 loop
         R := R or A.W (I);
      end loop;
      return R = 0;
   end Is_Zero_384;

   function In_Range (V : Big_Nat) return Boolean
   with Pre => N.Len = W384
   is
      T      : Big_Nat := V;
      Trial  : Arith_Result;
   begin
      if Is_Zero_384 (V) then
         return False;
      end if;
      T.Len := N.Len;
      Trial := CT_Sub (T, N, 0);
      return Trial.Carry = 1;  --  borrow = 1 means V < N
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
      R_Int, S_Int, H_Int : Big_Nat;
      W, U1, U2 : Big_Nat;
      G_Pt, Q_Pt : Jacobian;
      T1, T2 : Big_Nat;
      RX_Bytes : Byte_Seq (0 .. 47);
      RX_Int : Big_Nat;
      One : Big_Nat;
   begin
      Init_Field;
      Init_Order;

      --  Decode r, s and check they're in [1, n-1]
      Decode (R_Int, R);
      Decode (S_Int, S);
      R_Int.Len := N.Len;
      S_Int.Len := N.Len;
      if not In_Range (R_Int) or not In_Range (S_Int) then
         return False;
      end if;

      --  Decode hash
      Decode (H_Int, Byte_Seq (Hash));
      H_Int.Len := N.Len;

      --  w = s^(-1) mod n
      Inv_Mod_N (W, S_Int);

      --  u1 = hash * w mod n
      T1 := H_Int;
      To_Monty (T1, N, N_M0I);
      T2 := W;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (U1, T1, T2);
      --  Convert U1 from Montgomery to normal: multiply by 1
      Zero (One, N.Len);
      One.W (0) := 1;
      Mul_Mod_N (T1, U1, One);
      U1 := T1;

      --  u2 = r * w mod n
      T1 := R_Int;
      To_Monty (T1, N, N_M0I);
      T2 := W;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (U2, T1, T2);
      Mul_Mod_N (T1, U2, One);
      U2 := T1;

      --  Compute u1*G + u2*Q
      declare
         U1_Bytes, U2_Bytes : Byte_Seq (0 .. 47);
      begin
         Encode (U1_Bytes, U1);
         Encode (U2_Bytes, U2);

         Make_Generator (G_Pt);
         Make_Point (Q_Pt, Qx, Qy);

         Scalar_Mul (G_Pt, U1_Bytes);
         Scalar_Mul (Q_Pt, U2_Bytes);
         Point_Add (G_Pt, Q_Pt);

         To_Affine (G_Pt);
      end;

      --  Get x-coordinate back to normal form
      FE_From_Monty (T1, G_Pt.X);

      --  Encode x, decode, reduce mod n, compare with r
      Encode (RX_Bytes, T1);
      Decode (RX_Int, RX_Bytes);
      RX_Int.Len := N.Len;

      --  Reduce mod n: if RX >= N, subtract N
      declare
         Trial : constant Arith_Result := CT_Sub (RX_Int, N, 0);
         Final : constant Arith_Result := CT_Sub (RX_Int, N,
            CT_Not (Trial.Carry));
      begin
         RX_Int := Final.Value;
      end;

      --  Compare RX with R
      declare
         Diff : Word := 0;
      begin
         for I in 0 .. W384 - 1 loop
            Diff := Diff or (RX_Int.W (I) xor R_Int.W (I));
         end loop;
         return Diff = 0;
      end;
   end Verify;

end SPARKTLS.P384.ECDSA;
