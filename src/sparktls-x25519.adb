--  X25519 Curve25519 Diffie-Hellman (RFC 7748)
--
--  Uses SPARKTLS.Fiat_25519 for GF(2^255-19) field arithmetic.
--  Montgomery ladder and encode/decode from RFC 7748 §5.

with Interfaces;           use Interfaces;
with SPARKTLS.Fiat_25519;  use SPARKTLS.Fiat_25519;
with SPARKTLS.Ed25519;

package body SPARKTLS.X25519 with
   SPARK_Mode => On
is
   --  Rename Fiat_25519.FE locally so the rest of the code reads cleanly
   subtype FE is Fiat_25519.FE;

   --================================================================
   --  Encode/Decode between bytes and field elements
   --================================================================

   subtype Load_Offset is I32 range 0 .. 24;

   function Load_LE64 (S : Bytes_32; Offset : Load_Offset) return Unsigned_64 is
     (Unsigned_64 (S (Offset)) or
      Shift_Left (Unsigned_64 (S (Offset + 1)), 8) or
      Shift_Left (Unsigned_64 (S (Offset + 2)), 16) or
      Shift_Left (Unsigned_64 (S (Offset + 3)), 24) or
      Shift_Left (Unsigned_64 (S (Offset + 4)), 32) or
      Shift_Left (Unsigned_64 (S (Offset + 5)), 40) or
      Shift_Left (Unsigned_64 (S (Offset + 6)), 48) or
      Shift_Left (Unsigned_64 (S (Offset + 7)), 56));

   function Decode (S : Bytes_32) return FE is
      R : FE := (others => 0);
   begin
      R (0) := Load_LE64 (S, 0) and Fiat_25519.Mask51;
      R (1) := Shift_Right (Load_LE64 (S, 6), 3) and Fiat_25519.Mask51;
      R (2) := Shift_Right (Load_LE64 (S, 12), 6) and Fiat_25519.Mask51;
      R (3) := Shift_Right (Load_LE64 (S, 19), 1) and Fiat_25519.Mask51;
      R (4) := Shift_Right (Load_LE64 (S, 24), 12) and Fiat_25519.Mask51;
      return R;
   end Decode;

   procedure Store_LE64 (S : in out Bytes_32; Offset : Load_Offset; V : Unsigned_64)
   is
      function Lo8 (X : Unsigned_64) return Byte is (Byte (X mod 256));
   begin
      S (Offset)     := Lo8 (V);
      S (Offset + 1) := Lo8 (Shift_Right (V, 8));
      S (Offset + 2) := Lo8 (Shift_Right (V, 16));
      S (Offset + 3) := Lo8 (Shift_Right (V, 24));
      S (Offset + 4) := Lo8 (Shift_Right (V, 32));
      S (Offset + 5) := Lo8 (Shift_Right (V, 40));
      S (Offset + 6) := Lo8 (Shift_Right (V, 48));
      S (Offset + 7) := Lo8 (Shift_Right (V, 56));
   end Store_LE64;

   procedure Encode (S : out Bytes_32; F : in FE) is
      T : FE := F;
      Q : Unsigned_64;
      H : Unsigned_64;
   begin
      Fiat_25519.Carry (T);
      Fiat_25519.Carry (T);
      Q := (T (0) + 19) / (2**51);
      Q := (T (1) + Q) / (2**51);
      Q := (T (2) + Q) / (2**51);
      Q := (T (3) + Q) / (2**51);
      Q := (T (4) + Q) / (2**51);
      T (0) := T (0) + 19 * Q;
      Fiat_25519.Carry (T);

      S := (others => 0);
      H := T (0) or Shift_Left (T (1), 51);
      Store_LE64 (S, 0, H);
      H := Shift_Right (T (1), 13) or Shift_Left (T (2), 38);
      Store_LE64 (S, 8, H);
      H := Shift_Right (T (2), 26) or Shift_Left (T (3), 25);
      Store_LE64 (S, 16, H);
      H := Shift_Right (T (3), 39) or Shift_Left (T (4), 12);
      Store_LE64 (S, 24, H);
   end Encode;

   --================================================================
   --  Montgomery ladder (RFC 7748 §5)
   --================================================================

   procedure Scalar_Mult
     (Q : out Bytes_32;
      N : in  Bytes_32;
      P : in  Bytes_32)
   is
      E : Bytes_32 := N;
      X1, X2, Z2, X3, Z3 : FE;
      A, AA, B, BB, CB, DA, T : FE;
      Swap : Unsigned_64 := 0;
      K_T  : Unsigned_64;
   begin
      E (0)  := E (0) and 248;
      E (31) := (E (31) and 127) or 64;

      X1 := Decode (P);
      X2 := Fiat_25519.FE_One;
      Z2 := Fiat_25519.FE_Zero;
      X3 := X1;
      Z3 := Fiat_25519.FE_One;

      for Pos in reverse 0 .. 254 loop
         pragma Loop_Invariant
           (Is_Carried (X1) and Is_Carried (X2) and Is_Carried (Z2) and
            Is_Carried (X3) and Is_Carried (Z3) and Swap <= 1);
         K_T := Shift_Right (Unsigned_64 (E (N32 (Pos / 8))),
                             Pos mod 8) and 1;
         K_T := K_T xor Swap;
         Fiat_25519.CSwap (X2, X3, K_T);
         Fiat_25519.CSwap (Z2, Z3, K_T);
         Swap := Shift_Right (Unsigned_64 (E (N32 (Pos / 8))),
                              Pos mod 8) and 1;

         A  := Fiat_25519.Add (X2, Z2);
         AA := Fiat_25519.Sqr (A);
         B  := Fiat_25519.Sub (X2, Z2);
         BB := Fiat_25519.Sqr (B);
         T  := Fiat_25519.Sub (AA, BB);
         CB := Fiat_25519.Mul (Fiat_25519.Sub (X3, Z3), A);
         DA := Fiat_25519.Mul (Fiat_25519.Add (X3, Z3), B);

         X3 := Fiat_25519.Sqr (Fiat_25519.Add (DA, CB));
         Z3 := Fiat_25519.Mul (Fiat_25519.Sqr (Fiat_25519.Sub (DA, CB)), X1);
         X2 := Fiat_25519.Mul (AA, BB);
         Z2 := Fiat_25519.Scmul (T, 121665);
         Z2 := Fiat_25519.Mul (Fiat_25519.Add (Z2, AA), T);
      end loop;

      Fiat_25519.CSwap (X2, X3, Swap);
      Fiat_25519.CSwap (Z2, Z3, Swap);

      --  After loop: X2 and Z2 are carried (from loop invariant + CSwap post)
      pragma Assert (Fiat_25519.Is_Carried (X2));
      pragma Assert (Fiat_25519.Is_Carried (Z2));
      declare
         ZI : constant FE := Fiat_25519.Inv (Z2);
      begin
         pragma Assert (Fiat_25519.Is_Carried (ZI));
         for I in 0 .. 4 loop
            pragma Loop_Invariant
              (for all J in 0 .. I =>
                 ZI (J) <= 16#18_0000_0000_0000# and
                 X2 (J) <= 16#18_0000_0000_0000#);
         end loop;
         T := Fiat_25519.Mul (X2, ZI);
      end;
      Encode (Q, T);
   end Scalar_Mult;

   procedure Test_FE_Mul
     (A, B   : in  Bytes_32;
      Result : out Bytes_32)
   is
      FA : constant FE := Decode (A);
      FB : constant FE := Decode (B);
   begin
      Encode (Result, Fiat_25519.Mul (FA, FB));
   end Test_FE_Mul;

   procedure Test_Encode_Decode
     (Input  : in  Bytes_32;
      Output : out Bytes_32)
   is
      F : constant FE := Decode (Input);
   begin
      Encode (Output, F);
   end Test_Encode_Decode;

   procedure Scalar_Mult_Base
     (Q : out Bytes_32;
      N : in  Bytes_32)
   is
   begin
      SPARKTLS.Ed25519.Scalar_Mult_Base_To_Montgomery (Q, N);
   end Scalar_Mult_Base;

end SPARKTLS.X25519;
