--  SPARKTLS P-256 Field Arithmetic (body)
--
--  Hot-path field ops (mul, sqr, add, sub) use Fiat Crypto's
--  4×64-bit Montgomery arithmetic for ~4x speedup.
--  Legacy 9×30-bit code retained for ECDSA scalar Barrett reduction.

with SPARKTLS.Fiat_P256;

package body SPARKTLS.P256 with
   SPARK_Mode => On
is
   --  Inline helpers for 30-bit multiply (used by legacy Mul9/Square9)
   function MUL30 (A, B : U32) return U64 is
     (U64 (A) * U64 (B)) with Inline;

   function ARSH (X : I32; N : Natural) return I32 is
     (Shift_Right_Arithmetic (X, N)) with Inline;

   ---------------------------------------------------------------
   --  Constant-time helpers
   ---------------------------------------------------------------

   function CT_NEQ (A, B : U32) return U32 is
      Q : constant U32 := A xor B;
   begin
      return Shift_Right ((Q or (0 - Q)), 31);
   end CT_NEQ;

   function CT_EQ (A, B : U32) return U32 is
   begin
      return 1 - CT_NEQ (A, B);
   end CT_EQ;

   procedure CT_Copy
     (Ctl : in     U32;
      Dst : in out P256_FE;
      Src : in     P256_FE)
   is
      M : constant Unsigned_64 := -(Unsigned_64 (Ctl) and 1);
   begin
      for I in 0 .. 3 loop
         Dst (I) := Dst (I) xor (M and (Dst (I) xor Src (I)));
      end loop;
   end CT_Copy;

   ---------------------------------------------------------------
   --  Field arithmetic (delegated to Fiat Crypto)
   ---------------------------------------------------------------

   procedure Add_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE)
   is
   begin
      D := SPARKTLS.Fiat_P256.Add (A, B);
   end Add_F256;

   procedure Sub_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE)
   is
   begin
      D := SPARKTLS.Fiat_P256.Sub (A, B);
   end Sub_F256;

   procedure Mul_F256
     (D :    out P256_FE;
      A : in     P256_FE;
      B : in     P256_FE)
   is
   begin
      D := SPARKTLS.Fiat_P256.Mul (A, B);
   end Mul_F256;

   procedure Square_F256
     (D :    out P256_FE;
      A : in     P256_FE)
   is
   begin
      D := SPARKTLS.Fiat_P256.Sqr (A);
   end Square_F256;

   function FE_Is_Zero (A : P256_FE) return Boolean is
      T : Unsigned_64;
   begin
      SPARKTLS.Fiat_P256.Nonzero (T, A);
      return T = 0;
   end FE_Is_Zero;

   ---------------------------------------------------------------
   --  Byte conversion: big-endian bytes <-> Montgomery FE
   --  Fiat uses little-endian bytes internally; we reverse.
   ---------------------------------------------------------------

   procedure Bytes_To_FE
     (Dst : out P256_FE;
      Src : in  Byte_Seq)
   is
      LE : Byte_Seq (0 .. 31);
      Non_Monty : P256_FE;
   begin
      --  Reverse big-endian → little-endian
      for I in I32 range 0 .. 31 loop
         LE (I) := Src (Src'First + 31 - I);
      end loop;
      Non_Monty := SPARKTLS.Fiat_P256.From_Bytes (LE);
      Dst := SPARKTLS.Fiat_P256.To_Montgomery (Non_Monty);
   end Bytes_To_FE;

   procedure FE_To_Bytes
     (Dst : out Byte_Seq;
      Src : in  P256_FE)
   is
      Non_Monty : P256_FE;
      LE : Byte_Seq (0 .. 31);
   begin
      Non_Monty := SPARKTLS.Fiat_P256.From_Montgomery (Src);
      SPARKTLS.Fiat_P256.To_Bytes (LE, Non_Monty);
      --  Reverse little-endian → big-endian
      for I in I32 range 0 .. 31 loop
         Dst (Dst'First + I) := LE (31 - I);
      end loop;
   end FE_To_Bytes;

   ---------------------------------------------------------------
   --  Legacy 9×30-bit code (for ECDSA scalar Barrett reduction)
   ---------------------------------------------------------------

   procedure Mul9
     (D :    out P256_Wide;
      A : in     P256_Limbs;
      B : in     P256_Limbs)
   is
      T  : array (0 .. 16) of U64;
      CC : U64;
      W  : U64;
   begin
      T (0)  := MUL30 (A (0), B (0));
      T (1)  := MUL30 (A (0), B (1))
               + MUL30 (A (1), B (0));
      T (2)  := MUL30 (A (0), B (2))
               + MUL30 (A (1), B (1))
               + MUL30 (A (2), B (0));
      T (3)  := MUL30 (A (0), B (3))
               + MUL30 (A (1), B (2))
               + MUL30 (A (2), B (1))
               + MUL30 (A (3), B (0));
      T (4)  := MUL30 (A (0), B (4))
               + MUL30 (A (1), B (3))
               + MUL30 (A (2), B (2))
               + MUL30 (A (3), B (1))
               + MUL30 (A (4), B (0));
      T (5)  := MUL30 (A (0), B (5))
               + MUL30 (A (1), B (4))
               + MUL30 (A (2), B (3))
               + MUL30 (A (3), B (2))
               + MUL30 (A (4), B (1))
               + MUL30 (A (5), B (0));
      T (6)  := MUL30 (A (0), B (6))
               + MUL30 (A (1), B (5))
               + MUL30 (A (2), B (4))
               + MUL30 (A (3), B (3))
               + MUL30 (A (4), B (2))
               + MUL30 (A (5), B (1))
               + MUL30 (A (6), B (0));
      T (7)  := MUL30 (A (0), B (7))
               + MUL30 (A (1), B (6))
               + MUL30 (A (2), B (5))
               + MUL30 (A (3), B (4))
               + MUL30 (A (4), B (3))
               + MUL30 (A (5), B (2))
               + MUL30 (A (6), B (1))
               + MUL30 (A (7), B (0));
      T (8)  := MUL30 (A (0), B (8))
               + MUL30 (A (1), B (7))
               + MUL30 (A (2), B (6))
               + MUL30 (A (3), B (5))
               + MUL30 (A (4), B (4))
               + MUL30 (A (5), B (3))
               + MUL30 (A (6), B (2))
               + MUL30 (A (7), B (1))
               + MUL30 (A (8), B (0));
      T (9)  := MUL30 (A (1), B (8))
               + MUL30 (A (2), B (7))
               + MUL30 (A (3), B (6))
               + MUL30 (A (4), B (5))
               + MUL30 (A (5), B (4))
               + MUL30 (A (6), B (3))
               + MUL30 (A (7), B (2))
               + MUL30 (A (8), B (1));
      T (10) := MUL30 (A (2), B (8))
               + MUL30 (A (3), B (7))
               + MUL30 (A (4), B (6))
               + MUL30 (A (5), B (5))
               + MUL30 (A (6), B (4))
               + MUL30 (A (7), B (3))
               + MUL30 (A (8), B (2));
      T (11) := MUL30 (A (3), B (8))
               + MUL30 (A (4), B (7))
               + MUL30 (A (5), B (6))
               + MUL30 (A (6), B (5))
               + MUL30 (A (7), B (4))
               + MUL30 (A (8), B (3));
      T (12) := MUL30 (A (4), B (8))
               + MUL30 (A (5), B (7))
               + MUL30 (A (6), B (6))
               + MUL30 (A (7), B (5))
               + MUL30 (A (8), B (4));
      T (13) := MUL30 (A (5), B (8))
               + MUL30 (A (6), B (7))
               + MUL30 (A (7), B (6))
               + MUL30 (A (8), B (5));
      T (14) := MUL30 (A (6), B (8))
               + MUL30 (A (7), B (7))
               + MUL30 (A (8), B (6));
      T (15) := MUL30 (A (7), B (8))
               + MUL30 (A (8), B (7));
      T (16) := MUL30 (A (8), B (8));

      CC := 0;
      for I in Wide_Index range 0 .. 16 loop
         W := T (Integer (I)) + CC;
         D (I) := U32 (W and U64 (Limb_Mask));
         CC := Shift_Right (W, 30);
      end loop;
      D (17) := U32 (CC);
   end Mul9;

   procedure Square9
     (D :    out P256_Wide;
      A : in     P256_Limbs)
   is
      T  : array (0 .. 16) of U64;
      CC : U64;
      W  : U64;
   begin
      T (0)  := MUL30 (A (0), A (0));
      T (1)  := Shift_Left (MUL30 (A (0), A (1)), 1);
      T (2)  := MUL30 (A (1), A (1))
               + Shift_Left (MUL30 (A (0), A (2)), 1);
      T (3)  := Shift_Left (MUL30 (A (0), A (3))
               + MUL30 (A (1), A (2)), 1);
      T (4)  := MUL30 (A (2), A (2))
               + Shift_Left (MUL30 (A (0), A (4))
               + MUL30 (A (1), A (3)), 1);
      T (5)  := Shift_Left (MUL30 (A (0), A (5))
               + MUL30 (A (1), A (4))
               + MUL30 (A (2), A (3)), 1);
      T (6)  := MUL30 (A (3), A (3))
               + Shift_Left (MUL30 (A (0), A (6))
               + MUL30 (A (1), A (5))
               + MUL30 (A (2), A (4)), 1);
      T (7)  := Shift_Left (MUL30 (A (0), A (7))
               + MUL30 (A (1), A (6))
               + MUL30 (A (2), A (5))
               + MUL30 (A (3), A (4)), 1);
      T (8)  := MUL30 (A (4), A (4))
               + Shift_Left (MUL30 (A (0), A (8))
               + MUL30 (A (1), A (7))
               + MUL30 (A (2), A (6))
               + MUL30 (A (3), A (5)), 1);
      T (9)  := Shift_Left (MUL30 (A (1), A (8))
               + MUL30 (A (2), A (7))
               + MUL30 (A (3), A (6))
               + MUL30 (A (4), A (5)), 1);
      T (10) := MUL30 (A (5), A (5))
               + Shift_Left (MUL30 (A (2), A (8))
               + MUL30 (A (3), A (7))
               + MUL30 (A (4), A (6)), 1);
      T (11) := Shift_Left (MUL30 (A (3), A (8))
               + MUL30 (A (4), A (7))
               + MUL30 (A (5), A (6)), 1);
      T (12) := MUL30 (A (6), A (6))
               + Shift_Left (MUL30 (A (4), A (8))
               + MUL30 (A (5), A (7)), 1);
      T (13) := Shift_Left (MUL30 (A (5), A (8))
               + MUL30 (A (6), A (7)), 1);
      T (14) := MUL30 (A (7), A (7))
               + Shift_Left (MUL30 (A (6), A (8)), 1);
      T (15) := Shift_Left (MUL30 (A (7), A (8)), 1);
      T (16) := MUL30 (A (8), A (8));

      CC := 0;
      for I in Wide_Index range 0 .. 16 loop
         W := T (Integer (I)) + CC;
         D (I) := U32 (W and U64 (Limb_Mask));
         CC := Shift_Right (W, 30);
      end loop;
      D (17) := U32 (CC);
   end Square9;

   ---------------------------------------------------------------
   --  Legacy byte conversion (for ECDSA scalar arithmetic)
   ---------------------------------------------------------------

   procedure BE8_To_LE30
     (Dst : out P256_Limbs;
      Src : in  Byte_Seq)
   is
      Acc     : U32 := 0;
      Acc_Len : Natural := 0;
      DI      : I32 := 0;
      B       : U32;
   begin
      Dst := (others => 0);
      for J in reverse Src'Range loop
         B := U32 (Src (J));
         if Acc_Len < 22 then
            Acc := Acc or Shift_Left (B, Acc_Len);
            Acc_Len := Acc_Len + 8;
         else
            if DI <= 7 then
               Dst (DI) := (Acc or Shift_Left (B, Acc_Len))
                            and Limb_Mask;
               DI := DI + 1;
            end if;
            Acc := Shift_Right (B, 30 - Acc_Len);
            Acc_Len := Acc_Len - 22;
         end if;
      end loop;
      if DI <= 8 then
         Dst (DI) := Acc;
      end if;
   end BE8_To_LE30;

   procedure LE30_To_BE8
     (Dst : out Byte_Seq;
      Src : in  P256_Limbs)
   is
      Acc     : U32 := 0;
      Acc_Len : Natural := 0;
      SI      : I32 := 0;
      W       : U32;
   begin
      Dst := (others => 0);
      for J in reverse Dst'Range loop
         if Acc_Len < 8 then
            if SI <= 8 then
               W := Src (SI);
               SI := SI + 1;
            else
               W := 0;
            end if;
            Dst (J) := Byte ((Acc or Shift_Left (W, Acc_Len))
                       and 16#FF#);
            Acc := Shift_Right (W, 8 - Acc_Len);
            Acc_Len := Acc_Len + 22;
         else
            Dst (J) := Byte (Acc and 16#FF#);
            Acc := Shift_Right (Acc, 8);
            Acc_Len := Acc_Len - 8;
         end if;
      end loop;
   end LE30_To_BE8;

end SPARKTLS.P256;
