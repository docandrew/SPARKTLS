--  SPARKTLS P-256 Field Arithmetic (body)
--  Ported from BearSSL's ec_p256_m31.c

package body SPARKTLS.P256 with
   SPARK_Mode => On
is
   --  Inline helpers for 30-bit multiply (30x30 -> 60 bits fits U64)
   function MUL30 (A, B : U32) return U64 is
     (U64 (A) * U64 (B)) with Inline;

   --  Arithmetic right shift for I32 (sign-extending)
   function ARSH (X : I32; N : Natural) return I32 is
     (Shift_Right_Arithmetic (X, N)) with Inline;

   --  Arithmetic right shift for I64 (sign-extending)
   function ARSHW (X : I64; N : Natural) return I64 is
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
      Dst : in out P256_Limbs;
      Src : in     P256_Limbs)
   is
      M : constant U32 := 0 - Ctl;
   begin
      for I in Limb_Index loop
         Dst (I) := Dst (I) xor (M and (Dst (I) xor Src (I)));
      end loop;
   end CT_Copy;

   ---------------------------------------------------------------
   --  Schoolbook multiply 9x9 -> 18 limbs
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

      --  Propagate carries
      CC := 0;
      for I in Wide_Index range 0 .. 16 loop
         W := T (Integer (I)) + CC;
         D (I) := U32 (W and U64 (Limb_Mask));
         CC := Shift_Right (W, 30);
      end loop;
      D (17) := U32 (CC);
   end Mul9;

   ---------------------------------------------------------------
   --  Schoolbook square 9 -> 18 limbs
   ---------------------------------------------------------------

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

      --  Propagate carries
      CC := 0;
      for I in Wide_Index range 0 .. 16 loop
         W := T (Integer (I)) + CC;
         D (I) := U32 (W and U64 (Limb_Mask));
         CC := Shift_Right (W, 30);
      end loop;
      D (17) := U32 (CC);
   end Square9;

   ---------------------------------------------------------------
   --  NIST fast reduction (shared by Mul_F256 and Square_F256)
   --
   --  2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p)
   --
   --  For a word y at bit offset n (n >= 256):
   --    y*2^n = y*2^(n-32) - y*2^(n-64) - y*2^(n-160) + y*2^(n-256)
   ---------------------------------------------------------------

   procedure NIST_Reduce
     (D : out P256_Limbs;
      T : in  P256_Wide)
   is
      S  : P256_Wide_S;
      CC : I64;
      X  : I64 := 0;
      Z  : I32;
      C  : U32;
      W  : I32;
      Y  : I64;
   begin
      --  Copy to signed wide
      for I in Wide_Index loop
         S (I) := I64 (T (I));
      end loop;

      --  Fold high limbs 17..9 into low limbs
      for I in reverse Wide_Index range 9 .. 17 loop
         Y := S (I);
         S (I - 1) := S (I - 1) + ARSHW (Y, 2);
         S (I - 2) := S (I - 2) + I64 (Shift_Left (U64 (Y), 28)
                       and U64 (Limb_Mask));
         S (I - 2) := S (I - 2) - ARSHW (Y, 4);
         S (I - 3) := S (I - 3) - I64 (Shift_Left (U64 (Y), 26)
                       and U64 (Limb_Mask));
         S (I - 5) := S (I - 5) - ARSHW (Y, 10);
         S (I - 6) := S (I - 6) - I64 (Shift_Left (U64 (Y), 20)
                       and U64 (Limb_Mask));
         S (I - 8) := S (I - 8) + ARSHW (Y, 16);
         S (I - 9) := S (I - 9) + I64 (Shift_Left (U64 (Y), 14)
                       and U64 (Limb_Mask));
      end loop;

      --  Signed carry propagation
      CC := 0;
      for I in Limb_Index loop
         X := S (I) + CC;
         D (I) := U32 (U64 (X) and U64 (Limb_Mask));
         CC := ARSHW (X, 30);
      end loop;

      --  Extract carry beyond 2^256
      CC := ARSHW (X, 16);
      D (8) := D (8) and 16#FFFF#;

      --  One extra round of reduction for cc * 2^256
      --  BearSSL uses uint32_t z = (uint32_t)cc then does
      --  signed arithmetic via ARSH on z treated as signed.
      --  We work in U32 for the bit ops and I32 for the arithmetic.
      Z := I32 (CC);
      declare
         ZU : constant U32 := U32 (Z);
      begin
         D (3) := D (3) - Shift_Left (ZU, 6);
         D (6) := D (6) - (Shift_Left (ZU, 12) and Limb_Mask);
         D (7) := D (7) - U32 (ARSH (Z, 18));
         D (7) := D (7) + (Shift_Left (ZU, 14) and Limb_Mask);
         D (8) := D (8) + U32 (ARSH (Z, 16));

         --  If cc was negative, add p once
         C := Shift_Right (ZU, 31);
         D (0) := D (0) - C;
         D (3) := D (3) + Shift_Left (C, 6);
         D (6) := D (6) + Shift_Left (C, 12);
         D (7) := D (7) - Shift_Left (C, 14);
         D (8) := D (8) + Shift_Left (C, 16);
      end;

      --  Final carry propagation (signed, using z as carry)
      for I in Limb_Index loop
         W := I32 (D (I)) + Z;
         D (I) := U32 (W) and Limb_Mask;
         Z := ARSH (W, 30);
      end loop;
   end NIST_Reduce;

   ---------------------------------------------------------------
   --  Field addition
   ---------------------------------------------------------------

   procedure Add_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs)
   is
      W  : U32;
      CC : U32;
      Overflow : U32;
   begin
      CC := 0;
      W := 0;
      for I in Limb_Index loop
         W := A (I) + B (I) + CC;
         D (I) := W and Limb_Mask;
         CC := Shift_Right (W, 30);
      end loop;

      --  Reduce: if result >= 2^256, fold the overflow
      --  W still holds the last limb value after the loop
      Overflow := Shift_Right (D (8), 16);
      D (8) := D (8) and 16#FFFF#;
      D (3) := D (3) - Shift_Left (Overflow, 6);
      D (6) := D (6) - Shift_Left (Overflow, 12);
      D (7) := D (7) + Shift_Left (Overflow, 14);
      CC := Overflow;
      for I in Limb_Index loop
         declare
            WI : constant I32 := I32 (D (I)) + I32 (CC);
         begin
            D (I) := U32 (WI) and Limb_Mask;
            CC := U32 (ARSH (WI, 30));
         end;
      end loop;
   end Add_F256;

   ---------------------------------------------------------------
   --  Field subtraction (computes a - b + 2p)
   ---------------------------------------------------------------

   procedure Sub_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs)
   is
      W  : I32;
      CC : I32;
      Overflow : I32;
   begin
      --  The 2p constants added per-limb ensure result stays positive
      --  2p in 30-bit limbs: each limb of p doubled, with carry absorbed
      W := I32 (A (0)) - I32 (B (0)) - 2;
      D (0) := U32 (W) and Limb_Mask;
      W := I32 (A (1)) - I32 (B (1)) + ARSH (W, 30);
      D (1) := U32 (W) and Limb_Mask;
      W := I32 (A (2)) - I32 (B (2)) + ARSH (W, 30);
      D (2) := U32 (W) and Limb_Mask;
      W := I32 (A (3)) - I32 (B (3)) + ARSH (W, 30) + 16#80#;
      D (3) := U32 (W) and Limb_Mask;
      W := I32 (A (4)) - I32 (B (4)) + ARSH (W, 30);
      D (4) := U32 (W) and Limb_Mask;
      W := I32 (A (5)) - I32 (B (5)) + ARSH (W, 30);
      D (5) := U32 (W) and Limb_Mask;
      W := I32 (A (6)) - I32 (B (6)) + ARSH (W, 30) + 16#2000#;
      D (6) := U32 (W) and Limb_Mask;
      W := I32 (A (7)) - I32 (B (7)) + ARSH (W, 30) - 16#8000#;
      D (7) := U32 (W) and Limb_Mask;
      W := I32 (A (8)) - I32 (B (8)) + ARSH (W, 30) + 16#2_0000#;
      D (8) := U32 (W) and 16#FFFF#;

      --  Fold overflow
      Overflow := ARSH (W, 16);
      D (8) := D (8) and 16#FFFF#;
      D (3) := D (3) - U32 (Overflow * 64);      --  overflow << 6
      D (6) := D (6) - U32 (Overflow * 4096);     --  overflow << 12
      D (7) := D (7) + U32 (Overflow * 16384);    --  overflow << 14
      CC := Overflow;
      for I in Limb_Index loop
         W := I32 (D (I)) + CC;
         D (I) := U32 (W) and Limb_Mask;
         CC := ARSH (W, 30);
      end loop;
   end Sub_F256;

   ---------------------------------------------------------------
   --  Field multiplication
   ---------------------------------------------------------------

   procedure Mul_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs;
      B : in     P256_Limbs)
   is
      T : P256_Wide;
   begin
      Mul9 (T, A, B);
      NIST_Reduce (D, T);
   end Mul_F256;

   ---------------------------------------------------------------
   --  Field squaring
   ---------------------------------------------------------------

   procedure Square_F256
     (D :    out P256_Limbs;
      A : in     P256_Limbs)
   is
      T : P256_Wide;
   begin
      Square9 (T, A);
      NIST_Reduce (D, T);
   end Square_F256;

   ---------------------------------------------------------------
   --  Final reduction
   ---------------------------------------------------------------

   procedure Reduce_Final_F256
     (D          : in out P256_Limbs;
      Did_Reduce :    out U32)
   is
      T  : P256_Limbs;
      CC : U32;
      W  : U32;
   begin
      CC := 0;
      for I in Limb_Index loop
         W := D (I) - F256 (I) - CC;
         CC := Shift_Right (W, 31);
         T (I) := W and Limb_Mask;
      end loop;
      CC := CC xor 1;
      CT_Copy (CC, D, T);
      Did_Reduce := CC;
   end Reduce_Final_F256;

   ---------------------------------------------------------------
   --  Byte conversion: big-endian 32 bytes -> 9 x 30-bit limbs
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

   ---------------------------------------------------------------
   --  Byte conversion: 9 x 30-bit limbs -> big-endian 32 bytes
   ---------------------------------------------------------------

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
