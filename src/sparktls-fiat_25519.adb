--  SPARKTLS Fiat Curve25519 — GF(2^255-19) field arithmetic (body)
--
--  Every function is a line-by-line translation of fiat-crypto's
--  curve25519_64.c. The SSA form is preserved for performance.

package body SPARKTLS.Fiat_25519 with
   SPARK_Mode => On
is
   procedure Lemma_Reduced_Is_Mul_Safe (F : FE) is
   begin
      for I in 0 .. 4 loop
         pragma Assert (F (I) <= Mask51);
         pragma Loop_Invariant
           (for all J in 0 .. I => F (J) <= 16#20_0000_0000_0000#);
      end loop;
   end Lemma_Reduced_Is_Mul_Safe;

   --================================================================
   --  carry_mul (lines 133-243 of curve25519_64.c)
   --================================================================

   function Mul (A, B : FE) return FE is
      R : FE;
      x1, x2, x3, x4, x5     : Unsigned_128;
      x6, x7, x8, x9, x10    : Unsigned_128;
      x11, x12, x13, x14, x15 : Unsigned_128;
      x16, x17, x18, x19, x20 : Unsigned_128;
      x21, x22, x23, x24, x25 : Unsigned_128;
      x26                      : Unsigned_128;
      x27, x28                 : Unsigned_64;
      x29, x30, x31, x32, x33 : Unsigned_128;
      x34, x35                 : Unsigned_64;
      x36                      : Unsigned_128;
      x37, x38                 : Unsigned_64;
      x39                      : Unsigned_128;
      x40, x41                 : Unsigned_64;
      x42                      : Unsigned_128;
      x43, x44, x45, x46       : Unsigned_64;
      x47, x48, x49, x50       : Unsigned_64;
      x51, x52                 : Unsigned_64;
   begin
      x1  := Unsigned_128 (A (4)) * Unsigned_128 (B (4) * 19);
      x2  := Unsigned_128 (A (4)) * Unsigned_128 (B (3) * 19);
      x3  := Unsigned_128 (A (4)) * Unsigned_128 (B (2) * 19);
      x4  := Unsigned_128 (A (4)) * Unsigned_128 (B (1) * 19);
      x5  := Unsigned_128 (A (3)) * Unsigned_128 (B (4) * 19);
      x6  := Unsigned_128 (A (3)) * Unsigned_128 (B (3) * 19);
      x7  := Unsigned_128 (A (3)) * Unsigned_128 (B (2) * 19);
      x8  := Unsigned_128 (A (2)) * Unsigned_128 (B (4) * 19);
      x9  := Unsigned_128 (A (2)) * Unsigned_128 (B (3) * 19);
      x10 := Unsigned_128 (A (1)) * Unsigned_128 (B (4) * 19);
      x11 := Unsigned_128 (A (4)) * Unsigned_128 (B (0));
      x12 := Unsigned_128 (A (3)) * Unsigned_128 (B (1));
      x13 := Unsigned_128 (A (3)) * Unsigned_128 (B (0));
      x14 := Unsigned_128 (A (2)) * Unsigned_128 (B (2));
      x15 := Unsigned_128 (A (2)) * Unsigned_128 (B (1));
      x16 := Unsigned_128 (A (2)) * Unsigned_128 (B (0));
      x17 := Unsigned_128 (A (1)) * Unsigned_128 (B (3));
      x18 := Unsigned_128 (A (1)) * Unsigned_128 (B (2));
      x19 := Unsigned_128 (A (1)) * Unsigned_128 (B (1));
      x20 := Unsigned_128 (A (1)) * Unsigned_128 (B (0));
      x21 := Unsigned_128 (A (0)) * Unsigned_128 (B (4));
      x22 := Unsigned_128 (A (0)) * Unsigned_128 (B (3));
      x23 := Unsigned_128 (A (0)) * Unsigned_128 (B (2));
      x24 := Unsigned_128 (A (0)) * Unsigned_128 (B (1));
      x25 := Unsigned_128 (A (0)) * Unsigned_128 (B (0));
      x26 := x25 + (x10 + (x9 + (x7 + x4)));
      x27 := Unsigned_64 (Shift_Right (x26, 51));
      x28 := Unsigned_64 (x26 and 16#7_FFFF_FFFF_FFFF#);
      x29 := x21 + (x17 + (x14 + (x12 + x11)));
      x30 := x22 + (x18 + (x15 + (x13 + x1)));
      x31 := x23 + (x19 + (x16 + (x5 + x2)));
      x32 := x24 + (x20 + (x8 + (x6 + x3)));
      x33 := Unsigned_128 (x27) + x32;
      x34 := Unsigned_64 (Shift_Right (x33, 51));
      x35 := Unsigned_64 (x33 and 16#7_FFFF_FFFF_FFFF#);
      x36 := Unsigned_128 (x34) + x31;
      x37 := Unsigned_64 (Shift_Right (x36, 51));
      x38 := Unsigned_64 (x36 and 16#7_FFFF_FFFF_FFFF#);
      x39 := Unsigned_128 (x37) + x30;
      x40 := Unsigned_64 (Shift_Right (x39, 51));
      x41 := Unsigned_64 (x39 and 16#7_FFFF_FFFF_FFFF#);
      x42 := Unsigned_128 (x40) + x29;
      x43 := Unsigned_64 (Shift_Right (x42, 51));
      x44 := Unsigned_64 (x42 and 16#7_FFFF_FFFF_FFFF#);
      x45 := x43 * 19;
      x46 := x28 + x45;
      x47 := Shift_Right (x46, 51);
      x48 := x46 and Mask51;
      x49 := x47 + x35;
      x50 := Shift_Right (x49, 51);
      x51 := x49 and Mask51;
      x52 := x50 + x38;
      R := (x48, x51, x52, x41, x44);
      return R;
   end Mul;

   --================================================================
   --  carry_square (lines 252-358 of curve25519_64.c)
   --================================================================

   function Sqr (A : FE) return FE is
      R : FE;
      x1, x2, x3, x4, x5, x6, x7, x8 : Unsigned_64;
      x9, x10, x11, x12, x13, x14, x15 : Unsigned_128;
      x16, x17, x18, x19, x20           : Unsigned_128;
      x21, x22, x23, x24                : Unsigned_128;
      x25, x26                           : Unsigned_64;
      x27, x28, x29, x30, x31           : Unsigned_128;
      x32, x33                           : Unsigned_64;
      x34                                : Unsigned_128;
      x35, x36                           : Unsigned_64;
      x37                                : Unsigned_128;
      x38, x39                           : Unsigned_64;
      x40                                : Unsigned_128;
      x41, x42, x43, x44, x45           : Unsigned_64;
      x46, x47, x48, x49, x50           : Unsigned_64;
   begin
      x1  := A (4) * 19;
      x2  := x1 * 2;
      x3  := A (4) * 2;
      x4  := A (3) * 19;
      x5  := x4 * 2;
      x6  := A (3) * 2;
      x7  := A (2) * 2;
      x8  := A (1) * 2;
      x9  := Unsigned_128 (A (4)) * Unsigned_128 (x1);
      x10 := Unsigned_128 (A (3)) * Unsigned_128 (x2);
      x11 := Unsigned_128 (A (3)) * Unsigned_128 (x4);
      x12 := Unsigned_128 (A (2)) * Unsigned_128 (x2);
      x13 := Unsigned_128 (A (2)) * Unsigned_128 (x5);
      x14 := Unsigned_128 (A (2)) * Unsigned_128 (A (2));
      x15 := Unsigned_128 (A (1)) * Unsigned_128 (x2);
      x16 := Unsigned_128 (A (1)) * Unsigned_128 (x6);
      x17 := Unsigned_128 (A (1)) * Unsigned_128 (x7);
      x18 := Unsigned_128 (A (1)) * Unsigned_128 (A (1));
      x19 := Unsigned_128 (A (0)) * Unsigned_128 (x3);
      x20 := Unsigned_128 (A (0)) * Unsigned_128 (x6);
      x21 := Unsigned_128 (A (0)) * Unsigned_128 (x7);
      x22 := Unsigned_128 (A (0)) * Unsigned_128 (x8);
      x23 := Unsigned_128 (A (0)) * Unsigned_128 (A (0));
      x24 := x23 + (x15 + x13);
      x25 := Unsigned_64 (Shift_Right (x24, 51));
      x26 := Unsigned_64 (x24 and 16#7_FFFF_FFFF_FFFF#);
      x27 := x19 + (x16 + x14);
      x28 := x20 + (x17 + x9);
      x29 := x21 + (x18 + x10);
      x30 := x22 + (x12 + x11);
      x31 := Unsigned_128 (x25) + x30;
      x32 := Unsigned_64 (Shift_Right (x31, 51));
      x33 := Unsigned_64 (x31 and 16#7_FFFF_FFFF_FFFF#);
      x34 := Unsigned_128 (x32) + x29;
      x35 := Unsigned_64 (Shift_Right (x34, 51));
      x36 := Unsigned_64 (x34 and 16#7_FFFF_FFFF_FFFF#);
      x37 := Unsigned_128 (x35) + x28;
      x38 := Unsigned_64 (Shift_Right (x37, 51));
      x39 := Unsigned_64 (x37 and 16#7_FFFF_FFFF_FFFF#);
      x40 := Unsigned_128 (x38) + x27;
      x41 := Unsigned_64 (Shift_Right (x40, 51));
      x42 := Unsigned_64 (x40 and 16#7_FFFF_FFFF_FFFF#);
      x43 := x41 * 19;
      x44 := x26 + x43;
      x45 := Shift_Right (x44, 51);
      x46 := x44 and Mask51;
      x47 := x45 + x33;
      x48 := Shift_Right (x47, 51);
      x49 := x47 and Mask51;
      x50 := x48 + x36;
      R := (x46, x49, x50, x39, x42);
      return R;
   end Sqr;

   --  Add and Sub are expression functions defined in the spec

   --================================================================
   --  carry (lines 367-397 of curve25519_64.c)
   --================================================================

   procedure Carry_Once (F : in out FE) is
      x1  : constant Unsigned_64 := F (0);
      x2  : constant Unsigned_64 := Shift_Right (x1, 51) + F (1);
      x3  : constant Unsigned_64 := Shift_Right (x2, 51) + F (2);
      x4  : constant Unsigned_64 := Shift_Right (x3, 51) + F (3);
      x5  : constant Unsigned_64 := Shift_Right (x4, 51) + F (4);
      x6  : constant Unsigned_64 := (x1 and Mask51) + (Shift_Right (x5, 51) * 19);
      x7  : constant Unsigned_64 := Shift_Right (x6, 51) + (x2 and Mask51);
      x8  : constant Unsigned_64 := x6 and Mask51;
      x9  : constant Unsigned_64 := x7 and Mask51;
      x10 : constant Unsigned_64 := Shift_Right (x7, 51) + (x3 and Mask51);
      x11 : constant Unsigned_64 := x4 and Mask51;
      x12 : constant Unsigned_64 := x5 and Mask51;
   begin
      F (0) := x8;
      F (1) := x9;
      F (2) := x10;
      F (3) := x11;
      F (4) := x12;
   end Carry_Once;

   procedure Carry (F : in out FE) is
   begin
      Carry_Once (F);
      Carry_Once (F);
   end Carry;

   --================================================================
   --  carry_scmul (lines 912-971, parameterized)
   --================================================================

   function Scmul (A : FE; S : Unsigned_64) return FE is
      x1  : constant Unsigned_128 := Unsigned_128 (S) * Unsigned_128 (A (4));
      x2  : constant Unsigned_128 := Unsigned_128 (S) * Unsigned_128 (A (3));
      x3  : constant Unsigned_128 := Unsigned_128 (S) * Unsigned_128 (A (2));
      x4  : constant Unsigned_128 := Unsigned_128 (S) * Unsigned_128 (A (1));
      x5  : constant Unsigned_128 := Unsigned_128 (S) * Unsigned_128 (A (0));
      x6  : constant Unsigned_64  := Unsigned_64 (Shift_Right (x5, 51));
      x7  : constant Unsigned_64  := Unsigned_64 (x5 and 16#7_FFFF_FFFF_FFFF#);
      x8  : constant Unsigned_128 := Unsigned_128 (x6) + x4;
      x9  : constant Unsigned_64  := Unsigned_64 (Shift_Right (x8, 51));
      x10 : constant Unsigned_64  := Unsigned_64 (x8 and 16#7_FFFF_FFFF_FFFF#);
      x11 : constant Unsigned_128 := Unsigned_128 (x9) + x3;
      x12 : constant Unsigned_64  := Unsigned_64 (Shift_Right (x11, 51));
      x13 : constant Unsigned_64  := Unsigned_64 (x11 and 16#7_FFFF_FFFF_FFFF#);
      x14 : constant Unsigned_128 := Unsigned_128 (x12) + x2;
      x15 : constant Unsigned_64  := Unsigned_64 (Shift_Right (x14, 51));
      x16 : constant Unsigned_64  := Unsigned_64 (x14 and 16#7_FFFF_FFFF_FFFF#);
      x17 : constant Unsigned_128 := Unsigned_128 (x15) + x1;
      x18 : constant Unsigned_64  := Unsigned_64 (Shift_Right (x17, 51));
      x19 : constant Unsigned_64  := Unsigned_64 (x17 and 16#7_FFFF_FFFF_FFFF#);
      x20 : constant Unsigned_64  := x18 * 19;
      x21 : constant Unsigned_64  := x7 + x20;
      x22 : constant Unsigned_64  := Shift_Right (x21, 51);
      x23 : constant Unsigned_64  := x21 and Mask51;
      x24 : constant Unsigned_64  := x22 + x10;
      x25 : constant Unsigned_64  := Shift_Right (x24, 51);
      x26 : constant Unsigned_64  := x24 and Mask51;
      x27 : constant Unsigned_64  := x25 + x13;
   begin
      return FE'(x23, x26, x27, x16, x19);
   end Scmul;

   --================================================================
   --  Constant-time conditional swap
   --================================================================

   procedure CSwap (A, B : in out FE; Swap : Unsigned_64) is
      Mask : constant Unsigned_64 := -Swap;
      T : Unsigned_64;
   begin
      for I in 0 .. 4 loop
         T := Mask and (A (I) xor B (I));
         A (I) := A (I) xor T;
         B (I) := B (I) xor T;
      end loop;
   end CSwap;

   --================================================================
   --  Field inversion: z^(p-2) mod p via donna addition chain
   --================================================================

   function Inv (Z : FE) return FE is
      T0, T1, T2, T3 : FE;
   begin
      T0 := Sqr (Z);                                         -- z^2
      T1 := Sqr (T0);                                        -- z^4
      T1 := Sqr (T1);                                        -- z^8
      T1 := Mul (Z, T1);                                     -- z^9
      T0 := Mul (T0, T1);                                    -- z^11
      T2 := Sqr (T0);                                        -- z^22
      T1 := Mul (T1, T2);                                    -- z^31
      T2 := Sqr (T1);
      for I in 1 .. 4 loop
         pragma Loop_Invariant (Is_Mul_Safe (T2));
         T2 := Sqr (T2);
      end loop;
      T1 := Mul (T2, T1);                                    -- z^(2^10-1)
      T2 := Sqr (T1);
      for I in 1 .. 9 loop
         pragma Loop_Invariant (Is_Mul_Safe (T2));
         T2 := Sqr (T2);
      end loop;
      T2 := Mul (T2, T1);                                    -- z^(2^20-1)
      T3 := Sqr (T2);
      for I in 1 .. 19 loop
         pragma Loop_Invariant (Is_Mul_Safe (T3));
         T3 := Sqr (T3);
      end loop;
      T2 := Mul (T3, T2);                                    -- z^(2^40-1)
      for I in 1 .. 10 loop
         pragma Loop_Invariant (Is_Mul_Safe (T2));
         T2 := Sqr (T2);
      end loop;
      T1 := Mul (T2, T1);                                    -- z^(2^50-1)
      T2 := Sqr (T1);
      for I in 1 .. 49 loop
         pragma Loop_Invariant (Is_Mul_Safe (T2));
         T2 := Sqr (T2);
      end loop;
      T2 := Mul (T2, T1);                                    -- z^(2^100-1)
      T3 := Sqr (T2);
      for I in 1 .. 99 loop
         pragma Loop_Invariant (Is_Mul_Safe (T3));
         T3 := Sqr (T3);
      end loop;
      T2 := Mul (T3, T2);                                    -- z^(2^200-1)
      for I in 1 .. 50 loop
         pragma Loop_Invariant (Is_Mul_Safe (T2));
         T2 := Sqr (T2);
      end loop;
      T1 := Mul (T2, T1);                                    -- z^(2^250-1)
      for I in 1 .. 5 loop
         pragma Loop_Invariant (Is_Mul_Safe (T1));
         T1 := Sqr (T1);
      end loop;
      return Mul (T1, T0);                                    -- z^(2^255-21)
   end Inv;

end SPARKTLS.Fiat_25519;
