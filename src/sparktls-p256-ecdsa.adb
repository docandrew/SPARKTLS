--  SPARKTLS ECDSA P-256 Signature Verification (body)
--
--  Scalar mod-n arithmetic uses 4×64-bit limbs with Barrett reduction.
--  Wide multiplication via Unsigned_128.

with SPARKTLS.P256.Point; use SPARKTLS.P256.Point;

package body SPARKTLS.P256.ECDSA with
   SPARK_Mode => On
is
   --  ================================================================
   --  64-bit scalar types for mod-n arithmetic
   --  ================================================================

   type Scalar_64 is array (0 .. 3) of Unsigned_64;
   type Scalar_Wide is array (0 .. 7) of Unsigned_64;

   --  P-256 curve order n (little-endian 64-bit limbs)
   N64 : constant Scalar_64 :=
     (0 => 16#F3B9CAC2FC632551#,
      1 => 16#BCE6FAADA7179E84#,
      2 => 16#FFFFFFFFFFFFFFFF#,
      3 => 16#FFFFFFFF00000000#);

   --  Barrett constant mu = floor(2^512 / n)
   --  257 bits, stored as 5 limbs (top limb = 1)
   type Mu_Array is array (0 .. 4) of Unsigned_64;
   Mu64 : constant Mu_Array :=
     (0 => 16#012FFD85EEDF9BFE#,
      1 => 16#43190552DF1A6C21#,
      2 => 16#FFFFFFFEFFFFFFFF#,
      3 => 16#00000000FFFFFFFF#,
      4 => 16#0000000000000001#);

   ---------------------------------------------------------------
   --  Convert 32-byte big-endian to 4×64-bit LE scalar
   ---------------------------------------------------------------

   procedure Bytes_To_Scalar
     (D   : out Scalar_64;
      Src : in  ECDSA_Sig_Half)
   is
   begin
      --  Big-endian: Src(0) is MSB, Src(31) is LSB
      --  Little-endian limbs: D(0) = bytes 24..31, D(3) = bytes 0..7
      for L in 0 .. 3 loop
         declare
            Base : constant N32 := N32 (24 - L * 8);
            V : Unsigned_64 := 0;
         begin
            for B in 0 .. 7 loop
               V := V or Shift_Left (Unsigned_64 (Src (Base + N32 (B))),
                                     (7 - B) * 8);
            end loop;
            D (L) := V;
         end;
      end loop;
   end Bytes_To_Scalar;

   ---------------------------------------------------------------
   --  Convert 4×64-bit LE scalar to 32-byte big-endian
   ---------------------------------------------------------------

   procedure Scalar_To_Bytes
     (Dst : out ECDSA_Sig_Half;
      Src : in  Scalar_64)
   is
   begin
      for L in 0 .. 3 loop
         declare
            Base : constant N32 := N32 (24 - L * 8);
            V : constant Unsigned_64 := Src (L);
         begin
            for B in 0 .. 7 loop
               Dst (Base + N32 (B)) :=
                 Byte (Shift_Right (V, (7 - B) * 8) and 16#FF#);
            end loop;
         end;
      end loop;
   end Scalar_To_Bytes;

   ---------------------------------------------------------------
   --  4×4 schoolbook multiplication: 256-bit × 256-bit → 512-bit
   --  Uses Unsigned_128 for wide multiply-accumulate
   ---------------------------------------------------------------

   procedure Mul_Wide
     (D    : out Scalar_Wide;
      A, B : in  Scalar_64)
   is
      W : Unsigned_128;
      CC : Unsigned_128;
   begin
      D := (others => 0);

      for I in 0 .. 3 loop
         CC := 0;
         for J in 0 .. 3 loop
            W := Unsigned_128 (A (I)) * Unsigned_128 (B (J))
                 + Unsigned_128 (D (I + J)) + CC;
            D (I + J) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
            CC := Shift_Right (W, 64);
         end loop;
         D (I + 4) := Unsigned_64 (CC);
      end loop;
   end Mul_Wide;

   ---------------------------------------------------------------
   --  Squaring: 256-bit → 512-bit (uses Mul_Wide for simplicity)
   ---------------------------------------------------------------

   procedure Sqr_Wide
     (D : out Scalar_Wide;
      A : in  Scalar_64)
   is
   begin
      Mul_Wide (D, A, A);
   end Sqr_Wide;

   ---------------------------------------------------------------
   --  Subtract: D := A - B, returns borrow (0 or 1)
   ---------------------------------------------------------------

   procedure Sub_Scalar
     (D      : out Scalar_64;
      A, B   : in  Scalar_64;
      Borrow : out Unsigned_64)
   is
      W  : Unsigned_128;
      CC : Unsigned_128 := 0;
   begin
      for I in 0 .. 3 loop
         W := Unsigned_128 (A (I)) - Unsigned_128 (B (I)) - CC;
         D (I) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
         --  Borrow: if W < 0 (bit 64 set in two's complement)
         CC := Shift_Right (W, 127);  -- sign bit of 128-bit
      end loop;
      Borrow := Unsigned_64 (CC);
   end Sub_Scalar;

   ---------------------------------------------------------------
   --  Barrett reduction: given 512-bit product T, compute T mod n
   --
   --  1. q = floor(T * mu / 2^512)
   --  2. r = T - q * n (low 256 bits + carry)
   --  3. Conditional subtract n (at most twice)
   ---------------------------------------------------------------

   procedure Barrett_Reduce
     (D : out Scalar_64;
      T : in  Scalar_Wide)
   is
      --  T * mu: we need a 8×5 multiply, but only care about
      --  limbs 8+ (bits 512+) for the quotient.
      --  Actually: q = floor(T * mu >> 512).
      --  T is 8 limbs, mu is 5 limbs, product is 13 limbs.
      --  We need limbs 8..12 (5 limbs) of the product.
      --
      --  Optimization: we only need the high part, so we can skip
      --  computing product limbs 0..6 entirely. We need limb 7
      --  for the carry into limb 8+.
      --
      --  For correctness, compute the full product at first.

      --  Product T*mu (13 limbs, but we only store 14 for safety)
      type Wide13 is array (0 .. 13) of Unsigned_64;
      TM : Wide13 := (others => 0);

      Q  : Scalar_64;   --  quotient estimate (limbs 8..11 of T*mu)
      QN : Scalar_Wide;  --  q * n (512 bits)
      R  : Scalar_64;
      R4 : Unsigned_64;  --  5th limb of R (bits 256..319)
      Borrow : Unsigned_64;

      W  : Unsigned_128;
      CC : Unsigned_128;
   begin
      --  Step 1: Compute T * mu (8 × 5 schoolbook)
      for I in 0 .. 7 loop
         CC := 0;
         for J in 0 .. 4 loop
            declare
               K : constant Integer := I + J;
            begin
               if K <= 13 then
                  W := Unsigned_128 (T (I)) * Unsigned_128 (Mu64 (J))
                       + Unsigned_128 (TM (K)) + CC;
                  TM (K) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
                  CC := Shift_Right (W, 64);
               else
                  CC := 0;
               end if;
            end;
         end loop;
         if I + 5 <= 13 then
            TM (I + 5) := TM (I + 5) + Unsigned_64 (CC);
         end if;
      end loop;

      --  Step 2: Extract quotient q = limbs 8..11 of T*mu
      --  (This is floor(T * mu / 2^512))
      Q := (TM (8), TM (9), TM (10), TM (11));

      --  Step 3: Compute q * n (low 512 bits = 8 limbs)
      --  We only need the low 8 limbs since r < 3n < 2^258
      QN := (others => 0);
      for I in 0 .. 3 loop
         CC := 0;
         for J in 0 .. 3 loop
            declare
               K : constant Integer := I + J;
            begin
               if K <= 7 then
                  W := Unsigned_128 (Q (I)) * Unsigned_128 (N64 (J))
                       + Unsigned_128 (QN (K)) + CC;
                  QN (K) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
                  CC := Shift_Right (W, 64);
               end if;
            end;
         end loop;
         if I + 4 <= 7 then
            QN (I + 4) := QN (I + 4) + Unsigned_64 (CC);
         end if;
      end loop;

      --  Step 4: r = T - q*n (5 limbs, since R < 3n < 2^258)
      declare
         BW : Unsigned_128;
         BC : Unsigned_128 := 0;
      begin
         for I in 0 .. 3 loop
            BW := Unsigned_128 (T (I)) - Unsigned_128 (QN (I)) - BC;
            R (I) := Unsigned_64 (BW and 16#FFFF_FFFF_FFFF_FFFF#);
            BC := Shift_Right (BW, 127);
         end loop;
         --  5th limb
         BW := Unsigned_128 (T (4)) - Unsigned_128 (QN (4)) - BC;
         R4 := Unsigned_64 (BW and 16#FFFF_FFFF_FFFF_FFFF#);
      end;

      --  Step 5: Conditional subtract n (at most twice)
      --  R_actual = R4 * 2^256 + R.  R_actual < 3n < 2^258.
      --  Subtract n up to twice to bring into [0, n).
      for Round in 1 .. 2 loop
         Sub_Scalar (D, R, N64, Borrow);
         if R4 > 0 or Borrow = 0 then
            --  R_actual >= n: keep the subtraction
            R := D;
            R4 := R4 - Borrow;
         end if;
      end loop;
      D := R;
   end Barrett_Reduce;

   ---------------------------------------------------------------
   --  Modular multiplication: D := A * B mod n
   ---------------------------------------------------------------

   procedure Mul_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
      T : Scalar_Wide;
   begin
      Mul_Wide (T, A, B);
      Barrett_Reduce (D, T);
   end Mul_Mod_N;

   ---------------------------------------------------------------
   --  Modular squaring: D := A^2 mod n
   ---------------------------------------------------------------

   procedure Square_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64)
   is
      T : Scalar_Wide;
   begin
      Sqr_Wide (T, A);
      Barrett_Reduce (D, T);
   end Square_Mod_N;

   ---------------------------------------------------------------
   --  Modular addition: D := (A + B) mod n
   ---------------------------------------------------------------

   procedure Add_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
      W  : Unsigned_128;
      CC : Unsigned_128 := 0;
      Sum : Scalar_64;
      Tmp : Scalar_64;
      Borrow : Unsigned_64;
   begin
      --  Sum = A + B
      for I in 0 .. 3 loop
         W := Unsigned_128 (A (I)) + Unsigned_128 (B (I)) + CC;
         Sum (I) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
         CC := Shift_Right (W, 64);
      end loop;
      --  Try subtract n.
      --  If CC > 0, the true sum is 2^256 + Sum, which is > n,
      --  so we must subtract.  Sub_Scalar gives the right 256-bit result
      --  even with the implicit high bit (Tmp = 2^256 + Sum - n).
      Sub_Scalar (Tmp, Sum, N64, Borrow);
      if Unsigned_64 (CC) > 0 or Borrow = 0 then
         D := Tmp;
      else
         D := Sum;
      end if;
   end Add_Mod_N;

   ---------------------------------------------------------------
   --  Modular inversion: D := A^(n-2) mod n (Fermat)
   ---------------------------------------------------------------

   procedure Inv_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64)
   is
      --  n - 2 in big-endian bytes
      N_Minus_2 : constant Byte_Seq (0 .. 31) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#4F#);

      Result : Scalar_64;
      Tmp    : Scalar_64;
      Started : Boolean := False;
   begin
      Result := (0 => 1, others => 0);

      for I in N32 range 0 .. 31 loop
         for Bit in reverse Natural range 0 .. 7 loop
            if Started then
               Square_Mod_N (Tmp, Result);
               Result := Tmp;
            end if;

            if (Shift_Right (U32 (N_Minus_2 (I)), Bit) and 1) = 1 then
               if Started then
                  Mul_Mod_N (Tmp, Result, A);
                  Result := Tmp;
               else
                  Result := A;
                  Started := True;
               end if;
            end if;
         end loop;
      end loop;

      D := Result;
   end Inv_Mod_N;

   ---------------------------------------------------------------
   --  Check if scalar is zero (constant-time)
   ---------------------------------------------------------------

   function Is_Zero_Scalar (A : Scalar_64) return Boolean is
      Z : Unsigned_64 := 0;
   begin
      for I in 0 .. 3 loop
         Z := Z or A (I);
      end loop;
      return Z = 0;
   end Is_Zero_Scalar;

   ---------------------------------------------------------------
   --  Check if A < n (try subtract, check borrow)
   ---------------------------------------------------------------

   function Less_Than_Order (A : Scalar_64) return Boolean is
      Tmp    : Scalar_64;
      Borrow : Unsigned_64;
   begin
      Sub_Scalar (Tmp, A, N64, Borrow);
      return Borrow = 1;
   end Less_Than_Order;

   ---------------------------------------------------------------
   --  Reduce mod n: if A >= n, subtract n
   ---------------------------------------------------------------

   procedure Reduce_Once
     (A : in out Scalar_64)
   is
      Tmp    : Scalar_64;
      Borrow : Unsigned_64;
   begin
      Sub_Scalar (Tmp, A, N64, Borrow);
      if Borrow = 0 then
         A := Tmp;
      end if;
   end Reduce_Once;

   ---------------------------------------------------------------
   --  ECDSA Sign
   ---------------------------------------------------------------

   procedure Sign
     (Hash  : in     Bytes_32;
      D     : in     ECDSA_Sig_Half;
      K     : in     ECDSA_Sig_Half;
      R_Out :    out ECDSA_Sig_Half;
      S_Out :    out ECDSA_Sig_Half;
      OK    :    out Boolean)
   is
      K_S, D_S, H_S : Scalar_64;
      R_S, S_S      : Scalar_64;
      RD, Sum, K_Inv : Scalar_64;

      Pt     : P256_Jacobian;
      RX     : Byte_Seq (0 .. 31);
      RX_Half : ECDSA_Sig_Half;
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      Bytes_To_Scalar (K_S, K);
      Bytes_To_Scalar (D_S, D);
      Bytes_To_Scalar (H_S, ECDSA_Sig_Half (Hash));

      if Is_Zero_Scalar (K_S) or not Less_Than_Order (K_S) then
         return;
      end if;

      Reduce_Once (H_S);

      P256_Mulgen (Pt, Byte_Seq (K), 32);
      P256_To_Affine (Pt);

      FE_To_Bytes (RX, Pt.X);
      RX_Half := ECDSA_Sig_Half (RX);
      Bytes_To_Scalar (R_S, RX_Half);
      Reduce_Once (R_S);

      if Is_Zero_Scalar (R_S) then
         return;
      end if;

      --  s = k^(-1) * (hash + r*d) mod n
      Mul_Mod_N (RD, R_S, D_S);
      Add_Mod_N (Sum, H_S, RD);
      Inv_Mod_N (K_Inv, K_S);
      Mul_Mod_N (S_S, K_Inv, Sum);

      if Is_Zero_Scalar (S_S) then
         return;
      end if;

      Scalar_To_Bytes (R_Out, R_S);
      Scalar_To_Bytes (S_Out, S_S);
      OK := True;
   end Sign;

   ---------------------------------------------------------------
   --  ECDSA Verify
   ---------------------------------------------------------------

   function Verify
     (Hash : in Bytes_32;
      Qx   : in ECDSA_Sig_Half;
      Qy   : in ECDSA_Sig_Half;
      R    : in ECDSA_Sig_Half;
      S    : in ECDSA_Sig_Half) return Boolean
   is
      R_S, S_S    : Scalar_64;
      H_S         : Scalar_64;
      W_S         : Scalar_64;
      U1_S, U2_S  : Scalar_64;

      U1_Bytes, U2_Bytes : ECDSA_Sig_Half;

      PK_Enc : Byte_Seq (0 .. 64);
      RX     : Byte_Seq (0 .. 31);
      RX_S   : Scalar_64;
      Diff   : Scalar_64;

      OK     : U32;
      Borrow : Unsigned_64;
   begin
      Bytes_To_Scalar (R_S, R);
      Bytes_To_Scalar (S_S, S);

      --  Check r, s in [1, n-1]
      if Is_Zero_Scalar (R_S) or Is_Zero_Scalar (S_S) then
         return False;
      end if;
      if not Less_Than_Order (R_S) then
         return False;
      end if;
      if not Less_Than_Order (S_S) then
         return False;
      end if;

      Bytes_To_Scalar (H_S, ECDSA_Sig_Half (Hash));
      Reduce_Once (H_S);

      --  w = s^(-1) mod n
      Inv_Mod_N (W_S, S_S);

      --  u1 = hash * w mod n
      Mul_Mod_N (U1_S, H_S, W_S);

      --  u2 = r * w mod n
      Mul_Mod_N (U2_S, R_S, W_S);

      --  Convert back to bytes for P256_Muladd
      Scalar_To_Bytes (U1_Bytes, U1_S);
      Scalar_To_Bytes (U2_Bytes, U2_S);

      --  R = u1*G + u2*Q
      PK_Enc (0) := 16#04#;
      PK_Enc (1 .. 32) := Qx;
      PK_Enc (33 .. 64) := Qy;

      P256_Muladd (PK_Enc, Byte_Seq (U2_Bytes), 32,
                   Byte_Seq (U1_Bytes), 32, OK);

      if OK = 0 then
         return False;
      end if;

      --  Check R.x == r (mod n)
      RX := PK_Enc (1 .. 32);
      Bytes_To_Scalar (RX_S, ECDSA_Sig_Half (RX));
      Reduce_Once (RX_S);

      --  Constant-time comparison
      Sub_Scalar (Diff, RX_S, R_S, Borrow);
      return Is_Zero_Scalar (Diff) and Borrow = 0;
   end Verify;

   procedure Test_Mul_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, B_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Bytes_To_Scalar (B_S, B_Bytes);
      Mul_Mod_N (R_S, A_S, B_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Mul_Mod_N;

   procedure Test_Inv_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Inv_Mod_N (R_S, A_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Inv_Mod_N;

   procedure Test_Add_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, B_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Bytes_To_Scalar (B_S, B_Bytes);
      Add_Mod_N (R_S, A_S, B_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Add_Mod_N;

   procedure Test_Sqr_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Square_Mod_N (R_S, A_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Sqr_Mod_N;

end SPARKTLS.P256.ECDSA;
