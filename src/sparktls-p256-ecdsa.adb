--  SPARKTLS ECDSA P-256 Signature Verification (body)
--
--  Scalar mod-n arithmetic uses 30-bit limbs with Barrett reduction.

with SPARKTLS.P256.Point; use SPARKTLS.P256.Point;

package body SPARKTLS.P256.ECDSA with
   SPARK_Mode => On
is
   --  Curve order n in 30-bit limbs (little-endian)
   N_Order : constant P256_Limbs :=
     (16#3C632551#, 16#0EE72B0B#, 16#3179E84F#, 16#39BEAB69#,
      16#3FFFFFBC#, 16#3FFFFFFF#, 16#00000FFF#, 16#3FFFC000#,
      16#0000FFFF#);

   --  Barrett constant mu = floor(2^512 / n), in 30-bit limbs
   --  mu is 257 bits, fits in 9 limbs (limb 8 = 0x10000)
   Mu_Barrett : constant P256_Limbs :=
     (16#2EDF9BFE#, 16#04BFF617#, 16#31A6C210#, 16#064154B7#,
      16#3FFFFF43#, 16#3FFFFBFF#, 16#3FFFFFFF#, 16#00003FFF#,
      16#00010000#);

   --  Wide type for Barrett intermediate (36 limbs for 18x18 product,
   --  but we only need 18x9 since mu has 9 limbs, giving 27 limbs)
   subtype Barrett_Index is I32 range 0 .. 26;
   type Barrett_Wide is array (Barrett_Index) of U64;

   ---------------------------------------------------------------
   --  Multiply 18-limb value by 9-limb value -> 27-limb result
   --  Used for t * mu in Barrett reduction
   ---------------------------------------------------------------

   procedure Mul_18x9
     (D :    out Barrett_Wide;
      A : in     P256_Wide;
      B : in     P256_Limbs)
   is
      function MUL (X, Y : U32) return U64 is
        (U64 (X) * U64 (Y)) with Inline;
      CC : U64;
      W  : U64;
   begin
      D := (others => 0);

      --  Schoolbook: for each limb of A, multiply by all of B
      for I in Wide_Index loop
         CC := 0;
         for J in Limb_Index loop
            declare
               K : constant Barrett_Index := I + J;
            begin
               W := D (K) + MUL (A (I), B (J)) + CC;
               D (K) := W and U64 (Limb_Mask);
               CC := Shift_Right (W, 30);
            end;
         end loop;
         --  Propagate remaining carry
         if I + 9 <= 26 then
            D (I + 9) := D (I + 9) + CC;
         end if;
      end loop;
   end Mul_18x9;

   ---------------------------------------------------------------
   --  Multiply two 9-limb values -> 18-limb result (same as Mul9
   --  but takes/returns different types for clarity in Barrett)
   ---------------------------------------------------------------

   --  We reuse the existing Mul9 from the parent package.

   ---------------------------------------------------------------
   --  Subtract 9-limb values: D := A - B
   --  Returns borrow (0 = no borrow, 1 = borrow)
   ---------------------------------------------------------------

   procedure Sub_Order
     (D      :    out P256_Limbs;
      A      : in     P256_Limbs;
      B      : in     P256_Limbs;
      Borrow :    out U32)
   is
      W  : U32;
      CC : U32 := 0;
   begin
      for I in Limb_Index loop
         W := A (I) - B (I) - CC;
         D (I) := W and Limb_Mask;
         CC := Shift_Right (W, 31) and 1;
      end loop;
      Borrow := CC;
   end Sub_Order;

   ---------------------------------------------------------------
   --  Barrett reduction: given 18-limb product t, compute t mod n
   --
   --  Algorithm:
   --  1. q = floor((t * mu) / 2^540)   [540 = 18*30]
   --     Since t has 18 limbs and mu has 9 limbs, t*mu has 27 limbs.
   --     Dividing by 2^540 = shifting right 18 limbs.
   --     So q = limbs 18..26 of (t * mu), which is at most 9 limbs.
   --
   --  2. r = t - q * n (low 9 limbs only, since result < 3n < 2^258)
   --
   --  3. Conditionally subtract n at most twice.
   --
   --  Note: We use 2^540 instead of 2^512 because our limbs are
   --  30 bits wide (18 * 30 = 540), and mu was computed as
   --  floor(2^512 / n). We need to adjust: the product t*mu
   --  represents t * floor(2^512/n), so the quotient estimate is
   --  floor(t*mu / 2^512). In limb terms, 512 bits = 17.066 limbs.
   --  We approximate by taking limbs 17.. and adjusting.
   ---------------------------------------------------------------

   procedure Barrett_Reduce
     (D : out P256_Limbs;
      T : in  P256_Wide)
   is
      --  t * mu (27 limbs)
      TM : Barrett_Wide;

      --  Quotient estimate q (9 limbs) - extracted from high part
      Q : P256_Limbs;

      --  q * n (18 limbs)
      QN : P256_Wide;

      --  Intermediate result (9 limbs + possible carry)
      R  : P256_Limbs;
      Borrow : U32;

      --  For extracting q from the right bit position:
      --  We need bits 512..768 of (t * mu).
      --  512 bits = 17 limbs + 2 bits (17*30 = 510, so bit 512 is
      --  at position 2 within limb 17).
      --  So q ≈ (TM >> 510) >> 2 = shift TM right by 17 limbs,
      --  then shift the resulting value right by 2 bits.
   begin
      --  Step 1: Compute t * mu
      Mul_18x9 (TM, T, Mu_Barrett);

      --  Step 2: Extract quotient q from bits 512+ of TM
      --  Bit 512 of TM is at limb 17 (510 bits), bit offset 2.
      --  q_i = (TM(17+i) >> 2) | (TM(18+i) << 28) masked to 30 bits
      for I in Limb_Index loop
         declare
            Lo_Idx : constant Barrett_Index := 17 + I;
            Hi_Idx : constant I32 := 18 + I;
            Lo_Part : constant U64 := Shift_Right (TM (Lo_Idx), 2);
            Hi_Part : U64;
         begin
            if Hi_Idx <= 26 then
               Hi_Part := Shift_Left (TM (Hi_Idx), 28);
            else
               Hi_Part := 0;
            end if;
            Q (I) := U32 ((Lo_Part or Hi_Part) and U64 (Limb_Mask));
         end;
      end loop;

      --  Step 3: Compute q * n (18 limbs)
      Mul9 (QN, Q, N_Order);

      --  Step 4: r = t - q*n (low 9 limbs only, with borrow chain)
      --  Since r < 3n < 2^258, only 9 limbs matter.
      declare
         W  : I64;
         CC : I64 := 0;
      begin
         for I in Limb_Index loop
            W := I64 (T (I)) - I64 (QN (I)) + CC;
            R (I) := U32 (U64 (W) and U64 (Limb_Mask));
            CC := Shift_Right_Arithmetic (W, 30);
         end loop;
      end;

      --  Step 5: Conditional subtract n (at most twice)
      Sub_Order (D, R, N_Order, Borrow);
      if Borrow = 1 then
         --  R was < n, undo
         D := R;
      else
         --  D = R - n, might still be >= n
         R := D;
         Sub_Order (D, R, N_Order, Borrow);
         if Borrow = 1 then
            D := R;
         end if;
      end if;
   end Barrett_Reduce;

   ---------------------------------------------------------------
   --  Modular multiplication: D := A * B mod n
   ---------------------------------------------------------------

   procedure Mul_Mod_N
     (D : out P256_Limbs;
      A : in  P256_Limbs;
      B : in  P256_Limbs)
   is
      T : P256_Wide;
   begin
      Mul9 (T, A, B);
      Barrett_Reduce (D, T);
   end Mul_Mod_N;

   ---------------------------------------------------------------
   --  Modular squaring: D := A^2 mod n
   ---------------------------------------------------------------

   procedure Square_Mod_N
     (D : out P256_Limbs;
      A : in  P256_Limbs)
   is
      T : P256_Wide;
   begin
      Square9 (T, A);
      Barrett_Reduce (D, T);
   end Square_Mod_N;

   ---------------------------------------------------------------
   --  Modular inversion: D := A^(n-2) mod n (Fermat)
   ---------------------------------------------------------------

   procedure Inv_Mod_N
     (D : out P256_Limbs;
      A : in  P256_Limbs)
   is
      --  n - 2 in big-endian bytes
      N_Minus_2 : constant Byte_Seq (0 .. 31) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#4F#);

      Result : P256_Limbs;
      Tmp    : P256_Limbs;
      Started : Boolean := False;
   begin
      Result := FE_One;

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
   --  Check if a 9-limb value is zero (constant-time)
   ---------------------------------------------------------------

   function Is_Zero_Limbs (A : P256_Limbs) return Boolean is
      Z : U32 := 0;
   begin
      for I in Limb_Index loop
         Z := Z or A (I);
      end loop;
      return Z = 0;
   end Is_Zero_Limbs;

   ---------------------------------------------------------------
   --  Check if A < B for 9-limb values (try subtract, check borrow)
   ---------------------------------------------------------------

   function Less_Than_Order (A : P256_Limbs) return Boolean is
      Tmp    : P256_Limbs;
      Borrow : U32;
   begin
      Sub_Order (Tmp, A, N_Order, Borrow);
      return Borrow = 1;
   end Less_Than_Order;

   ---------------------------------------------------------------
   --  Convert 32-byte big-endian scalar to 9 x 30-bit limbs
   --  (reuses BE8_To_LE30 from parent package)
   ---------------------------------------------------------------

   procedure Scalar_From_Bytes
     (D   : out P256_Limbs;
      Src : in  ECDSA_Sig_Half)
   is
   begin
      BE8_To_LE30 (D, Byte_Seq (Src));
   end Scalar_From_Bytes;

   ---------------------------------------------------------------
   --  Convert 9 x 30-bit limbs to 32-byte big-endian scalar
   ---------------------------------------------------------------

   procedure Scalar_To_Bytes
     (Dst : out ECDSA_Sig_Half;
      Src : in  P256_Limbs)
   is
      Tmp : Byte_Seq (0 .. 31);
   begin
      LE30_To_BE8 (Tmp, Src);
      Dst := ECDSA_Sig_Half (Tmp);
   end Scalar_To_Bytes;

   ---------------------------------------------------------------
   --  Modular addition: D := (A + B) mod n
   ---------------------------------------------------------------

   procedure Add_Mod_N
     (D : out P256_Limbs;
      A : in  P256_Limbs;
      B : in  P256_Limbs)
   is
      CC : U32 := 0;
      W  : U32;
      Tmp    : P256_Limbs;
      Borrow : U32;
   begin
      for I in Limb_Index loop
         W := A (I) + B (I) + CC;
         D (I) := W and Limb_Mask;
         CC := Shift_Right (W, 30);
      end loop;
      Sub_Order (Tmp, D, N_Order, Borrow);
      if Borrow = 0 then
         D := Tmp;
      end if;
   end Add_Mod_N;

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
      K_Limbs, D_Limbs, H_Limbs : P256_Limbs;
      R_Limbs, S_Limbs          : P256_Limbs;
      RD, Sum, K_Inv            : P256_Limbs;
      Tmp    : P256_Limbs;
      Borrow : U32;

      Pt     : P256_Jacobian;
      RX     : Byte_Seq (0 .. 31);
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      Scalar_From_Bytes (K_Limbs, K);
      Scalar_From_Bytes (D_Limbs, D);
      Scalar_From_Bytes (H_Limbs, ECDSA_Sig_Half (Hash));

      if Is_Zero_Limbs (K_Limbs) or not Less_Than_Order (K_Limbs) then
         return;
      end if;

      if not Less_Than_Order (H_Limbs) then
         Sub_Order (Tmp, H_Limbs, N_Order, Borrow);
         H_Limbs := Tmp;
      end if;

      P256_Mulgen (Pt, Byte_Seq (K), 32);
      P256_To_Affine (Pt);

      LE30_To_BE8 (RX, Pt.X);
      Scalar_From_Bytes (R_Limbs, ECDSA_Sig_Half (RX));
      if not Less_Than_Order (R_Limbs) then
         Sub_Order (Tmp, R_Limbs, N_Order, Borrow);
         R_Limbs := Tmp;
      end if;

      if Is_Zero_Limbs (R_Limbs) then
         return;
      end if;

      Mul_Mod_N (RD, R_Limbs, D_Limbs);
      Add_Mod_N (Sum, H_Limbs, RD);
      Inv_Mod_N (K_Inv, K_Limbs);
      Mul_Mod_N (S_Limbs, K_Inv, Sum);

      if Is_Zero_Limbs (S_Limbs) then
         return;
      end if;

      Scalar_To_Bytes (R_Out, R_Limbs);
      Scalar_To_Bytes (S_Out, S_Limbs);
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
      R_Limbs, S_Limbs : P256_Limbs;
      H_Limbs          : P256_Limbs;
      W_Limbs          : P256_Limbs;
      U1_Limbs         : P256_Limbs;
      U2_Limbs         : P256_Limbs;

      U1_Bytes : ECDSA_Sig_Half;
      U2_Bytes : ECDSA_Sig_Half;

      PK_Enc : Byte_Seq (0 .. 64);
      RX     : Byte_Seq (0 .. 31);
      RX_Limbs : P256_Limbs;

      OK     : U32;
      Borrow : U32;
      Tmp    : P256_Limbs;
   begin
      --  Convert r, s to limbs
      Scalar_From_Bytes (R_Limbs, R);
      Scalar_From_Bytes (S_Limbs, S);

      --  Step 1: Check r, s in [1, n-1]
      if Is_Zero_Limbs (R_Limbs) or Is_Zero_Limbs (S_Limbs) then
         return False;
      end if;
      if not Less_Than_Order (R_Limbs) then
         return False;
      end if;
      if not Less_Than_Order (S_Limbs) then
         return False;
      end if;

      --  Convert hash to limbs, reduce mod n if needed
      Scalar_From_Bytes (H_Limbs, ECDSA_Sig_Half (Hash));
      if not Less_Than_Order (H_Limbs) then
         Sub_Order (Tmp, H_Limbs, N_Order, Borrow);
         H_Limbs := Tmp;
      end if;

      --  Step 2: w = s^(-1) mod n
      Inv_Mod_N (W_Limbs, S_Limbs);

      --  Step 3: u1 = hash * w mod n
      Mul_Mod_N (U1_Limbs, H_Limbs, W_Limbs);

      --  Step 4: u2 = r * w mod n
      Mul_Mod_N (U2_Limbs, R_Limbs, W_Limbs);

      --  Convert u1, u2 back to big-endian bytes for P256_Muladd
      Scalar_To_Bytes (U1_Bytes, U1_Limbs);
      Scalar_To_Bytes (U2_Bytes, U2_Limbs);

      --  Step 5: Compute R = u1*G + u2*Q using P256_Muladd
      PK_Enc (0) := 16#04#;
      PK_Enc (1 .. 32) := Qx;
      PK_Enc (33 .. 64) := Qy;

      P256_Muladd (PK_Enc, Byte_Seq (U2_Bytes), 32,
                   Byte_Seq (U1_Bytes), 32, OK);

      if OK = 0 then
         return False;
      end if;

      --  Step 6: Check R.x == r (mod n)
      RX := PK_Enc (1 .. 32);

      --  Reduce RX mod n if needed
      Scalar_From_Bytes (RX_Limbs, ECDSA_Sig_Half (RX));
      if not Less_Than_Order (RX_Limbs) then
         Sub_Order (Tmp, RX_Limbs, N_Order, Borrow);
         RX_Limbs := Tmp;
      end if;

      --  Compare with r (both already < n)
      --  Constant-time comparison via subtraction
      Sub_Order (Tmp, RX_Limbs, R_Limbs, Borrow);
      return Is_Zero_Limbs (Tmp) and Borrow = 0;
   end Verify;

end SPARKTLS.P256.ECDSA;
