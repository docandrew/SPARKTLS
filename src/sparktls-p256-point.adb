--  SPARKTLS P-256 Point Arithmetic (body)
--  Ported from BearSSL's ec_p256_m31.c

package body SPARKTLS.P256.Point with
   SPARK_Mode => On
is
   --  Curve parameter b in Montgomery representation.
   --  b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
   --  b_mont = b * R mod p where R = 2^256
   P256_B : constant P256_FE :=
     (16#D89CDF6229C4BDDF#,
      16#ACF005CD78843090#,
      16#E5A220ABF7212ED6#,
      16#DC30061D04874834#);

   --  Comb precomputed table for generator multiplication.
   --  T[k] = sum_{j=0}^{3} bit_j(k) * 2^(64j) * G  for k=0..15
   --  Points stored in Montgomery affine form (x_mont, y_mont).
   --  Computed from NIST P-256 generator, verified on curve.

   type Comb_Point is record
      X : P256_FE;
      Y : P256_FE;
   end record;
   type Comb_Table_T is array (0 .. 15) of Comb_Point;

   Comb_G : constant Comb_Table_T := (
     0 => (X => (0, 0, 0, 0),
           Y => (0, 0, 0, 0)),  --  infinity
     1 => (X => (16#79E730D418A9143C#, 16#75BA95FC5FEDB601#,
                  16#79FB732B77622510#, 16#18905F76A53755C6#),
           Y => (16#DDF25357CE95560A#, 16#8B4AB8E4BA19E45C#,
                  16#D2E88688DD21F325#, 16#8571FF1825885D85#)),
     2 => (X => (16#4F922FC516A0D2BB#, 16#0D5CC16C1A623499#,
                  16#9241CF3A57C62C8B#, 16#2F5E6961FD1B667F#),
           Y => (16#5C15C70BF5A01797#, 16#3D20B44D60956192#,
                  16#04911B37071FDB52#, 16#F648F9168D6F0F7B#)),
     3 => (X => (16#9E566847E137BBBC#, 16#E434469E8A6A0BEC#,
                  16#B1C4276179D73463#, 16#5ABE0285133D0015#),
           Y => (16#92AA837CC04C7DAB#, 16#573D9F4C43260C07#,
                  16#0C93156278E6CC37#, 16#94BB725B6B6F7383#)),
     4 => (X => (16#62A8C244BFE20925#, 16#91C19AC38FDCE867#,
                  16#5A96A5D5DD387063#, 16#61D587D421D324F6#),
           Y => (16#E87673A2A37173EA#, 16#2384800853778B65#,
                  16#10F8441E05BAB43E#, 16#FA11FE124621EFBE#)),
     5 => (X => (16#1C891F2B2CB19FFD#, 16#01BA8D5BB1923C23#,
                  16#B6D03D678AC5CA8E#, 16#586EB04C1F13BEDC#),
           Y => (16#0C35C6E527E8ED09#, 16#1E81A33C1819EDE2#,
                  16#278FD6C056C652FA#, 16#19D5AC0870864F11#)),
     6 => (X => (16#62577734D2B533D5#, 16#673B8AF6A1BDDDC0#,
                  16#577E7C9AA79EC293#, 16#BB6DE651C3B266B1#),
           Y => (16#E7E9303AB65259B3#, 16#D6A0AFD3D03A7480#,
                  16#C5AC83D19B3CFC27#, 16#60B4619A5D18B99B#)),
     7 => (X => (16#BD6A38E11AE5AA1C#, 16#B8B7652B49E73658#,
                  16#0B130014EE5F87ED#, 16#9D0F27B2AEEBFFCD#),
           Y => (16#CA9246317A730A55#, 16#9C955B2FDDBBC83A#,
                  16#07C1DFE0AC019A71#, 16#244A566D356EC48D#)),
     8 => (X => (16#56F8410EF4F8B16A#, 16#97241AFEC47B266A#,
                  16#0A406B8E6D9C87C1#, 16#803F3E02CD42AB1B#),
           Y => (16#7F0309A804DBEC69#, 16#A83B85F73BBAD05F#,
                  16#C6097273AD8E197F#, 16#C097440E5067ADC1#)),
     9 => (X => (16#846A56F2C379AB34#, 16#A8EE068B841DF8D1#,
                  16#20314459176C68EF#, 16#F1AF32D5915F1F30#),
           Y => (16#99C375315D75BD50#, 16#837CFFBAF72F67BC#,
                  16#0613A41848D7723F#, 16#23D0F130E2D41C8B#)),
    10 => (X => (16#ED93E225D5BE5A2B#, 16#6FE799835934F3C6#,
                  16#4314092622626FFC#, 16#50BBB4D97990216A#),
           Y => (16#378191C6E57EC63E#, 16#65422C40181DCDB2#,
                  16#41A8099B0236E0F6#, 16#2B10011801FE49C3#)),
    11 => (X => (16#FC68B5C59B391593#, 16#C385F5A2598270FC#,
                  16#7144F3AAD19ADCBB#, 16#DD55899983FBAE0C#),
           Y => (16#93B88B8E74B82FF4#, 16#D2E03C4071E734C9#,
                  16#9A7A9EAF43C0322A#, 16#E6E4C551149D6041#)),
    12 => (X => (16#5FE14BFE80EC21FE#, 16#F6CE116AC255BE82#,
                  16#98BC5A072F4A5D67#, 16#FAD27148DB7E63AF#),
           Y => (16#90C0B6AC29AB05B3#, 16#37A9A83C4E251AE6#,
                  16#0A7DC875C2AADE7D#, 16#77387DE39F0E1A84#)),
    13 => (X => (16#1E9ECC49A56C0DD7#, 16#A5CFFCD846086C74#,
                  16#8F7A1408F505AECE#, 16#B37B85C0BEF0C47E#),
           Y => (16#3596B6E4CC0E6A8F#, 16#FD6D4BBF6B388F23#,
                  16#ABA453FAC39CEF4E#, 16#9C135AC8F9F628D5#)),
    14 => (X => (16#0A1C729495C8F8BE#, 16#2961C4803BF362BF#,
                  16#9E418403DF63D4AC#, 16#C109F9CB91ECE900#),
           Y => (16#C2D095D058945705#, 16#B9083D96DDEB85C0#,
                  16#84692B8D7A40449B#, 16#9BC3344F2EEE1EE1#)),
    15 => (X => (16#0D5AE35642913074#, 16#55491B2748A542B1#,
                  16#469CA665B310732A#, 16#29591D525F1A4CC1#),
           Y => (16#E76F5B6BB84F983F#, 16#BE7EEF419F5F84E1#,
                  16#1200D49680BAA189#, 16#6376551F18EF332C#)));

   ---------------------------------------------------------------
   --  Constant-time conditional copy of Jacobian points
   ---------------------------------------------------------------

   procedure CT_Copy_Point
     (Ctl : in     U32;
      Dst : in out P256_Jacobian;
      Src : in     P256_Jacobian)
   is
   begin
      CT_Copy (Ctl, Dst.X, Src.X);
      CT_Copy (Ctl, Dst.Y, Src.Y);
      CT_Copy (Ctl, Dst.Z, Src.Z);
   end CT_Copy_Point;

   ---------------------------------------------------------------
   --  Constant-time lookup in the comb table (16 entries).
   --  Returns the affine point as a Jacobian (Z = 1, or Z = 0
   --  for the identity when Idx = 0).
   ---------------------------------------------------------------

   procedure Lookup_Comb
     (T   : out P256_Jacobian;
      Idx : in  U32)
   is
      M : U32;
   begin
      T := (X => FE_Zero, Y => FE_One, Z => FE_Zero);  --  identity

      for K in 1 .. 15 loop
         M := 0 - CT_EQ (Idx, U32 (K));
         CT_Copy (M, T.X, Comb_G (K).X);
         CT_Copy (M, T.Y, Comb_G (K).Y);
      end loop;

      --  Z = 1 for non-zero index (affine point), 0 for identity
      T.Z := FE_One;
      M := 0 - CT_EQ (Idx, 0);
      CT_Copy (M, T.Z, FE_Zero);
   end Lookup_Comb;

   ---------------------------------------------------------------
   --  Point doubling
   ---------------------------------------------------------------

   procedure P256_Double (Q : in out P256_Jacobian) is
      --  EFD dbl-2001-b formula optimized for a = -3 (3M + 5S)
      --  Saves 1 Mul vs generic BearSSL formula (4M + 4S) by computing
      --  Z' = (Y+Z)^2 - gamma - delta instead of Z' = 2*Y*Z.
      Dlt, Gamma, Beta, Alpha : P256_FE;
      T1, T2 : P256_FE;
   begin
      --  delta = Z^2
      Square_F256 (Dlt, Q.Z);                           -- 1S

      --  gamma = Y^2
      Square_F256 (Gamma, Q.Y);                           -- 2S

      --  beta = X * gamma
      Mul_F256 (Beta, Q.X, Gamma);                        -- 1M

      --  alpha = 3 * (X - delta) * (X + delta)   [uses a = -3]
      Sub_F256 (T1, Q.X, Dlt);
      Add_F256 (T2, Q.X, Dlt);
      Mul_F256 (Alpha, T1, T2);                           -- 2M
      Add_F256 (T1, Alpha, Alpha);
      Add_F256 (Alpha, Alpha, T1);                -- alpha = 3 * (X^2 - Z^4)

      --  X' = alpha^2 - 8*beta
      Add_F256 (T1, Beta, Beta);                  -- 2*beta
      Add_F256 (T1, T1, T1);                      -- 4*beta
      Add_F256 (T2, T1, T1);                      -- 8*beta
      Square_F256 (Q.X, Alpha);                           -- 3S
      Sub_F256 (Q.X, Q.X, T2);                   -- X' = alpha^2 - 8*beta

      --  Z' = (Y + Z)^2 - gamma - delta   [saves 1 Mul vs 2*Y*Z]
      Add_F256 (T1, Q.Y, Q.Z);
      Square_F256 (Q.Z, T1);                              -- 4S
      Sub_F256 (Q.Z, Q.Z, Gamma);
      Sub_F256 (Q.Z, Q.Z, Dlt);

      --  Y' = alpha * (4*beta - X') - 8*gamma^2
      Add_F256 (T1, Beta, Beta);                  -- 2*beta
      Add_F256 (T1, T1, T1);                      -- 4*beta
      Sub_F256 (T1, T1, Q.X);                    -- 4*beta - X'
      Mul_F256 (Q.Y, Alpha, T1);                          -- 3M
      Square_F256 (T2, Gamma);                             -- 5S
      Add_F256 (T2, T2, T2);                      -- 2*gamma^2
      Add_F256 (T2, T2, T2);                      -- 4*gamma^2
      Add_F256 (T2, T2, T2);                      -- 8*gamma^2
      Sub_F256 (Q.Y, Q.Y, T2);
   end P256_Double;

   ---------------------------------------------------------------
   --  Point addition (full Jacobian)
   ---------------------------------------------------------------

   procedure P256_Add
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32)
   is
      T1, T2, T3, T4, T5, T6, T7 : P256_FE;
      R64 : Unsigned_64;
   begin
      --  u1 = x1*z2^2 (in T1), s1 = y1*z2^3 (in T3)
      Square_F256 (T3, P2.Z);
      Mul_F256 (T1, P1.X, T3);
      Mul_F256 (T4, P2.Z, T3);
      Mul_F256 (T3, P1.Y, T4);

      --  u2 = x2*z1^2 (in T2), s2 = y2*z1^3 (in T4)
      Square_F256 (T4, P1.Z);
      Mul_F256 (T2, P2.X, T4);
      Mul_F256 (T5, P1.Z, T4);
      Mul_F256 (T4, P2.Y, T5);

      --  h = u2 - u1 (in T2), r = s2 - s1 (in T4)
      Sub_F256 (T2, T2, T1);
      Sub_F256 (T4, T4, T3);

      --  Check if r (T4) is nonzero — Montgomery zero is all-zero limbs
      R64 := T4 (0) or T4 (1) or T4 (2) or T4 (3);
      --  Fold 64-bit to 32-bit nonzero flag
      Ret := U32 (R64 and 16#FFFF_FFFF#) or U32 (Shift_Right (R64, 32));
      Ret := Shift_Right ((Ret or (0 - Ret)), 31);

      --  u1*h^2 (in T6), h^3 (in T5)
      Square_F256 (T7, T2);
      Mul_F256 (T6, T1, T7);
      Mul_F256 (T5, T7, T2);

      --  x3 = r^2 - h^3 - 2*u1*h^2
      Square_F256 (P1.X, T4);
      Sub_F256 (P1.X, P1.X, T5);
      Sub_F256 (P1.X, P1.X, T6);
      Sub_F256 (P1.X, P1.X, T6);

      --  y3 = r*(u1*h^2 - x3) - s1*h^3
      Sub_F256 (T6, T6, P1.X);
      Mul_F256 (P1.Y, T4, T6);
      Mul_F256 (T1, T5, T3);
      Sub_F256 (P1.Y, P1.Y, T1);

      --  z3 = h*z1*z2
      Mul_F256 (T1, P1.Z, P2.Z);
      Mul_F256 (P1.Z, T1, T2);
   end P256_Add;

   ---------------------------------------------------------------
   --  Point addition, mixed (P2 is affine: z2 = 1)
   ---------------------------------------------------------------

   procedure P256_Add_Mixed
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32)
   is
      T1, T2, T3, T4, T5, T6, T7 : P256_FE;
      R64 : Unsigned_64;
   begin
      --  u1 = x1 (in T1), s1 = y1 (in T3)
      T1 := P1.X;
      T3 := P1.Y;

      --  u2 = x2*z1^2 (in T2), s2 = y2*z1^3 (in T4)
      Square_F256 (T4, P1.Z);
      Mul_F256 (T2, P2.X, T4);
      Mul_F256 (T5, P1.Z, T4);
      Mul_F256 (T4, P2.Y, T5);

      --  h = u2 - u1 (in T2), r = s2 - s1 (in T4)
      Sub_F256 (T2, T2, T1);
      Sub_F256 (T4, T4, T3);

      --  Check if r (T4) is nonzero — Montgomery zero is all-zero limbs
      R64 := T4 (0) or T4 (1) or T4 (2) or T4 (3);
      --  Fold 64-bit to 32-bit nonzero flag
      Ret := U32 (R64 and 16#FFFF_FFFF#) or U32 (Shift_Right (R64, 32));
      Ret := Shift_Right ((Ret or (0 - Ret)), 31);

      --  u1*h^2 (in T6), h^3 (in T5)
      Square_F256 (T7, T2);
      Mul_F256 (T6, T1, T7);
      Mul_F256 (T5, T7, T2);

      --  x3 = r^2 - h^3 - 2*u1*h^2
      Square_F256 (P1.X, T4);
      Sub_F256 (P1.X, P1.X, T5);
      Sub_F256 (P1.X, P1.X, T6);
      Sub_F256 (P1.X, P1.X, T6);

      --  y3 = r*(u1*h^2 - x3) - s1*h^3
      Sub_F256 (T6, T6, P1.X);
      Mul_F256 (P1.Y, T4, T6);
      Mul_F256 (T1, T5, T3);
      Sub_F256 (P1.Y, P1.Y, T1);

      --  z3 = h*z1 (z2 = 1)
      Mul_F256 (P1.Z, P1.Z, T2);
   end P256_Add_Mixed;

   ---------------------------------------------------------------
   --  Convert to affine via modular inversion z^(p-2)
   ---------------------------------------------------------------

   --  Modular inversion in GF(p): D := A^(p-2) mod p
   procedure P256_Inv (D : out P256_FE; A : in P256_FE) is
      T1, T2 : P256_FE;
   begin
      --  Compute a^(2^31-1) via square-and-multiply
      T1 := A;
      for I in 0 .. 29 loop
         Square_F256 (T1, T1);
         Mul_F256 (T1, T1, A);
      end loop;

      --  Main exponentiation loop for p-2
      T2 := A;
      for I in 1 .. 255 loop
         Square_F256 (T2, T2);
         case I is
            when 31 | 190 | 221 | 252 =>
               Mul_F256 (T2, T2, T1);
            when 63 | 253 | 255 =>
               Mul_F256 (T2, T2, A);
            when others =>
               null;
         end case;
      end loop;
      D := T2;
   end P256_Inv;

   procedure P256_To_Affine (P : in out P256_Jacobian) is
      ZI, T1 : P256_FE;
   begin
      P256_Inv (ZI, P.Z);

      --  x := x * (1/z)^2, y := y * (1/z)^3
      Mul_F256 (T1, ZI, ZI);
      Mul_F256 (P.X, T1, P.X);
      Mul_F256 (T1, T1, ZI);
      Mul_F256 (P.Y, T1, P.Y);

      --  z := z * (1/z) = 1 (or 0 if z was 0)
      Mul_F256 (P.Z, P.Z, ZI);
   end P256_To_Affine;

   ---------------------------------------------------------------
   --  Decode uncompressed point (04 || X[32] || Y[32])
   ---------------------------------------------------------------

   procedure P256_Decode
     (P     :    out P256_Jacobian;
      Src   : in     Byte_Seq;
      Valid :    out U32)
   is
      TX, TY, T1, T2 : P256_FE;
      Bad   : U32;
   begin
      Bad := CT_NEQ (U32 (Src (0)), 16#04#);

      Bytes_To_FE (TX, Src (1 .. 32));
      Bytes_To_FE (TY, Src (33 .. 64));

      --  Check curve equation: y^2 = x^3 - 3x + b
      Square_F256 (T1, TX);
      Mul_F256 (T1, TX, T1);
      Square_F256 (T2, TY);
      Sub_F256 (T1, T1, TX);
      Sub_F256 (T1, T1, TX);
      Sub_F256 (T1, T1, TX);
      Add_F256 (T1, T1, P256_B);
      Sub_F256 (T1, T1, T2);

      --  Check if T1 is zero (curve equation satisfied)
      if not FE_Is_Zero (T1) then
         Bad := Bad or 1;
      end if;

      P.X := TX;
      P.Y := TY;
      P.Z := FE_One;
      Valid := CT_EQ (Bad, 0);
   end P256_Decode;

   ---------------------------------------------------------------
   --  Encode point to uncompressed format
   ---------------------------------------------------------------

   procedure P256_Encode
     (Dst : out Byte_Seq;
      P   : in  P256_Jacobian)
   is
   begin
      Dst (0) := 16#04#;
      FE_To_Bytes (Dst (1 .. 32), P.X);
      FE_To_Bytes (Dst (33 .. 64), P.Y);
   end P256_Encode;

   ---------------------------------------------------------------
   --  Scalar multiplication (2-bit window)
   ---------------------------------------------------------------

   procedure P256_Mul
     (P    : in out P256_Jacobian;
      X    : in     Byte_Seq;
      Xlen : in     N32)
   is
      QZ          : U32;
      P2, P3, Q   : P256_Jacobian;
      T, U        : P256_Jacobian;
      Bits, BNZ   : U32;
      Dummy       : U32;
   begin
      --  Precompute P2 = 2P, P3 = 3P
      P2 := P;
      P256_Double (P2);
      P3 := P;
      P256_Add (P3, P2, Dummy);

      --  Start with Q = 0 (identity)
      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      QZ := 1;

      for J in 0 .. Xlen - 1 loop
         declare
            Bx : constant U32 := U32 (X (J));
         begin
            --  Process 4 pairs of bits from byte (high to low)
            for K_Pair in reverse 0 .. 3 loop
               declare
                  Shift_Amt : constant Natural := Natural (K_Pair) * 2;
               begin
                  P256_Double (Q);
                  P256_Double (Q);

                  T := P;
                  U := Q;
                  Bits := Shift_Right (Bx, Shift_Amt) and 3;
                  BNZ := CT_NEQ (Bits, 0);
                  CT_Copy_Point (CT_EQ (Bits, 2), T, P2);
                  CT_Copy_Point (CT_EQ (Bits, 3), T, P3);
                  P256_Add (U, T, Dummy);
                  CT_Copy_Point (BNZ and QZ, Q, T);
                  CT_Copy_Point (BNZ and (not QZ), Q, U);
                  QZ := QZ and (not BNZ);
               end;
            end loop;
         end;
      end loop;
      P := Q;
   end P256_Mul;

   ---------------------------------------------------------------
   --  Generator multiplication using comb method with 4 teeth.
   --
   --  Scalar bits are arranged as 64 columns of 4 bits each,
   --  where column i contains bits {i, i+64, i+128, i+192}.
   --  Each column indexes into the 16-entry precomputed table.
   --  Evaluation uses Horner's method: 63 doublings + 63 adds
   --  instead of the old approach's 256 doublings + 64 adds.
   ---------------------------------------------------------------

   procedure P256_Mulgen
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32)
   is
      --  Zero-padded scalar (always 32 bytes, big-endian)
      S : Byte_Seq (0 .. 31) := (others => 0);

      Q       : P256_Jacobian;
      T, U    : P256_Jacobian;
      QZ      : U32;
      Idx     : U32;
      BNZ     : U32;
      Dummy   : U32;
      Bit_Pos : Natural;
      B0, B1, B2, B3 : U32;
   begin
      --  Copy scalar into zero-padded 32-byte buffer (right-aligned)
      if Xlen <= 32 then
         for I in 0 .. Xlen - 1 loop
            S (32 - Xlen + I) := X (I);
         end loop;
      else
         S := X (Xlen - 32 .. Xlen - 1);
      end if;

      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      QZ := 1;

      --  Process columns 63 downto 0
      --  Column i extracts bit i from each 64-bit quarter:
      --    b0 = bit i of quarter 3 (bytes 24..31, LSB quarter)
      --    b1 = bit i of quarter 2 (bytes 16..23)
      --    b2 = bit i of quarter 1 (bytes 8..15)
      --    b3 = bit i of quarter 0 (bytes 0..7, MSB quarter)
      for Col in reverse 0 .. 63 loop
         if QZ = 0 then
            P256_Double (Q);
         end if;

         --  Extract 4-bit column index from each quarter
         Bit_Pos := Col mod 8;
         declare
            Byte_In_Q : constant N32 := N32 (7 - Col / 8);
         begin
            B0 := Shift_Right (U32 (S (24 + Byte_In_Q)), Bit_Pos) and 1;
            B1 := Shift_Right (U32 (S (16 + Byte_In_Q)), Bit_Pos) and 1;
            B2 := Shift_Right (U32 (S (8  + Byte_In_Q)), Bit_Pos) and 1;
            B3 := Shift_Right (U32 (S (     Byte_In_Q)), Bit_Pos) and 1;
         end;
         Idx := B0 or Shift_Left (B1, 1) or Shift_Left (B2, 2)
                or Shift_Left (B3, 3);

         BNZ := CT_NEQ (Idx, 0);
         Lookup_Comb (T, Idx);
         U := Q;
         P256_Add_Mixed (U, T, Dummy);
         CT_Copy_Point (BNZ and QZ, Q, T);
         CT_Copy_Point (BNZ and (not QZ), Q, U);
         QZ := QZ and (not BNZ);
      end loop;

      P := Q;
   end P256_Mulgen;

   ---------------------------------------------------------------
   --  Combined multiply-add: A := [x]*A + [y]*G
   ---------------------------------------------------------------

   procedure P256_Muladd
     (A    : in out Byte_Seq;
      X    : in     Byte_Seq;
      Xlen : in     N32;
      Y    : in     Byte_Seq;
      Ylen : in     N32;
      OK   :    out U32)
   is
      PP, QQ : P256_Jacobian;
      R, T   : U32;
      Z      : U32;
      Dummy  : U32;
   begin
      P256_Decode (PP, A, R);
      P256_Mul (PP, X, Xlen);
      P256_Mulgen (QQ, Y, Ylen);

      --  Final addition (may fail if PP = QQ)
      P256_Add (PP, QQ, T);

      --  Check if Z coordinate is zero
      if FE_Is_Zero (PP.Z) then
         Z := 1;
      else
         Z := 0;
      end if;

      --  If Z=1 and T=0, then PP=QQ, use doubling instead
      P256_Double (QQ);
      CT_Copy_Point (Z and (not T), PP, QQ);

      P256_To_Affine (PP);
      P256_Encode (A, PP);
      R := R and (not (Z and T));
      OK := R;
   end P256_Muladd;

end SPARKTLS.P256.Point;
