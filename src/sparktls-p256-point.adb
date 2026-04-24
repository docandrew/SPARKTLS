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

   --  Precomputed window: k*G for k = 1..15
   --  Each entry is 18 U32 values: 9 for X, 9 for Y (affine, 30-bit limbs)
   --  These are in the legacy 30-bit representation and are converted
   --  to Montgomery P256_FE at lookup time.
   type Gwin_Entry is array (0 .. 17) of U32;
   type Gwin_Table is array (0 .. 14) of Gwin_Entry;

   Gwin : constant Gwin_Table := (
     0 => (16#1898C296#, 16#1284E517#, 16#1EB33A0F#, 16#00DF604B#,
           16#2440F277#, 16#339B958E#, 16#04247F8B#, 16#347CB84B#,
           16#00006B17#, 16#37BF51F5#, 16#2ED901A0#, 16#3315ECEC#,
           16#338CD5DA#, 16#0F9E162B#, 16#1FAD29F0#, 16#27F9B8EE#,
           16#10B8BF86#, 16#00004FE3#),
     1 => (16#07669978#, 16#182D23F1#, 16#3F21B35A#, 16#225A789D#,
           16#351AC3C0#, 16#08E00C12#, 16#34F7E8A5#, 16#1EC62340#,
           16#00007CF2#, 16#227873D1#, 16#3812DE74#, 16#0E982299#,
           16#1F6B798F#, 16#3430DBBA#, 16#366B1A7D#, 16#2D040293#,
           16#154436E3#, 16#00000777#),
     2 => (16#06E7FD6C#, 16#2D05986F#, 16#3ADA985F#, 16#31ADC87B#,
           16#0BF165E6#, 16#1FBE5475#, 16#30A44C8F#, 16#3934698C#,
           16#00005ECB#, 16#227D5032#, 16#29E6C49E#, 16#04FB83D9#,
           16#0AAC0D8E#, 16#24A2ECD8#, 16#2C1B3869#, 16#0FF7E374#,
           16#19031266#, 16#00008734#),
     3 => (16#2B030852#, 16#024C0911#, 16#05596EF5#, 16#07F8B6DE#,
           16#262BD003#, 16#3779967B#, 16#08FBBA02#, 16#128D4CB4#,
           16#0000E253#, 16#184ED8C6#, 16#310B08FC#, 16#30EE0055#,
           16#3F25B0FC#, 16#062D764E#, 16#3FB97F6A#, 16#33CC719D#,
           16#15D69318#, 16#0000E0F1#),
     4 => (16#03D033ED#, 16#05552837#, 16#35BE5242#, 16#2320BF47#,
           16#268FDFEF#, 16#13215821#, 16#140D2D78#, 16#02DE9454#,
           16#00005159#, 16#3DA16DA4#, 16#0742ED13#, 16#0D80888D#,
           16#004BC035#, 16#0A79260D#, 16#06FCDAFE#, 16#2727D8AE#,
           16#1F6A2412#, 16#0000E0C1#),
     5 => (16#3C2291A9#, 16#1AC2ABA4#, 16#3B215B4C#, 16#131D037A#,
           16#17DDE302#, 16#0C90B2E2#, 16#0602C92D#, 16#05CA9DA9#,
           16#0000B01A#, 16#0FC77FE2#, 16#35F1214E#, 16#07E16BDF#,
           16#003DDC07#, 16#2703791C#, 16#3038B7EE#, 16#3DAD56FE#,
           16#041D0C8D#, 16#0000E85C#),
     6 => (16#3187B2A3#, 16#0018A1C0#, 16#00FEF5B3#, 16#3E7E2E2A#,
           16#01FB607E#, 16#2CC199F0#, 16#37B4625B#, 16#0EDBE82F#,
           16#00008E53#, 16#01F400B4#, 16#15786A1B#, 16#3041B21C#,
           16#31CD8CF2#, 16#35900053#, 16#1A7E0E9B#, 16#318366D0#,
           16#076F780C#, 16#000073EB#),
     7 => (16#1B6FB393#, 16#13767707#, 16#3CE97DBB#, 16#348E2603#,
           16#354CADC1#, 16#09D0B4EA#, 16#1B053404#, 16#1DE76FBA#,
           16#000062D9#, 16#0F09957E#, 16#295029A8#, 16#3E76A78D#,
           16#3B547DAE#, 16#27CEE0A2#, 16#0575DC45#, 16#1D8244FF#,
           16#332F647A#, 16#0000AD5A#),
     8 => (16#10949EE0#, 16#1E7A292E#, 16#06DF8B3D#, 16#02B2E30B#,
           16#31F8729E#, 16#24E35475#, 16#30B71878#, 16#35EDBFB7#,
           16#0000EA68#, 16#0DD048FA#, 16#21688929#, 16#0DE823FE#,
           16#1C53FAA9#, 16#0EA0C84D#, 16#052A592A#, 16#1FCE7870#,
           16#11325CB2#, 16#00002A27#),
     9 => (16#04C5723F#, 16#30D81A50#, 16#048306E4#, 16#329B11C7#,
           16#223FB545#, 16#085347A8#, 16#2993E591#, 16#1B5ACA8E#,
           16#0000CEF6#, 16#04AF0773#, 16#28D2EEA9#, 16#2751EEEC#,
           16#037B4A7F#, 16#3B4C1059#, 16#08F37674#, 16#2AE906E1#,
           16#18A88A6A#, 16#00008786#),
     10 => (16#34BC21D1#, 16#0CCE474D#, 16#15048BF4#, 16#1D0BB409#,
            16#021CDA16#, 16#20DE76C3#, 16#34C59063#, 16#04EDE20E#,
            16#00003ED1#, 16#282A3740#, 16#0BE3BBF3#, 16#29889DAE#,
            16#03413697#, 16#34C68A09#, 16#210EBE93#, 16#0C8A224C#,
            16#0826B331#, 16#00009099#),
     11 => (16#0624E3C4#, 16#140317BA#, 16#2F82C99D#, 16#260C0A2C#,
            16#25D55179#, 16#194DCC83#, 16#3D95E462#, 16#356F6A05#,
            16#0000741D#, 16#0D4481D3#, 16#2657FC8B#, 16#1BA5CA71#,
            16#3AE44B0D#, 16#07B1548E#, 16#0E0D5522#, 16#05FDC567#,
            16#2D1AA70E#, 16#00000770#),
     12 => (16#06072C01#, 16#23857675#, 16#1EAD58A9#, 16#0B8A12D9#,
            16#1EE2FC79#, 16#0177CB61#, 16#0495A618#, 16#20DEB82B#,
            16#0000177C#, 16#2FC7BFD8#, 16#310EEF8B#, 16#1FB4DF39#,
            16#3B8530E8#, 16#0F4E7226#, 16#0246B6D0#, 16#2A558A24#,
            16#163353AF#, 16#000063BB#),
     13 => (16#24D2920B#, 16#1C249DCC#, 16#2069C5E5#, 16#09AB2F9E#,
            16#36DF3CF1#, 16#1991FD0C#, 16#062B97A7#, 16#1E80070E#,
            16#000054E7#, 16#20D0B375#, 16#2E9F20BD#, 16#35090081#,
            16#1C7A9DDC#, 16#22E7C371#, 16#087E3016#, 16#03175421#,
            16#3C6ECA7D#, 16#0000F599#),
     14 => (16#259B9D5F#, 16#0D9A318F#, 16#23A0EF16#, 16#00EBE4B7#,
            16#088265AE#, 16#2CDE2666#, 16#2BAE7ADF#, 16#1371A5C6#,
            16#0000F045#, 16#0D034F36#, 16#1F967378#, 16#1B5FA3F4#,
            16#0EC8739D#, 16#1643E62A#, 16#1653947E#, 16#22D1F4E6#,
            16#0FB8D64B#, 16#0000B5B9#));

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
   --  Constant-time table lookup for Gwin
   --  Table is in legacy 30-bit limb format; convert to Montgomery
   --  P256_FE at lookup time.
   ---------------------------------------------------------------

   procedure Lookup_Gwin
     (T   : out P256_Jacobian;
      Idx : in  U32)
   is
      XY : array (0 .. 17) of U32 := (others => 0);
      M  : U32;
      Tmp_Limbs : P256_Limbs;
      Tmp_Bytes : Byte_Seq (0 .. 31);
   begin
      --  Constant-time selection from table
      for K in 0 .. 14 loop
         M := 0 - CT_EQ (Idx, U32 (K) + 1);
         for U in 0 .. 17 loop
            XY (U) := XY (U) or (M and Gwin (K) (U));
         end loop;
      end loop;

      --  Convert X from 30-bit limbs to Montgomery FE
      for I in Limb_Index loop
         Tmp_Limbs (I) := XY (Integer (I));
      end loop;
      LE30_To_BE8 (Tmp_Bytes, Tmp_Limbs);
      Bytes_To_FE (T.X, Tmp_Bytes);

      --  Convert Y from 30-bit limbs to Montgomery FE
      for I in Limb_Index loop
         Tmp_Limbs (I) := XY (Integer (I) + 9);
      end loop;
      LE30_To_BE8 (Tmp_Bytes, Tmp_Limbs);
      Bytes_To_FE (T.Y, Tmp_Bytes);

      --  Affine point: z = 1
      T.Z := FE_One;
   end Lookup_Gwin;

   ---------------------------------------------------------------
   --  Point doubling
   ---------------------------------------------------------------

   procedure P256_Double (Q : in out P256_Jacobian) is
      T1, T2, T3, T4 : P256_FE;
   begin
      --  z^2 in T1
      Square_F256 (T1, Q.Z);

      --  x+z^2 in T2, x-z^2 in T1
      Add_F256 (T2, Q.X, T1);
      Sub_F256 (T1, Q.X, T1);

      --  3*(x+z^2)*(x-z^2) in T1  (m)
      Mul_F256 (T3, T1, T2);
      Add_F256 (T1, T3, T3);
      Add_F256 (T1, T3, T1);

      --  2*y^2 in T3, 4*x*y^2 in T2  (s)
      Square_F256 (T3, Q.Y);
      Add_F256 (T3, T3, T3);
      Mul_F256 (T2, Q.X, T3);
      Add_F256 (T2, T2, T2);

      --  x' = m^2 - 2*s
      Square_F256 (Q.X, T1);
      Sub_F256 (Q.X, Q.X, T2);
      Sub_F256 (Q.X, Q.X, T2);

      --  z' = 2*y*z
      Mul_F256 (T4, Q.Y, Q.Z);
      Add_F256 (Q.Z, T4, T4);

      --  y' = m*(s - x') - 8*y^4
      Sub_F256 (T2, T2, Q.X);
      Mul_F256 (Q.Y, T1, T2);
      Square_F256 (T4, T3);
      Add_F256 (T4, T4, T4);
      Sub_F256 (Q.Y, Q.Y, T4);
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

   procedure P256_To_Affine (P : in out P256_Jacobian) is
      T1, T2 : P256_FE;
   begin
      --  Compute z^(2^31-1) via square-and-multiply
      T1 := P.Z;
      for I in 0 .. 29 loop
         Square_F256 (T1, T1);
         Mul_F256 (T1, T1, P.Z);
      end loop;

      --  Main exponentiation loop for p-2
      T2 := P.Z;
      for I in 1 .. 255 loop
         Square_F256 (T2, T2);
         case I is
            when 31 | 190 | 221 | 252 =>
               Mul_F256 (T2, T2, T1);
            when 63 | 253 | 255 =>
               Mul_F256 (T2, T2, P.Z);
            when others =>
               null;
         end case;
      end loop;

      --  x := x * (1/z)^2, y := y * (1/z)^3
      Mul_F256 (T1, T2, T2);
      Mul_F256 (P.X, T1, P.X);
      Mul_F256 (T1, T1, T2);
      Mul_F256 (P.Y, T1, P.Y);

      --  z := z * (1/z) = 1 (or 0 if z was 0)
      Mul_F256 (P.Z, P.Z, T2);
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
   --  Generator multiplication (4-bit window with precomputed table)
   ---------------------------------------------------------------

   procedure P256_Mulgen
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32)
   is
      Q           : P256_Jacobian;
      T, U        : P256_Jacobian;
      QZ          : U32;
      Bits, BNZ   : U32;
      BX          : U32;
      Dummy       : U32;
   begin
      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      QZ := 1;

      for J in 0 .. Xlen - 1 loop
         BX := U32 (X (J));
         for K in 0 .. 1 loop
            P256_Double (Q);
            P256_Double (Q);
            P256_Double (Q);
            P256_Double (Q);

            Bits := Shift_Right (BX, 4) and 16#0F#;
            BNZ := CT_NEQ (Bits, 0);
            Lookup_Gwin (T, Bits);
            U := Q;
            P256_Add_Mixed (U, T, Dummy);
            CT_Copy_Point (BNZ and QZ, Q, T);
            CT_Copy_Point (BNZ and (not QZ), Q, U);
            QZ := QZ and (not BNZ);
            BX := Shift_Left (BX, 4);
         end loop;
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
