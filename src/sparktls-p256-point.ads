--  SPARKTLS P-256 Point Arithmetic
--  Ported from BearSSL's ec_p256_m31.c (Thomas Pornin, MIT license)
--
--  Jacobian coordinates: affine (X,Y) = (x/z^2, y/z^3)
--  Point at infinity has z = 0.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P256.Point with
   SPARK_Mode => On
is
   type P256_Jacobian is record
      X : P256_Limbs := FE_Zero;
      Y : P256_Limbs := FE_Zero;
      Z : P256_Limbs := FE_Zero;
   end record;

   --  Identity point (at infinity)
   P256_Identity : constant P256_Jacobian :=
     (X => FE_Zero, Y => FE_One, Z => FE_Zero);

   --  Constant-time conditional copy of Jacobian points
   procedure CT_Copy_Point
     (Ctl : in     U32;
      Dst : in out P256_Jacobian;
      Src : in     P256_Jacobian) with Inline;

   --  Point doubling (works for all valid points including infinity)
   procedure P256_Double (Q : in out P256_Jacobian);

   --  Point addition (full Jacobian).
   --  Ret is 0 if P1+P2 might need special handling.
   procedure P256_Add
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32);

   --  Point addition, mixed (P2 is affine, i.e. P2.z = 1)
   procedure P256_Add_Mixed
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32);

   --  Convert to affine coordinates (or all zeros for infinity)
   procedure P256_To_Affine (P : in out P256_Jacobian);

   --  Decode 65-byte uncompressed point (04 || X || Y).
   --  Valid is 1 if valid, 0 if not.
   procedure P256_Decode
     (P     :    out P256_Jacobian;
      Src   : in     Byte_Seq;
      Valid :    out U32)
   with Pre => Src'Length = 65 and Src'First = 0;

   --  Encode point to 65-byte uncompressed format.
   --  Point must be in affine coordinates.
   procedure P256_Encode
     (Dst : out Byte_Seq;
      P   : in  P256_Jacobian)
   with Pre => Dst'Length = 65 and Dst'First = 0;

   --  Scalar multiplication: P := [x] * P
   procedure P256_Mul
     (P    : in out P256_Jacobian;
      X    : in     Byte_Seq;
      Xlen : in     N32)
   with Pre => X'First = 0 and Xlen <= X'Length;

   --  Generator multiplication: P := [x] * G
   procedure P256_Mulgen
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32)
   with Pre => X'First = 0 and Xlen <= X'Length;

   --  Combined multiply-add for ECDSA: A := [x]*A + [y]*G
   --  A is a 65-byte encoded point (modified in place).
   --  OK is 1 on success, 0 on failure.
   procedure P256_Muladd
     (A    : in out Byte_Seq;
      X    : in     Byte_Seq;
      Xlen : in     N32;
      Y    : in     Byte_Seq;
      Ylen : in     N32;
      OK   :    out U32)
   with Pre => A'Length = 65 and A'First = 0
               and X'First = 0 and Xlen <= X'Length
               and Y'First = 0 and Ylen <= Y'Length;

   --  Generator point (uncompressed, 65 bytes)
   P256_G : constant Byte_Seq (0 .. 64) :=
     (16#04#, 16#6B#, 16#17#, 16#D1#, 16#F2#, 16#E1#, 16#2C#, 16#42#,
      16#47#, 16#F8#, 16#BC#, 16#E6#, 16#E5#, 16#63#, 16#A4#, 16#40#,
      16#F2#, 16#77#, 16#03#, 16#7D#, 16#81#, 16#2D#, 16#EB#, 16#33#,
      16#A0#, 16#F4#, 16#A1#, 16#39#, 16#45#, 16#D8#, 16#98#, 16#C2#,
      16#96#, 16#4F#, 16#E3#, 16#42#, 16#E2#, 16#FE#, 16#1A#, 16#7F#,
      16#9B#, 16#8E#, 16#E7#, 16#EB#, 16#4A#, 16#7C#, 16#0F#, 16#9E#,
      16#16#, 16#2B#, 16#CE#, 16#33#, 16#57#, 16#6B#, 16#31#, 16#5E#,
      16#CE#, 16#CB#, 16#B6#, 16#40#, 16#68#, 16#37#, 16#BF#, 16#51#,
      16#F5#);

   --  Curve order n (big-endian, 32 bytes)
   P256_N : constant Byte_Seq (0 .. 31) :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
      16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#51#);

end SPARKTLS.P256.Point;
