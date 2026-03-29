--  SPARKTLS P-384 Field Arithmetic (internal)
--
--  Montgomery-based arithmetic mod p384 using SPARK-proven BigNat.
--  Shared by P384.ECDSA and P384.Point.

with SPARKNaCl;        use SPARKNaCl;
with SPARKTLS.BigNat;  use SPARKTLS.BigNat;

private package SPARKTLS.P384.Field with
   SPARK_Mode => On
is
   W384 : constant := 12;  --  384 bits = 12 x 32-bit words

   --  P-384 constants (big-endian byte arrays)
   P384_P : constant Byte_Seq (0 .. 47) :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FE#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#FF#, 16#FF#, 16#FF#, 16#FF#);

   P384_N : constant Byte_Seq (0 .. 47) :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
      16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
      16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);

   P384_GX : constant Byte_Seq (0 .. 47) :=
     (16#AA#, 16#87#, 16#CA#, 16#22#, 16#BE#, 16#8B#, 16#05#, 16#37#,
      16#8E#, 16#B1#, 16#C7#, 16#1E#, 16#F3#, 16#20#, 16#AD#, 16#74#,
      16#6E#, 16#1D#, 16#3B#, 16#62#, 16#8B#, 16#A7#, 16#9B#, 16#98#,
      16#59#, 16#F7#, 16#41#, 16#E0#, 16#82#, 16#54#, 16#2A#, 16#38#,
      16#55#, 16#02#, 16#F2#, 16#5D#, 16#BF#, 16#55#, 16#29#, 16#6C#,
      16#3A#, 16#54#, 16#5E#, 16#38#, 16#72#, 16#76#, 16#0A#, 16#B7#);

   P384_GY : constant Byte_Seq (0 .. 47) :=
     (16#36#, 16#17#, 16#DE#, 16#4A#, 16#96#, 16#26#, 16#2C#, 16#6F#,
      16#5D#, 16#9E#, 16#98#, 16#BF#, 16#92#, 16#92#, 16#DC#, 16#29#,
      16#F8#, 16#F4#, 16#1D#, 16#BD#, 16#28#, 16#9A#, 16#14#, 16#7C#,
      16#E9#, 16#DA#, 16#31#, 16#13#, 16#B5#, 16#F0#, 16#B8#, 16#C0#,
      16#0A#, 16#60#, 16#B1#, 16#CE#, 16#1D#, 16#7E#, 16#81#, 16#9D#,
      16#7A#, 16#43#, 16#1D#, 16#7C#, 16#90#, 16#EA#, 16#0E#, 16#5F#);

   --  Jacobian point type using BigNat
   type Jacobian is record
      X, Y, Z : Big_Nat;
   end record;

   --  Module state (initialized lazily)
   P       : Big_Nat;
   P_M0I   : Word;

   --  Initialization (idempotent)
   procedure Init_Field
   with Post => P.Len = W384;

   --  Field arithmetic mod p (Montgomery form)
   --  All field elements must have Len = W384
   procedure FE_Add (D : out Big_Nat; A, B : Big_Nat)
   with Pre => A.Len = W384 and B.Len = W384 and P.Len = W384;
   procedure FE_Sub (D : out Big_Nat; A, B : Big_Nat)
   with Pre => A.Len = W384 and B.Len = W384 and P.Len = W384;
   procedure FE_Mul (D : out Big_Nat; A, B : Big_Nat)
   with Pre => A.Len = W384 and B.Len = W384 and P.Len = W384;
   procedure FE_Sqr (D : out Big_Nat; A : Big_Nat)
   with Pre => A.Len = W384 and P.Len = W384;
   procedure FE_To_Monty (X : in out Big_Nat)
   with Pre => X.Len = W384 and P.Len = W384;
   procedure FE_From_Monty (D : out Big_Nat; A : Big_Nat)
   with Pre  => A.Len = W384 and P.Len = W384,
        Post => D.Len = W384;
   procedure FE_Inv (D : out Big_Nat; A : Big_Nat)
   with Pre => A.Len = W384 and P.Len = W384;
   function  FE_Is_Zero (A : Big_Nat) return Boolean;

   --  Point operations
   procedure Point_Double (Q : in out Jacobian);
   procedure Point_Add (P1 : in out Jacobian; P2 : Jacobian);
   procedure Scalar_Mul (P_Pt : in out Jacobian; K : Byte_Seq);
   procedure To_Affine (Pt : in out Jacobian);

   --  Build generator point in Montgomery/Jacobian form
   procedure Make_Generator (G : out Jacobian);

   --  Build a point from 48-byte big-endian X, Y coordinates
   procedure Make_Point (Pt : out Jacobian; Qx, Qy : Byte_Seq)
   with Pre => Qx'Length = 48 and Qy'Length = 48;

end SPARKTLS.P384.Field;
