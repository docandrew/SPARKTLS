--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.

with Interfaces;           use Interfaces;
with SPARKTLS.BigNat;      use SPARKTLS.BigNat;
with SPARKTLS.P384.Field;  use SPARKTLS.P384.Field;

package body SPARKTLS.P384.Point with
   SPARK_Mode => On
is
   procedure P384_Mulgen
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq)
   with SPARK_Mode => Off is
      G      : Jacobian;
      T1     : Big_Nat;
      Coords : Byte_Seq (0 .. 47);
   begin
      PK_Out := (others => 0);
      Init_Field;
      Make_Generator (G);
      Scalar_Mul (G, SK);
      To_Affine (G);

      PK_Out (0) := 16#04#;
      FE_From_Monty (T1, G.X);
      Encode (Coords, T1);
      PK_Out (1 .. 48) := Coords;
      FE_From_Monty (T1, G.Y);
      Encode (Coords, T1);
      PK_Out (49 .. 96) := Coords;
   end P384_Mulgen;

   procedure P384_ECDHE
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq)
   with SPARK_Mode => Off is
      Q      : Jacobian;
      T1     : Big_Nat;
      Coords : Byte_Seq (0 .. 47);
   begin
      Secret := (others => 0);
      OK := False;

      if Peer_PK (0) /= 16#04# then
         return;
      end if;

      Init_Field;
      Make_Point (Q, Peer_PK (1 .. 48), Peer_PK (49 .. 96));
      Scalar_Mul (Q, SK);

      if FE_Is_Zero (Q.Z) then
         return;
      end if;

      To_Affine (Q);
      FE_From_Monty (T1, Q.X);
      Encode (Coords, T1);
      Secret := Bytes_48 (Coords);
      OK := True;
   end P384_ECDHE;

end SPARKTLS.P384.Point;
