--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.

with Interfaces;        use Interfaces;
with SPARKTLS.RSA;      use SPARKTLS.RSA;
with SPARKTLS.P384.Field; use SPARKTLS.P384.Field;

package body SPARKTLS.P384.Point with
   SPARK_Mode => Off
is
   --  Generate public key from private scalar:
   --  Computes [SK] * G and encodes as 97-byte uncompressed point (04 || X || Y).
   procedure P384_Mulgen
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq)
   is
      G   : Jacobian;
      T1  : Big_Int;
   begin
      PK_Out := (others => 0);
      Init_Field;
      Make_Generator (G);
      Scalar_Mul (G, SK);
      To_Affine (G);

      --  Encode: 04 || X (48 bytes) || Y (48 bytes)
      PK_Out (0) := 16#04#;
      FE_From_Monty (T1, G.X);
      Encode (Byte_Seq (PK_Out (1 .. 48)), 48, T1);
      FE_From_Monty (T1, G.Y);
      Encode (Byte_Seq (PK_Out (49 .. 96)), 48, T1);
   end P384_Mulgen;

   --  ECDHE shared secret:
   --  Computes x-coordinate of [SK] * Peer_PK.
   procedure P384_ECDHE
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq)
   is
      Q   : Jacobian;
      T1  : Big_Int;
   begin
      Secret := (others => 0);
      OK := False;

      --  Validate: must start with 0x04 (uncompressed)
      if Peer_PK (0) /= 16#04# then
         return;
      end if;

      Init_Field;

      --  Parse peer public key
      Make_Point (Q,
                  Peer_PK (1 .. 48),
                  Peer_PK (49 .. 96));

      --  Scalar multiply: Q := [SK] * Q
      Scalar_Mul (Q, SK);

      --  Check result is not point at infinity
      if FE_Is_Zero (Q.Z) then
         return;
      end if;

      --  Convert to affine and extract x-coordinate
      To_Affine (Q);
      FE_From_Monty (T1, Q.X);
      Encode (Byte_Seq (Secret), 48, T1);
      OK := True;
   end P384_ECDHE;

end SPARKTLS.P384.Point;
