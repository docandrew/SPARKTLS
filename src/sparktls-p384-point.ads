--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.  Reuses Big_Int infrastructure from RSA.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P384.Point with
   SPARK_Mode => On
is
   --  Generate public key from private scalar:
   --  Computes [SK] * G and encodes as 97-byte uncompressed point (04 || X || Y).
   procedure P384_Mulgen
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq)
   with Pre => PK_Out'First = 0 and PK_Out'Length = 97
               and SK'First = 0 and SK'Length = 48;

   --  ECDHE shared secret:
   --  Computes x-coordinate of [SK] * Peer_PK.
   --  Peer_PK is 97-byte uncompressed point.
   --  Returns 48-byte x-coordinate in Secret, OK = True on success.
   procedure P384_ECDHE
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq)
   with Pre => SK'First = 0 and SK'Length = 48
               and Peer_PK'First = 0 and Peer_PK'Length = 97;

end SPARKTLS.P384.Point;
