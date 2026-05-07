with Ada.Text_IO; use Ada.Text_IO;
with SPARKNaCl;   use SPARKNaCl;
with Interfaces; use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256;
procedure Test_Sha_Empty is
   H : SPARKTLSCrypto.Hashing.SHA256.Digest;
   Empty : Byte_Seq (0 .. -1) := (others => 0);
   Hex : constant String := "0123456789abcdef";
begin
   SPARKTLSCrypto.Hashing.SHA256.Hash (H, Empty);
   for I in N32 range 0 .. 31 loop
      Put (Hex (1 + Natural (Shift_Right (Unsigned_8 (H (I)), 4))));
      Put (Hex (1 + Natural (Unsigned_8 (H (I)) and 16#0F#)));
   end loop;
   New_Line;
end;
