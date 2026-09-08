with Interfaces; use Interfaces;

package body Det_Random_Lib is

   procedure Det_Random (Output : out Byte_Seq) is
   begin
      for I in Output'Range loop
         Output (I) := Byte (16#A0# + (Natural (I - Output'First) mod 16));
      end loop;
   end Det_Random;

end Det_Random_Lib;
