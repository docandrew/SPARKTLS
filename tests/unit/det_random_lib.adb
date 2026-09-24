with Interfaces; use Interfaces;
with SPARKTLS.RBG;
with SPARKTLS.RBG.Testing;

package body Det_Random_Lib is

   procedure Det_Random (Output : out Byte_Seq; OK : out Boolean) is
   begin
      for I in Output'Range loop
         Output (I) := Byte (16#A0# + (Natural (I - Output'First) mod 16));
      end loop;
      OK := True;
   end Det_Random;

   procedure Reset is
      OK : Boolean;
   begin
      SPARKTLS.RBG.Shutdown;
      SPARKTLS.RBG.Testing.Init_From (Det_Random'Access, OK);
      pragma Assert (OK);
   end Reset;

end Det_Random_Lib;
