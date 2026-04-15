with Ada.Text_IO;
with SPARKEntropy;

package body Entropy_Random is

   State : SPARKEntropy.Entropy_State;

   procedure Init is
      OK : Boolean;
   begin
      SPARKEntropy.Init (State, OK);
      if not OK then
         Ada.Text_IO.Put_Line ("FATAL: entropy source init failed");
         raise Program_Error with "entropy init failed";
      end if;
   end Init;

   procedure Random (Output : out SPARKNaCl.Byte_Seq) is
      use type SPARKNaCl.N32;
      Len : constant Natural := Natural (Output'Length);
      Buf : SPARKEntropy.Byte_Seq (0 .. Len - 1);
      OK  : Boolean;
   begin
      SPARKEntropy.Generate (State, Buf, OK);
      if not OK then
         Ada.Text_IO.Put_Line ("FATAL: entropy generation failed");
         raise Program_Error with "entropy generation failed";
      end if;
      for I in 0 .. Len - 1 loop
         Output (Output'First + SPARKNaCl.N32 (I)) :=
            SPARKNaCl.Byte (Buf (I));
      end loop;
   end Random;

end Entropy_Random;
