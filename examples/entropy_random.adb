with Ada.Streams.Stream_IO;

package body Entropy_Random is

   procedure Init is
   begin
      null;  --  /dev/urandom needs no initialization
   end Init;

   procedure Random (Output : out SPARKNaCl.Byte_Seq) is
      use Ada.Streams;
      use Ada.Streams.Stream_IO;
      use type SPARKNaCl.N32;
      F    : File_Type;
      Buf  : Stream_Element_Array (1 .. Stream_Element_Offset (Output'Length));
      Last : Stream_Element_Offset;
   begin
      Open (F, In_File, "/dev/urandom");
      Read (F, Buf, Last);
      Close (F);
      if Last /= Buf'Last then
         raise Program_Error with "short read from /dev/urandom";
      end if;
      for I in 0 .. Output'Length - 1 loop
         Output (Output'First + SPARKNaCl.N32 (I)) :=
            SPARKNaCl.Byte (Buf (Stream_Element_Offset (I) + 1));
      end loop;
   end Random;

end Entropy_Random;
