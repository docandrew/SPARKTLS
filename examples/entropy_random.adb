--  /dev/urandom-backed entropy for the examples and tests. Not SPARK.
--
--  The read is serialised through a protected object: the example servers
--  handle one connection per task, and two tasks opening the same file at
--  once fail GNAT's shared-file check ("reopening shared file"), which
--  surfaced as dropped connections under TLS-Anvil (2026-09-14).
with Ada.Streams.Stream_IO;
package body Entropy_Random is

   protected Urandom is
      procedure Read (Output : out SPARKNaCl.Byte_Seq);
   end Urandom;

   protected body Urandom is
      procedure Read (Output : out SPARKNaCl.Byte_Seq) is
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
      end Read;
   end Urandom;

   procedure Init is
   begin
      null;  --  /dev/urandom needs no initialization
   end Init;

   procedure Random (Output : out SPARKNaCl.Byte_Seq) is
   begin
      Urandom.Read (Output);
   end Random;

end Entropy_Random;
