--  /dev/urandom-backed entropy for the examples and tests. Not SPARK.
--
--  Pooled: one 4 KB read refills a buffer that is then handed out in
--  slices, so a handshake (about twenty Random calls) costs a fraction of
--  a syscall instead of twenty of them. The kernel derives a fresh key for
--  every getrandom/urandom read regardless of size, so the cost is per
--  call, not per byte; before pooling the example server spent ~16% of its
--  CPU in the kernel's ChaCha (perf, 2026-09-21). Consumed bytes are
--  zeroed as they leave the pool.
--
--  The pool is a protected object: the example servers handle one
--  connection per task, and two tasks reading the same file at once fail
--  GNAT's shared-file check ("reopening shared file"), which surfaced as
--  dropped connections under TLS-Anvil (2026-09-14).
with Ada.Streams.Stream_IO;
package body Entropy_Random is
   use type SPARKNaCl.N32;

   Pool_Size : constant := 4096;

   protected Urandom is
      procedure Read (Output : out SPARKNaCl.Byte_Seq);
   private
      Pool : SPARKNaCl.Byte_Seq (0 .. Pool_Size - 1) := (others => 0);
      Left : Natural := 0;   --  unread bytes at the end of Pool
   end Urandom;

   protected body Urandom is

      procedure Refill is
         use Ada.Streams;
         use Ada.Streams.Stream_IO;
         F    : File_Type;
         Buf  : Stream_Element_Array (1 .. Pool_Size);
         Last : Stream_Element_Offset;
      begin
         Open (F, In_File, "/dev/urandom");
         Read (F, Buf, Last);
         Close (F);
         if Last /= Buf'Last then
            raise Program_Error with "short read from /dev/urandom";
         end if;
         for I in Pool'Range loop
            Pool (I) := SPARKNaCl.Byte (Buf (Stream_Element_Offset (I) + 1));
         end loop;
         Left := Pool_Size;
      end Refill;

      procedure Read (Output : out SPARKNaCl.Byte_Seq) is
      begin
         for I in Output'Range loop
            if Left = 0 then
               Refill;
            end if;
            --  Hand out from the top of the pool downwards, zeroing as we go
            Output (I) := Pool (SPARKNaCl.N32 (Left - 1));
            Pool (SPARKNaCl.N32 (Left - 1)) := 0;
            Left := Left - 1;
         end loop;
      end Read;

   end Urandom;

   procedure Init is
   begin
      null;  --  the pool fills on first use
   end Init;

   procedure Random (Output : out SPARKNaCl.Byte_Seq) is
   begin
      Urandom.Read (Output);
   end Random;

end Entropy_Random;
