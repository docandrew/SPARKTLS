with System.Storage_Elements; use System.Storage_Elements;
with Interfaces;              use Interfaces;
with SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;

--  SPARK_Mode Off: the check reads the module's own loaded image between
--  linker-defined symbols, through address overlays. The hash itself is
--  SPARKTLSCrypto's proven SHA-256.
package body SPARKTLS.Integrity with SPARK_Mode => Off is

   --  Bracketing symbols defined by ld/sparktls_fips.ld; only their
   --  addresses are used.
   Text_Start   : constant Character
     with Import, Convention => C, External_Name => "__fips_text_start";
   Text_End     : constant Character
     with Import, Convention => C, External_Name => "__fips_text_end";
   Rodata_Start : constant Character
     with Import, Convention => C, External_Name => "__fips_rodata_start";
   Rodata_End   : constant Character
     with Import, Convention => C, External_Name => "__fips_rodata_end";

   --  The expected MACs, code then read-only data, written by fips_inject.
   --  Its own section keeps it outside both hashed ranges; Volatile keeps
   --  the compiler from folding the placeholder into the comparison.
   Expected : SPARKNaCl.Byte_Seq (0 .. 63) := (others => 16#A5#)
     with Volatile, Export, Convention => C,
          External_Name  => "sparktls_fips_expected_hmac",
          Linker_Section => ".fips_hmac";

   --  HMAC-SHA-256 (RFC 2104) with a fixed key of 32 zero bytes, as
   --  BoringSSL and AWS-LC use; FIPS 140-3 permits a fixed integrity key.
   --  Computed incrementally over the loaded image in slices, never copying
   --  it: a debug build's module is several megabytes, and the one-shot
   --  HMAC builds its whole message on the stack. tools/fips_inject makes
   --  the same computation over the file.
   Slice : constant := 65_536;

   function Region_MAC (First, Last : System.Address) return SPARKNaCl.Byte_Seq is
      use SPARKNaCl;
      package H renames SPARKTLSCrypto.Hashing.SHA256;
      Len   : constant Storage_Offset := Last - First;
      --  The zero key padded to the 64-byte block, XORed with ipad / opad.
      Ipad  : constant Byte_Seq (0 .. 63) := (others => 16#36#);
      Opad  : constant Byte_Seq (0 .. 63) := (others => 16#5C#);
      Ctx   : H.Context;
      Inner : H.Digest;
      Outer : H.Digest;
      Done  : Storage_Offset := 0;
   begin
      if Len <= 0 then
         return (0 .. 31 => 0);
      end if;
      H.Init (Ctx);
      H.Update (Ctx, Ipad);
      while Done < Len loop
         declare
            N     : constant Storage_Offset := Storage_Offset'Min (Slice, Len - Done);
            Piece : Byte_Seq (0 .. N32 (N) - N32 (1)) with Import, Address => First + Done;
         begin
            H.Update (Ctx, Piece);
            Done := Done + N;
         end;
      end loop;
      H.Final (Ctx, Inner);
      H.Init (Ctx);
      H.Update (Ctx, Opad);
      H.Update (Ctx, Byte_Seq (Inner));
      H.Final (Ctx, Outer);
      return Byte_Seq (Outer);
   end Region_MAC;

   procedure Check (Intact : out Boolean) is
      use SPARKNaCl;
      Got  : constant Byte_Seq :=
        Region_MAC (Text_Start'Address, Text_End'Address)
        & Region_MAC (Rodata_Start'Address, Rodata_End'Address);
      Want : constant Byte_Seq (0 .. 63) := Expected;
      Diff : Byte := 0;
   begin
      --  Constant-time for form's sake; nothing here is secret.
      for I in Want'Range loop
         Diff := Diff or (Got (I) xor Want (I));
      end loop;
      Intact := Diff = 0;
   end Check;

end SPARKTLS.Integrity;
