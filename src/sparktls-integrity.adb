with System.Storage_Elements; use System.Storage_Elements;
with Interfaces;              use Interfaces;
with SPARKNaCl;
with SPARKNaCl.MAC;
with SPARKNaCl.Hashing.SHA256;

--  SPARK_Mode Off: the check reads the module's own loaded image between
--  linker-defined symbols, through address overlays. The MAC itself is
--  SPARKNaCl's proven HMAC-SHA-256.
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

   --  FIPS 140-3 permits a fixed key for the integrity MAC; BoringSSL and
   --  AWS-LC use the same 32 zero bytes.
   Key : constant SPARKNaCl.Byte_Seq (0 .. 31) := (others => 0);

   function Region_MAC (First, Last : System.Address) return SPARKNaCl.Byte_Seq is
      use SPARKNaCl;
      Len : constant Storage_Offset := Last - First;
      D   : Hashing.SHA256.Digest;
   begin
      if Len <= 0 or else Len > Storage_Offset (N32'Last - 64) then
         return (0 .. 31 => 0);
      end if;
      declare
         Region : Byte_Seq (0 .. N32 (Len) - N32 (1)) with Import, Address => First;
      begin
         MAC.HMAC_SHA_256 (D, Region, Key);
      end;
      return Byte_Seq (D);
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
