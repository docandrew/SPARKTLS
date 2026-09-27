--  FIPS 140-3 pre-operational software integrity test (AS05.05, IG 10.2.A).
--
--  The library's linker script (ld/sparktls_fips.ld) gathers the module's
--  code and read-only data into .fips_text and .fips_rodata; after the
--  final link, tools/fips_inject writes HMAC-SHA-256 of both into
--  .fips_hmac. Check recomputes the two MACs over the module as loaded in
--  memory and compares. It fails for a binary that fips_inject has not
--  processed, and for any change to the module's bytes since.
package SPARKTLS.Integrity
  with SPARK_Mode     => On,
       Abstract_State => (Module_Image with External => Async_Writers)
is
   procedure Check (Intact : out Boolean)
   with Global => (Input => Module_Image);
end SPARKTLS.Integrity;
