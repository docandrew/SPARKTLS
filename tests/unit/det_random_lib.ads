--  Library-level deterministic random source for unit tests.

with SPARKNaCl;            use SPARKNaCl;

package Det_Random_Lib is

   procedure Det_Random (Output : out Byte_Seq);
   --  Fills Output with a fixed pattern derived from the offset, so
   --  test output is reproducible across runs.

end Det_Random_Lib;
