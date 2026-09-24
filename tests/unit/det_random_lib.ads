--  Deterministic randomness for the unit tests: a fixed-pattern ENTROPY
--  SOURCE behind SPARKTLS.RBG, so the DRBG's output is reproducible
--  across runs and identical after every Reset. Not a CSPRNG.
with SPARKNaCl;            use SPARKNaCl;

package Det_Random_Lib is

   --  Entropy_Source_Fn: fills Output with a fixed pattern derived from
   --  the offset; always succeeds.
   procedure Det_Random (Output : out Byte_Seq; OK : out Boolean);

   --  (Re)instantiate SPARKTLS.RBG from Det_Random: the generator is shut
   --  down and started again, so its output sequence restarts from the
   --  same first byte. Call at the start of a test, and again before any
   --  build whose bytes must match an earlier one.
   procedure Reset;

end Det_Random_Lib;
