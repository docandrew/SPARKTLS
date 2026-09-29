--  Every random byte the CLI uses (key generation, ECDSA blinding,
--  certificate serial numbers) comes from SPARKTLS.RBG, the module's
--  SP 800-90A generator, started once by SPARKTLS.Initialize in FIPS mode:
--  the algorithm self-tests and the software integrity test run first, as
--  for any application. The raw entropy source only seeds the generator.
with X509;

package CLI_Random is
   --  Start the module if it is not running. OK = False: it could not start
   --  (a self-test, the integrity test or the entropy source failed); the
   --  reason has been printed on standard error.
   procedure Start (OK : out Boolean);

   --  Fill Output from the generator, starting the module first if needed.
   --  OK = False: the module is not running or the draw failed; Output is
   --  then all zero and must not be used.
   procedure Get (Output : out X509.Byte_Seq; OK : out Boolean);
end CLI_Random;
