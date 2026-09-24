--  Test-only entropy injection for SPARKTLS.RBG.
--
--  SPARKTLS.RBG always draws from SPARKEntropy. Unit tests and fuzzers
--  need reproducible randomness, and some need a source that fails; this
--  child reaches the parent's private Init_With to plug one in.
--
--  IMPORTANT: like SPARKTLS.Test_Support, this unit lives under tests/,
--  NOT src/, and is never compiled into or shipped with libsparktls. Do not
--  move it into src/: that would hand consumers a supported way to seed the
--  library's generator from something other than its entropy source.
with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.RBG.Testing is

   --  A stand-in entropy source: fill Output, OK = False to report a
   --  persistent failure.
   type Test_Source is access procedure (Output : out Byte_Seq; OK : out Boolean);

   --  Start the generator on Source instead of SPARKEntropy. Start_Fails
   --  makes the entropy source's start-up test fail. Core_Requests, when
   --  not 0, shortens the core DRBG's reseed interval (normally the
   --  SP 800-90A maximum) so its reseed from Source can be reached. The usual Init rules
   --  apply: a no-op while Ready (call Shutdown first to restart).
   procedure Init_From
     (Source          : Test_Source;
      OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      Reseed_Requests : Positive := Default_Reseed_Requests;
      Core_Requests   : Natural := 0;
      Start_Fails     : Boolean := False)
   with Pre => Source /= null;

end SPARKTLS.RBG.Testing;
