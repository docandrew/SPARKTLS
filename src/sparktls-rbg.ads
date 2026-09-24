--  The random bit generator behind every random byte SPARKTLS uses.
--
--  Construction (SP 800-90C section 7): a two-level DRBG tree. Both DRBGs
--  are SP 800-90A HMAC_DRBGs (SHA-256, SPARKTLSCrypto.HMAC_DRBG).
--
--    * The core DRBG is the root. It is seeded from a full-entropy source,
--      SPARKEntropy (CPU jitter, SP 800-90B health tests with intermittent
--      and persistent failure tiers inside it), and reseeded from it only at
--      the SP 800-90A limit of 2**48 requests, so in practice never unless
--      the application calls Reseed.
--    * The serving DRBG answers every Random request. It is seeded from the
--      core and reseeded from the core every Reseed_Requests requests
--      (7.1.2.2: a non-root DRBG's randomness source is its parent).
--
--  The jitter source takes milliseconds, the core microseconds, so after
--  Init no request waits on jitter. The application's whole duty is to
--  call Init once, before the first handshake.
--
--  Init is the start-up request of SP 800-90C 8.1.1 and reaches both
--  components: it starts SPARKEntropy (its 1024-sample start-up health
--  test), runs the DRBG's known-answer self-test (instantiate, reseed,
--  generate; SP 800-90A 11.3), instantiates the core from 48 source bytes
--  (3s/2 bits at s = 256), then the serving DRBG from 48 core bytes.
--  Serving reseeds take 32 core bytes (s bits); core reseeds 32 source
--  bytes.
--
--  Concurrency: one protected object, protected procedures and functions
--  only (no entries), legal under Ravenscar, Jorvik and the full runtime.
--  Both DRBGs run inside it, so no two requests share state; their SHA-NI
--  hashing is justified as non-blocking where it is called. The jitter
--  source runs outside it (its timer read is not provably non-blocking)
--  and is used by one task at a time: Init, Reseed, or the one task the
--  object hands a due core reseed to while the others keep generating
--  (SP 800-90C 7.3.1 item 12).
--
--  Failure (SP 800-90C 8.1.2, SP 800-90A 11.4.2): when the entropy source
--  reports a persistent failure, or a self-test fails, the generator
--  latches into Error, Random hands back nothing (all zero) from then on,
--  and On_Failure is called once so the application can shut down
--  carefully. The library never raises or exits; SPARKTLS.Draw turns the
--  zeros into Entropy_Failure for every session that draws afterwards.
--  Init again re-runs every start-up test and returns to service.
--
--  Process duplication: a fork, or a restored VM snapshot, copies the whole
--  generator, and both copies then produce the same bytes. The library
--  cannot detect either; the application calls Reseed in the new process
--  (or after the restore) before it next draws.
with SPARKNaCl; use SPARKNaCl;
with SPARKEntropy;

package SPARKTLS.RBG with
   SPARK_Mode => On
is

   --  Told once when the generator latches into Error. Called outside the
   --  generator's protected object; must be quick and must not call Random.
   type Entropy_Failure_Fn is access procedure;

   type RBG_Status is (Uninstantiated, Ready, Error);

   Default_Reseed_Requests : constant := 4096;   --  serving-DRBG requests between reseeds

   --  Start the entropy source and both DRBGs (see above). OK = False if a
   --  start-up test failed or the platform timer has no usable jitter;
   --  Status is then Error. A no-op returning OK = True while Ready. OSR is
   --  the jitter source's oversampling rate for this platform (see
   --  SPARKEntropy.Min_OSR). Reseed_Requests is the serving DRBG's interval.
   procedure Init
     (OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      OSR             : SPARKEntropy.OSR_Range := SPARKEntropy.Min_OSR;
      Reseed_Requests : Positive := Default_Reseed_Requests);

   --  Reseed the core from fresh entropy-source output, then the serving
   --  DRBG from the core. Takes as long as the jitter source (milliseconds),
   --  in the calling task only. Call it in a forked child or after a VM
   --  restore (see above), or on the application's own schedule. OK = False
   --  when the generator is not Ready, when another task is seeding it at
   --  that moment (call again), or when the source failed: Status is then
   --  Error and On_Failure has been called, as for any source failure.
   procedure Reseed (OK : out Boolean);

   --  Fill Output from the generator. All zero unless Status = Ready.
   procedure Random (Output : out Byte_Seq);

   --  Sanitize the generator and return to Uninstantiated, so the next
   --  Init starts everything afresh (orderly shutdown, tests).
   procedure Shutdown;

   --  Volatile: they read the generator's protected state. In SPARK code
   --  bind the result to a constant before using it in an expression.
   function Status return RBG_Status with Volatile_Function;

   --  Serving-DRBG reseeds since Init (each from the core).
   function Reseeds return Natural with Volatile_Function;

   --  The entropy source's oversampling rate in force (raised by one for
   --  every intermittent health failure it recovered from) and the count of
   --  such recoveries, as of its last use. For the application's logging.
   function Entropy_OSR return Natural with Volatile_Function;
   function Entropy_Resets return Natural with Volatile_Function;

private

   --  A stand-in entropy source, for the test-only child
   --  SPARKTLS.RBG.Testing (tests/support, never shipped). Init uses
   --  SPARKEntropy, called directly; Init_With runs the same start-up
   --  sequence on Source instead (Start_OK = False simulates a failed
   --  source start-up test). Core_Requests shortens the core's reseed
   --  interval so tests reach its reseed from the source; 0 is the
   --  SP 800-90A maximum that Init uses.
   type Entropy_Source_Fn is access procedure (Output : out Byte_Seq; OK : out Boolean);

   procedure Init_With
     (Source          : Entropy_Source_Fn;
      Start_OK        : Boolean;
      OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      OSR             : Natural := SPARKEntropy.Min_OSR;
      Reseed_Requests : Positive := Default_Reseed_Requests;
      Core_Requests   : Natural := 0)
   with Pre => Source /= null;

end SPARKTLS.RBG;
