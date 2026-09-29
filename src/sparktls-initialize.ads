--  Start the SPARKTLS module. Call it once, before any Configure.
--
--  The first call in a process runs the FIPS 140-3 algorithm self-tests
--  (SPARKTLS.Self_Tests). With Mode = FIPS, the default, it also runs the
--  software integrity test (SPARKTLS.Integrity), which needs the executable
--  to have been through tools/fips_inject after linking, and the module
--  then offers approved algorithms only: Configure refuses sessions with
--  Algorithms => Non_FIPS. With Mode = Non_FIPS the integrity test is
--  skipped (no linker step needed) and sessions may use either setting.
--
--  It then starts the entropy source and the random bit generator
--  (SPARKTLS.RBG). OK = False means the module is in its error state: a
--  self-test, the integrity test or the entropy source failed, and no
--  session can start. A self-test or integrity failure lasts until the
--  process restarts. A second call while the module is running is a no-op
--  returning OK = True.
--
--  On_Failure, OSR and Reseed_Requests are as for SPARKTLS.RBG.Init.
with SPARKEntropy;
with SPARKTLS.RBG;

procedure SPARKTLS.Initialize
  (OK              : out Boolean;
   Mode            : FIPS_Mode := FIPS;
   On_Failure      : SPARKTLS.RBG.Entropy_Failure_Fn := null;
   OSR             : SPARKEntropy.OSR_Range := SPARKEntropy.Min_OSR;
   Reseed_Requests : Positive := SPARKTLS.RBG.Default_Reseed_Requests)
  with SPARK_Mode => On;
