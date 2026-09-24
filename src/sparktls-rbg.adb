with SPARKTLSCrypto.HMAC_DRBG;
with SHAKE;

package body SPARKTLS.RBG with
   SPARK_Mode => On
is
   package DRBG renames SPARKTLSCrypto.HMAC_DRBG;
   use type SHAKE.SHAKE256.States;

   Seed_Len    : constant := 48;   --  3s/2 bits at instantiation
   Reseed_Len  : constant := 32;   --  s bits at reseed
   Empty       : constant Byte_Seq (0 .. -1) := (others => 0);

   ----------------------------------------------------------------------------
   --  The entropy source: SPARKEntropy, one state for the process. Used by
   --  one task at a time (Init, Reseed, or the task Gen handed a core
   --  reseed to), never inside the protected object.
   ----------------------------------------------------------------------------

   Jitter : SPARKEntropy.Entropy_State;

   procedure Jitter_Start (OSR : Natural; OK : out Boolean) is
      Rate : constant SPARKEntropy.OSR_Range :=
        (if OSR in SPARKEntropy.OSR_Range then OSR else SPARKEntropy.Min_OSR);
   begin
      SPARKEntropy.Init (Jitter, OK, Rate);
   end Jitter_Start;

   procedure Jitter_Get (Output : out Byte_Seq; OK : out Boolean) is
   begin
      Output := (others => 0);
      OK := False;
      if Output'Length = 0
        or else SHAKE.SHAKE256.State_Of (Jitter.Pool) /= SHAKE.SHAKE256.Updating
      then
         return;   --  never started, or not in a state that can produce
      end if;
      declare
         Raw : SPARKEntropy.Byte_Seq (0 .. Natural (Output'Length) - 1);
      begin
         SPARKEntropy.Generate (Jitter, Raw, OK);
         for I in Output'Range loop
            Output (I) := Byte (Raw (Natural (I - Output'First)));
         end loop;
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "*is set by*");
         Raw := (others => 0);
         pragma Warnings (GNATprove, On, "*is set by*");
         pragma Warnings (GNATprove, On, "statement has no effect");
      end;
   end Jitter_Get;

   ----------------------------------------------------------------------------
   --  The tree's two seeding steps, each a few HMACs. Called only from
   --  inside Gen.
   ----------------------------------------------------------------------------

   --  Instantiate Serving from 48 bytes (3s/2 bits) of Core output
   --  (SP 800-90C 2.2 item 11). OK = False, Serving uninstantiated, when the
   --  core must be reseeded first.
   procedure Spawn (Core : in out DRBG.State; Serving : out DRBG.State; OK : out Boolean)
   with Global => null,
        Pre    => DRBG.Instantiated (Core),
        Post   => DRBG.Instantiated (Core) and then (if OK then DRBG.Instantiated (Serving))
   is
      Seed : Byte_Seq (0 .. Seed_Len - 1);
   begin
      DRBG.Sanitize (Serving);
      DRBG.Generate (Core, Empty, Seed, OK);
      if OK then
         declare
            Entropy : constant Byte_Seq (0 .. 31) := Seed (0 .. 31);
            Nonce   : constant Byte_Seq (0 .. 15) := Seed (32 .. 47);
         begin
            DRBG.Instantiate (Serving, Entropy, Nonce, Empty);
         end;
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Spawn;

   --  Reseed Serving from 32 bytes (s bits) of Core output. OK = False,
   --  nothing reseeded, when the core must be reseeded first.
   procedure Refresh (Core, Serving : in out DRBG.State; OK : out Boolean)
   with Global => null,
        Pre    => DRBG.Instantiated (Core) and DRBG.Instantiated (Serving),
        Post   => DRBG.Instantiated (Core) and DRBG.Instantiated (Serving)
   is
      Seed : Byte_Seq (0 .. Reseed_Len - 1);
   begin
      DRBG.Generate (Core, Empty, Seed, OK);
      if OK then
         DRBG.Reseed (Serving, Seed, Empty);
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Refresh;

   --  Reseed Core from Seed (source output), then Serving from Core. OK =
   --  False only if the fresh core could not serve, which the DRBG's
   --  contracts do not rule out.
   procedure Reseed_Tree
     (Core, Serving : in out DRBG.State;
      Seed          : Byte_Seq;
      OK            : out Boolean)
   with Global => null,
        Pre    => DRBG.Instantiated (Core) and DRBG.Instantiated (Serving)
                  and Seed'First = 0 and Seed'Length = Reseed_Len,
        Post   => DRBG.Instantiated (Core) and DRBG.Instantiated (Serving)
   is
   begin
      DRBG.Reseed (Core, Seed, Empty);
      Refresh (Core, Serving, OK);
   end Reseed_Tree;

   ----------------------------------------------------------------------------
   --  The generator
   ----------------------------------------------------------------------------

   protected Gen is
      --  Claim the start-up sequence: False if already Ready or another
      --  task is seeding.
      procedure Begin_Init (Go : out Boolean);

      --  Instantiate the core from Seed (source output), then the serving
      --  DRBG from the core. OK = False leaves the generator unchanged.
      procedure Instantiate
        (Seed          : Byte_Seq;
         Source        : Entropy_Source_Fn;
         Failure       : Entropy_Failure_Fn;
         Requests      : Positive;
         Core_Interval : Unsigned_64;
         OK            : out Boolean)
      with Pre => Seed'First = 0 and Seed'Length = Seed_Len
                  and Core_Interval in 1 .. DRBG.Max_Reseed_Interval;

      --  Serve Output if Ready, first reseeding the serving DRBG from the
      --  core when its interval is up. If the core itself is due a reseed
      --  and no other task is drawing a seed, this task is handed that
      --  reseed instead: Need_Seed, with the source to draw from; Output is
      --  then zero.
      procedure Draw
        (Output    : out Byte_Seq;
         Need_Seed : out Boolean;
         Source    : out Entropy_Source_Fn)
      with Pre => Output'First = 0 and Output'Length in 1 .. DRBG.Max_Request;

      --  Claim a reseed from the source for the calling task (Reseed):
      --  False if not Ready or another task is already seeding.
      procedure Begin_Reseed (Go : out Boolean; Source : out Entropy_Source_Fn);

      --  Reseed the core from Seed (source output) and the serving DRBG
      --  from the core, ending the claim.
      procedure Reseed_Core (Seed : Byte_Seq)
      with Pre => Seed'First = 0 and Seed'Length = Reseed_Len;

      --  Reseed_Core, then serve Output, in one protected action (the task
      --  Draw handed the core reseed to).
      procedure Reseed_Core_And_Draw (Seed : Byte_Seq; Output : out Byte_Seq)
      with Pre => Seed'First = 0 and Seed'Length = Reseed_Len
                  and Output'First = 0 and Output'Length in 1 .. DRBG.Max_Request;

      --  Latch into Error (ending any claim). Notify is True exactly once,
      --  with the failure callback to invoke.
      procedure Fail (Notify : out Boolean; Failure : out Entropy_Failure_Fn);

      procedure Note_Source (OSR, Resets : Natural);

      procedure Stop;

      function Current return RBG_Status;
      function Reseed_Count return Natural;
      function Source_OSR return Natural;
      function Source_Resets return Natural;
   private
      Core        : DRBG.State;
      Serving     : DRBG.State;
      St          : RBG_Status := Uninstantiated;
      Seeding     : Boolean := False;   --  one task is drawing from the source
      Since_Seed  : Natural := 0;       --  serving requests since its last seed
      Interval    : Positive := Default_Reseed_Requests;
      Count       : Natural := 0;
      Notified    : Boolean := False;
      Source_Fn   : Entropy_Source_Fn := null;   --  null: SPARKEntropy (Jitter)
      Failure_Fn  : Entropy_Failure_Fn := null;
      Src_OSR     : Natural := 0;
      Src_Resets  : Natural := 0;
   end Gen;

   protected body Gen is

      --  The DRBGs hash through SPARKTLSCrypto.Hashing.SHA256, whose
      --  SHA-NI block function and its dispatcher are SPARK_Mode => Off, so
      --  gnatprove cannot see that they never block and reports each DRBG
      --  call here as potentially blocking. They are straight-line
      --  computation: register and memory arithmetic on the hash state and
      --  one message block, the dispatch reading a constant set at
      --  elaboration, with no I/O, delay, entry call or task interaction.
      --  Each call is justified individually below.

      procedure Begin_Init (Go : out Boolean) is
      begin
         Go := St /= Ready and then not Seeding;
         if Go then
            Seeding := True;
         end if;
      end Begin_Init;

      procedure Instantiate
        (Seed          : Byte_Seq;
         Source        : Entropy_Source_Fn;
         Failure       : Entropy_Failure_Fn;
         Requests      : Positive;
         Core_Interval : Unsigned_64;
         OK            : out Boolean)
      is
         Entropy : constant Byte_Seq (0 .. 31) := Seed (0 .. 31);
         Nonce   : constant Byte_Seq (0 .. 15) := Seed (32 .. 47);
      begin
         DRBG.Instantiate (Core, Entropy, Nonce, Empty, Core_Interval);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
         Spawn (Core, Serving, OK);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
         if not OK then
            DRBG.Sanitize (Core);
            return;   --  St and Seeding stay as they are; the caller fails
         end if;
         --  The serving DRBG's own limit is the SP 800-90A maximum; its
         --  reseed policy is counted here.
         St         := Ready;
         Seeding    := False;
         Since_Seed := 0;
         Interval   := Requests;
         Count      := 0;
         Notified   := False;
         Source_Fn  := Source;
         Failure_Fn := Failure;
      end Instantiate;

      procedure Draw
        (Output    : out Byte_Seq;
         Need_Seed : out Boolean;
         Source    : out Entropy_Source_Fn)
      is
         OK : Boolean;
      begin
         Output := (others => 0);
         Need_Seed := False;
         Source := Source_Fn;
         if St /= Ready
           or else not DRBG.Instantiated (Core)
           or else not DRBG.Instantiated (Serving)
         then
            return;
         end if;
         if Since_Seed >= Interval then
            Refresh (Core, Serving, OK);
            pragma Annotate (GNATprove, False_Positive,
               "call to potentially blocking subprogram",
               "SHA-256 block functions are straight-line computation");
            if OK then
               Since_Seed := 0;
               if Count < Natural'Last then
                  Count := Count + 1;
               end if;
            elsif not Seeding then
               --  The core is at its own limit: fetch it a seed.
               Seeding := True;
               Need_Seed := True;
               return;
            end if;
            --  Otherwise another task is fetching the core's seed; the
            --  serving DRBG keeps generating meanwhile (7.3.1 item 12).
         end if;
         DRBG.Generate (Serving, Empty, Output, OK);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
         if OK then
            if Since_Seed < Natural'Last then
               Since_Seed := Since_Seed + 1;
            end if;
         else
            Output := (others => 0);   --  past the SP 800-90A maximum
         end if;
      end Draw;

      procedure Begin_Reseed (Go : out Boolean; Source : out Entropy_Source_Fn) is
      begin
         Go := St = Ready and then not Seeding;
         Source := Source_Fn;
         if Go then
            Seeding := True;
         end if;
      end Begin_Reseed;

      --  Reseed the tree from Seed and restart the serving count, ending
      --  the claim.
      procedure Reseed_From (Seed : Byte_Seq)
      with Pre => Seed'First = 0 and Seed'Length = Reseed_Len
      is
         OK : Boolean;
      begin
         Seeding := False;
         if St /= Ready
           or else not DRBG.Instantiated (Core)
           or else not DRBG.Instantiated (Serving)
         then
            return;
         end if;
         Reseed_Tree (Core, Serving, Seed, OK);
         if OK then
            Since_Seed := 0;
            if Count < Natural'Last then
               Count := Count + 1;
            end if;
         end if;
      end Reseed_From;

      procedure Reseed_Core (Seed : Byte_Seq) is
      begin
         Reseed_From (Seed);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
      end Reseed_Core;

      procedure Reseed_Core_And_Draw (Seed : Byte_Seq; Output : out Byte_Seq) is
         OK : Boolean;
      begin
         Output := (others => 0);
         Reseed_From (Seed);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
         if St /= Ready or else not DRBG.Instantiated (Serving) then
            return;
         end if;
         DRBG.Generate (Serving, Empty, Output, OK);
         pragma Annotate (GNATprove, False_Positive,
            "call to potentially blocking subprogram",
            "SHA-256 block functions are straight-line computation");
         if OK then
            if Since_Seed < Natural'Last then
               Since_Seed := Since_Seed + 1;
            end if;
         else
            Output := (others => 0);
         end if;
      end Reseed_Core_And_Draw;

      procedure Fail (Notify : out Boolean; Failure : out Entropy_Failure_Fn) is
      begin
         DRBG.Sanitize (Core);
         DRBG.Sanitize (Serving);
         St := Error;
         Seeding := False;
         Notify := not Notified;
         Notified := True;
         Failure := Failure_Fn;
      end Fail;

      procedure Note_Source (OSR, Resets : Natural) is
      begin
         Src_OSR := OSR;
         Src_Resets := Resets;
      end Note_Source;

      procedure Stop is
      begin
         DRBG.Sanitize (Core);
         DRBG.Sanitize (Serving);
         St         := Uninstantiated;
         Seeding    := False;
         Since_Seed := 0;
         Count      := 0;
         Notified   := False;
         Source_Fn  := null;
         Failure_Fn := null;
         Src_OSR    := 0;
         Src_Resets := 0;
      end Stop;

      function Current return RBG_Status is (St);
      function Reseed_Count return Natural is (Count);
      function Source_OSR return Natural is (Src_OSR);
      function Source_Resets return Natural is (Src_Resets);

   end Gen;

   --  After a use of the jitter source, record its health for logging.
   procedure Note_Jitter is
   begin
      Gen.Note_Source (SPARKEntropy.Current_OSR (Jitter),
                       SPARKEntropy.Intermittent_Resets (Jitter));
   end Note_Jitter;

   --  Reseed_Len bytes from the source: the jitter source when Source is
   --  null, else Source (tests only).
   procedure Get_Seed (Source : Entropy_Source_Fn; Seed : out Byte_Seq; OK : out Boolean)
   with Pre => Seed'First = 0 and Seed'Length = Reseed_Len
   is
   begin
      if Source = null then
         Jitter_Get (Seed, OK);
         Note_Jitter;
      else
         Source.all (Seed, OK);
      end if;
      OK := OK and then not All_Zero_Bytes (Seed);
   end Get_Seed;

   --  Persistent failure of the entropy source (SP 800-90C 8.1.2.1):
   --  terminate until it is repaired and retested (a new Init).
   procedure Source_Failed is
      Notify  : Boolean;
      Failure : Entropy_Failure_Fn;
   begin
      Gen.Fail (Notify, Failure);
      if Notify and then Failure /= null then
         Failure.all;
      end if;
   end Source_Failed;

   --  The start-up sequence (SP 800-90C 8.1.1), on the jitter source when
   --  Injected is null, else on Injected (tests only).
   procedure Start_Up
     (Injected        : Entropy_Source_Fn;
      Injected_Start  : Boolean;
      OSR             : Natural;
      OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn;
      Reseed_Requests : Positive;
      Core_Requests   : Natural)
   is
      Seed     : Byte_Seq (0 .. Seed_Len - 1) := (others => 0);
      Go       : Boolean;
      Start_OK : Boolean;
      Seed_OK  : Boolean := False;
      Notify   : Boolean;
      Failure  : Entropy_Failure_Fn;
      Core_Interval : constant Unsigned_64 :=
        (if Core_Requests = 0 then DRBG.Max_Reseed_Interval else Unsigned_64 (Core_Requests));
   begin
      OK := False;
      Gen.Begin_Init (Go);
      if not Go then
         declare
            St : constant RBG_Status := Gen.Current;
         begin
            OK := St = Ready;   --  already running (or another task is starting it)
         end;
         return;
      end if;
      --  1. The entropy source's start-up health tests.
      if Injected = null then
         Jitter_Start (OSR, Start_OK);
         Note_Jitter;
      else
         Start_OK := Injected_Start;
      end if;
      --  2. The DRBG's known-answer self-test (SP 800-90A 11.3).
      --  3. The core from 3s/2 bits of source output, the serving DRBG
      --     from the core.
      if Start_OK and then DRBG.Self_Test then
         if Injected = null then
            Jitter_Get (Seed, Seed_OK);
         else
            Injected.all (Seed, Seed_OK);
         end if;
         if Seed_OK and then not All_Zero_Bytes (Seed) then
            Gen.Instantiate (Seed, Injected, On_Failure, Reseed_Requests, Core_Interval, OK);
         end if;
      end if;
      if not OK then
         Gen.Fail (Notify, Failure);
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Start_Up;

   procedure Init_With
     (Source          : Entropy_Source_Fn;
      Start_OK        : Boolean;
      OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      OSR             : Natural := SPARKEntropy.Min_OSR;
      Reseed_Requests : Positive := Default_Reseed_Requests;
      Core_Requests   : Natural := 0)
   is
   begin
      Start_Up (Source, Start_OK, OSR, OK, On_Failure, Reseed_Requests, Core_Requests);
   end Init_With;

   procedure Init
     (OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      OSR             : SPARKEntropy.OSR_Range := SPARKEntropy.Min_OSR;
      Reseed_Requests : Positive := Default_Reseed_Requests)
   is
   begin
      Start_Up (null, True, OSR, OK, On_Failure, Reseed_Requests, 0);
   end Init;

   procedure Reseed (OK : out Boolean) is
      Go     : Boolean;
      Source : Entropy_Source_Fn;
      Seed   : Byte_Seq (0 .. Reseed_Len - 1) := (others => 0);
   begin
      OK := False;
      Gen.Begin_Reseed (Go, Source);
      if not Go then
         return;
      end if;
      Get_Seed (Source, Seed, OK);
      if OK then
         Gen.Reseed_Core (Seed);
      else
         Source_Failed;
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Reseed;

   --  One request of at most Max_Request bytes, taking over a due core
   --  reseed when handed one.
   procedure Draw_Chunk (Buf : out Byte_Seq)
   with Pre => Buf'First = 0 and Buf'Length in 1 .. DRBG.Max_Request
   is
      Need_Seed : Boolean;
      Source    : Entropy_Source_Fn;
      Seed      : Byte_Seq (0 .. Reseed_Len - 1) := (others => 0);
      Seed_OK   : Boolean;
   begin
      Gen.Draw (Buf, Need_Seed, Source);
      if not Need_Seed then
         return;
      end if;
      Get_Seed (Source, Seed, Seed_OK);
      if Seed_OK then
         Gen.Reseed_Core_And_Draw (Seed, Buf);
      else
         Source_Failed;
         Buf := (others => 0);
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Draw_Chunk;

   procedure Random (Output : out Byte_Seq) is
      Pos  : N32;
      Last : N32;   --  index of the last byte of the current chunk
   begin
      Output := (others => 0);
      if Output'Length = 0 then
         return;
      end if;
      Pos := Output'First;
      loop
         pragma Loop_Invariant (Pos in Output'Range);
         pragma Loop_Variant (Increases => Pos);
         Last := Pos + N32'Min (DRBG.Max_Request - 1, Output'Last - Pos);
         declare
            Len : constant N32 := Last - Pos + 1;
            Buf : Byte_Seq (0 .. Len - 1);
         begin
            Draw_Chunk (Buf);
            Output (Pos .. Last) := Buf;
            pragma Warnings (GNATprove, Off, "statement has no effect");
            pragma Warnings (GNATprove, Off, "*is set by*");
            Sanitize (Buf);
            pragma Warnings (GNATprove, On, "*is set by*");
            pragma Warnings (GNATprove, On, "statement has no effect");
         end;
         exit when Last = Output'Last;
         Pos := Last + 1;
      end loop;
   end Random;

   procedure Shutdown is
   begin
      Gen.Stop;
   end Shutdown;

   function Status return RBG_Status is (Gen.Current);
   function Reseeds return Natural is (Gen.Reseed_Count);
   function Entropy_OSR return Natural is (Gen.Source_OSR);
   function Entropy_Resets return Natural is (Gen.Source_Resets);

end SPARKTLS.RBG;
