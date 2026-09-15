--  Dudect-style statistical timing analysis helper.
--
--  Runs the supplied subject closure many times with two different
--  secret inputs, captures rdtsc cycle counts, and applies Welch's
--  t-test to the timing distributions. If |t| exceeds a threshold
--  (4.5 → ~99.999% confidence), the timing is statistically
--  correlated with the secret input — i.e. a side-channel.
--
--  Important details that make a dudect harness sound vs. flaky:
--   - Interleave samples (don't run all of class 0 then all of
--     class 1 — system load drifts contaminate that), and randomise
--     which class goes first in each pair (a fixed order turns any
--     first-slot/second-slot effect into a constant class offset).
--   - Drop "outlier" samples at the high tail (interrupts, page
--     faults, etc. show up as large positive cycle counts).
--   - Do many iterations: 100K+ for rare leaks, 10K for obvious ones.

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Numerics.Elementary_Functions;
   use Ada.Numerics.Elementary_Functions;
with Interfaces;  use Interfaces;
with System.Machine_Code; use System.Machine_Code;

package body Dudect_Helpers is

   --------------------
   --  rdtsc wrapper
   --------------------

   function Rdtsc return Unsigned_64 is
      Lo, Hi : Unsigned_32;
   begin
      Asm ("rdtsc",
           Outputs => (Unsigned_32'Asm_Output ("=a", Lo),
                       Unsigned_32'Asm_Output ("=d", Hi)),
           Volatile => True);
      return Unsigned_64 (Hi) * 2**32 or Unsigned_64 (Lo);
   end Rdtsc;

   ----------------------------------------------------------------
   --  Run a subject N times each for two secret-input classes,
   --  interleaving to even out drift, drop outliers, and report
   --  Welch's t-statistic.
   ----------------------------------------------------------------

   --  Core: per class, an untimed Prepare followed by a timed Subject,
   --  both told the class as a Boolean. The two public forms map onto
   --  it: the two-closure form dispatches on the Boolean (a branch, so
   --  two code paths; fine for slow subjects), the dudect form passes
   --  it straight through to the caller's Prepare and ignores it in
   --  Subject.
   procedure Time_Test_Core
     (Name      : String;
      Prepare   : not null access procedure (Second : Boolean);
      Subject   : not null access procedure (Second : Boolean);
      N         : Positive;
      Threshold : Float)
   is
      type Sample_Array is array (Positive range <>) of Unsigned_64;
      subtype Samples is Sample_Array (1 .. N);
      --  Indexed by the class Boolean so the store after each
      --  measurement is the same instruction for both classes.
      T : array (Boolean) of Samples;

      --  Warm-up: prime caches / branch predictor. Discarded.
      Warmup : constant := 1_000;

      --  Per-iteration class order, and ONE code path for both classes.
      --
      --  Running class 0 first and class 1 second in every pair let a
      --  systematic slot effect (back-to-back rdtsc, cache/TLB state
      --  left by the previous call, frequency ramp, ...) appear as a
      --  constant offset between the classes. On a ~5K-cycle subject
      --  with n = 20K the standard error of the mean difference is
      --  ~0.3 cycles, so a 1-2 cycle slot bias alone reads as t = 5..9
      --  and fails the 4.5 threshold even though the code is
      --  data-oblivious (observed on dudect_aead; class 0 was slower by
      --  the same 1-2 cycles in every run). Real dudect draws the class
      --  at random per sample for this reason. Drawing the order at
      --  random averages the slot bias out while keeping n equal per
      --  class. xorshift64 with a fixed seed: reproducible, no I/O.
      --
      --  The order must also not select between two copies of the
      --  measurement code. An `if` with a Measure call per arm gets
      --  Measure inlined four times, so each class runs through its own
      --  two copies of the rdtsc/call sequence at its own addresses,
      --  and how those alias in the branch predictors varies with the
      --  per-process load address. Measured: t up to ~20 with the class
      --  a pure data value in the subject, sign flipping between
      --  builds and runs. So: one Measure call site, the class is a
      --  Boolean computed with xor and used as an array index, never
      --  branched on.
      Rng : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;

      procedure Measure (Second : Boolean; Cycles : out Unsigned_64) is
         Pre, Post : Unsigned_64;
      begin
         Prepare (Second);
         Pre := Rdtsc;
         Subject (Second);
         Post := Rdtsc;
         Cycles := Post - Pre;
      end Measure;
   begin
      for I in 1 .. Warmup loop
         Prepare (False);
         Subject (False);
         Prepare (True);
         Subject (True);
      end loop;

      --  Interleaved measurement, random order within each pair.
      for I in 1 .. N loop
         Rng := Rng xor Shift_Left (Rng, 13);
         Rng := Rng xor Shift_Right (Rng, 7);
         Rng := Rng xor Shift_Left (Rng, 17);
         declare
            First_Is_Second : constant Boolean := (Rng and 1) = 1;
         begin
            for Slot in Boolean loop
               declare
                  Class : constant Boolean := First_Is_Second xor Slot;
               begin
                  Measure (Class, T (Class) (I));
               end;
            end loop;
         end;
      end loop;

      --  Compute trimmed mean and variance. Drop the top 5% as
      --  outliers (typically interrupts, etc.).
      declare
         function Trimmed_Stats
           (S : Sample_Array; Mean, Var : out Float)
            return Natural
         is
            --  Naive: compute median-ish cutoff via simple max-trim.
            --  For 50K samples this is fine.
            Cutoff_Pct : constant := 0.05;
            Drop : constant Natural := Natural (Float (S'Length) * Cutoff_Pct);
            Sorted : Sample_Array := S;
            Sum : Long_Float := 0.0;
            Sq  : Long_Float := 0.0;
            M   : Long_Float;
            Cnt : Natural;
         begin
            --  Bubble-sort top Drop elements out — bad O() but small.
            for Pass in 1 .. Drop loop
               for I in Sorted'First .. Sorted'Last - Pass loop
                  if Sorted (I) > Sorted (I + 1) then
                     declare
                        Tmp : constant Unsigned_64 := Sorted (I);
                     begin
                        Sorted (I) := Sorted (I + 1);
                        Sorted (I + 1) := Tmp;
                     end;
                  end if;
               end loop;
            end loop;
            Cnt := Sorted'Length - Drop;
            for I in Sorted'First .. Sorted'First + Cnt - 1 loop
               Sum := Sum + Long_Float (Sorted (I));
            end loop;
            M := Sum / Long_Float (Cnt);
            for I in Sorted'First .. Sorted'First + Cnt - 1 loop
               Sq := Sq + (Long_Float (Sorted (I)) - M) ** 2;
            end loop;
            Mean := Float (M);
            Var := Float (Sq / Long_Float (Cnt - 1));
            return Cnt;
         end Trimmed_Stats;

         M0, M1, V0, V1 : Float;
         N0, N1 : Natural;
         T_Stat : Float;
      begin
         N0 := Trimmed_Stats (T (False), M0, V0);
         N1 := Trimmed_Stats (T (True), M1, V1);
         T_Stat := abs (M0 - M1) /
           Sqrt (V0 / Float (N0) + V1 / Float (N1));

         Put_Line (Name & ":");
         Put_Line ("  class0 mean = " & M0'Image
                   & "  var = " & V0'Image
                   & "  n = " & N0'Image);
         Put_Line ("  class1 mean = " & M1'Image
                   & "  var = " & V1'Image
                   & "  n = " & N1'Image);
         Put_Line ("  Welch's t  = " & T_Stat'Image
                   & "   (threshold = " & Threshold'Image & ")");
         if T_Stat > Threshold then
            Put_Line ("  *** TIMING DEPENDS ON SECRET INPUT ***");
         else
            Put_Line ("  ok — timing independent of secret"
                      & " (within statistical noise)");
         end if;
      end;
   end Time_Test_Core;

   procedure Time_Test
     (Name      : String;
      Subject_0 : not null access procedure;
      Subject_1 : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5)
   is
      procedure No_Prepare (Second : Boolean) is null;
      procedure Dispatch (Second : Boolean) is
      begin
         if Second then
            Subject_1.all;
         else
            Subject_0.all;
         end if;
      end Dispatch;
   begin
      Time_Test_Core
        (Name, No_Prepare'Access, Dispatch'Access, N, Threshold);
   end Time_Test;

   procedure Time_Test
     (Name      : String;
      Prepare   : not null access procedure (Second : Boolean);
      Subject   : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5)
   is
      procedure Run (Second : Boolean) is
         pragma Unreferenced (Second);
      begin
         Subject.all;
      end Run;
   begin
      Time_Test_Core (Name, Prepare, Run'Access, N, Threshold);
   end Time_Test;

end Dudect_Helpers;
