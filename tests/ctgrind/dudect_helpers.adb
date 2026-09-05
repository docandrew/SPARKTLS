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
--     class 1 — system load drifts contaminate that).
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

   procedure Time_Test
     (Name      : String;
      Subject_0 : not null access procedure;
      Subject_1 : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5)
   is
      type Sample_Array is array (Positive range <>) of Unsigned_64;
      T0 : Sample_Array (1 .. N);
      T1 : Sample_Array (1 .. N);

      --  Warm-up: prime caches / branch predictor. Discarded.
      Warmup : constant := 1_000;
   begin
      for I in 1 .. Warmup loop
         Subject_0.all;
         Subject_1.all;
      end loop;

      --  Interleaved measurement.
      for I in 1 .. N loop
         declare
            Pre, Post : Unsigned_64;
         begin
            Pre := Rdtsc;
            Subject_0.all;
            Post := Rdtsc;
            T0 (I) := Post - Pre;

            Pre := Rdtsc;
            Subject_1.all;
            Post := Rdtsc;
            T1 (I) := Post - Pre;
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
         N0 := Trimmed_Stats (T0, M0, V0);
         N1 := Trimmed_Stats (T1, M1, V1);
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
   end Time_Test;

end Dudect_Helpers;
