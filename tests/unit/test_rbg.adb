--  SPARKTLS.RBG: the two-level DRBG tree behind every random byte. Driven
--  with a scripted source so the reseed and failure paths run
--  deterministically.
with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.RBG;
with SPARKTLS.RBG.Testing;

procedure Test_RBG is
   use SPARKTLS.RBG;
   Total, Pass, Fail : Natural := 0;
   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1; Put_Line ("  PASS: " & Name);
      else Fail := Fail + 1; Put_Line ("  FAIL: " & Name); end if;
   end Check;

   --  Scripted entropy source: Calls counts requests; fails from Fail_After on.
   Calls      : Natural := 0;
   Fail_After : Natural := Natural'Last;
   procedure Source (Output : out Byte_Seq; OK : out Boolean) is
   begin
      Calls := Calls + 1;
      for I in Output'Range loop
         Output (I) := Byte ((Natural (I) * 7 + Calls * 13) mod 251 + 1);
      end loop;
      OK := Calls < Fail_After;
      if not OK then
         Output := (others => 0);
      end if;
   end Source;

   Failures : Natural := 0;
   procedure On_Failure is
   begin
      Failures := Failures + 1;
   end On_Failure;

   function All_Zero (B : Byte_Seq) return Boolean is (for all I in B'Range => B (I) = 0);

   OK  : Boolean;
   A, B : Byte_Seq (0 .. 31);
begin
   Put_Line ("--- SPARKTLS.RBG ---");
   Shutdown;
   Random (A);
   Check ("uninstantiated -> Random gives zeros", All_Zero (A));
   Check ("status Uninstantiated", Status = Uninstantiated);

   --  Short serving interval so its reseed from the core runs.
   Testing.Init_From (Source'Unrestricted_Access, OK, On_Failure'Unrestricted_Access, Reseed_Requests => 3);
   Check ("Init OK", OK);
   Check ("status Ready", Status = Ready);
   Check ("one source call at instantiation", Calls = 1);
   Random (A); Random (B);
   Check ("output is not zero", not All_Zero (A) and not All_Zero (B));
   Check ("consecutive requests differ", A /= B);
   Check ("no reseed yet (2 of 3 requests)", Reseeds = 0 and Calls = 1);
   Random (A);                       --  3rd request: still within the interval
   Random (B);                       --  4th: serving reseed due first
   Check ("serving reseed after the interval, from the core not the source",
          Reseeds = 1 and Calls = 1);
   Check ("output continues after reseed", not All_Zero (B));
   Testing.Init_From (Source'Unrestricted_Access, OK);
   Check ("Init while Ready is a no-op", OK and Calls = 1);

   --  Reseed on request: fresh source output into the core.
   Reseed (OK);
   Random (A);
   Check ("Reseed draws the source once and reseeds the tree",
          OK and Calls = 2 and Reseeds = 2 and not All_Zero (A));

   --  Large request spans several DRBG requests.
   declare
      Big : Byte_Seq (0 .. 200_000);
   begin
      Random (Big);
      Check ("200 KB request served", not All_Zero (Big (0 .. 31)) and not All_Zero (Big (199_970 .. 200_000)));
   end;

   --  The core at its own limit: the next serving reseed hands the core
   --  reseed to the drawing task. Core interval 2: its instantiation of the
   --  serving DRBG is request 1, the first serving reseed request 2.
   Shutdown;
   Calls := 0;
   Testing.Init_From (Source'Unrestricted_Access, OK, On_Failure'Unrestricted_Access,
                      Reseed_Requests => 1, Core_Requests => 2);
   Random (A);                       --  serving request 1
   Random (A);                       --  serving reseed from the core (its request 2)
   Check ("core serves within its limit", OK and Reseeds = 1 and Calls = 1);
   Random (B);                       --  core past its limit: reseed from the source
   Check ("core reseeded from the source at its limit",
          Reseeds = 2 and Calls = 2 and not All_Zero (B) and A /= B);

   --  The source dies: the next core reseed latches the generator.
   Fail_After := Calls + 1;
   for I in 1 .. 8 loop
      Random (A);
   end loop;
   Check ("latched into Error", Status = Error);
   Check ("zeros once latched", All_Zero (A));
   Check ("On_Failure called exactly once", Failures = 1);
   Random (A);
   Check ("still zeros, still one notice", All_Zero (A) and Failures = 1);
   Reseed (OK);
   Check ("Reseed refused while in Error", not OK and Status = Error);

   --  Init brings it back.
   Fail_After := Natural'Last;
   Testing.Init_From (Source'Unrestricted_Access, OK, On_Failure'Unrestricted_Access);
   Random (A);
   Check ("re-Init after Error is a fresh instantiation", OK and Status = Ready);
   Shutdown;
   Check ("Shutdown returns to Uninstantiated", Status = Uninstantiated);
   Testing.Init_From (Source'Unrestricted_Access, OK, On_Failure'Unrestricted_Access);
   Random (A);
   Check ("re-Init returns to service", OK and Status = Ready and not All_Zero (A));

   --  A failing source on Reseed latches the generator, like any failure.
   Fail_After := Calls + 1;
   Reseed (OK);
   Random (A);
   Check ("Reseed from a dead source -> Error, zeros, one more notice",
          not OK and Status = Error and All_Zero (A) and Failures = 2);
   Fail_After := Natural'Last;

   --  The entropy source's start-up test is part of Init (SP 800-90C 8.1.1).
   Shutdown;
   Testing.Init_From (Source'Unrestricted_Access, OK, Start_Fails => True);
   Random (A);
   Check ("failing source start-up test -> Init fails, Error, zeros",
          not OK and Status = Error and All_Zero (A));
   Testing.Init_From (Source'Unrestricted_Access, OK);
   Check ("Init again re-runs the start-up tests and recovers", OK and Status = Ready);

   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_RBG;
