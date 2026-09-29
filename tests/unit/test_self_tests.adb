--  The FIPS 140-3 algorithm self-tests (SPARKTLS.Self_Tests) pass on this
--  build, and how long they take (they run once, in SPARKTLS.Initialize).
with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with SPARKTLS.Self_Tests;

procedure Test_Self_Tests is
   HMAC_OK, Rest_OK : Boolean;
   T0, T1, T2       : Time;
begin
   T0 := Clock;
   SPARKTLS.Self_Tests.HMAC_SHA256 (HMAC_OK);
   T1 := Clock;
   SPARKTLS.Self_Tests.Remaining (Rest_OK);
   T2 := Clock;
   if not HMAC_OK then
      raise Program_Error with "HMAC-SHA-256 self-test failed";
   end if;
   if not Rest_OK then
      raise Program_Error with "algorithm self-tests failed";
   end if;
   Put_Line ("PASS: FIPS algorithm self-tests (HMAC-SHA-256"
             & Duration'Image (To_Duration (T1 - T0) * 1000.0) & " ms, the rest"
             & Duration'Image (To_Duration (T2 - T1) * 1000.0) & " ms)");
end Test_Self_Tests;
