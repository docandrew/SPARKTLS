--  Runs the FIPS 140-3 software integrity test and reports the result:
--  exit status 0 if it behaves as expected, 1 if not. A freshly linked
--  binary fails the test until tools/fips_inject has written the expected
--  MACs into it:
--
--     bin/tools/fips_inject bin/examples/fips_integrity_check
--
--  Usage:
--    fips_integrity_check             SPARKTLS.Integrity.Check alone
--    fips_integrity_check --rbg       Initialize in FIPS mode (integrity test on)
--    fips_integrity_check --rbg --non-fips
--                                     Initialize in Non_FIPS mode (no integrity test)
--    fips_integrity_check --sequence  Non_FIPS Initialize, RBG.Shutdown, then
--                                     FIPS and Non_FIPS Initialize: on a binary
--                                     fips_inject has not processed, the FIPS
--                                     Initialize fails and the failure stays
--                                     latched
--    fips_integrity_check --mismatch  FIPS Initialize, then client Configure:
--                                     Algorithms => Non_FIPS is refused
--                                     (Bad_Configuration), FIPS is accepted
with Ada.Command_Line; use Ada.Command_Line;
with Ada.Text_IO;      use Ada.Text_IO;
with SPARKTLS;
with SPARKTLS.Integrity;
with SPARKTLS.Initialize;
with SPARKTLS.RBG;
with SPARKTLS.Client;

procedure FIPS_Integrity_Check is
   function Has (Flag : String) return Boolean is
   begin
      for I in 1 .. Argument_Count loop
         if Argument (I) = Flag then
            return True;
         end if;
      end loop;
      return False;
   end Has;

   procedure Report (OK : Boolean; What : String) is
   begin
      Put_Line (What & ": " & (if OK then "OK" else "FAIL"));
      if not OK then
         Set_Exit_Status (Failure);
      end if;
   end Report;

   Pool : SPARKTLS.Handshake_Pool (Size => 2);
   OK   : Boolean;
begin
   if Has ("--mismatch") then
      SPARKTLS.Initialize (OK, Mode => SPARKTLS.FIPS);
      Report (OK, "FIPS Initialize");
      declare
         use type SPARKTLS.Connection_State;
         use type SPARKTLS.Error_Code;
         Refused  : SPARKTLS.Session :=
           SPARKTLS.Client.Configure
             ((Skip_Verify => True, Algorithms => SPARKTLS.Non_FIPS, others => <>), Pool);
         Accepted : SPARKTLS.Session :=
           SPARKTLS.Client.Configure
             ((Skip_Verify => True, Algorithms => SPARKTLS.FIPS, others => <>), Pool);
      begin
         Report (SPARKTLS.State (Refused) = SPARKTLS.Error_State
                 and then SPARKTLS.Last_Error (Refused) = SPARKTLS.Bad_Configuration,
                 "Non_FIPS session refused");
         Report (SPARKTLS.State (Accepted) /= SPARKTLS.Error_State, "FIPS session accepted");
         SPARKTLS.Drop (Refused, Pool);
         SPARKTLS.Drop (Accepted, Pool);
      end;
   elsif Has ("--sequence") then
      SPARKTLS.Initialize (OK, Mode => SPARKTLS.Non_FIPS);
      Report (OK, "Non_FIPS Init");
      SPARKTLS.RBG.Shutdown;
      SPARKTLS.Initialize (OK, Mode => SPARKTLS.FIPS);
      Report (not OK, "FIPS Init refused");
      SPARKTLS.Initialize (OK, Mode => SPARKTLS.Non_FIPS);
      Report (not OK, "failure latched");
   elsif Has ("--rbg") then
      SPARKTLS.Initialize
        (OK, Mode => (if Has ("--non-fips") then SPARKTLS.Non_FIPS else SPARKTLS.FIPS));
      Report (OK, "Initialize");
   else
      SPARKTLS.Integrity.Check (OK);
      Report (OK, "integrity");
   end if;
end FIPS_Integrity_Check;
