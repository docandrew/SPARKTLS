--  Runs the FIPS 140-3 software integrity test (SPARKTLS.Integrity) and
--  reports the result: exit status 0 if the module is intact, 1 if not.
--  A freshly linked binary fails until tools/fips_inject has written the
--  expected MACs into it:
--
--     bin/tools/fips_inject bin/examples/fips_integrity_check
with Ada.Command_Line;
with Ada.Text_IO;
with SPARKTLS.Integrity;

procedure FIPS_Integrity_Check is
   Intact : Boolean;
begin
   SPARKTLS.Integrity.Check (Intact);
   if Intact then
      Ada.Text_IO.Put_Line ("integrity: OK");
   else
      Ada.Text_IO.Put_Line ("integrity: FAIL");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end FIPS_Integrity_Check;
