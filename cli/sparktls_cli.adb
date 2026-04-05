with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with Cmd_Show;
with Cmd_Verify;

procedure SPARKTLS_CLI is

   procedure Print_Usage is
   begin
      Put_Line ("sparktls - certificate inspection and validation tool");
      New_Line;
      Put_Line ("Usage: sparktls <command> [options]");
      New_Line;
      Put_Line ("Commands:");
      Put_Line ("  show <cert.der> [--brief]        Display certificate fields");
      Put_Line ("  verify <cert.der> --ca <ca.der>  Validate certificate chain");
      Put_Line ("         [--ca <int.der>]           (multiple --ca for chain)");
      Put_Line ("         [--host hostname]           Check hostname match");
      New_Line;
      Put_Line ("All certificates must be DER-encoded.");
   end Print_Usage;

begin
   if Ada.Command_Line.Argument_Count = 0 then
      Print_Usage;
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   declare
      Cmd : constant String := Ada.Command_Line.Argument (1);
   begin
      if Cmd = "show" then
         Cmd_Show.Run;
      elsif Cmd = "verify" then
         Cmd_Verify.Run;
      elsif Cmd = "help" or Cmd = "--help" or Cmd = "-h" then
         Print_Usage;
      else
         Put_Line (Standard_Error, "Unknown command: " & Cmd);
         New_Line;
         Print_Usage;
         Ada.Command_Line.Set_Exit_Status (2);
      end if;
   end;
end SPARKTLS_CLI;
