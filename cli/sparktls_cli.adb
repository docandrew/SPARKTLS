with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with Cmd_Show;
with Cmd_Verify;
with Cmd_Generate;
with Cmd_Create;
with Cmd_Sign;
with Cmd_CSR;
with Cmd_Devcert;

procedure SPARKTLS_CLI is

   procedure Print_Usage is
   begin
      Put_Line ("sparktls - certificate inspection and validation tool");
      New_Line;
      Put_Line ("Usage: sparktls <command> [options]");
      New_Line;
      Put_Line ("Commands:");
      Put_Line ("  show <cert.pem>                     Display certificate fields");
      Put_Line ("  verify <cert.pem> --ca <ca.pem>     Validate certificate chain");
      New_Line;
      Put_Line ("  generate <algo> key to <file>        Generate a keypair");
      Put_Line ("    algo: ed25519, p256, p384");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls generate p256 key to server.key");
      Put_Line ("  sparktls show server.crt");
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
      elsif Cmd = "generate" then
         Cmd_Generate.Run;
      elsif Cmd = "create" then
         if Ada.Command_Line.Argument_Count >= 2
            and then Ada.Command_Line.Argument (2) = "csr"
         then
            Cmd_CSR.Run_Create;
         else
            Cmd_Create.Run;
         end if;
      elsif Cmd = "sign" then
         Cmd_Sign.Run;
      elsif Cmd = "sign-csr" then
         Cmd_CSR.Run_Sign;
      elsif Cmd = "devcert" then
         Cmd_Devcert.Run;
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
