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
      Put_Line ("sparktls_cli - SPARKTLS certificate utility");
      New_Line;
      Put_Line ("Usage: sparktls_cli <command> [options]");
      New_Line;
      Put_Line ("Commands:");
      Put_Line ("  generate <algo> key to <file>");
      Put_Line ("      Generate a PEM private key. algo: ed25519, p256, p384");
      Put_Line ("  devcert <name> to <key-file> <cert-file> [options]");
      Put_Line ("      Generate a key and self-signed development certificate");
      New_Line;
      Put_Line ("  create cert for <name> using <key> to <file> [options]");
      Put_Line ("      Create a self-signed leaf certificate");
      Put_Line ("  create ca for <name> using <key> to <file> [options]");
      Put_Line ("      Create a self-signed CA certificate");
      Put_Line ("  sign <leaf-key> with-ca <ca-key> <ca-cert> for <name> to <file> [options]");
      Put_Line ("      Issue a leaf certificate from an existing CA");
      New_Line;
      Put_Line ("  create csr for <name> using <key> to <file> [with-san <names>]");
      Put_Line ("      Create a PEM certificate signing request");
      Put_Line ("  sign-csr <csr.pem> with-ca <ca-key> <ca-cert> to <file> [valid-for <days>]");
      Put_Line ("      Sign a PEM CSR with an existing CA");
      New_Line;
      Put_Line ("  show <cert.pem|cert.der> [--brief]");
      Put_Line ("      Display parsed certificate fields");
      Put_Line ("  verify <cert.pem|cert.der> --ca <ca.pem|ca.der> [--ca <int>] [--host <name>]");
      Put_Line ("      Validate a certificate chain and optional hostname");
      New_Line;
      Put_Line ("Common options:");
      Put_Line ("  valid-for <days>       Certificate validity period");
      Put_Line ("  with-san <n1,n2,...>   DNS names or IPv4 addresses");
      Put_Line ("  with-org <org>         Organization name");
      Put_Line ("  algo <ed25519|p256|p384>  devcert key algorithm");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls_cli devcert localhost to server.key server.crt");
      Put_Line ("  sparktls_cli generate p256 key to ca.key");
      Put_Line ("  sparktls_cli create ca for ""Local Test CA"" using ca.key to ca.crt");
      Put_Line ("  sparktls_cli sign server.key with-ca ca.key ca.crt for localhost to server.crt");
      New_Line;
      Put_Line ("Note: certificate inputs may be PEM or DER.");
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
