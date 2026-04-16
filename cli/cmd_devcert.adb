--  sparktls devcert <name> to <key-file> <cert-file> [options]
--
--  One command to generate a key + self-signed cert for dev/testing.
--  Defaults: P-256, 365 days, SANs auto-populated.

with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with X509;           use type X509.N32;
with Key_Util;
with Cert_Builder;
with PEM_Util;

package body Cmd_Devcert is

   procedure Print_Usage is
   begin
      Put_Line ("Usage: sparktls devcert <name> to <key-file> <cert-file> [options]");
      New_Line;
      Put_Line ("Options:");
      Put_Line ("  algo <ed25519|p256|p384>    Key algorithm (default: p256)");
      Put_Line ("  valid-for <days>            Validity (default: 365)");
      Put_Line ("  with-san <n1,n2,...>         Extra SANs (auto-adds name + localhost)");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls devcert localhost to server.key server.crt");
      Put_Line ("  sparktls devcert myapp.local to app.key app.crt algo ed25519");
   end Print_Usage;

   function Is_IP (S : String) return Boolean is
   begin
      for C of S loop
         if C not in '0' .. '9' | '.' then
            return False;
         end if;
      end loop;
      return True;
   end Is_IP;

   procedure Add_SAN
     (SANs      : in out Cert_Builder.SAN_Array;
      SAN_Count : in out Natural;
      Name      : String;
      IP        : Boolean)
   is
   begin
      if SAN_Count >= Cert_Builder.Max_SANs or Name'Length = 0 then
         return;
      end if;
      --  Check for duplicates
      for I in 1 .. SAN_Count loop
         if SANs (I).Name_Len = Name'Length
            and then SANs (I).Name (1 .. SANs (I).Name_Len) = Name
         then
            return;
         end if;
      end loop;
      SAN_Count := SAN_Count + 1;
      declare
         Len : constant Natural :=
            Natural'Min (Name'Length, SANs (SAN_Count).Name'Length);
      begin
         SANs (SAN_Count).Name (1 .. Len) :=
            Name (Name'First .. Name'First + Len - 1);
         SANs (SAN_Count).Name_Len := Len;
         SANs (SAN_Count).Is_IP := IP;
      end;
   end Add_SAN;

   procedure Run is
      use Ada.Command_Line;

      --  Parse: devcert <name> to <key-file> <cert-file> [options]
      --  Args:  1=devcert 2=name 3=to 4=key-file 5=cert-file [6+]
      Name     : String (1 .. 128) := (others => ASCII.NUL);
      Name_Len : Natural := 0;
      Key_Path : String (1 .. 256) := (others => ASCII.NUL);
      Key_Len  : Natural := 0;
      Cert_Path : String (1 .. 256) := (others => ASCII.NUL);
      Cert_Len : Natural := 0;
      Algo     : Key_Util.Key_Algorithm := Key_Util.Algo_P256;
      Days     : Natural := 365;
      SANs     : Cert_Builder.SAN_Array := (others => <>);
      SAN_Count : Natural := 0;
      I : Positive;
   begin
      if Argument_Count < 5
         or else Argument (3) /= "to"
      then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      declare
         N : constant String := Argument (2);
         K : constant String := Argument (4);
         C : constant String := Argument (5);
      begin
         Name_Len := Natural'Min (N'Length, Name'Length);
         Name (1 .. Name_Len) := N (N'First .. N'First + Name_Len - 1);
         Key_Len := Natural'Min (K'Length, Key_Path'Length);
         Key_Path (1 .. Key_Len) := K (K'First .. K'First + Key_Len - 1);
         Cert_Len := Natural'Min (C'Length, Cert_Path'Length);
         Cert_Path (1 .. Cert_Len) := C (C'First .. C'First + Cert_Len - 1);
      end;

      --  Auto-populate SANs
      if Is_IP (Name (1 .. Name_Len)) then
         Add_SAN (SANs, SAN_Count, Name (1 .. Name_Len), True);
      else
         Add_SAN (SANs, SAN_Count, Name (1 .. Name_Len), False);
      end if;
      --  Always add localhost + 127.0.0.1 for dev convenience
      Add_SAN (SANs, SAN_Count, "localhost", False);
      Add_SAN (SANs, SAN_Count, "127.0.0.1", True);

      --  Parse optional args
      I := 6;
      while I <= Argument_Count loop
         declare
            Arg : constant String := Argument (I);
         begin
            if Arg = "algo" and then I < Argument_Count then
               I := I + 1;
               declare
                  A : constant String := Argument (I);
               begin
                  if A = "ed25519" then
                     Algo := Key_Util.Algo_Ed25519;
                  elsif A = "p256" then
                     Algo := Key_Util.Algo_P256;
                  elsif A = "p384" then
                     Algo := Key_Util.Algo_P384;
                  else
                     Put_Line (Standard_Error, "Unknown algorithm: " & A);
                     Set_Exit_Status (1);
                     return;
                  end if;
               end;
            elsif Arg = "valid-for" and then I < Argument_Count then
               I := I + 1;
               begin
                  Days := Natural'Value (Argument (I));
               exception
                  when others =>
                     Put_Line (Standard_Error, "Invalid days: " & Argument (I));
                     Set_Exit_Status (1);
                     return;
               end;
            elsif Arg = "with-san" and then I < Argument_Count then
               I := I + 1;
               declare
                  V     : constant String := Argument (I);
                  Start : Positive := V'First;
               begin
                  for J in V'Range loop
                     if V (J) = ',' or J = V'Last then
                        declare
                           E : constant Positive :=
                              (if V (J) = ',' then J - 1 else J);
                           S : constant String := V (Start .. E);
                        begin
                           if S'Length > 0 then
                              Add_SAN (SANs, SAN_Count, S, Is_IP (S));
                           end if;
                        end;
                        Start := J + 1;
                     end if;
                  end loop;
               end;
            else
               Put_Line (Standard_Error, "Unknown option: " & Arg);
               Set_Exit_Status (2);
               return;
            end if;
         end;
         I := I + 1;
      end loop;

      --  Generate key
      declare
         Priv_DER : X509.Byte_Seq (0 .. 511) := (others => 0);
         Priv_Len : X509.N32;
         SPKI_DER : X509.Byte_Seq (0 .. 511) := (others => 0);
         SPKI_Len : X509.N32;
         Gen_OK, Write_OK : Boolean;
      begin
         Key_Util.Generate_Key (Algo, Priv_DER, Priv_Len,
                                SPKI_DER, SPKI_Len, Gen_OK);
         if not Gen_OK then
            Put_Line (Standard_Error, "Key generation failed");
            Set_Exit_Status (1);
            return;
         end if;

         PEM_Util.Write_PEM_File
           (Key_Path (1 .. Key_Len),
            Priv_DER (0 .. Priv_Len - 1),
            "PRIVATE KEY", Write_OK);
         if not Write_OK then
            Put_Line (Standard_Error, "Failed to write " &
                      Key_Path (1 .. Key_Len));
            Set_Exit_Status (1);
            return;
         end if;

         --  Load the key back to get signing material
         declare
            Key : Key_Util.Private_Key;
         begin
            Key_Util.Load_Private_Key (Key_Path (1 .. Key_Len), Key);
            if not Key.Valid then
               Put_Line (Standard_Error, "Failed to reload key");
               Set_Exit_Status (1);
               return;
            end if;

            --  Build self-signed cert
            declare
               Params : Cert_Builder.Cert_Params;
               C_DER  : Cert_Builder.Cert_DER_Buf := (others => 0);
               C_Len  : X509.N32;
               Build_OK : Boolean;
            begin
               Params.Subject.CN (1 .. Name_Len) := Name (1 .. Name_Len);
               Params.Subject.CN_Len := Name_Len;
               Params.Issuer := Params.Subject;
               Params.Key := Key;
               Params.SPKI (0 .. Key.SPKI_Len - 1) :=
                  Key.SPKI (0 .. Key.SPKI_Len - 1);
               Params.SPKI_Len := Key.SPKI_Len;
               Params.Is_CA := False;
               Params.Valid_Days := Days;
               Params.SANs := SANs;
               Params.SAN_Count := SAN_Count;

               Cert_Builder.Build_Certificate
                 (Params, C_DER, C_Len, Build_OK);

               if not Build_OK then
                  Put_Line (Standard_Error, "Certificate construction failed");
                  Set_Exit_Status (1);
                  return;
               end if;

               PEM_Util.Write_PEM_File
                 (Cert_Path (1 .. Cert_Len),
                  C_DER (0 .. C_Len - 1),
                  "CERTIFICATE", Write_OK);

               if not Write_OK then
                  Put_Line (Standard_Error, "Failed to write " &
                            Cert_Path (1 .. Cert_Len));
                  Set_Exit_Status (1);
                  return;
               end if;

               Put_Line ("Wrote " & Key_Path (1 .. Key_Len) &
                         " + " & Cert_Path (1 .. Cert_Len) &
                         " (P-256, " & Name (1 .. Name_Len) & ")");
            end;
         end;
      end;
   end Run;

end Cmd_Devcert;
