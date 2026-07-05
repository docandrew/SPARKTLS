--  sparktls_cli create cert for <name> using <key> to <file> [options]
--  sparktls_cli create ca for <name> using <key> to <file> [options]

with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with X509;           use type X509.N32;
with Key_Util;
with Cert_Builder;
with PEM_Util;

package body Cmd_Create is

   procedure Print_Usage is
   begin
      Put_Line ("Usage:");
      Put_Line ("  sparktls_cli create cert for <name> using <key> to <file> [options]");
      Put_Line ("  sparktls_cli create ca for <name> using <key> to <file> [options]");
      New_Line;
      Put_Line ("Options:");
      Put_Line ("  valid-for <days>           Validity period (default: 365)");
      Put_Line ("  with-san <n1,n2,...>        Subject Alt Names (DNS/IP auto-detected)");
      Put_Line ("  with-org <org>             Organization name");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls_cli create cert for localhost using server.key to server.crt");
      Put_Line ("  sparktls_cli create ca for ""My CA"" using ca.key to ca.crt valid-for 3650");
   end Print_Usage;

   procedure Run is
      use Ada.Command_Line;

      --  Parse: create (cert|ca) for <name> using <key> to <file> [opts]
      --  Args:  1=create 2=cert|ca 3=for 4=<name> 5=using 6=<key> 7=to 8=<file>
      Is_CA    : Boolean := False;
      Name     : String (1 .. 128) := (others => ASCII.NUL);
      Name_Len : Natural := 0;
      Key_Path : String (1 .. 256) := (others => ASCII.NUL);
      Key_Len  : Natural := 0;
      Out_Path : String (1 .. 256) := (others => ASCII.NUL);
      Out_Len  : Natural := 0;
      Days     : Natural := 365;
      Org      : String (1 .. 128) := (others => ASCII.NUL);
      Org_Len  : Natural := 0;
      SANs     : Cert_Builder.SAN_Array := (others => <>);
      SAN_Count : Natural := 0;

      I : Positive;
   begin
      if Argument_Count < 8 then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      --  Parse cert|ca
      declare
         Kind : constant String := Argument (2);
      begin
         if Kind = "ca" then
            Is_CA := True;
         elsif Kind /= "cert" then
            Put_Line (Standard_Error, "Expected 'cert' or 'ca', got: " & Kind);
            Set_Exit_Status (2);
            return;
         end if;
      end;

      --  Validate structure words
      if Argument (3) /= "for" or else
         Argument (5) /= "using" or else
         Argument (7) /= "to"
      then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      --  Extract positional args
      declare
         N : constant String := Argument (4);
         K : constant String := Argument (6);
         O : constant String := Argument (8);
      begin
         Name_Len := Natural'Min (N'Length, Name'Length);
         Name (1 .. Name_Len) := N (N'First .. N'First + Name_Len - 1);
         Key_Len := Natural'Min (K'Length, Key_Path'Length);
         Key_Path (1 .. Key_Len) := K (K'First .. K'First + Key_Len - 1);
         Out_Len := Natural'Min (O'Length, Out_Path'Length);
         Out_Path (1 .. Out_Len) := O (O'First .. O'First + Out_Len - 1);
      end;

      --  Parse optional args
      I := 9;
      while I <= Argument_Count loop
         declare
            Arg : constant String := Argument (I);
         begin
            if Arg = "valid-for" and then I < Argument_Count then
               I := I + 1;
               begin
                  Days := Natural'Value (Argument (I));
               exception
                  when others =>
                     Put_Line (Standard_Error, "Invalid days: " & Argument (I));
                     Set_Exit_Status (1);
                     return;
               end;
            elsif Arg = "with-org" and then I < Argument_Count then
               I := I + 1;
               declare
                  V : constant String := Argument (I);
               begin
                  Org_Len := Natural'Min (V'Length, Org'Length);
                  Org (1 .. Org_Len) := V (V'First .. V'First + Org_Len - 1);
               end;
            elsif Arg = "with-san" and then I < Argument_Count then
               I := I + 1;
               --  Parse comma-separated SANs
               declare
                  V    : constant String := Argument (I);
                  Start : Positive := V'First;
               begin
                  for J in V'Range loop
                     if V (J) = ',' or J = V'Last then
                        declare
                           E : constant Positive :=
                              (if V (J) = ',' then J - 1 else J);
                           S : constant String := V (Start .. E);
                        begin
                           if SAN_Count < Cert_Builder.Max_SANs
                              and then S'Length > 0
                           then
                              SAN_Count := SAN_Count + 1;
                              declare
                                 Len : constant Natural :=
                                    Natural'Min (S'Length,
                                       SANs (SAN_Count).Name'Length);
                              begin
                                 SANs (SAN_Count).Name (1 .. Len) :=
                                    S (S'First .. S'First + Len - 1);
                                 SANs (SAN_Count).Name_Len := Len;
                                 --  Auto-detect IP vs DNS
                                 SANs (SAN_Count).Is_IP := False;
                                 for C of S loop
                                    if C = '.' then
                                       declare
                                          All_Digits : Boolean := True;
                                       begin
                                          for D of S loop
                                             if D not in '0'..'9' | '.' then
                                                All_Digits := False;
                                             end if;
                                          end loop;
                                          if All_Digits then
                                             SANs (SAN_Count).Is_IP := True;
                                          end if;
                                       end;
                                       exit;
                                    end if;
                                 end loop;
                              end;
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

      --  Load private key
      declare
         Key : Key_Util.Private_Key;
      begin
         Key_Util.Load_Private_Key (Key_Path (1 .. Key_Len), Key);
         if not Key.Valid then
            Put_Line (Standard_Error, "Failed to load key: " &
                      Key_Path (1 .. Key_Len));
            Set_Exit_Status (1);
            return;
         end if;

         --  Build certificate
         declare
            Params : Cert_Builder.Cert_Params;
            Cert_DER : Cert_Builder.Cert_DER_Buf := (others => 0);
            Cert_Len : X509.N32;
            Build_OK : Boolean;
            Write_OK : Boolean;
         begin
            Params.Subject.CN (1 .. Name_Len) := Name (1 .. Name_Len);
            Params.Subject.CN_Len := Name_Len;
            Params.Subject.Org (1 .. Org_Len) := Org (1 .. Org_Len);
            Params.Subject.Org_Len := Org_Len;

            --  Self-signed: issuer = subject
            Params.Issuer := Params.Subject;

            Params.Key := Key;
            Params.SPKI (0 .. Key.SPKI_Len - 1) :=
               Key.SPKI (0 .. Key.SPKI_Len - 1);
            Params.SPKI_Len := Key.SPKI_Len;
            Params.Is_CA := Is_CA;
            Params.Valid_Days := Days;
            Params.SANs := SANs;
            Params.SAN_Count := SAN_Count;

            Put_Line ("Creating " &
                      (if Is_CA then "CA" else "leaf") &
                      " certificate for " & Name (1 .. Name_Len) & "...");

            Cert_Builder.Build_Certificate
              (Params, Cert_DER, Cert_Len, Build_OK);

            if not Build_OK then
               Put_Line (Standard_Error, "Certificate construction failed");
               Set_Exit_Status (1);
               return;
            end if;

            PEM_Util.Write_PEM_File
              (Path  => Out_Path (1 .. Out_Len),
               DER   => Cert_DER (0 .. Cert_Len - 1),
               Label => "CERTIFICATE",
               OK    => Write_OK);

            if not Write_OK then
               Put_Line (Standard_Error, "Failed to write " &
                         Out_Path (1 .. Out_Len));
               Set_Exit_Status (1);
               return;
            end if;

            Put_Line ("Wrote " & Out_Path (1 .. Out_Len) &
                      " (" & Cert_Len'Image & " bytes DER)");
         end;
      end;
   end Run;

end Cmd_Create;
