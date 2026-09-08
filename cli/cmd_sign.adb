--  sparktls_cli sign <leaf-key> with-ca <ca-key> <ca-cert> for <name> to <file> [opts]

with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with X509;           use type X509.N32;
with Key_Util;
with Cert_Builder;
with PEM_Util;
with SPARKTLS.PEM;
with CLI_Util;

package body Cmd_Sign is

   procedure Print_Usage is
   begin
      Put_Line ("Usage:");
      Put_Line ("  sparktls_cli sign <leaf-key> with-ca <ca-key> <ca-cert>");
      Put_Line ("    for <name> to <file> [options]");
      New_Line;
      Put_Line ("Options:");
      Put_Line ("  valid-for <days>           Validity period (default: 365)");
      Put_Line ("  with-san <n1,n2,...>        Subject Alt Names");
      Put_Line ("  with-org <org>             Organization name");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls_cli sign server.key with-ca ca.key ca.crt \");
      Put_Line ("    for localhost to server.crt with-san localhost,127.0.0.1");
   end Print_Usage;

   --  Read a text file
   function Read_Text_File (Path : String) return String is
      use Ada.Text_IO;
      F      : File_Type;
      Result : String (1 .. 65536) := (others => ' ');
      Len    : Natural := 0;
      Line   : String (1 .. 1024);
      Last   : Natural;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Get_Line (F, Line, Last);
         if Len + Last + 1 <= Result'Last then
            Result (Len + 1 .. Len + Last) := Line (1 .. Last);
            Len := Len + Last;
            Result (Len + 1) := ASCII.LF;
            Len := Len + 1;
         end if;
      end loop;
      Close (F);
      return Result (1 .. Len);
   exception
      when others => return "";
   end Read_Text_File;

   procedure Run is
      use Ada.Command_Line;

      --  Parse: sign <leaf-key> with-ca <ca-key> <ca-cert> for <name> to <file>
      --  Args:  1=sign  2=leaf-key  3=with-ca  4=ca-key  5=ca-cert
      --         6=for   7=name     8=to       9=file

      Leaf_Key_Path : String (1 .. 256) := (others => ASCII.NUL);
      Leaf_Key_Len  : Natural := 0;
      CA_Key_Path   : String (1 .. 256) := (others => ASCII.NUL);
      CA_Key_Len    : Natural := 0;
      CA_Cert_Path  : String (1 .. 256) := (others => ASCII.NUL);
      CA_Cert_Len   : Natural := 0;
      Name          : String (1 .. 128) := (others => ASCII.NUL);
      Name_Len      : Natural := 0;
      Out_Path      : String (1 .. 256) := (others => ASCII.NUL);
      Out_Len       : Natural := 0;
      Days          : Natural := 365;
      Org           : String (1 .. 128) := (others => ASCII.NUL);
      Org_Len       : Natural := 0;
      SANs          : Cert_Builder.SAN_Array := (others => <>);
      SAN_Count     : Natural := 0;

      I : Positive;
   begin
      if Argument_Count < 9 then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      --  Validate structure words
      if Argument (3) /= "with-ca" or else
         Argument (6) /= "for" or else
         Argument (8) /= "to"
      then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      --  Extract positional args
      declare
         procedure Copy (Src : String; Dst : in out String;
                         Len : out Natural) is
            L : constant Natural := Natural'Min (Src'Length, Dst'Length);
         begin
            Dst (1 .. L) := Src (Src'First .. Src'First + L - 1);
            Len := L;
         end Copy;
      begin
         Copy (Argument (2), Leaf_Key_Path, Leaf_Key_Len);
         Copy (Argument (4), CA_Key_Path, CA_Key_Len);
         Copy (Argument (5), CA_Cert_Path, CA_Cert_Len);
         Copy (Argument (7), Name, Name_Len);
         Copy (Argument (9), Out_Path, Out_Len);
      end;

      --  Parse optional args (same as cmd_create)
      I := 10;
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
                  L : constant Natural :=
                     Natural'Min (V'Length, Org'Length);
               begin
                  Org (1 .. L) := V (V'First .. V'First + L - 1);
                  Org_Len := L;
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
                           if SAN_Count < Cert_Builder.Max_SANs
                              and then S'Length > 0
                           then
                              SAN_Count := SAN_Count + 1;
                              declare
                                 Len : constant Natural :=
                                    Natural'Min (S'Length,
                                       SANs (SAN_Count).Name'Length);
                                 All_Digits : Boolean := True;
                              begin
                                 SANs (SAN_Count).Name (1 .. Len) :=
                                    S (S'First .. S'First + Len - 1);
                                 SANs (SAN_Count).Name_Len := Len;
                                 for C of S loop
                                    if C not in '0'..'9' | '.' then
                                       All_Digits := False;
                                    end if;
                                 end loop;
                                 SANs (SAN_Count).Is_IP := All_Digits;
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

      --  Load CA key
      declare
         CA_Key : Key_Util.Private_Key;
      begin
         Key_Util.Load_Private_Key (CA_Key_Path (1 .. CA_Key_Len), CA_Key);
         if not CA_Key.Valid then
            Put_Line (Standard_Error, "Failed to load CA key: " &
                      CA_Key_Path (1 .. CA_Key_Len));
            Set_Exit_Status (1);
            return;
         end if;

         --  Load leaf key (to extract SPKI for the cert)
         declare
            Leaf_Key : Key_Util.Private_Key;
         begin
            Key_Util.Load_Private_Key
              (Leaf_Key_Path (1 .. Leaf_Key_Len), Leaf_Key);
            if not Leaf_Key.Valid then
               Put_Line (Standard_Error, "Failed to load leaf key: " &
                         Leaf_Key_Path (1 .. Leaf_Key_Len));
               Set_Exit_Status (1);
               return;
            end if;

            --  Load CA cert to extract issuer DN
            declare
               CA_Cert_Text : constant String :=
                  Read_Text_File (CA_Cert_Path (1 .. CA_Cert_Len));
               CA_PEM : SPARKTLS.PEM.Decode_Result;
               CA_Cert : X509.Certificate;
               CA_OK   : Boolean;
            begin
               if CA_Cert_Text'Length = 0 then
                  Put_Line (Standard_Error, "Failed to read CA cert");
                  Set_Exit_Status (1);
                  return;
               end if;

               SPARKTLS.PEM.Decode (CA_Cert_Text, CA_PEM);
               if not CA_PEM.OK then
                  Put_Line (Standard_Error, "Failed to decode CA cert PEM");
                  Set_Exit_Status (1);
                  return;
               end if;

               X509.Parse (CA_PEM.DER (0 .. CA_PEM.DER_Len - 1),
                           CA_Cert, CA_OK);
               if not CA_OK or else not X509.Is_Valid (CA_Cert) then
                  Put_Line (Standard_Error, "Invalid CA certificate");
                  Set_Exit_Status (1);
                  return;
               end if;

               --  Extract issuer DN from CA cert's subject
               declare
                  Params : Cert_Builder.Cert_Params;
                  Cert_DER : Cert_Builder.Cert_DER_Buf := (others => 0);
                  Cert_Len : X509.N32;
                  Build_OK : Boolean;
                  Write_OK : Boolean;

                  CN_Span  : constant X509.Span := X509.Subject_CN (CA_Cert);
                  Org_Span : constant X509.Span := X509.Subject_Org (CA_Cert);
               begin
                  --  Set issuer from CA cert's subject
                  if CN_Span.Present then
                     declare
                        CN : constant String :=
                           CLI_Util.Span_To_String
                             (CA_PEM.DER (0 .. CA_PEM.DER_Len - 1),
                              CN_Span);
                        L : constant Natural :=
                           Natural'Min (CN'Length,
                              Params.Issuer.CN'Length);
                     begin
                        Params.Issuer.CN (1 .. L) :=
                           CN (CN'First .. CN'First + L - 1);
                        Params.Issuer.CN_Len := L;
                     end;
                  end if;

                  if Org_Span.Present then
                     declare
                        O : constant String :=
                           CLI_Util.Span_To_String
                             (CA_PEM.DER (0 .. CA_PEM.DER_Len - 1),
                              Org_Span);
                        L : constant Natural :=
                           Natural'Min (O'Length,
                              Params.Issuer.Org'Length);
                     begin
                        Params.Issuer.Org (1 .. L) :=
                           O (O'First .. O'First + L - 1);
                        Params.Issuer.Org_Len := L;
                     end;
                  end if;

                  --  Set subject
                  Params.Subject.CN (1 .. Name_Len) := Name (1 .. Name_Len);
                  Params.Subject.CN_Len := Name_Len;
                  Params.Subject.Org (1 .. Org_Len) := Org (1 .. Org_Len);
                  Params.Subject.Org_Len := Org_Len;

                  --  Signing key is the CA key
                  Params.Key := CA_Key;

                  --  SPKI is from the leaf key
                  Params.SPKI (0 .. Leaf_Key.SPKI_Len - 1) :=
                     Leaf_Key.SPKI (0 .. Leaf_Key.SPKI_Len - 1);
                  Params.SPKI_Len := Leaf_Key.SPKI_Len;

                  Params.Is_CA := False;
                  Params.Valid_Days := Days;
                  Params.SANs := SANs;
                  Params.SAN_Count := SAN_Count;

                  Put_Line ("Signing certificate for " &
                            Name (1 .. Name_Len) & "...");

                  Cert_Builder.Build_Certificate
                    (Params, Cert_DER, Cert_Len, Build_OK);

                  if not Build_OK then
                     Put_Line (Standard_Error, "Certificate signing failed");
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
         end;
      end;
   end Run;

end Cmd_Sign;
