--  sparktls create csr for <name> using <key> to <file> [with-san ...]
--  sparktls sign-csr <csr> with-ca <ca-key> <ca-cert> to <file> [valid-for N]

with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with X509;           use type X509.N32;
with Key_Util;
with Cert_Builder;
with CSR_Builder;
with PEM_Util;
with SPARKTLS.PEM;
with CLI_Util;

package body Cmd_CSR is

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

   --  sparktls create csr for <name> using <key> to <file> [with-san ...]
   --  Args: 1=create 2=csr 3=for 4=name 5=using 6=key 7=to 8=file [9+]
   procedure Run_Create is
      use Ada.Command_Line;
      Name     : String (1 .. 128) := (others => ASCII.NUL);
      Name_Len : Natural := 0;
      Key_Path : String (1 .. 256) := (others => ASCII.NUL);
      Key_Len  : Natural := 0;
      Out_Path : String (1 .. 256) := (others => ASCII.NUL);
      Out_Len  : Natural := 0;
      SANs     : Cert_Builder.SAN_Array := (others => <>);
      SAN_Count : Natural := 0;
      I : Positive;
   begin
      if Argument_Count < 8
         or else Argument (3) /= "for"
         or else Argument (5) /= "using"
         or else Argument (7) /= "to"
      then
         Put_Line ("Usage: sparktls create csr for <name> using <key> to <file>");
         Set_Exit_Status (2);
         return;
      end if;

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

      --  Parse optional with-san
      I := 9;
      while I <= Argument_Count loop
         if Argument (I) = "with-san" and then I < Argument_Count then
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
         end if;
         I := I + 1;
      end loop;

      --  Load key and build CSR
      declare
         Key : Key_Util.Private_Key;
      begin
         Key_Util.Load_Private_Key (Key_Path (1 .. Key_Len), Key);
         if not Key.Valid then
            Put_Line (Standard_Error, "Failed to load key");
            Set_Exit_Status (1);
            return;
         end if;

         declare
            Subject : Cert_Builder.DN;
            CSR_DER : CSR_Builder.CSR_DER_Buf := (others => 0);
            CSR_Len : X509.N32;
            Build_OK, Write_OK : Boolean;
         begin
            Subject.CN (1 .. Name_Len) := Name (1 .. Name_Len);
            Subject.CN_Len := Name_Len;

            CSR_Builder.Build_CSR
              (Key, Subject, SANs, SAN_Count, CSR_DER, CSR_Len, Build_OK);

            if not Build_OK then
               Put_Line (Standard_Error, "CSR construction failed");
               Set_Exit_Status (1);
               return;
            end if;

            PEM_Util.Write_PEM_File
              (Out_Path (1 .. Out_Len),
               CSR_DER (0 .. CSR_Len - 1),
               "CERTIFICATE REQUEST",
               Write_OK);

            if not Write_OK then
               Put_Line (Standard_Error, "Failed to write " &
                         Out_Path (1 .. Out_Len));
               Set_Exit_Status (1);
               return;
            end if;

            Put_Line ("Wrote " & Out_Path (1 .. Out_Len) &
                      " (" & CSR_Len'Image & " bytes DER)");
         end;
      end;
   end Run_Create;

   --  sparktls sign-csr <csr> with-ca <ca-key> <ca-cert> to <file> [valid-for N]
   --  Args: 1=sign-csr 2=csr 3=with-ca 4=ca-key 5=ca-cert 6=to 7=file [8+]
   procedure Run_Sign is
      use Ada.Command_Line;
      Days : Natural := 365;
   begin
      if Argument_Count < 7
         or else Argument (3) /= "with-ca"
         or else Argument (6) /= "to"
      then
         Put_Line ("Usage: sparktls sign-csr <csr.pem> with-ca <ca.key> <ca.crt> to <cert.pem>");
         Set_Exit_Status (2);
         return;
      end if;

      --  Parse optional valid-for
      declare
         I : Positive := 8;
      begin
         while I <= Argument_Count loop
            if Argument (I) = "valid-for" and then I < Argument_Count then
               I := I + 1;
               begin
                  Days := Natural'Value (Argument (I));
               exception
                  when others =>
                     Put_Line (Standard_Error, "Invalid days");
                     Set_Exit_Status (1);
                     return;
               end;
            end if;
            I := I + 1;
         end loop;
      end;

      --  Load CSR
      declare
         CSR_Text : constant String := Read_Text_File (Argument (2));
         CSR_PEM  : SPARKTLS.PEM.Decode_Result;
      begin
         if CSR_Text'Length = 0 then
            Put_Line (Standard_Error, "Failed to read CSR");
            Set_Exit_Status (1);
            return;
         end if;

         SPARKTLS.PEM.Decode (CSR_Text, CSR_PEM);
         if not CSR_PEM.OK then
            Put_Line (Standard_Error, "Failed to decode CSR PEM");
            Set_Exit_Status (1);
            return;
         end if;

         --  Parse CSR to extract subject and SPKI
         declare
            Subject  : Cert_Builder.DN;
            SPKI     : X509.Byte_Seq (0 .. 255) := (others => 0);
            SPKI_Len : X509.N32;
            Parse_OK : Boolean;
         begin
            CSR_Builder.Parse_CSR
              (CSR_PEM.DER (0 .. CSR_PEM.DER_Len - 1),
               Subject, SPKI, SPKI_Len, Parse_OK);

            if not Parse_OK then
               Put_Line (Standard_Error, "Failed to parse CSR");
               Set_Exit_Status (1);
               return;
            end if;

            Put_Line ("CSR subject: CN=" & Subject.CN (1 .. Subject.CN_Len));

            --  Load CA key
            declare
               CA_Key : Key_Util.Private_Key;
            begin
               Key_Util.Load_Private_Key (Argument (4), CA_Key);
               if not CA_Key.Valid then
                  Put_Line (Standard_Error, "Failed to load CA key");
                  Set_Exit_Status (1);
                  return;
               end if;

               --  Load CA cert for issuer DN
               declare
                  CA_Text : constant String := Read_Text_File (Argument (5));
                  CA_PEM  : SPARKTLS.PEM.Decode_Result;
                  CA_Cert : X509.Certificate;
                  CA_OK   : Boolean;
               begin
                  if CA_Text'Length = 0 then
                     Put_Line (Standard_Error, "Failed to read CA cert");
                     Set_Exit_Status (1);
                     return;
                  end if;

                  SPARKTLS.PEM.Decode (CA_Text, CA_PEM);
                  if not CA_PEM.OK then
                     Put_Line (Standard_Error, "Failed to decode CA cert PEM");
                     Set_Exit_Status (1);
                     return;
                  end if;

                  X509.Parse (CA_PEM.DER (0 .. CA_PEM.DER_Len - 1),
                              CA_Cert, CA_OK);
                  if not CA_OK then
                     Put_Line (Standard_Error, "Invalid CA cert");
                     Set_Exit_Status (1);
                     return;
                  end if;

                  --  Build cert from CSR data
                  declare
                     Params : Cert_Builder.Cert_Params;
                     Cert_DER : Cert_Builder.Cert_DER_Buf := (others => 0);
                     Cert_Len : X509.N32;
                     Build_OK, Write_OK : Boolean;

                     CN_Span  : constant X509.Span :=
                        X509.Subject_CN (CA_Cert);
                     Org_Span : constant X509.Span :=
                        X509.Subject_Org (CA_Cert);
                  begin
                     --  Issuer from CA cert
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

                     --  Subject from CSR
                     Params.Subject := Subject;
                     Params.Key := CA_Key;
                     Params.SPKI (0 .. SPKI_Len - 1) :=
                        SPKI (0 .. SPKI_Len - 1);
                     Params.SPKI_Len := SPKI_Len;
                     Params.Is_CA := False;
                     Params.Valid_Days := Days;

                     --  TODO: extract SANs from CSR extensionRequest

                     Cert_Builder.Build_Certificate
                       (Params, Cert_DER, Cert_Len, Build_OK);

                     if not Build_OK then
                        Put_Line (Standard_Error, "Certificate signing failed");
                        Set_Exit_Status (1);
                        return;
                     end if;

                     PEM_Util.Write_PEM_File
                       (Argument (7),
                        Cert_DER (0 .. Cert_Len - 1),
                        "CERTIFICATE",
                        Write_OK);

                     if not Write_OK then
                        Put_Line (Standard_Error, "Failed to write cert");
                        Set_Exit_Status (1);
                        return;
                     end if;

                     Put_Line ("Wrote " & Argument (7) &
                               " (" & Cert_Len'Image & " bytes DER)");
                  end;
               end;
            end;
         end;
      end;
   end Run_Sign;

end Cmd_CSR;
