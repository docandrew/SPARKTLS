with Ada.Command_Line;
with Ada.Text_IO;       use Ada.Text_IO;
with SPARKNaCl;
with X509;
with SPARKTLS.Cert_Verify;
with CLI_Util;          use CLI_Util;

package body Cmd_Verify is

   Max_Chain : constant := 10;

   type Cert_Entry is record
      Data  : Byte_Seq_Access := null;
      Cert  : X509.Certificate;
      Valid : Boolean := False;
      Label : access String := null;  --  "end-entity", "intermediate", "CA"
   end record;

   procedure Run is
      use Ada.Command_Line;
      use type X509.N32;

      --  Argument parsing
      Leaf_Path  : access String := null;
      CA_Paths   : array (1 .. Max_Chain) of access String := (others => null);
      CA_Count   : Natural := 0;
      Hostname   : access String := null;
      I          : Natural := 2;

      --  Chain: index 0 = leaf, 1..N = CAs (in order provided)
      Chain   : array (0 .. Max_Chain) of Cert_Entry;
      N_Certs : Natural := 0;

      All_OK  : Boolean := True;
   begin
      --  Parse arguments: sparktls verify <cert.der> --ca <ca.der> [--host name]
      while I <= Argument_Count loop
         declare
            Arg : constant String := Argument (I);
         begin
            if Arg = "--ca" then
               I := I + 1;
               if I > Argument_Count then
                  Put_Line (Standard_Error, "Error: --ca requires a file");
                  Set_Exit_Status (2);
                  return;
               end if;
               if CA_Count >= Max_Chain then
                  Put_Line (Standard_Error, "Error: too many --ca files");
                  Set_Exit_Status (2);
                  return;
               end if;
               CA_Count := CA_Count + 1;
               CA_Paths (CA_Count) := new String'(Argument (I));
            elsif Arg = "--host" then
               I := I + 1;
               if I > Argument_Count then
                  Put_Line (Standard_Error, "Error: --host requires a name");
                  Set_Exit_Status (2);
                  return;
               end if;
               Hostname := new String'(Argument (I));
            elsif Arg (Arg'First) = '-' then
               Put_Line (Standard_Error, "Unknown option: " & Arg);
               Set_Exit_Status (2);
               return;
            else
               if Leaf_Path /= null then
                  Put_Line (Standard_Error,
                            "Error: multiple leaf certs given");
                  Set_Exit_Status (2);
                  return;
               end if;
               Leaf_Path := new String'(Arg);
            end if;
         end;
         I := I + 1;
      end loop;

      if Leaf_Path = null then
         Put_Line (Standard_Error,
                   "Usage: sparktls verify <cert.der> --ca <ca.der>" &
                   " [--ca <int.der>] [--host hostname]");
         Set_Exit_Status (2);
         return;
      end if;

      if CA_Count = 0 then
         Put_Line (Standard_Error,
                   "Error: at least one --ca file is required");
         Set_Exit_Status (2);
         return;
      end if;

      --  Load leaf cert
      declare
         OK : Boolean;
      begin
         Read_DER_File (Leaf_Path.all, Chain (0).Data, OK);
         if not OK then
            Set_Exit_Status (1);
            return;
         end if;
         X509.Parse (Chain (0).Data.all, Chain (0).Cert, OK);
         Chain (0).Valid := OK;
         Chain (0).Label := new String'("end-entity");
         if not OK then
            Put_Line (Standard_Error,
                      "Error: failed to parse leaf cert: " & Leaf_Path.all);
            Set_Exit_Status (1);
            return;
         end if;
      end;

      --  Load CA certs
      for J in 1 .. CA_Count loop
         declare
            OK : Boolean;
         begin
            Read_DER_File (CA_Paths (J).all, Chain (J).Data, OK);
            if not OK then
               Set_Exit_Status (1);
               return;
            end if;
            X509.Parse (Chain (J).Data.all, Chain (J).Cert, OK);
            Chain (J).Valid := OK;
            if X509.Is_CA (Chain (J).Cert) then
               Chain (J).Label := new String'("CA");
            else
               Chain (J).Label := new String'("intermediate");
            end if;
            if not OK then
               Put_Line (Standard_Error,
                         "Error: failed to parse CA cert: " &
                         CA_Paths (J).all);
               Set_Exit_Status (1);
               return;
            end if;
         end;
      end loop;
      N_Certs := CA_Count + 1;

      --  Print chain summary
      Put_Line ("Chain:");
      for J in 0 .. N_Certs - 1 loop
         declare
            CN : constant X509.Span := X509.Subject_CN (Chain (J).Cert);
            CN_Str : constant String :=
               (if CN.Present then Span_To_String (Chain (J).Data.all, CN)
                else "(no CN)");
            Idx : constant String := Natural'Image (J);
         begin
            Put_Line ("  [" & Idx (Idx'First + 1 .. Idx'Last) & "] CN=" &
                      CN_Str & " (" & Chain (J).Label.all & ")");
         end;
      end loop;
      New_Line;

      --  Validate each link in the chain
      Put_Line ("Checks:");
      declare
         N : constant X509.Date_Time := Now;
      begin
         for J in 0 .. N_Certs - 1 loop
            --  Structural validity
            declare
               SV : constant Boolean :=
                  X509.Is_Structurally_Valid (Chain (J).Cert, N);
            begin
               Put_Check (J, "Structural validity", SV);
               if not SV then All_OK := False; end if;
            end;

            --  Date validity
            declare
               DV : constant Boolean :=
                  X509.Is_Date_Valid (Chain (J).Cert, N);
            begin
               Put_Check (J, "Date validity", DV,
                          (if not DV then "expired or not yet valid"
                           else ""));
               if not DV then All_OK := False; end if;
            end;

            --  Chain checks (leaf and intermediates against their issuer)
            if J < N_Certs - 1 then
               declare
                  Issuer_Idx : constant Natural := J + 1;
               begin
                  --  Issuer DN match
                  declare
                     IM : constant Boolean :=
                        X509.Issuer_Matches
                          (Chain (J).Cert, Chain (J).Data.all,
                           Chain (Issuer_Idx).Cert,
                           Chain (Issuer_Idx).Data.all);
                  begin
                     Put_Check (J, "Issuer DN match", IM);
                     if not IM then All_OK := False; end if;
                  end;

                  --  Issuer may sign
                  declare
                     MS : constant Boolean :=
                        X509.Issuer_May_Sign (Chain (Issuer_Idx).Cert);
                  begin
                     Put_Check (J, "Issuer may sign", MS);
                     if not MS then All_OK := False; end if;
                  end;

                  --  Issuer EKU allows signing
                  declare
                     ES : constant Boolean :=
                        X509.Issuer_EKU_Allows_Signing
                          (Chain (Issuer_Idx).Cert);
                  begin
                     Put_Check (J, "Issuer EKU allows signing", ES);
                     if not ES then All_OK := False; end if;
                  end;

                  --  Name constraints
                  declare
                     NC : constant Boolean :=
                        X509.Satisfies_Name_Constraints
                          (Chain (J).Cert, Chain (J).Data.all,
                           Chain (Issuer_Idx).Cert,
                           Chain (Issuer_Idx).Data.all);
                  begin
                     Put_Check (J, "Name constraints", NC);
                     if not NC then All_OK := False; end if;
                  end;

                  --  Issuer is CA (for non-leaf certs being issued)
                  if J > 0 then
                     declare
                        CA : constant Boolean :=
                           X509.Is_CA (Chain (J).Cert);
                     begin
                        Put_Check (J, "Is CA", CA);
                        if not CA then All_OK := False; end if;
                     end;
                  end if;

                  --  Signature verification (crypto)
                  --  Cert_Verify takes SPARKNaCl.Byte_Seq; overlay
                  --  the X509.Byte_Seq (identical layout, not SPARK).
                  declare
                     Algo : constant X509.Algorithm_ID :=
                        X509.Sig_Algorithm (Chain (J).Cert);
                     NaCl_DER : SPARKNaCl.Byte_Seq
                       (0 .. SPARKNaCl.N32 (Chain (J).Data'Last));
                     for NaCl_DER'Address use
                        Chain (J).Data.all'Address;
                     pragma Import (Ada, NaCl_DER);
                     SV : constant Boolean :=
                        SPARKTLS.Cert_Verify.Verify_Cert_Signature
                          (NaCl_DER,
                           Chain (J).Cert,
                           Chain (Issuer_Idx).Cert);
                  begin
                     Put_Check (J, "Signature (" & Algo_Name (Algo) & ")",
                                SV);
                     if not SV then All_OK := False; end if;
                  end;

                  --  Path length constraint
                  if X509.Has_Path_Len_Constraint
                       (Chain (Issuer_Idx).Cert)
                  then
                     declare
                        PL : constant Natural :=
                           X509.Path_Len_Constraint
                             (Chain (Issuer_Idx).Cert);
                        --  J = depth below issuer (0 = end-entity)
                        OK : constant Boolean := J <= PL;
                     begin
                        Put_Check (J, "Path length", OK,
                                   (if not OK then "depth exceeds limit"
                                    else ""));
                        if not OK then All_OK := False; end if;
                     end;
                  end if;
               end;
            end if;
         end loop;

         --  Hostname check on leaf
         if Hostname /= null then
            declare
               HM : constant Boolean :=
                  X509.Matches_Hostname
                    (Chain (0).Cert,
                     Chain (0).Data.all,
                     Hostname.all);
            begin
               Put_Check (0, "Hostname (" & Hostname.all & ")", HM);
               if not HM then All_OK := False; end if;
            end;
         end if;
      end;

      --  Final result
      New_Line;
      if All_OK then
         Put_Line ("Result: VALID");
         Set_Exit_Status (0);
      else
         Put_Line ("Result: INVALID");
         Set_Exit_Status (1);
      end if;

      --  Cleanup
      for J in 0 .. N_Certs - 1 loop
         Free (Chain (J).Data);
      end loop;
   end Run;

end Cmd_Verify;
