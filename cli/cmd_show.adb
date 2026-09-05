with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with Interfaces;
with X509;
with CLI_Util;       use CLI_Util;

package body Cmd_Show is

   procedure Show_Full
     (DER  : X509.Byte_Seq;
      Cert : X509.Certificate)
   is
      use type X509.N32;
      use type X509.Algorithm_ID;

      function Span_Str (S : X509.Span) return String is
      begin
         if S.Present then
            return Span_To_String (DER, S);
         else
            return "(not present)";
         end if;
      end Span_Str;

      function Span_Hex (S : X509.Span) return String is
         Len : constant X509.N32 := X509.Span_Length (S);
      begin
         if not S.Present or Len = 0 then
            return "(not present)";
         end if;
         return To_Hex_Trunc (DER (S.First .. S.First + Len - 1));
      end Span_Hex;

   begin
      Put_Line ("Certificate:");

      --  Version & Serial
      Put_Field ("Version", Natural'Image (X509.Version (Cert)));
      Put_Field ("Serial", Span_Hex (X509.Serial (Cert)));
      Put_Field ("Signature Algo",
                 Algo_Name (X509.Sig_Algorithm (Cert)));

      --  Issuer
      New_Line;
      Put_Line ("  Issuer:");
      Put_Field ("  CN", Span_Str (X509.Issuer_CN (Cert)));
      Put_Field ("  O", Span_Str (X509.Issuer_Org (Cert)));
      Put_Field ("  C", Span_Str (X509.Issuer_Country (Cert)));

      --  Subject
      New_Line;
      Put_Line ("  Subject:");
      Put_Field ("  CN", Span_Str (X509.Subject_CN (Cert)));
      Put_Field ("  O", Span_Str (X509.Subject_Org (Cert)));
      Put_Field ("  C", Span_Str (X509.Subject_Country (Cert)));

      --  Validity
      New_Line;
      Put_Line ("  Validity:");
      Put_Field ("  Not Before", Format_Date (X509.Not_Before (Cert)));
      Put_Field ("  Not After", Format_Date (X509.Not_After (Cert)));
      declare
         N : constant X509.Date_Time := Now;
      begin
         if X509.Is_Date_Valid (Cert, N) then
            Put_Field ("  Status", "valid (current)");
         else
            Put_Field ("  Status", "EXPIRED or not yet valid");
         end if;
      end;

      --  SANs
      if X509.SAN_Count (Cert) > 0 then
         New_Line;
         Put_Line ("  Subject Alt Names:");
         for I in 1 .. X509.SAN_Count (Cert) loop
            declare
               S : constant X509.Span := X509.SAN_DNS (Cert, I);
            begin
               Put_Field ("  DNS", Span_Str (S));
            end;
         end loop;
      end if;

      --  Public Key
      New_Line;
      Put_Line ("  Public Key:");
      Put_Field ("  Algorithm",
                 PK_Description (X509.PK_Algorithm (Cert),
                                 X509.PK_Length (Cert)));
      if X509.PK_Length (Cert) > 0
         and then X509.PK_Length (Cert) <= X509.Max_PK_Bytes
      then
         Put_Field ("  Key Data",
                    To_Hex_Trunc (X509.PK_Data (Cert)));
      end if;
      if X509.PK_Algorithm (Cert) = X509.Algo_RSA then
         Put_Field ("  Exponent",
                    Interfaces.Unsigned_32'Image
                      (X509.RSA_Exponent (Cert)));
      end if;

      --  Extensions
      if X509.Has_Extensions (Cert) then
         New_Line;
         Put_Line ("  Extensions:");

         --  Basic Constraints
         if X509.Is_CA (Cert) then
            if X509.Has_Path_Len_Constraint (Cert) then
               Put_Field ("  Basic Constraints",
                          "CA=TRUE, pathLen=" &
                          Natural'Image (X509.Path_Len_Constraint (Cert)));
            else
               Put_Field ("  Basic Constraints", "CA=TRUE");
            end if;
         else
            Put_Field ("  Basic Constraints", "CA=FALSE");
         end if;

         --  Key Usage
         if X509.Has_Key_Usage (Cert) then
            declare
               KU : String (1 .. 200);
               Pos : Natural := 0;

               procedure Append (S : String) is
               begin
                  if Pos > 0 then
                     Pos := Pos + 2;
                     KU (Pos - 1 .. Pos) := ", ";
                  end if;
                  KU (Pos + 1 .. Pos + S'Length) := S;
                  Pos := Pos + S'Length;
               end Append;
            begin
               if X509.KU_Digital_Signature (Cert) then
                  Append ("Digital Signature");
               end if;
               if X509.KU_Key_Encipherment (Cert) then
                  Append ("Key Encipherment");
               end if;
               if X509.KU_Key_Cert_Sign (Cert) then
                  Append ("Certificate Sign");
               end if;
               if X509.KU_CRL_Sign (Cert) then
                  Append ("CRL Sign");
               end if;
               if Pos > 0 then
                  Put_Field ("  Key Usage", KU (1 .. Pos));
               else
                  Put_Field ("  Key Usage", "(none)");
               end if;
            end;
         end if;

         --  Subject Key ID
         declare
            SKID : constant X509.Span := X509.Subject_Key_ID (Cert);
         begin
            if SKID.Present then
               Put_Field ("  Subject Key ID", Span_Hex (SKID));
            end if;
         end;

         --  Authority Key ID
         declare
            AKID : constant X509.Span := X509.Authority_Key_ID (Cert);
         begin
            if AKID.Present then
               Put_Field ("  Authority Key ID", Span_Hex (AKID));
            end if;
         end;
      end if;

      --  Structural validation
      New_Line;
      declare
         N : constant X509.Date_Time := Now;
      begin
         if X509.Is_Structurally_Valid (Cert, N) then
            Put_Field ("Structural Check", "PASS");
         else
            Put_Field ("Structural Check", "FAIL");
            --  Show which checks failed
            if X509.Has_Unknown_Critical_Extension (Cert) then
               Put_Line ("    - unknown critical extension");
            end if;
            if X509.Has_Bad_Serial (Cert) then
               Put_Line ("    - bad serial number");
            end if;
            if X509.Has_Bad_Time_Format (Cert) then
               Put_Line ("    - bad time format");
            end if;
            if X509.Has_Bad_SAN (Cert) then
               Put_Line ("    - bad SAN");
            end if;
            if X509.Has_Bad_PubKey (Cert) then
               Put_Line ("    - bad public key");
            end if;
            if X509.Has_Bad_DER (Cert) then
               Put_Line ("    - DER encoding error");
            end if;
            if X509.Has_Duplicate_Extension (Cert) then
               Put_Line ("    - duplicate extension");
            end if;
            if X509.Has_Bad_Extension_Criticality (Cert) then
               Put_Line ("    - bad extension criticality");
            end if;
            if X509.Has_Bad_Cert_Policy (Cert) then
               Put_Line ("    - bad certificate policy");
            end if;
            if X509.Has_Bad_AKID (Cert) then
               Put_Line ("    - bad AKID");
            end if;
            if X509.Has_Bad_Subject_Encoding (Cert) then
               Put_Line ("    - bad subject encoding");
            end if;
            if X509.Has_Bad_EKU_Content (Cert) then
               Put_Line ("    - bad EKU content");
            end if;
            if X509.Has_Bad_CRL_DP (Cert) then
               Put_Line ("    - bad CRL distribution point");
            end if;
            if X509.Has_Bad_Ext_Content (Cert) then
               Put_Line ("    - bad extension content");
            end if;
            if X509.Has_Key_Cert_Sign_Without_CA (Cert) then
               Put_Line ("    - keyCertSign without CA");
            end if;
            if X509.Has_Path_Len_Without_CA (Cert) then
               Put_Line ("    - pathLen without CA");
            end if;
            if not X509.Is_Date_Valid (Cert, N) then
               Put_Line ("    - certificate expired or not yet valid");
            end if;
         end if;
      end;

      --  Signature value
      New_Line;
      Put_Line ("  Signature:");
      Put_Field ("  Algorithm",
                 Algo_Name (X509.Sig_Algorithm (Cert)));
      if X509.Sig_Length (Cert) > 0
         and then X509.Sig_Length (Cert) <= X509.Max_Sig_Bytes
      then
         Put_Field ("  Value",
                    To_Hex_Trunc (X509.Sig_Data (Cert)));
      end if;
   end Show_Full;

   procedure Show_Brief
     (DER  : X509.Byte_Seq;
      Cert : X509.Certificate)
   is
      use type X509.N32;

      function Span_Str (S : X509.Span) return String is
      begin
         if S.Present then
            return Span_To_String (DER, S);
         else
            return "";
         end if;
      end Span_Str;

      function Name_Line (CN, Org, Country : X509.Span) return String is
         S : String (1 .. 500);
         Pos : Natural := 0;

         procedure Add (Label : String; V : X509.Span) is
            Val : constant String := Span_Str (V);
         begin
            if Val'Length > 0 then
               if Pos > 0 then
                  S (Pos + 1 .. Pos + 2) := ", ";
                  Pos := Pos + 2;
               end if;
               S (Pos + 1 .. Pos + Label'Length) := Label;
               Pos := Pos + Label'Length;
               S (Pos + 1 .. Pos + Val'Length) := Val;
               Pos := Pos + Val'Length;
            end if;
         end Add;
      begin
         Add ("CN=", CN);
         Add ("O=", Org);
         Add ("C=", Country);
         if Pos = 0 then
            return "(empty)";
         end if;
         return S (1 .. Pos);
      end Name_Line;

   begin
      Put_Line ("Subject:  " &
                Name_Line (X509.Subject_CN (Cert),
                           X509.Subject_Org (Cert),
                           X509.Subject_Country (Cert)));
      Put_Line ("Issuer:   " &
                Name_Line (X509.Issuer_CN (Cert),
                           X509.Issuer_Org (Cert),
                           X509.Issuer_Country (Cert)));
      Put_Line ("Valid:    " &
                Format_Date (X509.Not_Before (Cert)) & " -- " &
                Format_Date (X509.Not_After (Cert)));

      --  SANs
      if X509.SAN_Count (Cert) > 0 then
         declare
            Line : String (1 .. 2000);
            Pos  : Natural := 0;
         begin
            for I in 1 .. X509.SAN_Count (Cert) loop
               declare
                  S   : constant X509.Span := X509.SAN_DNS (Cert, I);
                  Val : constant String := Span_Str (S);
               begin
                  if Val'Length > 0 then
                     if Pos > 0 then
                        Line (Pos + 1 .. Pos + 2) := ", ";
                        Pos := Pos + 2;
                     end if;
                     Line (Pos + 1 .. Pos + Val'Length) := Val;
                     Pos := Pos + Val'Length;
                  end if;
               end;
            end loop;
            if Pos > 0 then
               Put_Line ("SANs:     " & Line (1 .. Pos));
            end if;
         end;
      end if;

      Put_Line ("Key:      " &
                PK_Description (X509.PK_Algorithm (Cert),
                                X509.PK_Length (Cert)));
      Put_Line ("Sig:      " &
                Algo_Name (X509.Sig_Algorithm (Cert)));
   end Show_Brief;

   ----------------------------------------------------------------
   --  Run
   ----------------------------------------------------------------

   procedure Run is
      use Ada.Command_Line;
      File_Path : access String := null;
      Brief     : Boolean := False;
      I         : Natural := 2;
   begin
      --  Parse arguments: sparktls_cli show <file> [--brief]
      while I <= Argument_Count loop
         declare
            Arg : constant String := Argument (I);
         begin
            if Arg = "--brief" or Arg = "-b" then
               Brief := True;
            elsif Arg (Arg'First) = '-' then
               Put_Line (Standard_Error,
                         "Unknown option: " & Arg);
               Ada.Command_Line.Set_Exit_Status (2);
               return;
            else
               if File_Path /= null then
                  Put_Line (Standard_Error,
                            "Error: multiple files given");
                  Ada.Command_Line.Set_Exit_Status (2);
                  return;
               end if;
               File_Path := new String'(Arg);
            end if;
         end;
         I := I + 1;
      end loop;

      if File_Path = null then
         Put_Line (Standard_Error,
                   "Usage: sparktls_cli show <cert.pem|cert.der> [--brief]");
         Ada.Command_Line.Set_Exit_Status (2);
         return;
      end if;

      --  Load and parse
      declare
         Data : Byte_Seq_Access;
         OK   : Boolean;
         Cert : X509.Certificate;
      begin
         Read_Cert_File (File_Path.all, Data, OK);
         if not OK then
            Ada.Command_Line.Set_Exit_Status (1);
            return;
         end if;

         X509.Parse (Data.all, Cert, OK);
         if not OK then
            Put_Line (Standard_Error, "Error: failed to parse certificate");
            Free (Data);
            Ada.Command_Line.Set_Exit_Status (1);
            return;
         end if;

         if Brief then
            Show_Brief (Data.all, Cert);
         else
            Show_Full (Data.all, Cert);
         end if;

         Free (Data);
      end;
   end Run;

end Cmd_Show;
