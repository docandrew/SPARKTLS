--  sparktls generate <algo> key to <file>

with Ada.Command_Line;
with Ada.Text_IO;    use Ada.Text_IO;
with X509; use type X509.N32;
with Key_Util;
with PEM_Util;

package body Cmd_Generate is

   procedure Print_Usage is
   begin
      Put_Line ("Usage: sparktls generate <algo> key to <file>");
      New_Line;
      Put_Line ("  algo: ed25519, p256, p384");
      New_Line;
      Put_Line ("Examples:");
      Put_Line ("  sparktls generate p256 key to server.key");
      Put_Line ("  sparktls generate ed25519 key to ca.key");
   end Print_Usage;

   procedure Run is
      use Ada.Command_Line;
      Algo_Str : constant String :=
        (if Argument_Count >= 2 then Argument (2) else "");
      Algo     : Key_Util.Key_Algorithm;
      Out_Path : constant String :=
        (if Argument_Count >= 5 then Argument (5) else "");

      Priv_DER : X509.Byte_Seq (0 .. 511) := (others => 0);
      Priv_Len : X509.N32;
      SPKI_DER : X509.Byte_Seq (0 .. 511) := (others => 0);
      SPKI_Len : X509.N32;
      Gen_OK   : Boolean;
      Write_OK : Boolean;
   begin
      --  Parse: generate <algo> key to <file>
      --  Args:    1=generate  2=algo  3=key  4=to  5=file
      if Argument_Count < 5
         or else Argument (3) /= "key"
         or else Argument (4) /= "to"
      then
         Print_Usage;
         Set_Exit_Status (2);
         return;
      end if;

      --  Parse algorithm
      if Algo_Str = "ed25519" then
         Algo := Key_Util.Algo_Ed25519;
      elsif Algo_Str = "p256" then
         Algo := Key_Util.Algo_P256;
      elsif Algo_Str = "p384" then
         Algo := Key_Util.Algo_P384;
      else
         Put_Line (Standard_Error,
                   "Unknown algorithm: " & Algo_Str);
         Put_Line (Standard_Error,
                   "Supported: ed25519, p256, p384");
         Set_Exit_Status (1);
         return;
      end if;

      Put_Line ("Generating " & Algo_Str & " key...");

      Key_Util.Generate_Key
        (Algo     => Algo,
         Priv_DER => Priv_DER,
         Priv_Len => Priv_Len,
         SPKI_DER => SPKI_DER,
         SPKI_Len => SPKI_Len,
         OK       => Gen_OK);

      if not Gen_OK then
         Put_Line (Standard_Error, "Key generation failed");
         Set_Exit_Status (1);
         return;
      end if;

      PEM_Util.Write_PEM_File
        (Path  => Out_Path,
         DER   => Priv_DER (0 .. Priv_Len - 1),
         Label => "PRIVATE KEY",
         OK    => Write_OK);

      if not Write_OK then
         Put_Line (Standard_Error,
                   "Failed to write " & Out_Path);
         Set_Exit_Status (1);
         return;
      end if;

      Put_Line ("Wrote " & Out_Path &
                " (" & Priv_Len'Image & " bytes DER)");
   end Run;

end Cmd_Generate;
