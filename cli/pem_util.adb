with Interfaces.C;
with Interfaces.C.Strings;
with GNAT.OS_Lib;
with Ada.Directories;
with Ada.Text_IO;
with SPARKTLSCrypto.Base64;

package body PEM_Util is
   use type X509.N32;

   function Encode_PEM
     (DER   : X509.Byte_Seq;
      Label : String) return String
   is
      --  Convert DER bytes to a String for Base64.Encode
      Plain : String (1 .. Natural (DER'Length));
   begin
      for I in DER'Range loop
         Plain (Natural (I - DER'First) + 1) := Character'Val (DER (I));
      end loop;

      declare
         B64 : constant String :=
            SPARKTLSCrypto.Base64.To_String
              (SPARKTLSCrypto.Base64.Encode (Plain));
         Header : constant String :=
            "-----BEGIN " & Label & "-----" & ASCII.LF;
         Footer : constant String :=
            "-----END " & Label & "-----";

         --  Insert line breaks every 64 characters
         Lines_Len : constant Natural :=
            B64'Length + (B64'Length / 64) + 1;
         Result : String (1 .. Header'Length + Lines_Len + Footer'Length);
         Pos    : Natural := 0;

         procedure Append (S : String) is
         begin
            Result (Pos + 1 .. Pos + S'Length) := S;
            Pos := Pos + S'Length;
         end Append;
      begin
         Append (Header);

         declare
            I : Natural := B64'First;
         begin
            while I <= B64'Last loop
               declare
                  Line_End : constant Natural :=
                     Natural'Min (I + 63, B64'Last);
               begin
                  Append (B64 (I .. Line_End));
                  Append ((1 => ASCII.LF));
                  I := Line_End + 1;
               end;
            end loop;
         end;

         Append (Footer);
         return Result (1 .. Pos);
      end;
   end Encode_PEM;

   --  open(2) with O_CREAT|O_EXCL: a private key is created 0600 and no
   --  existing file is ever replaced (the old Ada.Text_IO.Create wrote
   --  keys world-readable under the umask and truncated whatever was
   --  there). Certificates and CSRs get 0644.
   O_WRONLY : constant := 1;
   O_CREAT  : constant := 8#100#;
   O_EXCL   : constant := 8#200#;
   function C_Open (Path : Interfaces.C.Strings.chars_ptr; Flags : Interfaces.C.int;
                    Mode : Interfaces.C.unsigned) return Interfaces.C.int;
   pragma Import (C, C_Open, "open");

   procedure Write_PEM_File
     (Path  : String;
      DER   : X509.Byte_Seq;
      Label : String;
      OK    : out Boolean)
   is
      use type Interfaces.C.int;
      PEM     : constant String := Encode_PEM (DER, Label);
      Secret  : constant Boolean := Label = "PRIVATE KEY";
      C_Path  : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Path);
      FD      : Interfaces.C.int;
      Written : Integer;
   begin
      OK := False;
      if Ada.Directories.Exists (Path) then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "Error: " & Path & " already exists; remove it or choose another name");
         Interfaces.C.Strings.Free (C_Path);
         return;
      end if;
      FD := C_Open (C_Path, O_WRONLY + O_CREAT + O_EXCL, (if Secret then 8#600# else 8#644#));
      Interfaces.C.Strings.Free (C_Path);
      if FD < 0 then
         Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "Error: cannot create " & Path);
         return;
      end if;
      Written := GNAT.OS_Lib.Write (GNAT.OS_Lib.File_Descriptor (FD), PEM'Address, PEM'Length);
      GNAT.OS_Lib.Close (GNAT.OS_Lib.File_Descriptor (FD));
      OK := Written = PEM'Length;
   end Write_PEM_File;

end PEM_Util;
