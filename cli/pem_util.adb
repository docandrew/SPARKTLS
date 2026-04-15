with Ada.Text_IO;
with Base64;

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
            Base64.To_String (Base64.Encode (Plain));
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

   procedure Write_PEM_File
     (Path  : String;
      DER   : X509.Byte_Seq;
      Label : String;
      OK    : out Boolean)
   is
      use Ada.Text_IO;
      F   : File_Type;
      PEM : constant String := Encode_PEM (DER, Label);
   begin
      OK := False;
      Create (F, Out_File, Path);
      Put (F, PEM);
      Close (F);
      OK := True;
   exception
      when others =>
         if Is_Open (F) then Close (F); end if;
   end Write_PEM_File;

end PEM_Util;
