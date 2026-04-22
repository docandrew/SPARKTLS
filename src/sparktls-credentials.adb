with Ada.Text_IO;
with X509;
use type X509.Byte_Seq;
with SPARKTLS.PEM;           use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Credentials.Parsing;

package body SPARKTLS.Credentials with
   SPARK_Mode => Off
   --  SPARK_Mode Off: Read_File performs file I/O with exceptions.
   --  All pure parsing is in Credentials.Parsing (SPARK_Mode On).
is
   --  Read entire file into a String (file I/O — only non-SPARK code)
   function Read_File (Path : String) return String is
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
   end Read_File;

   --  Load_Identity_PEM delegates to SPARK-verified parsing
   procedure Load_Identity_PEM
     (Id       : out Identity;
      Cert_PEM : String;
      Key_PEM  : String;
      OK       : out Boolean)
   is
   begin
      Parsing.Load_Identity_PEM (Id, Cert_PEM, Key_PEM, OK);
   end Load_Identity_PEM;

   --  Load_Identity: file I/O wrapper around Load_Identity_PEM
   procedure Load_Identity
     (Id        : out Identity;
      Cert_Path : String;
      Key_Path  : String;
      OK        : out Boolean)
   is
      Cert_Text : constant String := Read_File (Cert_Path);
      Key_Text  : constant String := Read_File (Key_Path);
   begin
      Id := (others => <>);
      OK := False;

      if Cert_Text'Length = 0 or Key_Text'Length = 0 then
         return;
      end if;

      Load_Identity_PEM (Id, Cert_Text, Key_Text, OK);
   end Load_Identity;

   --  Load_Trust_Store: file I/O + PEM decode + cert loading
   procedure Load_Trust_Store
     (Store : out Trust_Store;
      Path  : String;
      OK    : out Boolean)
   is
      use type X509.N32;
      Text : constant String := Read_File (Path);
      DER_Buf  : X509.Byte_Seq (0 .. 65535) := (others => 0);
      DER_Pos  : X509.N32 := 0;
      Pos      : Positive;
   begin
      Store := (others => <>);
      OK := False;

      if Text'Length = 0 then return; end if;

      Pos := Text'First;
      while Pos <= Text'Last loop
         declare
            Begin_Marker : constant String := "-----BEGIN ";
            End_Marker   : constant String := "-----END ";
            Found : Boolean := False;
         begin
            while Pos + Begin_Marker'Length - 1 <= Text'Last loop
               if Text (Pos .. Pos + Begin_Marker'Length - 1) =
                  Begin_Marker
               then
                  Found := True;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            if not Found then exit; end if;
         end;

         declare
            R : PEM.Decode_Result;
         begin
            PEM.Decode (Text (Pos .. Text'Last), R);

            if R.OK and then R.Label = PEM.Label_Certificate then
               if DER_Pos + R.DER_Len <= X509.N32 (DER_Buf'Last) + 1 then
                  for I in X509.N32 range 0 .. R.DER_Len - 1 loop
                     DER_Buf (DER_Pos + I) := R.DER (I);
                  end loop;
                  DER_Pos := DER_Pos + R.DER_Len;
               end if;
            end if;
         end;

         declare
            End_Marker : constant String := "-----END ";
            Found : Boolean := False;
         begin
            while Pos + End_Marker'Length - 1 <= Text'Last loop
               if Text (Pos .. Pos + End_Marker'Length - 1) =
                  End_Marker
               then
                  Found := True;
                  while Pos <= Text'Last
                     and then Text (Pos) /= ASCII.LF
                  loop
                     Pos := Pos + 1;
                  end loop;
                  if Pos <= Text'Last then
                     Pos := Pos + 1;
                  end if;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            if not Found then exit; end if;
         end;
      end loop;

      if DER_Pos > 0 then
         declare
            Loaded : Natural;
         begin
            Cert_Verify.Load_Roots (Store, DER_Buf (0 .. DER_Pos - 1),
                                    Loaded, OK);
         end;
      end if;
   end Load_Trust_Store;

end SPARKTLS.Credentials;
