with Ada.Directories;
with Ada.Text_IO;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with SPARKTLS.PEM;           use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;

package body SPARKTLS.System_Roots with
   SPARK_Mode => Off
is
   --  Well-known CA bundle paths on Linux
   Bundle_Paths : constant array (1 .. 3) of access constant String :=
     (1 => new String'("/etc/ssl/certs/ca-certificates.crt"),
      2 => new String'("/etc/pki/tls/certs/ca-bundle.crt"),
      3 => new String'("/etc/ssl/ca-bundle.pem"));

   --  Read entire file into a String
   function Read_File (Path : String) return String is
      use Ada.Text_IO;
      F      : File_Type;
      Result : String (1 .. 1024 * 1024) := (others => ' ');
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

   --  Decode all PEM certs from text and add to store
   procedure Load_PEM_Certs
     (Store  : in out Trust_Store;
      Text   : String;
      Loaded : out Natural)
   is
      Pos    : Positive := Text'First;
      Result : PEM.Decode_Result;
      Add_OK : Boolean;
   begin
      Loaded := 0;

      --  Find each PEM block in the text
      while Pos <= Text'Last loop
         --  Look for next "-----BEGIN"
         declare
            Begin_Marker : constant String := "-----BEGIN ";
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

            if not Found then
               return;
            end if;
         end;

         --  Decode starting from this position
         PEM.Decode (Text (Pos .. Text'Last), Result);

         if Result.OK and then Result.Label = PEM.Label_Certificate then
            Cert_Verify.Add_Root
              (Store,
               Result.DER (0 .. Result.DER_Len - 1),
               Add_OK);
            if Add_OK then
               Loaded := Loaded + 1;
            end if;
         end if;

         --  Skip past this block to find the next one
         declare
            End_Marker : constant String := "-----END ";
            Found : Boolean := False;
         begin
            while Pos + End_Marker'Length - 1 <= Text'Last loop
               if Text (Pos .. Pos + End_Marker'Length - 1) =
                  End_Marker
               then
                  --  Skip to end of line
                  while Pos <= Text'Last
                     and then Text (Pos) /= ASCII.LF
                  loop
                     Pos := Pos + 1;
                  end loop;
                  Found := True;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;

            if not Found then
               return;
            end if;
         end;

         Pos := Pos + 1;
      end loop;
   end Load_PEM_Certs;

   procedure Load_Bundle
     (Store  : in out Trust_Store;
      Path   : String;
      Loaded : out Natural;
      OK     : out Boolean)
   is
      Text : constant String := Read_File (Path);
   begin
      Loaded := 0;
      OK := False;

      if Text'Length = 0 then
         return;
      end if;

      Load_PEM_Certs (Store, Text, Loaded);
      OK := Loaded > 0;
   end Load_Bundle;

   procedure Load
     (Store  : out Trust_Store;
      Loaded : out Natural;
      OK     : out Boolean)
   is
   begin
      Store := (others => <>);
      Loaded := 0;
      OK := False;

      for I in Bundle_Paths'Range loop
         if Ada.Directories.Exists (Bundle_Paths (I).all) then
            Load_Bundle (Store, Bundle_Paths (I).all, Loaded, OK);
            if OK then
               return;
            end if;
         end if;
      end loop;
   end Load;

end SPARKTLS.System_Roots;
