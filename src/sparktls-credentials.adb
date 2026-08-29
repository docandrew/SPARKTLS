with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with X509;
use type X509.Byte_Seq;
with SPARKTLS.PEM; use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Credentials.Parsing;

package body SPARKTLS.Credentials
  with
    SPARK_Mode => Off
    --  SPARK_Mode Off: Read_File performs file I/O with exceptions.
    --  All pure parsing is in Credentials.Parsing (SPARK_Mode On).
is
   --  Read entire file into a String (file I/O â only non-SPARK code)
   --  Read a file into a String. Capped at 1 MB â matches the
   --  PEM.Max_PEM_Input precondition. Mozilla's CA bundle is ~220 KB
   --  with ~140 roots; the previous 64 KB cap silently truncated
   --  after ~43 certs which is why real-world chain validation
   --  failed against any site whose root sat past that line.
   --
   --  Allocated on the heap (Strings_Edit-style) so a 1 MB local
   --  doesn't tax the stack.
   function Read_File (Path : String) return String is
      use Ada.Text_IO;
      Max_Bytes : constant := 1_048_576;  --  1 MB
      type Buf_Access is access all String;
      Buf  : Buf_Access := new String (1 .. Max_Bytes);
      F    : File_Type;
      Len  : Natural := 0;
      Line : String (1 .. 4096);
      Last : Natural;
      procedure Free is new Ada.Unchecked_Deallocation (String, Buf_Access);
   begin
      Buf.all := (others => ' ');
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Get_Line (F, Line, Last);
         if Len + Last + 1 <= Buf'Last then
            Buf (Len + 1 .. Len + Last) := Line (1 .. Last);
            Len := Len + Last;
            Buf (Len + 1) := ASCII.LF;
            Len := Len + 1;
         end if;
      end loop;
      Close (F);
      declare
         Result : constant String := Buf (1 .. Len);
      begin
         Free (Buf);
         return Result;
      end;
   exception
      when others =>
         if Buf /= null then
            Free (Buf);
         end if;
         return "";
   end Read_File;

   --  Load_Identity_PEM delegates to SPARK-verified parsing
   procedure Load_Identity_PEM
     (Id : out Identity; Cert_PEM : String; Key_PEM : String; OK : out Boolean) is
   begin
      Parsing.Load_Identity_PEM (Id, Cert_PEM, Key_PEM, OK);
   end Load_Identity_PEM;

   --  Load_Identity: file I/O wrapper around Load_Identity_PEM
   procedure Load_Identity
     (Id : out Identity; Cert_Path : String; Key_Path : String; OK : out Boolean)
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

   --  Load_Trust_Store: file I/O + PEM decode + per-cert Add_Root.
   --
   --  Walks the PEM text once, decoding each CERTIFICATE block and
   --  immediately calling Cert_Verify.Add_Root on its DER. Avoids
   --  an intermediate batched DER buffer so the only size limit is
   --  the trust store itself (Max_Root_Pool_Size). The earlier
   --  implementation used a 64 KB DER_Buf which silently dropped
   --  certs past ~43 entries on real Mozilla CA bundles (~220 KB,
   --  ~140 roots).
   procedure Load_Trust_Store (Store : out Trust_Store; Path : String; OK : out Boolean) is
      use type X509.N32;
      Text   : constant String := Read_File (Path);
      Pos    : Positive;
      Loaded : Natural := 0;
   begin
      Store := (others => <>);
      OK := False;

      if Text'Length = 0 then
         return;
      end if;

      Pos := Text'First;
      while Pos <= Text'Last loop
         declare
            Begin_Marker : constant String := "-----BEGIN ";
            Found        : Boolean := False;
         begin
            while Pos + Begin_Marker'Length - 1 <= Text'Last loop
               if Text (Pos .. Pos + Begin_Marker'Length - 1) = Begin_Marker then
                  Found := True;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            if not Found then
               exit;
            end if;
         end;

         declare
            R : PEM.Decode_Result;
         begin
            PEM.Decode (Text (Pos .. Text'Last), R);

            if R.OK
              and then R.Label = PEM.Label_Certificate
              and then R.DER_Len > 0
              and then R.DER_Len <= X509.N32 (Max_Cert_DER)
            then
               declare
                  One_DER : X509.Byte_Seq (0 .. R.DER_Len - 1);
                  Add_OK  : Boolean;
               begin
                  for I in X509.N32 range 0 .. R.DER_Len - 1 loop
                     One_DER (I) := R.DER (I);
                  end loop;
                  if Store.Root_Count < Max_Root_Pool_Size then
                     Cert_Verify.Add_Root (Store, One_DER, Add_OK);
                     if Add_OK then
                        Loaded := Loaded + 1;
                     end if;
                  end if;
               end;
            end if;
         end;

         declare
            End_Marker : constant String := "-----END ";
            Found      : Boolean := False;
         begin
            while Pos + End_Marker'Length - 1 <= Text'Last loop
               if Text (Pos .. Pos + End_Marker'Length - 1) = End_Marker then
                  Found := True;
                  while Pos <= Text'Last and then Text (Pos) /= ASCII.LF loop
                     Pos := Pos + 1;
                  end loop;
                  if Pos <= Text'Last then
                     Pos := Pos + 1;
                  end if;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            if not Found then
               exit;
            end if;
         end;
      end loop;

      OK := Loaded > 0;
   end Load_Trust_Store;

end SPARKTLS.Credentials;
