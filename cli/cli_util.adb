with Ada.Calendar;
with Ada.Streams;         use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Directories;
with Interfaces;          use Interfaces;
with SPARKTLS.PEM;

package body CLI_Util is

   Hex_Chars : constant String := "0123456789ABCDEF";

   function Hex_Byte (B : X509.Byte) return String is
      V : constant Natural := Natural (B);
   begin
      return (1 => Hex_Chars (V / 16 + 1),
              2 => Hex_Chars (V mod 16 + 1));
   end Hex_Byte;

   --  Pad a string to at least Width characters
   function Pad (S : String; Width : Natural) return String is
   begin
      if S'Length >= Width then
         return S;
      end if;
      return S & (1 .. Width - S'Length => ' ');
   end Pad;

   ----------------------------------------------------------------
   --  Read_DER_File
   ----------------------------------------------------------------

   procedure Read_DER_File
     (Path : String;
      Data : out Byte_Seq_Access;
      OK   : out Boolean)
   is
      use Ada.Streams.Stream_IO;
   begin
      Data := null;
      OK := False;

      if not Ada.Directories.Exists (Path) then
         Put_Line (Standard_Error, "Error: file not found: " & Path);
         return;
      end if;

      declare
         Size : constant Natural :=
            Natural (Ada.Directories.Size (Path));
         File : Ada.Streams.Stream_IO.File_Type;
         Buf  : Ada.Streams.Stream_Element_Array (1 .. Stream_Element_Offset (Size));
         Last : Stream_Element_Offset;
      begin
         if Size = 0 then
            Put_Line (Standard_Error, "Error: file is empty: " & Path);
            return;
         end if;

         Open (File, In_File, Path);
         Read (File, Buf, Last);
         Close (File);

         Data := new X509.Byte_Seq (0 .. X509.N32 (Last) - 1);
         for I in 1 .. Last loop
            Data (X509.N32 (I - 1)) := X509.Byte (Buf (I));
         end loop;
         OK := True;
      exception
         when others =>
            if Is_Open (File) then
               Close (File);
            end if;
            Put_Line (Standard_Error, "Error: cannot read: " & Path);
      end;
   end Read_DER_File;

   ----------------------------------------------------------------
   --  Read_Cert_File
   ----------------------------------------------------------------

   procedure Read_Cert_File
     (Path : String;
      Data : out Byte_Seq_Access;
      OK   : out Boolean)
   is
      use Ada.Streams.Stream_IO;
      use type SPARKTLS.PEM.PEM_Label;
   begin
      Data := null;
      OK := False;

      if not Ada.Directories.Exists (Path) then
         Put_Line (Standard_Error, "Error: file not found: " & Path);
         return;
      end if;

      declare
         Size : constant Natural :=
            Natural (Ada.Directories.Size (Path));
         File : Ada.Streams.Stream_IO.File_Type;
         Buf  : Ada.Streams.Stream_Element_Array
           (1 .. Stream_Element_Offset (Size));
         Last : Stream_Element_Offset;
      begin
         if Size = 0 then
            Put_Line (Standard_Error, "Error: file is empty: " & Path);
            return;
         end if;

         Open (File, In_File, Path);
         Read (File, Buf, Last);
         Close (File);

         if Last > 0 and then Character'Val (Buf (1)) = '-' then
            if Natural (Last) > SPARKTLS.PEM.Max_PEM_Input then
               Put_Line (Standard_Error, "Error: PEM file is too large: " &
                         Path);
               return;
            end if;

            declare
               Text : String (1 .. Natural (Last));
               PEM  : SPARKTLS.PEM.Decode_Result;
            begin
               for I in 1 .. Last loop
                  Text (Natural (I)) := Character'Val (Buf (I));
               end loop;

               SPARKTLS.PEM.Decode (Text, PEM);
               if not PEM.OK then
                  Put_Line (Standard_Error,
                            "Error: failed to decode PEM certificate: " &
                            Path);
                  return;
               end if;

               if PEM.Label /= SPARKTLS.PEM.Label_Certificate then
                  Put_Line (Standard_Error,
                            "Error: PEM block is not a certificate: " &
                            Path);
                  return;
               end if;

               Data := new X509.Byte_Seq (0 .. PEM.DER_Len - 1);
               Data.all := PEM.DER (0 .. PEM.DER_Len - 1);
               OK := True;
            end;
         else
            Data := new X509.Byte_Seq (0 .. X509.N32 (Last) - 1);
            for I in 1 .. Last loop
               Data (X509.N32 (I - 1)) := X509.Byte (Buf (I));
            end loop;
            OK := True;
         end if;
      exception
         when others =>
            if Is_Open (File) then
               Close (File);
            end if;
            Put_Line (Standard_Error, "Error: cannot read: " & Path);
      end;
   end Read_Cert_File;

   ----------------------------------------------------------------
   --  Span_To_String
   ----------------------------------------------------------------

   function Span_To_String
     (DER : X509.Byte_Seq;
      S   : X509.Span) return String
   is
      Len : constant Natural := Natural (X509.Span_Length (S));
   begin
      if not S.Present or Len = 0 then
         return "";
      end if;
      declare
         Result : String (1 .. Len);
      begin
         for I in 0 .. X509.N32 (Len - 1) loop
            Result (Natural (I) + 1) := Character'Val (DER (S.First + I));
         end loop;
         return Result;
      end;
   end Span_To_String;

   ----------------------------------------------------------------
   --  To_Hex
   ----------------------------------------------------------------

   function To_Hex (Data : X509.Byte_Seq) return String is
   begin
      if Data'Length = 0 then
         return "(empty)";
      end if;
      --  Each byte = 2 hex chars + colon separator (except last)
      declare
         Len    : constant Natural := Natural (Data'Length);
         Result : String (1 .. Len * 3 - 1);
         Pos    : Natural := 1;
      begin
         for I in Data'Range loop
            declare
               H : constant String := Hex_Byte (Data (I));
            begin
               Result (Pos)     := H (1);
               Result (Pos + 1) := H (2);
               Pos := Pos + 2;
               if I < Data'Last then
                  Result (Pos) := ':';
                  Pos := Pos + 1;
               end if;
            end;
         end loop;
         return Result;
      end;
   end To_Hex;

   ----------------------------------------------------------------
   --  To_Hex_Trunc
   ----------------------------------------------------------------

   function To_Hex_Trunc
     (Data : X509.Byte_Seq;
      Max  : Natural := 20) return String
   is
      Len : constant Natural := Natural (Data'Length);
   begin
      if Len <= Max then
         return To_Hex (Data);
      end if;
      declare
         Prefix : constant X509.Byte_Seq :=
            Data (Data'First .. Data'First + X509.N32 (Max) - 1);
         N_Str  : constant String := Natural'Image (Len);
      begin
         return To_Hex (Prefix) & "... (" &
                N_Str (N_Str'First + 1 .. N_Str'Last) & " bytes)";
      end;
   end To_Hex_Trunc;

   ----------------------------------------------------------------
   --  Algo_Name
   ----------------------------------------------------------------

   function Algo_Name (A : X509.Algorithm_ID) return String is
   begin
      case A is
         when X509.Algo_RSA              => return "RSA";
         when X509.Algo_RSA_PKCS1_SHA1   => return "RSA-PKCS1-SHA1";
         when X509.Algo_RSA_PKCS1_SHA256 => return "RSA-PKCS1-SHA256";
         when X509.Algo_RSA_PKCS1_SHA384 => return "RSA-PKCS1-SHA384";
         when X509.Algo_RSA_PKCS1_SHA512 => return "RSA-PKCS1-SHA512";
         when X509.Algo_RSA_PSS          => return "RSA-PSS";
         when X509.Algo_ECDSA_P256_SHA256 => return "ECDSA-P256-SHA256";
         when X509.Algo_ECDSA_P384_SHA384 => return "ECDSA-P384-SHA384";
         when X509.Algo_Ed25519          => return "Ed25519";
         when X509.Algo_EC_P256          => return "EC P-256";
         when X509.Algo_EC_P384          => return "EC P-384";
         when X509.Algo_EC_Ed25519       => return "EC Ed25519";
         when X509.Algo_Unknown          => return "Unknown";
      end case;
   end Algo_Name;

   ----------------------------------------------------------------
   --  PK_Description
   ----------------------------------------------------------------

   function PK_Description
     (Algo : X509.Algorithm_ID;
      Len  : X509.N32) return String
   is
      Bits : constant String := Natural'Image (Natural (Len) * 8);
   begin
      case Algo is
         when X509.Algo_RSA =>
            return "RSA (" &
                   Bits (Bits'First + 1 .. Bits'Last) & " bits)";
         when X509.Algo_EC_P256 =>
            return "EC P-256 (256 bits)";
         when X509.Algo_EC_P384 =>
            return "EC P-384 (384 bits)";
         when X509.Algo_EC_Ed25519 =>
            return "Ed25519 (256 bits)";
         when others =>
            return Algo_Name (Algo) & " (" &
                   Bits (Bits'First + 1 .. Bits'Last) & " bits)";
      end case;
   end PK_Description;

   ----------------------------------------------------------------
   --  Format_Date
   ----------------------------------------------------------------

   function Format_Date (D : X509.Date_Time) return String is

      function Pad2 (N : Natural) return String is
         S : constant String := Natural'Image (N);
         Raw : constant String := S (S'First + 1 .. S'Last);
      begin
         if Raw'Length = 1 then
            return "0" & Raw;
         end if;
         return Raw;
      end Pad2;

      function Pad4 (N : Natural) return String is
         S : constant String := Natural'Image (N);
         Raw : constant String := S (S'First + 1 .. S'Last);
      begin
         if Raw'Length < 4 then
            return (1 .. 4 - Raw'Length => '0') & Raw;
         end if;
         return Raw;
      end Pad4;

   begin
      return Pad4 (D.Year) & "-" &
             Pad2 (D.Month) & "-" &
             Pad2 (D.Day) & " " &
             Pad2 (D.Hour) & ":" &
             Pad2 (D.Minute) & ":" &
             Pad2 (D.Second) & " UTC";
   end Format_Date;

   ----------------------------------------------------------------
   --  Now
   ----------------------------------------------------------------

   function Now return X509.Date_Time is
      use Ada.Calendar;
      T      : constant Time := Clock;
      Y      : Year_Number;
      Mo     : Month_Number;
      D      : Day_Number;
      Secs   : Day_Duration;
      S_Int  : Natural;
      Hr     : Natural;
      Mn     : Natural;
      Sc     : Natural;
   begin
      Split (T, Y, Mo, D, Secs);
      S_Int := Natural (Secs);
      if S_Int >= 86400 then
         S_Int := 86399;
      end if;
      Hr := S_Int / 3600;
      Mn := (S_Int mod 3600) / 60;
      Sc := S_Int mod 60;
      return (Year   => Y,
              Month  => Mo,
              Day    => D,
              Hour   => Hr,
              Minute => Mn,
              Second => Sc);
   end Now;

   ----------------------------------------------------------------
   --  Put_Field
   ----------------------------------------------------------------

   procedure Put_Field (Label : String; Value : String) is
   begin
      Put ("  " & Pad (Label & ":", 20) & " " & Value);
      New_Line;
   end Put_Field;

   ----------------------------------------------------------------
   --  Put_Check
   ----------------------------------------------------------------

   procedure Put_Check
     (Index  : Natural;
      Label  : String;
      OK     : Boolean;
      Detail : String := "")
   is
      Idx_Str : constant String := Natural'Image (Index);
      Dots    : constant String (1 .. 40 - Label'Length) :=
         (others => '.');
   begin
      Put ("  [" & Idx_Str (Idx_Str'First + 1 .. Idx_Str'Last) & "] " &
           Label & " " & Dots & " ");
      if OK then
         Put_Line ("OK");
      elsif Detail'Length > 0 then
         Put_Line ("FAIL (" & Detail & ")");
      else
         Put_Line ("FAIL");
      end if;
   end Put_Check;

end CLI_Util;
