--  x509-limbo test validator for SPARKTLS/SPARKx509.
--
--  Exit codes: 0 = valid, 1 = invalid, 2 = error

with Ada.Command_Line;
with Ada.Text_IO;
with SPARKNaCl;     use SPARKNaCl;
with X509;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.PEM;  use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;
with SPARKTLS.Credentials;

procedure X509_Validate is
   use type X509.N32;
   use type PEM_Label;

   function Read_File (Path : String) return String is
      use Ada.Text_IO;
      F      : File_Type;
      Result : String (1 .. 131072) := (others => ' ');
      Len    : Natural := 0;
      Line   : String (1 .. 2048);
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

   --  Find the next PEM BEGIN marker starting at Pos
   procedure Find_Next_PEM (Text : String; Pos : in out Positive;
                            Found : out Boolean) is
      Marker : constant String := "-----BEGIN ";
   begin
      Found := False;
      while Pos + Marker'Length - 1 <= Text'Last loop
         if Text (Pos .. Pos + Marker'Length - 1) = Marker then
            Found := True;
            return;
         end if;
         Pos := Pos + 1;
      end loop;
   end Find_Next_PEM;

   --  Skip past an END marker
   procedure Skip_Past_End (Text : String; Pos : in out Positive) is
      Marker : constant String := "-----END ";
   begin
      while Pos + Marker'Length - 1 <= Text'Last loop
         if Text (Pos .. Pos + Marker'Length - 1) = Marker then
            while Pos <= Text'Last and then Text (Pos) /= ASCII.LF loop
               Pos := Pos + 1;
            end loop;
            if Pos <= Text'Last then Pos := Pos + 1; end if;
            return;
         end if;
         Pos := Pos + 1;
      end loop;
   end Skip_Past_End;

   --  Load all PEM certs from file into a Cert_Pool
   procedure Load_Pool
     (Path  : String;
      Pool  : out Cert_Pool;
      Count : out Natural)
   is
      Text : constant String := Read_File (Path);
      Pos  : Positive := Text'First;
      Found : Boolean;
   begin
      Pool := (others => (Cert    => <>,
                           DER     => (others => 0),
                           DER_Len => 0,
                           Present => False));
      Count := 0;

      if Text'Length = 0 then return; end if;

      while Pos <= Text'Last and Count < Max_Pool_Size loop
         Find_Next_PEM (Text, Pos, Found);
         exit when not Found;

         declare
            R : Decode_Result;
         begin
            Decode (Text (Pos .. Text'Last), R);
            if R.OK and then R.Label = Label_Certificate
               and then R.DER_Len > 0
            then
               declare
                  DLen : constant X509.N32 := R.DER_Len;
                  DER  : X509.Byte_Seq (0 .. DLen - 1);
                  P_OK : Boolean;
               begin
                  for I in X509.N32 range 0 .. DLen - 1 loop
                     DER (I) := R.DER (I);
                  end loop;
                  X509.Parse (DER, Pool (Count).Cert, P_OK);
                  if P_OK then
                     Pool (Count).DER (0 .. DLen - 1) :=
                        R.DER (0 .. DLen - 1);
                     Pool (Count).DER_Len := DLen;
                     Pool (Count).Present := True;
                     Count := Count + 1;
                  end if;
               end;
            end if;
         end;

         Skip_Past_End (Text, Pos);
      end loop;
   end Load_Pool;

   --  Parse first PEM cert from file
   procedure Load_Peer
     (Path     : String;
      Cert     : out X509.Certificate;
      Cert_DER : out Cert_DER_Buf;
      Cert_Len : out X509.N32;
      OK       : out Boolean)
   is
      Text : constant String := Read_File (Path);
      R    : Decode_Result;
   begin
      Cert_DER := (others => 0);
      Cert_Len := 0;
      OK := False;

      if Text'Length = 0 then return; end if;

      Decode (Text, R);
      if not R.OK or else R.Label /= Label_Certificate
         or else R.DER_Len = 0
      then
         return;
      end if;

      Cert_Len := R.DER_Len;
      declare
         DER : X509.Byte_Seq (0 .. Cert_Len - 1);
         P_OK : Boolean;
      begin
         DER := R.DER (0 .. Cert_Len - 1);
         X509.Parse (DER, Cert, P_OK);
         if not P_OK then
            Cert_Len := 0;
            return;
         end if;
         --  Copy raw DER into Cert_DER_Buf
         Cert_DER (0 .. Cert_Len - 1) := R.DER (0 .. Cert_Len - 1);
         OK := True;
      end;
   end Load_Peer;

   --  Convert unix timestamp to X509.Date_Time
   function Unix_To_DateTime (Secs : Natural) return X509.Date_Time is
      DT    : X509.Date_Time := (others => 0);
      R     : Natural := Secs;
      Days  : Natural;
      Y     : Natural := 1970;
      M     : Natural := 1;
      type Month_Days is array (1 .. 12) of Natural;
      MD    : constant Month_Days :=
         (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
      Leap  : Boolean;
      YDays : Natural;
      MLen  : Natural;
   begin
      DT.Second := R mod 60; R := R / 60;
      DT.Minute := R mod 60; R := R / 60;
      DT.Hour   := R mod 24;
      Days := R / 24;

      loop
         Leap := (Y mod 4 = 0 and Y mod 100 /= 0) or Y mod 400 = 0;
         YDays := (if Leap then 366 else 365);
         exit when Days < YDays;
         Days := Days - YDays;
         Y := Y + 1;
      end loop;
      DT.Year := Y;

      loop
         Leap := (Y mod 4 = 0 and Y mod 100 /= 0) or Y mod 400 = 0;
         MLen := MD (M);
         if M = 2 and Leap then MLen := MLen + 1; end if;
         exit when Days < MLen;
         Days := Days - MLen;
         M := M + 1;
         if M > 12 then M := 1; Y := Y + 1; end if;
      end loop;
      DT.Month := M;
      DT.Day   := Days + 1;

      return DT;
   end Unix_To_DateTime;

   --  Parse a string of digits as Natural
   function Parse_Nat (S : String) return Natural is
      V : Natural := 0;
   begin
      for C of S loop
         exit when C not in '0' .. '9';
         V := V * 10 + (Character'Pos (C) - Character'Pos ('0'));
      end loop;
      return V;
   end Parse_Nat;

   Roots     : Trust_Store;
   Roots_OK  : Boolean;
   Peer_Cert : X509.Certificate;
   Peer_DER  : Cert_DER_Buf;
   Peer_Len  : X509.N32;
   Peer_OK   : Boolean;
   Ints      : Cert_Pool;
   Int_Count : Natural := 0;
   Hostname  : String (1 .. 255) := (others => ASCII.NUL);
   Host_Len  : Natural := 0;
   Val_Time  : X509.Date_Time := (Year => 2025, Month => 1, Day => 1,
                                    others => 0);
begin
   if Ada.Command_Line.Argument_Count < 2 then
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   --  Load peer cert
   Load_Peer (Ada.Command_Line.Argument (1),
              Peer_Cert, Peer_DER, Peer_Len, Peer_OK);
   if not Peer_OK then
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   --  Load trust store
   Credentials.Load_Trust_Store
     (Roots, Ada.Command_Line.Argument (2), Roots_OK);
   if not Roots_OK then
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   --  Parse remaining arguments
   declare
      I : Positive := 3;
   begin
      while I <= Ada.Command_Line.Argument_Count loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (I);
         begin
            if Arg = "--hostname"
               and I < Ada.Command_Line.Argument_Count
            then
               I := I + 1;
               declare
                  H : constant String := Ada.Command_Line.Argument (I);
               begin
                  if H'Length <= 255 then
                     Hostname (1 .. H'Length) := H;
                     Host_Len := H'Length;
                  end if;
               end;
            elsif Arg = "--time"
               and I < Ada.Command_Line.Argument_Count
            then
               I := I + 1;
               Val_Time := Unix_To_DateTime
                  (Parse_Nat (Ada.Command_Line.Argument (I)));
            elsif Arg (Arg'First) /= '-' then
               Load_Pool (Arg, Ints, Int_Count);
            end if;
         end;
         I := I + 1;
      end loop;
   end;

   --  Validate
   declare
      use Cert_Verify;
      Result : Validation_Result;
   begin
      Result := Validate_Chain
        (Leaf_DER   => Peer_DER (0 .. Peer_Len - 1),
         Leaf       => Peer_Cert,
         Ints       => Ints,
         Int_Count  => Int_Count,
         Roots      => Roots.Roots,
         Root_Count => Roots.Root_Count,
         Now        => Val_Time,
         Hostname   => Hostname (1 .. Host_Len));

      if Result = Valid then
         Ada.Command_Line.Set_Exit_Status (0);
      else
         Ada.Command_Line.Set_Exit_Status (1);
      end if;
   end;

exception
   when others =>
      Ada.Command_Line.Set_Exit_Status (2);
end X509_Validate;
