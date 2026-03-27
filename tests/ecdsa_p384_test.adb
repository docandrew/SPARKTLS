with Ada.Text_IO;       use Ada.Text_IO;
with Ada.Strings.Fixed; use Ada.Strings.Fixed;
with Interfaces;        use Interfaces;
with SPARKNaCl;         use SPARKNaCl;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLS.P384.ECDSA;

procedure ECDSA_P384_Test is
   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;
   Skip_Count : Natural := 0;
   Vec_Count  : Natural := 0;

   --  Parse a single hex character to a nibble
   function Hex_Val (C : Character) return Byte is
   begin
      case C is
         when '0' .. '9' => return Byte (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' => return Byte (Character'Pos (C) - Character'Pos ('a') + 10);
         when 'A' .. 'F' => return Byte (Character'Pos (C) - Character'Pos ('A') + 10);
         when others      => return 0;
      end case;
   end Hex_Val;

   --  Parse a hex string into a Byte_Seq
   procedure Parse_Hex (S : String; Dst : out Byte_Seq) is
      J : N32 := Dst'First;
   begin
      Dst := (others => 0);
      for I in 0 .. (S'Length / 2) - 1 loop
         exit when J > Dst'Last;
         Dst (J) := Hex_Val (S (S'First + I * 2)) * 16 +
                    Hex_Val (S (S'First + I * 2 + 1));
         J := J + 1;
      end loop;
   end Parse_Hex;

   --  Extract value after "Key = " from a line
   function Value_Of (Line : String) return String is
      Eq : constant Natural := Index (Line, "= ");
   begin
      if Eq = 0 then
         return "";
      end if;
      return Line (Eq + 2 .. Line'Last);
   end Value_Of;

   File     : File_Type;
   In_P384  : Boolean := False;
   Have_Msg : Boolean := False;
   Have_Qx  : Boolean := False;
   Have_Qy  : Boolean := False;
   Have_R   : Boolean := False;
   Have_S   : Boolean := False;

   Msg_Hex  : String (1 .. 1024);
   Msg_Len  : Natural := 0;
   Qx_Buf   : Byte_Seq (0 .. 47);
   Qy_Buf   : Byte_Seq (0 .. 47);
   R_Buf    : Byte_Seq (0 .. 47);
   S_Buf    : Byte_Seq (0 .. 47);

   procedure Reset_Vector is
   begin
      Have_Msg := False;
      Have_Qx  := False;
      Have_Qy  := False;
      Have_R   := False;
      Have_S   := False;
      Msg_Len  := 0;
   end Reset_Vector;

begin
   Put_Line ("ECDSA P-384 SHA-384 Test Vectors (NIST CAVP SigVer)");
   Put_Line ("===================================================");

   Open (File, In_File, "/tmp/186-4ecdsatestvectors/SigVer.rsp");

   while not End_Of_File (File) loop
      declare
         Line : constant String := Get_Line (File);
      begin
         --  Look for our section
         if Line'Length >= 14 and then
            Line (Line'First .. Line'First + 13) = "[P-384,SHA-384"
         then
            In_P384 := True;
            Reset_Vector;

         elsif In_P384 and then Line'Length > 0 and then
               Line (Line'First) = '['
         then
            --  Hit next section, stop
            exit;

         elsif In_P384 then
            if Line'Length > 6 and then
               Line (Line'First .. Line'First + 4) = "Msg ="
            then
               declare
                  V : constant String := Value_Of (Line);
               begin
                  Msg_Len := V'Length;
                  Msg_Hex (1 .. Msg_Len) := V;
                  Have_Msg := True;
               end;

            elsif Line'Length > 5 and then
                  Line (Line'First .. Line'First + 3) = "Qx ="
            then
               Parse_Hex (Value_Of (Line), Qx_Buf);
               Have_Qx := True;

            elsif Line'Length > 5 and then
                  Line (Line'First .. Line'First + 3) = "Qy ="
            then
               Parse_Hex (Value_Of (Line), Qy_Buf);
               Have_Qy := True;

            elsif Line'Length > 4 and then
                  Line (Line'First .. Line'First + 2) = "R ="
            then
               Parse_Hex (Value_Of (Line), R_Buf);
               Have_R := True;

            elsif Line'Length > 4 and then
                  Line (Line'First .. Line'First + 2) = "S ="
            then
               Parse_Hex (Value_Of (Line), S_Buf);
               Have_S := True;

            elsif Line'Length > 8 and then
                  Line (Line'First .. Line'First + 7) = "Result ="
            then
               if Have_Msg and Have_Qx and Have_Qy and Have_R and Have_S then
                  Vec_Count := Vec_Count + 1;

                  declare
                     Expect : constant Boolean :=
                        Line (Line'First + 9) = 'P';
                     Msg_Bytes : Byte_Seq (0 .. N32 (Msg_Len / 2) - 1);
                     H         : SPARKNaCl.Hashing.SHA384.Digest;
                     Got       : Boolean;
                  begin
                     Parse_Hex (Msg_Hex (1 .. Msg_Len), Msg_Bytes);
                     SPARKNaCl.Hashing.SHA384.Hash (H, Msg_Bytes);

                     Got := SPARKTLS.P384.ECDSA.Verify
                       (Hash => H,
                        Qx   => Qx_Buf,
                        Qy   => Qy_Buf,
                        R    => R_Buf,
                        S    => S_Buf);

                     if Got = Expect then
                        Pass_Count := Pass_Count + 1;
                     else
                        Put_Line ("  FAIL vector" & Vec_Count'Image &
                                  " (expected " & Expect'Image &
                                  ", got " & Got'Image & ")");
                        Fail_Count := Fail_Count + 1;
                     end if;
                  end;
               else
                  Skip_Count := Skip_Count + 1;
               end if;

               Reset_Vector;
            end if;
         end if;
      end;
   end loop;

   Close (File);

   New_Line;
   Put_Line ("Vectors:" & Vec_Count'Image &
              " tested," & Skip_Count'Image & " skipped");
   Put_Line ("Results:" & Pass_Count'Image & " passed," &
              Fail_Count'Image & " failed");
   if Fail_Count = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("SOME TESTS FAILED");
   end if;
end ECDSA_P384_Test;
