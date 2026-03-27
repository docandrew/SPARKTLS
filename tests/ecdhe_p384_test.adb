--  ECDHE P-384 Test
--
--  Tests P-384 scalar multiplication and key exchange:
--    1. KeyPair vectors from NIST CAVP KeyPair.rsp: verify [d]*G = (Qx, Qy)
--    2. Round-trip ECDHE: Alice and Bob compute matching shared secrets
--    3. Edge cases: zero scalar, bad prefix

with Ada.Text_IO;       use Ada.Text_IO;
with Ada.Strings.Fixed; use Ada.Strings.Fixed;
with Interfaces;        use Interfaces;
with SPARKNaCl;         use SPARKNaCl;
with SPARKTLS.P384.Point;

procedure ECDHE_P384_Test is
   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   function Hex_Val (C : Character) return Byte is
   begin
      case C is
         when '0' .. '9' => return Byte (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' => return Byte (Character'Pos (C) - Character'Pos ('a') + 10);
         when 'A' .. 'F' => return Byte (Character'Pos (C) - Character'Pos ('A') + 10);
         when others      => return 0;
      end case;
   end Hex_Val;

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

   procedure To_Hex (B : Byte_Seq; S : out String) is
      Hex : constant String := "0123456789abcdef";
   begin
      for I in B'Range loop
         S (S'First + Natural (I - B'First) * 2) :=
            Hex (Natural (Shift_Right (Unsigned_8 (B (I)), 4)) + 1);
         S (S'First + Natural (I - B'First) * 2 + 1) :=
            Hex (Natural (B (I) and 16#0F#) + 1);
      end loop;
   end To_Hex;

   procedure Check (Name : String; Pass : Boolean) is
   begin
      if Pass then
         Put_Line ("  PASS: " & Name);
         Pass_Count := Pass_Count + 1;
      else
         Put_Line ("  FAIL: " & Name);
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

   function Value_Of (Line : String) return String is
      Eq : constant Natural := Index (Line, "= ");
   begin
      if Eq = 0 then
         return "";
      end if;
      return Line (Eq + 2 .. Line'Last);
   end Value_Of;

begin
   Put_Line ("ECDHE P-384 Tests");
   Put_Line ("=================");
   New_Line;

   --  Test 1: NIST CAVP KeyPair vectors
   --  Verify [d]*G = (Qx, Qy) for each P-384 key pair
   Put_Line ("Test 1: NIST CAVP P-384 KeyPair vectors ([d]*G = Q)");
   declare
      use Ada.Text_IO;
      File     : File_Type;
      In_P384  : Boolean := False;
      Have_D   : Boolean := False;
      Have_Qx  : Boolean := False;
      Have_Qy  : Boolean := False;
      Vec_Num  : Natural := 0;

      D_Buf  : Byte_Seq (0 .. 47);
      Qx_Buf : Byte_Seq (0 .. 47);
      Qy_Buf : Byte_Seq (0 .. 47);

      procedure Reset is
      begin
         Have_D  := False;
         Have_Qx := False;
         Have_Qy := False;
      end Reset;

      procedure Try_Vector is
         PK_Out : Byte_Seq (0 .. 96);
      begin
         if not (Have_D and Have_Qx and Have_Qy) then
            return;
         end if;

         Vec_Num := Vec_Num + 1;

         --  Compute [d]*G
         SPARKTLS.P384.Point.P384_Mulgen (PK_Out, D_Buf);

         --  Check Qx matches (bytes 1..48 of uncompressed point)
         declare
            Match_X : constant Boolean := PK_Out (1 .. 48) = Qx_Buf;
            Match_Y : constant Boolean := PK_Out (49 .. 96) = Qy_Buf;
         begin
            if Match_X and Match_Y then
               Check ("KeyPair vector" & Vec_Num'Image, True);
            else
               Check ("KeyPair vector" & Vec_Num'Image, False);
               if not Match_X then
                  declare
                     Got_Hex : String (1 .. 96);
                     Exp_Hex : String (1 .. 96);
                  begin
                     To_Hex (PK_Out (1 .. 48), Got_Hex);
                     To_Hex (Qx_Buf, Exp_Hex);
                     Put_Line ("    Qx got:      " & Got_Hex);
                     Put_Line ("    Qx expected: " & Exp_Hex);
                  end;
               end if;
               if not Match_Y then
                  declare
                     Got_Hex : String (1 .. 96);
                     Exp_Hex : String (1 .. 96);
                  begin
                     To_Hex (PK_Out (49 .. 96), Got_Hex);
                     To_Hex (Qy_Buf, Exp_Hex);
                     Put_Line ("    Qy got:      " & Got_Hex);
                     Put_Line ("    Qy expected: " & Exp_Hex);
                  end;
               end if;
            end if;
         end;

         Reset;
      end Try_Vector;

   begin
      Open (File, In_File, "/tmp/186-4ecdsatestvectors/KeyPair.rsp");

      while not End_Of_File (File) loop
         declare
            Raw  : constant String := Get_Line (File);
            --  Strip trailing CR (Windows line endings)
            Line : constant String :=
               (if Raw'Length > 0 and then Raw (Raw'Last) = ASCII.CR
                then Raw (Raw'First .. Raw'Last - 1) else Raw);
         begin
            if Line'Length >= 6 and then
               Line (Line'First .. Line'First + 5) = "[P-384"
            then
               In_P384 := True;
               Reset;

            elsif In_P384 and then Line'Length > 2 and then
                  Line (Line'First .. Line'First + 1) = "[P"
            then
               --  Hit next curve section, try pending vector and stop
               Try_Vector;
               exit;

            elsif In_P384 then
               if Line'Length > 4 and then
                  Line (Line'First .. Line'First + 1) = "d "
               then
                  Parse_Hex (Value_Of (Line), D_Buf);
                  Have_D := True;

               elsif Line'Length > 5 and then
                     Line (Line'First .. Line'First + 2) = "Qx "
               then
                  Parse_Hex (Value_Of (Line), Qx_Buf);
                  Have_Qx := True;

               elsif Line'Length > 5 and then
                     Line (Line'First .. Line'First + 2) = "Qy "
               then
                  Parse_Hex (Value_Of (Line), Qy_Buf);
                  Have_Qy := True;
                  --  Qy is last field; try the vector
                  Try_Vector;
               end if;
            end if;
         end;
      end loop;

      Close (File);
      Put_Line ("  (" & Vec_Num'Image & " vectors tested)");
   end;

   New_Line;

   --  Test 2: Round-trip key exchange
   Put_Line ("Test 2: Round-trip key exchange");
   declare
      --  Deterministic "private keys" (not cryptographically random, just for test)
      Alice_SK : Byte_Seq (0 .. 47);
      Bob_SK   : Byte_Seq (0 .. 47);
      Alice_PK : Byte_Seq (0 .. 96);
      Bob_PK   : Byte_Seq (0 .. 96);
      Secret_AB : SPARKTLS.Bytes_48;
      Secret_BA : SPARKTLS.Bytes_48;
      OK_AB, OK_BA : Boolean;
   begin
      Parse_Hex (
         "c9806898a0b37d771f9ba4605f84c8b57c0e159a767ddec8" &
         "c3fb05b8e8fb8d6b645f0c3678f3a842692c0fc15fa0d8c1",
         Alice_SK);
      Parse_Hex (
         "5e0de67a7890ac3835b1e38e665f72196d14fce9b3a3e6b0" &
         "01b1e100d3d4e81b2ee2d1c84b4a5a35f3a86f78e38c9e4d",
         Bob_SK);

      SPARKTLS.P384.Point.P384_Mulgen (Alice_PK, Alice_SK);
      SPARKTLS.P384.Point.P384_Mulgen (Bob_PK, Bob_SK);

      Check ("Alice PK format (0x04 prefix)", Alice_PK (0) = 16#04#);
      Check ("Bob PK format (0x04 prefix)", Bob_PK (0) = 16#04#);

      SPARKTLS.P384.Point.P384_ECDHE (Secret_AB, OK_AB, Alice_SK, Bob_PK);
      SPARKTLS.P384.Point.P384_ECDHE (Secret_BA, OK_BA, Bob_SK, Alice_PK);

      Check ("Alice->Bob ECDHE succeeds", OK_AB);
      Check ("Bob->Alice ECDHE succeeds", OK_BA);
      Check ("Shared secrets match",
             OK_AB and OK_BA and
             Byte_Seq (Secret_AB) = Byte_Seq (Secret_BA));

      if OK_AB then
         declare
            Hex : String (1 .. 96);
         begin
            To_Hex (Byte_Seq (Secret_AB), Hex);
            Put_Line ("  Shared secret: " & Hex);
         end;
      end if;
   end;

   New_Line;

   --  Test 3: Edge cases
   Put_Line ("Test 3: Edge cases");
   declare
      Zero_SK  : constant Byte_Seq (0 .. 47) := (others => 0);
      Dummy_PK : Byte_Seq (0 .. 96);
      Secret   : SPARKTLS.Bytes_48;
      OK       : Boolean;
   begin
      --  Generate a valid PK (scalar = 1)
      declare
         SK : Byte_Seq (0 .. 47) := (others => 0);
      begin
         SK (47) := 1;
         SPARKTLS.P384.Point.P384_Mulgen (Dummy_PK, SK);
      end;

      --  Zero scalar should produce identity → fail
      SPARKTLS.P384.Point.P384_ECDHE (Secret, OK, Zero_SK, Dummy_PK);
      Check ("Zero scalar rejected", not OK);

      --  Invalid peer PK (wrong prefix)
      declare
         Bad_PK : Byte_Seq (0 .. 96) := (others => 0);
      begin
         Bad_PK (0) := 16#05#;
         SPARKTLS.P384.Point.P384_ECDHE (Secret, OK, Dummy_PK (1 .. 48), Bad_PK);
         Check ("Bad prefix rejected", not OK);
      end;
   end;

   New_Line;
   Put_Line ("Results:" & Pass_Count'Image & " passed," &
              Fail_Count'Image & " failed");
   if Fail_Count = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("SOME TESTS FAILED");
   end if;
end ECDHE_P384_Test;
