--  Regression: peer alert descriptions map to the matching
--  Error_Code through Error_From_Alert. Before the fix the TLS 1.3 server
--  used Error_Code'Val (enum position) and every other receive site
--  reported Unexpected_Message regardless of what the peer said.

with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;
with SPARKNaCl;        use SPARKNaCl;
with SPARKTLS;         use SPARKTLS;

procedure Test_Error_From_Alert is
   Total, Pass, Fail : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   procedure Expect (Desc : Byte; Want : Error_Code) is
   begin
      Check ("alert" & Desc'Image & " ->" & Want'Image,
             Error_From_Alert (Desc) = Want);
   end Expect;
begin
   Put_Line ("--- SPARKTLS.Error_From_Alert ---");
   Expect (40,  Handshake_Failure);
   Expect (42,  Bad_Certificate);
   Expect (43,  Bad_Certificate);
   Expect (44,  Certificate_Verify_Failed);
   Expect (45,  Certificate_Expired);
   Expect (46,  Certificate_Unknown);
   Expect (47,  Illegal_Parameter);
   Expect (48,  Certificate_Verify_Failed);
   Expect (49,  Certificate_Verify_Failed);
   Expect (50,  Decode_Error);
   Expect (51,  Certificate_Verify_Failed);
   Expect (70,  Protocol_Version);
   Expect (71,  Handshake_Failure);
   Expect (80,  Internal_Error);
   Expect (109, Missing_Extension);
   Expect (110, Unsupported_Extension);
   Expect (112, Illegal_Parameter);
   Expect (116, Certificate_Required);
   Expect (120, No_Application_Protocol);
   --  Unknown / unmapped descriptions fall back to Handshake_Failure.
   Expect (0,   Handshake_Failure);
   Expect (10,  Handshake_Failure);
   Expect (255, Handshake_Failure);
   --  The positional mapping the fix removed: a peer's decode_error (50)
   --  and protocol_version (70) must not land on whatever enum literal
   --  happens to sit at that position.
   Check ("decode_error is not reported as Unexpected_Message",
          Error_From_Alert (50) /= Unexpected_Message);
   Check ("protocol_version is not reported as Unexpected_Message",
          Error_From_Alert (70) /= Unexpected_Message);
   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image
             & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Error_From_Alert;
