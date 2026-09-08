with Ada.Text_IO;        use Ada.Text_IO;
with Interfaces;         use Interfaces;
with SPARKNaCl;          use SPARKNaCl;
with SPARKTLS;
with SPARKTLS.Key_Schedule_12;

procedure Test_PRF12 is
   use SPARKTLS.Key_Schedule_12;

   Secret : constant Byte_Seq (0 .. 31) := (others => 16#AB#);
   Seed   : constant Byte_Seq (0 .. 31) := (others => 16#CD#);

   Out1 : Byte_Seq (0 .. 47) := (others => 0);
   Out2 : Byte_Seq (0 .. 47) := (others => 0);
   Out3 : Byte_Seq (0 .. 47) := (others => 0);
   EMS_Expected : constant Byte_Seq (0 .. 47) :=
     (16#4F#, 16#CE#, 16#10#, 16#D7#, 16#24#, 16#42#, 16#EA#, 16#1E#,
      16#42#, 16#2A#, 16#CF#, 16#51#, 16#91#, 16#15#, 16#18#, 16#81#,
      16#79#, 16#6A#, 16#35#, 16#06#, 16#AD#, 16#10#, 16#54#, 16#C7#,
      16#FD#, 16#AA#, 16#B8#, 16#CA#, 16#9B#, 16#DA#, 16#E0#, 16#7C#,
      16#B6#, 16#9C#, 16#3A#, 16#64#, 16#24#, 16#E4#, 16#21#, 16#93#,
      16#97#, 16#93#, 16#9B#, 16#49#, 16#05#, 16#92#, 16#45#, 16#70#);

   Master : SPARKTLS.Bytes_48;
   CR : constant Bytes_32 := (others => 16#01#);
   SR : constant Bytes_32 := (others => 16#02#);
begin
   Put_Line ("=== TLS 1.2 PRF Test ===");

   --  Test 1: basic PRF output
   PRF_SHA256 (Out1, Secret, "test label", Seed);
   Put ("PRF(first 8):");
   for I in 0 .. 7 loop
      Put (Unsigned_8'Image (Unsigned_8 (Out1 (N32 (I)))));
   end loop;
   New_Line;

   --  Test 2: deterministic
   PRF_SHA256 (Out2, Secret, "test label", Seed);
   Put_Line (if Out1 = Out2 then "PASS: deterministic"
             else "FAIL: not deterministic!");

   --  Test 3: different label = different output
   PRF_SHA256 (Out3, Secret, "other label", Seed);
   Put_Line (if Out1 /= Out3 then "PASS: label sensitivity"
             else "FAIL: label insensitive!");

   --  Test 4: extended master secret PRF shape, checked against an
   --  independent Python hmac/hashlib oracle.
   PRF_SHA256 (Out3, Secret, "extended master secret", Seed);
   Put_Line (if Out3 = EMS_Expected then "PASS: EMS PRF vector"
             else "FAIL: EMS PRF vector!");

   --  Test 5: master secret
   Derive_Master_Secret_12 (Master, Secret, CR, SR, False);
   Put ("Master(first 8):");
   for I in 0 .. 7 loop
      Put (Unsigned_8'Image (Unsigned_8 (Master (N32 (I)))));
   end loop;
   New_Line;

   --  Test 6: different randoms = different master
   declare
      Master2 : SPARKTLS.Bytes_48;
   begin
      Derive_Master_Secret_12 (Master2, Secret, CR,
                               Bytes_32'(others => 16#03#), False);
      Put_Line (if Master /= Master2 then "PASS: random sensitivity"
                else "FAIL: random insensitive!");
   end;

   --  Test 7: finished verify_data
   declare
      VD : Verify_Data_12;
      TH : constant Byte_Seq (0 .. 31) := (others => 16#EE#);
   begin
      Compute_Finished_12 (VD, Master, Label_Client_Finished, TH, False);
      Put ("Finished(12B):");
      for I in 0 .. 11 loop
         Put (Unsigned_8'Image (Unsigned_8 (VD (N32 (I)))));
      end loop;
      New_Line;

      declare
         VD2 : Verify_Data_12;
      begin
         Compute_Finished_12 (VD2, Master, Label_Server_Finished, TH, False);
         Put_Line (if VD /= VD2 then "PASS: finished label sensitivity"
                   else "FAIL: labels same!");
      end;
   end;

   --  Test 8: key expansion
   declare
      CK : Byte_Seq (0 .. 15) := (others => 0);
      SK : Byte_Seq (0 .. 15) := (others => 0);
      CI : Byte_Seq (0 .. 11) := (others => 0);
      SI : Byte_Seq (0 .. 11) := (others => 0);
   begin
      --  Use_SHA384 = False (TLS 1.2 SHA-256 PRF). The trailing
      --  arg was added when the TLS 1.2 SHA-384 cipher path landed.
      Expand_Keys_12
        (CK, SK, CI, SI, Master, SR, CR, 16, 4, False);
      Put_Line (if CK /= SK then "PASS: client/server keys differ"
                else "FAIL: keys identical!");
      Put_Line (if CI /= SI then "PASS: client/server IVs differ"
                else "FAIL: IVs identical!");
   end;

   Put_Line ("=== Done ===");
end Test_PRF12;
