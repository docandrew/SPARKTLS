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

   --  Test 4: master secret
   Derive_Master_Secret_12 (Master, Secret, CR, SR, False);
   Put ("Master(first 8):");
   for I in 0 .. 7 loop
      Put (Unsigned_8'Image (Unsigned_8 (Master (N32 (I)))));
   end loop;
   New_Line;

   --  Test 5: different randoms = different master
   declare
      Master2 : SPARKTLS.Bytes_48;
   begin
      Derive_Master_Secret_12 (Master2, Secret, CR,
                               Bytes_32'(others => 16#03#), False);
      Put_Line (if Master /= Master2 then "PASS: random sensitivity"
                else "FAIL: random insensitive!");
   end;

   --  Test 6: finished verify_data
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

   --  Test 7: key expansion
   declare
      CK : Byte_Seq (0 .. 15) := (others => 0);
      SK : Byte_Seq (0 .. 15) := (others => 0);
      CI : Byte_Seq (0 .. 3)  := (others => 0);
      SI : Byte_Seq (0 .. 3)  := (others => 0);
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
