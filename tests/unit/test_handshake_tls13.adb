with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;  use Interfaces;
with SPARKNaCl;   use SPARKNaCl;
with SPARKTLS.Handshake.TLS13;

procedure Test_Handshake_TLS13 is
   Verify_Data : Bytes_32;
   Result      : Byte_Seq (0 .. 35);
   Len         : N32;
   Failures    : Natural := 0;

   procedure Check (Name : String; Condition : Boolean) is
   begin
      if Condition then
         Put_Line ("  PASS: " & Name);
      else
         Put_Line ("  FAIL: " & Name);
         Failures := Failures + 1;
      end if;
   end Check;
begin
   for I in Verify_Data'Range loop
      Verify_Data (I) := Byte (I);
   end loop;

   SPARKTLS.Handshake.TLS13.Build_Finished (Verify_Data, Result, Len);

   Check ("Finished length is 36", Len = 36);
   Check ("Finished type is 0x14", Result (0) = 16#14#);
   Check
     ("Finished body length is 32",
      Result (1 .. 3) = Byte_Seq'(16#00#, 16#00#, 16#20#));
   Check
     ("Finished payload is verify_data",
      (for all I in Verify_Data'Range => Result (4 + I) = Verify_Data (I)));

   if Failures /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Handshake_TLS13;
