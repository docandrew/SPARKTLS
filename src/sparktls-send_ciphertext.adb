procedure SPARKTLS.Send_Ciphertext (S : in out Session; Bytes_Sent : out N32)
with SPARK_Mode => On
is
   Count : constant N32 := Available (S.Output);
begin
   Bytes_Sent := 0;
   if Count = 0 then
      return;
   end if;
   Send (S.Output.Storage
           (Ix (S.Output.Read_Pos) .. Ix (S.Output.Write_Pos - 1)), Bytes_Sent);
   --  Keep the cursor valid even when a non-SPARK callback violates its
   --  contract in a build with assertions disabled.
   if Bytes_Sent > Count then
      raise Constraint_Error with "transport accepted more than offered";
   end if;
   S.Output.Read_Pos := S.Output.Read_Pos + Bytes_Sent;
   if S.Output.Read_Pos = S.Output.Write_Pos then
      S.Output.Read_Pos := 0;
      S.Output.Write_Pos := 0;
   end if;
end SPARKTLS.Send_Ciphertext;
