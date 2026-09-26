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
   --  Unreachable under the formal's contract, but the actual callback is
   --  often non-SPARK and its Post goes unchecked with assertions disabled.
   --  A count above what was offered is a transport bug: consume nothing
   --  and fail the session rather than move Read_Pos past Write_Pos.
   if Bytes_Sent > Count then
      Bytes_Sent := 0;
      Set_State (S, Error_State);
      S.Last_Error := Internal_Error;
      return;
   end if;
   S.Output.Read_Pos := S.Output.Read_Pos + Bytes_Sent;
   if S.Output.Read_Pos = S.Output.Write_Pos then
      S.Output.Read_Pos := 0;
      S.Output.Write_Pos := 0;
   end if;
end SPARKTLS.Send_Ciphertext;
