package body Send_Ciphertext_Proof with SPARK_Mode => On is
   procedure Send (Data : RBT_A.Bytes; Sent : out N32) is
   begin
      Sent := N32'Min (Limit, N32 (Data'Length));
   end Send;
end Send_Ciphertext_Proof;
