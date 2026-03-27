package body SPARKTLS.RFLX_Bridge with
   SPARK_Mode => Off
is
   use type RBT.Index;

   function To_RFLX (Data : Byte_Seq) return RBT.Bytes is
      Result : RBT.Bytes (1 .. RBT.Index (Data'Length));
   begin
      for I in Data'Range loop
         Result (RBT.Index (I - Data'First + 1)) := RBT.Byte (Data (I));
      end loop;
      return Result;
   end To_RFLX;

   function To_NaCl (Data : RBT.Bytes) return Byte_Seq is
      Result : Byte_Seq (0 .. N32 (Data'Length) - 1);
   begin
      for I in Data'Range loop
         Result (N32 (I - Data'First)) := SPARKNaCl.Byte (Data (I));
      end loop;
      return Result;
   end To_NaCl;

end SPARKTLS.RFLX_Bridge;
