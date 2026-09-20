package body SPARKTLS.External_Signing with
  SPARK_Mode => On
is
   procedure ECDSA_Raw_To_DER
     (Raw      : in     Byte_Seq;
      Half_Len : in     N32;
      DER_Out  :    out Byte_Seq;
      DER_Len  :    out N32;
      OK       :    out Boolean)
   is
   begin
      DER_Out := (others => 0);
      DER_Len := 0;
      OK := False;
      if Raw'Length /= 2 * Half_Len then
         return;
      end if;
      declare
         --  ECDSA_To_DER wants both halves based at 0.
         R_Half : constant Byte_Seq (0 .. Half_Len - 1) := Raw (0 .. Half_Len - 1);
         S_Half : constant Byte_Seq (0 .. Half_Len - 1) := Raw (Half_Len .. 2 * Half_Len - 1);
      begin
         Handshake.ECDSA_To_DER (R_Half, S_Half, Half_Len, DER_Out, DER_Len);
      end;
      OK := DER_Len > 0;
   end ECDSA_Raw_To_DER;
end SPARKTLS.External_Signing;
