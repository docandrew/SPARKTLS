with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Client.TLS12.Packed with
   SPARK_Mode => On
is
   procedure Shift_To_Next_Packed_Message
     (Reasm_Buf         : in out Byte_Seq_Access;
      Reasm_Len         : in out N32;
      Reasm_Need        : in out N32;
      Reasm_Hdr_Pending : in out Boolean;
      Msg_Type          :    out Byte;
      Msg_Len           :    out N32;
      More_Packed       :    out Boolean;
      Bad_Next          :    out Boolean)
   with Pre  => Reasm_Buf /= null
                and then Reasm_Buf'First = 0
                and then Reasm_Buf'Length <= Max_HS_Msg
                and then not Reasm_Hdr_Pending
                and then Reasm_Need >= 4
                and then Reasm_Need < Reasm_Len
                and then Reasm_Need <= N32 (Reasm_Buf'Length)
                and then Reasm_Len <= N32 (Reasm_Buf'Length),
        Post => (if Bad_Next then
                    Reasm_Buf = null
                    and then Reasm_Len = 0
                    and then Reasm_Need = 0
                    and then not Reasm_Hdr_Pending
                  else
                    Reasm_Buf /= null
                    and then Reasm_Buf'First = 0
                    and then Reasm_Buf'Length <= Max_HS_Msg
                    and then Reasm_Need > 0
                    and then Reasm_Need >= 4
                    and then Reasm_Len <= N32 (Reasm_Buf'Length)
                    and then Reasm_Need <= N32 (Reasm_Buf'Length)
                    and then
                      (if Reasm_Hdr_Pending then
                         Reasm_Need = 4 and then Reasm_Len < 4)
                    and then
                      (if More_Packed then
                         Reasm_Need >= 4
                         and then Reasm_Need <= Reasm_Len
                         and then Reasm_Len < Reasm_Len'Old
                         and then Msg_Len <= Reasm_Need - 4
                         and then Msg_Len <= Max_HS_Msg - 4));

end SPARKTLS.Client.TLS12.Packed;
