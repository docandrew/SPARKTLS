with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Client.TLS12.Packed with
   SPARK_Mode => On
is
   --  Takes the reassembly state as ONE record rather than three loose
   --  in-out scalars. The Reasm_Info predicate then carries what used to be
   --  hand-written here: "not Hdr_Pending and Need >= 4" is exactly
   --  Phase = Reasm_Body, and the buffer-length bounds are gone entirely
   --  because Len and Need are HS_Msg_Len and the buffer is fixed-size.
   procedure Shift_To_Next_Packed_Message
     (Reasm_Buf   : in out Byte_Seq_Access;
      Reasm       : in out Reasm_Info;
      Msg_Type    :    out Byte;
      Msg_Len     :    out N32;
      More_Packed :    out Boolean;
      Bad_Next    :    out Boolean)
   with Pre  => Reasm_Buf /= null
                and then Reasm.Phase = Reasm_Body
                and then Reasm.Need < Reasm.Len,
        Post => (if Bad_Next then
                    Reasm_Buf = null
                    and then Reasm.Phase = Reasm_Idle
                  else
                    Reasm_Buf /= null
                    and then Reasm.Need >= 4
                    and then
                      (if More_Packed then
                         Reasm.Phase = Reasm_Body
                         and then Reasm.Need <= Reasm.Len
                         and then Reasm.Len < Reasm.Len'Old
                         and then Msg_Len <= Reasm.Need - 4
                         and then Msg_Len <= Max_HS_Msg - 4));

end SPARKTLS.Client.TLS12.Packed;
