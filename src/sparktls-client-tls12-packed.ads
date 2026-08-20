with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Client.TLS12.Packed with
   SPARK_Mode => On
is
   --  Everything the old contract spelled out by hand -- a non-null buffer,
   --  'First = 0, 'Length bounds, "not Hdr_Pending and Need >= 4" -- is now
   --  carried by the types: Reasm_Buffer is a fixed-size array, and
   --  Phase = Reasm_Body IS "not header-pending and Need >= 4" via the
   --  Reasm_Info predicate.
   procedure Shift_To_Next_Packed_Message
     (Reasm_Buf   : in out Reasm_Buffer;
      Reasm       : in out Reasm_Info;
      Msg_Type    :    out Byte;
      Msg_Len     :    out N32;
      More_Packed :    out Boolean;
      Bad_Next    :    out Boolean)
   with Pre  => Reasm.Phase = Reasm_Body
                and then Reasm.Need < Reasm.Len,
        Post => (if Bad_Next then
                    Reasm.Phase = Reasm_Idle
                  else
                    Reasm.Need >= 4
                    and then
                      (if More_Packed then
                         Reasm.Phase = Reasm_Body
                         and then Reasm.Need <= Reasm.Len
                         and then Reasm.Len < Reasm.Len'Old
                         and then Msg_Len <= Reasm.Need - 4
                         and then Msg_Len <= Max_HS_Msg - 4));

end SPARKTLS.Client.TLS12.Packed;
