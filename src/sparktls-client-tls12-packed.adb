with SPARKNaCl; use SPARKNaCl;

package body SPARKTLS.Client.TLS12.Packed with
   SPARK_Mode => On
is
      procedure Shift_To_Next_Packed_Message
        (Reasm_Buf   : in out Byte_Seq_Access;
         Reasm       : in out Reasm_Info;
         Msg_Type    :    out Byte;
         Msg_Len     :    out N32;
         More_Packed :    out Boolean;
         Bad_Next    :    out Boolean)
      is
         Old_Need : constant N32 := Reasm.Need;
         Leftover : constant N32 := Reasm.Len - Old_Need;
      begin
      Msg_Type := 0;
      Msg_Len := 0;
      More_Packed := False;
      Bad_Next := False;

         pragma Assert (Old_Need + Leftover = Reasm.Len);
         pragma Assert
           (Old_Need + Leftover <= N32 (Reasm_Buf'Length));

      --  Forward shift via explicit loop: SPARK forbids
      --  potentially-overlapping array-slice assignment.
      for I in N32 range 0 .. Leftover - 1 loop
            pragma Loop_Invariant
              (I <= Leftover - 1
               and Reasm_Buf /= null
               and Reasm_Buf'First = 0
               and Old_Need + Leftover <= N32 (Reasm_Buf'Length));
            Reasm_Buf (I) := Reasm_Buf (Old_Need + I);
         end loop;
         Reasm := (Reasm with delta Len => Leftover);

      if Leftover < 4 then
         --  Partial header at tail; defer to next call via the
         --  Hdr_Pending sentinel. The buffer is already Max_HS_Msg
         --  (Reasm_Buffer is a fixed subtype), so the leftover bytes are
         --  already in place at 0 .. Leftover - 1 after the shift above.
         --  Only the stale tail needs clearing.
            Reasm_Buf (Leftover .. Max_HS_Msg - 1) := (others => 0);
            Reasm := (Phase => Reasm_Header, Len => Leftover, Need => 4);
         else
            declare
               Next_Len : constant N32 :=
                  N32 (Reasm_Buf (1)) * 65536
                  + N32 (Reasm_Buf (2)) * 256
                  + N32 (Reasm_Buf (3));
               Next_Total : constant N32 := Next_Len + 4;
            begin
               if Next_Total > Max_HS_Msg then
                  Free_Byte_Seq (Reasm_Buf);
                  Reasm := (Phase => Reasm_Idle, Len => 0, Need => 0);
                  Bad_Next := True;
                  return;
               end if;

            if Leftover >= Next_Total then
                  --  Next message complete; loop to dispatch it.
                  pragma Assert (Old_Need > 0);
                  pragma Assert (Leftover < Old_Need + Leftover);
                  Msg_Type := Reasm_Buf (0);
                  Msg_Len := Next_Len;
                  Reasm := (Reasm with delta Need => Next_Total);
                  pragma Assert (Reasm.Phase = Reasm_Body);
                  pragma Assert (Msg_Len <= Reasm.Need - 4);
                  pragma Assert (Reasm.Need <= Reasm.Len);
                  pragma Assert (Reasm.Len < Old_Need + Leftover);
                  More_Packed := True;
               else
                  --  Partial body; defer to next call.
                  --  No grow step: Next_Total <= Max_HS_Msg is enforced
                  --  by the explicit rejection above, and the buffer is
                  --  always exactly Max_HS_Msg, so it already fits.
                  Reasm := (Reasm with delta Need => Next_Total);
               end if;
            end;
         end if;
   end Shift_To_Next_Packed_Message;

end SPARKTLS.Client.TLS12.Packed;
