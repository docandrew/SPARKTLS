with SPARKNaCl; use SPARKNaCl;

package body SPARKTLS.Client.TLS12.Packed with
   SPARK_Mode => On
is
      procedure Shift_To_Next_Packed_Message
        (Reasm_Buf         : in out Byte_Seq_Access;
         Reasm_Len         : in out N32;
         Reasm_Need        : in out N32;
         Reasm_Hdr_Pending : in out Boolean;
         Msg_Type    :    out Byte;
         Msg_Len     :    out N32;
         More_Packed :    out Boolean;
         Bad_Next    :    out Boolean)
      is
         Old_Need : constant N32 := Reasm_Need;
         Leftover : constant N32 := Reasm_Len - Old_Need;
      begin
      Msg_Type := 0;
      Msg_Len := 0;
      More_Packed := False;
      Bad_Next := False;

         pragma Assert (Old_Need + Leftover = Reasm_Len);
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
         Reasm_Len := Leftover;

      if Leftover < 4 then
         --  Partial header at tail; defer to next call via
         --  Hdr_Pending sentinel.
            Reasm_Need := 4;
            Reasm_Hdr_Pending := True;
            pragma Assert (Reasm_Need <= N32 (Reasm_Buf'Length));
         else
            pragma Assert (Reasm_Buf'Last >= 3);
            declare
               Next_Len : constant N32 :=
                  N32 (Reasm_Buf (1)) * 65536
                  + N32 (Reasm_Buf (2)) * 256
                  + N32 (Reasm_Buf (3));
               Next_Total : constant N32 := Next_Len + 4;
            begin
               if Next_Total > Max_HS_Msg then
                  Free_Byte_Seq (Reasm_Buf);
                  Reasm_Len := 0;
                  Reasm_Need := 0;
                  Reasm_Hdr_Pending := False;
                  Bad_Next := True;
                  return;
               end if;

            if Leftover >= Next_Total then
                  --  Next message complete; loop to dispatch it.
                  pragma Assert (Old_Need > 0);
                  pragma Assert (Leftover < Old_Need + Leftover);
                  Msg_Type := Reasm_Buf (0);
                  Msg_Len := Next_Len;
                  Reasm_Need := Next_Total;
                  pragma Assert (Msg_Len <= Reasm_Need - 4);
                  pragma Assert (Reasm_Need <= Reasm_Len);
                  pragma Assert (Reasm_Len < Old_Need + Leftover);
                  More_Packed := True;
               else
                  --  Partial body; defer to next call.
                  if Next_Total > N32 (Reasm_Buf'Length) then
                     declare
                        New_Buf : Byte_Seq_Access :=
                           new Byte_Seq'(0 .. Next_Total - 1 => 0);
                  begin
                     pragma Assert (New_Buf /= null);
                        pragma Assert (New_Buf'First = 0);
                        pragma Assert (New_Buf'Length = Next_Total);
                        New_Buf (0 .. Leftover - 1) :=
                           Reasm_Buf (0 .. Leftover - 1);
                        Free_Byte_Seq (Reasm_Buf);
                        Reasm_Buf := New_Buf;
                     end;
                  end if;
                  pragma Assert (Next_Total <= N32 (Reasm_Buf'Length));
                  Reasm_Need := Next_Total;
               end if;
            end;
         end if;
   end Shift_To_Next_Packed_Message;

end SPARKTLS.Client.TLS12.Packed;
