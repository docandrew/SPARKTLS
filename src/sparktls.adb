package body SPARKTLS with
   SPARK_Mode => On
is

   --================================================================
   --  Compact
   --  Shift unread data to the front of the buffer to reclaim space
   --================================================================
   procedure Compact (Buf : in out IO_Buffer)
   with Post => Buf.Read_Pos = 0
                and Available (Buf) = Available (Buf'Old)
   is
      Len : constant N32 := Available (Buf);
   begin
      if Buf.Read_Pos > 0 and Len > 0 then
         Buf.Data (0 .. Len - 1) :=
            Buf.Data (Buf.Read_Pos .. Buf.Read_Pos + Len - 1);
         Buf.Read_Pos  := 0;
         Buf.Write_Pos := Len;
      elsif Len = 0 then
         Buf.Read_Pos  := 0;
         Buf.Write_Pos := 0;
      end if;
   end Compact;

   --================================================================
   --  Feed_Input
   --================================================================
   procedure Feed_Input
     (S         : in out Session;
      Data      : in     Byte_Seq;
      Bytes_Fed :    out N32)
   is
      Space : N32;
      Count : N32;
   begin
      --  Compact if we're running low on write space
      if Free_Space (S.Input) < N32 (Data'Length) then
         Compact (S.Input);
      end if;

      Space := Free_Space (S.Input);

      if Space = 0 or Data'Length = 0 then
         Bytes_Fed := 0;
         return;
      end if;

      Count := N32'Min (Space, N32 (Data'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= Space);
      pragma Assert (S.Input.Write_Pos + Count <= IO_Buffer_Capacity);

      S.Input.Data (S.Input.Write_Pos .. S.Input.Write_Pos + Count - 1) :=
         Data (0 .. Count - 1);
      S.Input.Write_Pos := S.Input.Write_Pos + Count;

      Bytes_Fed := Count;
   end Feed_Input;

   --================================================================
   --  Drain_Output
   --================================================================
   procedure Drain_Output
     (S              : in out Session;
      Dest           :    out Byte_Seq;
      Bytes_Drained  :    out N32)
   is
      Avail : constant N32 := Available (S.Output);
      Count : N32;
   begin
      Dest := (others => 0);

      if Avail = 0 or Dest'Length = 0 then
         Bytes_Drained := 0;
         return;
      end if;

      Count := N32'Min (Avail, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= Avail);
      pragma Assert (S.Output.Read_Pos + Count <= S.Output.Write_Pos);

      Dest (0 .. Count - 1) :=
         S.Output.Data (S.Output.Read_Pos ..
                        S.Output.Read_Pos + Count - 1);

      S.Output.Read_Pos := S.Output.Read_Pos + Count;

      --  Compact after draining
      if Available (S.Output) = 0 then
         S.Output.Read_Pos  := 0;
         S.Output.Write_Pos := 0;
      end if;

      Bytes_Drained := Count;
   end Drain_Output;

   --================================================================
   --  Read_App_Data
   --================================================================
   procedure Read_App_Data
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   is
      Count : N32;
   begin
      Dest := (others => 0);

      if S.App_Data_Len = 0 or Dest'Length = 0 then
         Bytes_Read := 0;
         return;
      end if;

      pragma Assert (S.App_Data_Len <= Max_Record_Plaintext);
      Count := N32'Min (S.App_Data_Len, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= S.App_Data_Len);
      pragma Assert (Count <= Max_Record_Plaintext);

      Dest (0 .. Count - 1) := S.App_Data (0 .. Count - 1);

      --  Shift remaining data forward
      if Count < S.App_Data_Len then
         pragma Assert (S.App_Data_Len - Count >= 1);
         S.App_Data (0 .. S.App_Data_Len - Count - 1) :=
            S.App_Data (Count .. S.App_Data_Len - 1);
      end if;

      S.App_Data_Len := S.App_Data_Len - Count;
      Bytes_Read := Count;
   end Read_App_Data;

end SPARKTLS;
