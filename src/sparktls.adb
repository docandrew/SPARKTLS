with Ada.Unchecked_Deallocation;

package body SPARKTLS with
   SPARK_Mode => On
is
   procedure Free_Byte_Seq (Ptr : in out Byte_Seq_Access) is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => Byte_Seq, Name => Byte_Seq_Access);
   begin
      Dealloc (Ptr);
   end Free_Byte_Seq;

   --  RFC 7748 §6.1 / RFC 8422 §5.10: see the contract in the spec.
   --  The body accumulates a byte-wise OR; the loop invariant ties
   --  the accumulator to the existence of a non-zero byte seen so
   --  far, allowing gnatprove to discharge the function-level Post.
   function Shared_Secret_Is_Acceptable_X25519
     (Shared_Secret : Byte_Seq) return Boolean
   is
      Acc : Byte := 0;
   begin
      for I in Shared_Secret'Range loop
         pragma Loop_Invariant
           ((Acc /= 0) =
              (for some J in Shared_Secret'First .. I - 1
                 => Shared_Secret (J) /= 0));
         Acc := Acc or Shared_Secret (I);
      end loop;
      return Acc /= 0;
   end Shared_Secret_Is_Acceptable_X25519;

   --  RFC 8422 §5.1.2: see contract in spec.
   --  Returns True iff the list is non-empty AND contains at least
   --  one occurrence of 0 (uncompressed). Deprecated formats {1, 2}
   --  are silently tolerated alongside 0.
   function EC_Point_Formats_Acceptable
     (List : Byte_Seq) return Boolean
   is
   begin
      if List'Length = 0 then
         return False;
      end if;
      for I in List'Range loop
         pragma Loop_Invariant
           (not (for some J in List'First .. I - 1 => List (J) = 0));
         if List (I) = 0 then
            return True;
         end if;
      end loop;
      return False;
   end EC_Point_Formats_Acceptable;

   --================================================================
   --  Set_State
   --================================================================
   procedure Set_State (S : in out Session; To : Connection_State) is
   begin
      S.State := To;
   end Set_State;

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
   --  Feed_Ciphertext
   --================================================================
   procedure Feed_Ciphertext
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
   end Feed_Ciphertext;

   --================================================================
   --  Drain_Ciphertext
   --================================================================
   procedure Drain_Ciphertext
     (S              : in out Session;
      Dest           :    out Byte_Seq;
      Bytes_Drained  :    out N32)
   is
      Avail : constant N32 := Available (S.Output);
      Count : N32;
   begin
      if Avail = 0 or Dest'Length = 0 then
         Dest := (others => 0);
         Bytes_Drained := 0;
         return;
      end if;

      Count := N32'Min (Avail, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= Avail);
      pragma Assert (S.Output.Read_Pos + Count <= S.Output.Write_Pos);

      --  Copy data, then zero only the unused tail
      Dest (0 .. Count - 1) :=
         S.Output.Data (S.Output.Read_Pos ..
                        S.Output.Read_Pos + Count - 1);
      if Count < N32 (Dest'Length) then
         Dest (Count .. Dest'Last) := (others => 0);
      end if;

      S.Output.Read_Pos := S.Output.Read_Pos + Count;

      --  Compact after draining
      if Available (S.Output) = 0 then
         S.Output.Read_Pos  := 0;
         S.Output.Write_Pos := 0;
      end if;

      Bytes_Drained := Count;
   end Drain_Ciphertext;

   --================================================================
   --  Read_Plaintext
   --================================================================
   procedure Read_Plaintext
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   is
      Count : N32;
   begin
      if S.App_Data_Len = 0 or Dest'Length = 0 then
         Dest := (others => 0);
         Bytes_Read := 0;
         return;
      end if;

      pragma Assert (S.App_Data_Len <= Max_Record_Plaintext);
      Count := N32'Min (S.App_Data_Len, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= S.App_Data_Len);
      pragma Assert (Count <= Max_Record_Plaintext);

      Dest (0 .. Count - 1) := S.App_Data (0 .. Count - 1);
      if Count < N32 (Dest'Length) then
         Dest (Count .. Dest'Last) := (others => 0);
      end if;

      --  Shift remaining data forward
      if Count < S.App_Data_Len then
         pragma Assert (S.App_Data_Len - Count >= 1);
         S.App_Data (0 .. S.App_Data_Len - Count - 1) :=
            S.App_Data (Count .. S.App_Data_Len - 1);
      end if;

      S.App_Data_Len := S.App_Data_Len - Count;
      Bytes_Read := Count;
   end Read_Plaintext;

   procedure Sanitize_Keys (S : in out Session) is
   begin
      --  Zero traffic keys (both directions)
      S.Client_App.Key := (others => 0);
      S.Client_App.IV  := (others => 0);
      S.Client_App.Counter := 0;
      S.Server_App.Key := (others => 0);
      S.Server_App.IV  := (others => 0);
      S.Server_App.Counter := 0;

      --  Zero resumption master secret
      S.Res_Master     := (others => 0);
      S.Res_Master_Len := 0;

      --  Zero TLS 1.2 implicit IVs
      S.Client_IV_12 := (others => 0);
      S.Server_IV_12 := (others => 0);
      S.Client_Seq_12 := 0;
      S.Server_Seq_12 := 0;
   end Sanitize_Keys;

end SPARKTLS;
