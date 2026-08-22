package body SPARKTLS_Reassembly with SPARK_Mode => On is

   function Used (B : Buffer) return HS_Msg_Len is (B.Filled);

   function Free_Space (B : Buffer) return HS_Msg_Len is
     (Max_HS_Msg - B.Filled);

   function Header_Ready (B : Buffer) return Boolean is (B.Filled >= 4);

   --  Bounded by construction: three bytes give 0 .. 2**24 - 1, so the + 4
   --  cannot overflow N32. It CAN exceed Max_HS_Msg, which is a protocol
   --  error rather than an arithmetic one -- Message_Too_Large reports it.
   function Declared_Size (B : Buffer) return N32 is
     (4
      + 65536 * N32 (B.Data (1))
      +   256 * N32 (B.Data (2))
      +         N32 (B.Data (3)));

   function Declared_Type (B : Buffer) return Byte is (B.Data (0));

   function Message_Too_Large (B : Buffer) return Boolean is
     (Header_Ready (B) and then Declared_Size (B) > Max_HS_Msg);

   function Has_Message (B : Buffer) return Boolean is
     (Header_Ready (B) and then B.Filled >= Declared_Size (B));

   function Wanted (B : Buffer) return HS_Msg_Len is
     (if not Header_Ready (B) then 4 - B.Filled
      elsif B.Filled >= Declared_Size (B) then 0
      else Declared_Size (B) - B.Filled);

   function Message_Length (B : Buffer) return HS_Msg_Len is
     (Declared_Size (B));

   function Message (B : Buffer) return Byte_Seq is
     (B.Data (0 .. Declared_Size (B) - 1));

   procedure Reset (B : out Buffer) is
   begin
      B := (Data => (others => 0), Filled => 0);
   end Reset;

   procedure Append (B : in out Buffer; Data : Wire_Chunk) is
      Start : constant HS_Msg_Len := B.Filled;
      N     : constant HS_Msg_Len := Data'Length;
   begin
      for I in N32 range 0 .. N - 1 loop
         pragma Loop_Invariant (Start + N <= Max_HS_Msg);
         pragma Loop_Invariant (B.Filled = Start);
         B.Data (Start + I) := Data (Data'First + I);
      end loop;
      B.Filled := Start + N;
   end Append;

   procedure Consume (B : in out Buffer) is
      --  Safe from the PRECONDITION alone: Has_Message gives
      --  Filled >= Declared_Size, and not Message_Too_Large gives
      --  Declared_Size <= Max_HS_Msg. This is the ONE subtraction that
      --  13 scattered sites in the old design each had to justify separately.
      Size : constant HS_Msg_Len := Declared_Size (B);
      Left : constant HS_Msg_Len := B.Filled - Size;
   begin
      for I in N32 range 0 .. Left - 1 loop
         pragma Loop_Invariant (Size + Left = B.Filled);
         pragma Loop_Invariant (B.Filled = B.Filled'Loop_Entry);
         B.Data (I) := B.Data (Size + I);
      end loop;
      B.Filled := Left;
   end Consume;

end SPARKTLS_Reassembly;
