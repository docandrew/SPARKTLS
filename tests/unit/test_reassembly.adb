--  Unit test for SPARKTLS.Reassembly -- the handshake reassembly ADT.
--
--  This is the oracle for porting the old Len/Need accounting onto the new
--  Buffer. It exercises every framing shape the TLS record layer can hand us,
--  including the ones that historically broke: packed flights, headers split
--  across records, and zero-body messages.
--
--  Runs with no network and no ports, so it also executes under --checked
--  (-gnata), which BoGo and the integration suite cannot.

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Reassembly;

procedure Test_Reassembly is

   package R renames SPARKTLS.Reassembly;

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   --  Build a handshake message: 1-byte type, 3-byte big-endian body length,
   --  then Body_Len bytes of Filler.
   function Msg (Kind : Byte; Body_Len : N32; Filler : Byte) return Byte_Seq is
      M : Byte_Seq (0 .. Body_Len + 3) := (others => Filler);
   begin
      M (0) := Kind;
      M (1) := Byte (Body_Len / 65536);
      M (2) := Byte ((Body_Len / 256) mod 256);
      M (3) := Byte (Body_Len mod 256);
      return M;
   end Msg;

   B : R.Buffer;

begin
   Put_Line ("=== test_reassembly ===");

   ---------------------------------------------------------------------
   --  Empty buffer
   ---------------------------------------------------------------------
   R.Reset (B);
   Check ("empty: no message", not R.Has_Message (B));
   Check ("empty: used = 0", R.Used (B) = 0);
   Check ("empty: full free space", R.Free_Space (B) = Max_HS_Msg);
   Check ("empty: header not ready", not R.Header_Ready (B));
   Check ("empty: not too large", not R.Message_Too_Large (B));

   ---------------------------------------------------------------------
   --  One whole message in one append
   ---------------------------------------------------------------------
   R.Reset (B);
   R.Append (B, Msg (16#08#, 10, 16#AA#));
   Check ("whole: has message", R.Has_Message (B));
   Check ("whole: length = 14", R.Message_Length (B) = 14);
   Check ("whole: used = 14", R.Used (B) = 14);
   Check ("whole: type byte survives", R.Message (B) (0) = 16#08#);
   Check ("whole: body byte survives", R.Message (B) (4) = 16#AA#);
   R.Consume (B);
   Check ("whole: empty after consume", R.Used (B) = 0);
   Check ("whole: no message after consume", not R.Has_Message (B));

   ---------------------------------------------------------------------
   --  Header split across records -- BoGo MaxHandshakeRecordLength=1
   ---------------------------------------------------------------------
   R.Reset (B);
   declare
      M : constant Byte_Seq := Msg (16#0B#, 6, 16#BB#);
   begin
      R.Append (B, M (0 .. 0));
      Check ("split hdr: 1 byte, header not ready", not R.Header_Ready (B));
      Check ("split hdr: 1 byte, no message", not R.Has_Message (B));
      R.Append (B, M (1 .. 2));
      Check ("split hdr: 3 bytes, header not ready", not R.Header_Ready (B));
      R.Append (B, M (3 .. 3));
      Check ("split hdr: 4 bytes, header ready", R.Header_Ready (B));
      Check ("split hdr: 4 bytes, still incomplete", not R.Has_Message (B));
      Check ("split hdr: declared size = 10", R.Declared_Size (B) = 10);
      R.Append (B, M (4 .. M'Last));
      Check ("split hdr: complete", R.Has_Message (B));
      Check ("split hdr: length = 10", R.Message_Length (B) = 10);
   end;

   ---------------------------------------------------------------------
   --  Body split across many records
   ---------------------------------------------------------------------
   R.Reset (B);
   declare
      M : constant Byte_Seq := Msg (16#0D#, 100, 16#CC#);
      P : N32 := 0;
   begin
      while P <= M'Last loop
         declare
            Last : constant N32 := N32'Min (P + 6, M'Last);
         begin
            R.Append (B, M (P .. Last));
            P := Last + 1;
         end;
         if P <= M'Last then
            Check ("split body: incomplete while filling",
                   not R.Has_Message (B));
         end if;
      end loop;
      Check ("split body: complete at end", R.Has_Message (B));
      Check ("split body: length = 104", R.Message_Length (B) = 104);
   end;

   ---------------------------------------------------------------------
   --  PACKED: three messages in one append -- the case that broke twice
   ---------------------------------------------------------------------
   R.Reset (B);
   declare
      M1 : constant Byte_Seq := Msg (16#02#, 5,  16#11#);   --  9 bytes
      M2 : constant Byte_Seq := Msg (16#0B#, 20, 16#22#);   --  24 bytes
      M3 : constant Byte_Seq := Msg (16#0E#, 0,  16#33#);   --  4 bytes, no body
      Packed : Byte_Seq (0 .. M1'Length + M2'Length + M3'Length - 1);
      I : N32 := 0;
   begin
      for K in M1'Range loop Packed (I) := M1 (K); I := I + 1; end loop;
      for K in M2'Range loop Packed (I) := M2 (K); I := I + 1; end loop;
      for K in M3'Range loop Packed (I) := M3 (K); I := I + 1; end loop;

      R.Append (B, Packed);
      Check ("packed: used = 37", R.Used (B) = 37);

      Check ("packed: msg1 present", R.Has_Message (B));
      Check ("packed: msg1 length 9", R.Message_Length (B) = 9);
      Check ("packed: msg1 type", R.Message (B) (0) = 16#02#);
      R.Consume (B);

      --  STILL true after Consume: this is the whole packed case, and it
      --  needs no separate "available" concept.
      Check ("packed: msg2 present after consume", R.Has_Message (B));
      Check ("packed: msg2 length 24", R.Message_Length (B) = 24);
      Check ("packed: msg2 type", R.Message (B) (0) = 16#0B#);
      Check ("packed: msg2 body", R.Message (B) (4) = 16#22#);
      R.Consume (B);

      --  Zero-body message: Declared_Size = 4 exactly.
      Check ("packed: msg3 present", R.Has_Message (B));
      Check ("packed: msg3 length 4 (zero body)", R.Message_Length (B) = 4);
      Check ("packed: msg3 type", R.Message (B) (0) = 16#0E#);
      R.Consume (B);

      Check ("packed: drained", R.Used (B) = 0);
      Check ("packed: no message when drained", not R.Has_Message (B));
   end;

   ---------------------------------------------------------------------
   --  PACKED + PARTIAL: whole message followed by a fragment
   ---------------------------------------------------------------------
   R.Reset (B);
   declare
      M1 : constant Byte_Seq := Msg (16#08#, 2, 16#44#);    --  6 bytes
      M2 : constant Byte_Seq := Msg (16#0F#, 50, 16#55#);   --  54 bytes
      Part : Byte_Seq (0 .. M1'Length + 9);
      I : N32 := 0;
   begin
      for K in M1'Range loop Part (I) := M1 (K); I := I + 1; end loop;
      for K in 0 .. 9 loop Part (I) := M2 (N32 (K)); I := I + 1; end loop;

      R.Append (B, Part);
      Check ("packed+partial: first complete", R.Has_Message (B));
      Check ("packed+partial: first length 6", R.Message_Length (B) = 6);
      R.Consume (B);
      Check ("packed+partial: remainder buffered", R.Used (B) = 10);
      Check ("packed+partial: header of second readable",
             R.Header_Ready (B));
      Check ("packed+partial: second incomplete", not R.Has_Message (B));
      Check ("packed+partial: second declared 54",
             R.Declared_Size (B) = 54);
      R.Append (B, M2 (10 .. M2'Last));
      Check ("packed+partial: second now complete", R.Has_Message (B));
      Check ("packed+partial: second length 54", R.Message_Length (B) = 54);
   end;

   ---------------------------------------------------------------------
   --  Oversized declaration -- peer-controlled, must be reported not trusted
   ---------------------------------------------------------------------
   R.Reset (B);
   declare
      Hdr : Byte_Seq (0 .. 3);
   begin
      Hdr (0) := 16#0B#;
      Hdr (1) := 16#FF#;      --  ~16.7 MB, far beyond Max_HS_Msg
      Hdr (2) := 16#FF#;
      Hdr (3) := 16#FF#;
      R.Append (B, Hdr);
      Check ("oversize: header ready", R.Header_Ready (B));
      Check ("oversize: flagged too large", R.Message_Too_Large (B));
      Check ("oversize: not reported complete", not R.Has_Message (B));
   end;

   ---------------------------------------------------------------------
   --  Free_Space accounting -- what callers check peer lengths against
   ---------------------------------------------------------------------
   R.Reset (B);
   Check ("space: full when empty", R.Free_Space (B) = Max_HS_Msg);
   R.Append (B, Msg (16#08#, 96, 16#66#));
   Check ("space: reduced by 100", R.Free_Space (B) = Max_HS_Msg - 100);
   Check ("space: used + free = capacity",
          R.Used (B) + R.Free_Space (B) = Max_HS_Msg);

   Put_Line ("  test_reassembly:" & Total'Image & " total," &
             Pass'Image & " passed," & Fail'Image & " failed");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Reassembly;
