package body SPARKTLS.HS_Pool with
   SPARK_Mode => On
is

   procedure Acquire (Slot : out Slot_Count) is
   begin
      Slot := No_Slot;
      for I in Slot_Index loop
         if not In_Use (I) then
            In_Use (I) := True;
            Slot := I;
            return;
         end if;
         pragma Loop_Invariant (Slot = No_Slot);
      end loop;
   end Acquire;

   procedure Release (Slot : Slot_Index) is
   begin
      SPARKTLS_Reassembly.Reset (Slots (Slot).Reasm);
      Slots (Slot).Peer_Leaf.Present := False;
      Slots (Slot).Peer_Leaf.DER := (others => 0);
      Slots (Slot).Peer_Leaf.DER_Len := 0;
      for I in Slots (Slot).Peer_Ints'Range loop
         Slots (Slot).Peer_Ints (I).Present := False;
         Slots (Slot).Peer_Ints (I).DER := (others => 0);
         Slots (Slot).Peer_Ints (I).DER_Len := 0;
      end loop;
      In_Use (Slot) := False;
   end Release;

end SPARKTLS.HS_Pool;
