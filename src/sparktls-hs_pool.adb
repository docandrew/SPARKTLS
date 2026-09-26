package body SPARKTLS.HS_Pool
  with SPARK_Mode => On
is

   procedure Acquire (Pool : in out Handshake_Pool; Slot : out Slot_Count) is
   begin
      Slot := No_Slot;
      for I in Pool.In_Use'Range loop
         if not Pool.In_Use (I) then
            Pool.In_Use (I) := True;
            Slot := I;
            return;
         end if;
         pragma Loop_Invariant (Slot = No_Slot);
      end loop;
   end Acquire;

   procedure Release (Pool : in out Handshake_Pool; Slot : Slot_Index) is
   begin
      SPARKTLS_Reassembly.Reset (Pool.Slots (Slot).Reasm);
      Pool.Slots (Slot).Peer_Leaf.Present := False;
      Pool.Slots (Slot).Peer_Leaf.DER := (others => 0);
      Pool.Slots (Slot).Peer_Leaf.DER_Len := 0;
      for I in Pool.Slots (Slot).Peer_Ints'Range loop
         Pool.Slots (Slot).Peer_Ints (I).Present := False;
         Pool.Slots (Slot).Peer_Ints (I).DER := (others => 0);
         Pool.Slots (Slot).Peer_Ints (I).DER_Len := 0;
      end loop;
      Pool.Slots (Slot).Peer_Int_Count := 0;
      Pool.Slots (Slot).Stapled_OCSP := (others => 0);
      Pool.Slots (Slot).Stapled_OCSP_Len := 0;
      Pool.Slots (Slot).Stapled_Too_Big := False;
      --  The RecordFlux arena held the handshake messages of this
      --  connection (key shares, certificates, ...). The slot is reused
      --  by the next connection: clear it, as the header promises.
      Pool.Slots (Slot).Arena_Storage := (others => 0);
      Pool.In_Use (Slot) := False;
   end Release;

end SPARKTLS.HS_Pool;
