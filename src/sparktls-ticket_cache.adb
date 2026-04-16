package body SPARKTLS.Ticket_Cache with
   SPARK_Mode => On
is

   procedure Store
     (Cache   : in out Ticket_Store;
      PSK     : Bytes_48;
      PSK_Len : N32;
      Suite   : Unsigned_16;
      Age_Add : Unsigned_32;
      ID_Out  : out Ticket_ID)
   is
      Idx : constant Natural := Cache.Next;
   begin
      --  Derive ID from PSK bytes + index (caller provides proper random)
      ID_Out := (others => 0);
      for I in N32 range 0 .. Ticket_ID_Len - 1 loop
         ID_Out (I) := PSK (I) xor Byte (Idx mod 256);
      end loop;

      Cache.Entries (Idx) :=
        (ID      => ID_Out,
         PSK     => PSK,
         PSK_Len => PSK_Len,
         Suite   => Suite,
         Age_Add => Age_Add,
         Valid   => True);

      if Cache.Next = Max_Cached_Tickets - 1 then
         Cache.Next := 0;
      else
         Cache.Next := Cache.Next + 1;
      end if;
   end Store;

   procedure Lookup
     (Cache   : Ticket_Store;
      ID      : Byte_Seq;
      PSK     : out Bytes_48;
      PSK_Len : out N32;
      Suite   : out Unsigned_16;
      Found   : out Boolean)
   is
   begin
      PSK := (others => 0);
      PSK_Len := 0;
      Suite := 0;
      Found := False;

      for I in Cache.Entries'Range loop
         if Cache.Entries (I).Valid then
            declare
               Match : Boolean := True;
            begin
               for J in Ticket_ID'Range loop
                  if Cache.Entries (I).ID (J) /= ID (J) then
                     Match := False;
                     exit;
                  end if;
               end loop;
               if Match then
                  PSK := Cache.Entries (I).PSK;
                  PSK_Len := Cache.Entries (I).PSK_Len;
                  Suite := Cache.Entries (I).Suite;
                  Found := True;
                  return;
               end if;
            end;
         end if;
      end loop;
   end Lookup;

end SPARKTLS.Ticket_Cache;
