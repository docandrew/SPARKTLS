with SPARKTLSCrypto.Hashing.SHA256;

package body SPARKTLS.Ticket_Cache
  with SPARK_Mode => On
is

   procedure Store
     (Cache       : in out Ticket_Store;
      PSK         : Bytes_48;
      PSK_Len     : N32;
      Suite       : Unsigned_16;
      Age_Add     : Unsigned_32;
      Client_Auth : Boolean;
      ID_Out      : out Ticket_ID)
   is
      Idx : constant Natural := Cache.Next;
      D   : SPARKTLSCrypto.Hashing.SHA256.Digest;
   begin
      --  SR-02: ID = one-way SHA-256(PSK) truncated to 16 bytes. On the wire
      --  in cleartext but unlinkable to the PSK (hashing all 48 bytes; the
      --  32-byte PSK's tail is deterministically zero, so the id is stable).
      --  SR-03: record whether the originating session was client-authed.
      SPARKTLSCrypto.Hashing.SHA256.Hash (D, Byte_Seq (PSK));
      ID_Out := D (0 .. Ticket_ID_Len - 1);
      Cache.Entries (Idx) :=
        (ID          => ID_Out,
         PSK         => PSK,
         PSK_Len     => PSK_Len,
         Suite       => Suite,
         Age_Add     => Age_Add,
         Client_Auth => Client_Auth,
         Valid       => True);

      if Cache.Next = Max_Cached_Tickets - 1 then
         Cache.Next := 0;
      else
         Cache.Next := Cache.Next + 1;
      end if;
   end Store;

   procedure Lookup
     (Cache       : Ticket_Store;
      ID          : Byte_Seq;
      Want_Suite  : Unsigned_16;
      PSK         : out Bytes_48;
      PSK_Len     : out N32;
      Suite       : out Unsigned_16;
      Client_Auth : out Boolean;
      Found       : out Boolean) is
   begin
      PSK := (others => 0);
      PSK_Len := 0;
      Suite := 0;
      Client_Auth := False;
      Found := False;

      for I in Cache.Entries'Range loop
         pragma Loop_Invariant (if Found then Suite = Want_Suite);
         if Cache.Entries (I).Valid and then Cache.Entries (I).Suite = Want_Suite then
            declare
               --  Constant-time identity compare: OR the byte differences
               --  together across the WHOLE id (no early exit), so the
               --  compare time does not depend on where a wrong id first
               --  differs (SR-02). Diff = 0 iff every byte matched.
               Diff : Byte := 0;
            begin
               for J in Ticket_ID'Range loop
                  Diff := Diff or (Cache.Entries (I).ID (J) xor ID (J));
               end loop;
               if Diff = 0 then
                  PSK := Cache.Entries (I).PSK;
                  PSK_Len := Cache.Entries (I).PSK_Len;
                  Suite := Cache.Entries (I).Suite;
                  Client_Auth := Cache.Entries (I).Client_Auth;
                  Found := True;
                  return;
               end if;
            end;
         end if;
      end loop;
   end Lookup;

end SPARKTLS.Ticket_Cache;
