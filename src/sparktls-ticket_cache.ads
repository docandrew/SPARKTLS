--  Server-side session ticket cache operations.
--  Types are defined in parent package SPARKTLS.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Ticket_Cache with
   SPARK_Mode => On
is
   --  RFC 8446 §4.6.1: Store a NewSessionTicket's PSK.
   --  Round-robin: if cache is full, overwrites the oldest entry.
   --  Cache.Next always points to a valid index.
   procedure Store
     (Cache   : in out Ticket_Store;
      PSK     : Bytes_48;
      PSK_Len : N32;
      Suite   : Unsigned_16;
      Age_Add : Unsigned_32;
      ID_Out  : out Ticket_ID)
   with Pre  => PSK_Len in 32 | 48                            --  SHA-256 or SHA-384
                and Cache.Next in 0 .. Max_Cached_Tickets - 1,
        Post => Cache.Next in 0 .. Max_Cached_Tickets - 1;   --  index stays valid

   --  RFC 8446 §4.2.11: Look up a pre_shared_key identity.
   --  Lookup is read-only — does not modify the cache.
   procedure Lookup
     (Cache   : Ticket_Store;
      ID      : Byte_Seq;
      PSK     : out Bytes_48;
      PSK_Len : out N32;
      Suite   : out Unsigned_16;
      Found   : out Boolean)
   with Pre  => ID'First = 0 and ID'Length = Ticket_ID_Len;

end SPARKTLS.Ticket_Cache;
