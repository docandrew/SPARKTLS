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
   --
   --  Want_Suite is the cipher suite the server has already negotiated
   --  for this connection. RFC 8446 §4.2.11 forbids resuming a PSK
   --  under a different cipher suite (would allow downgrade and breaks
   --  the key schedule's hash binding). Lookup enforces this by only
   --  reporting Found => True when the cached suite matches Want_Suite;
   --  the Post-condition lets callers prove RFC compliance.
   procedure Lookup
     (Cache      : Ticket_Store;
      ID         : Byte_Seq;
      Want_Suite : Unsigned_16;
      PSK        : out Bytes_48;
      PSK_Len    : out N32;
      Suite      : out Unsigned_16;
      Found      : out Boolean)
   with Pre  => ID'First = 0 and ID'Length = Ticket_ID_Len,
        Post => (if Found then Suite = Want_Suite);

   --  RFC 8446 §8.2: 0-RTT replay protection. Mark the entry for ID
   --  as no-longer-valid so a subsequent Lookup with the same ID
   --  returns Found => False. Called once the server commits to
   --  accepting 0-RTT on this ticket — single-use semantics make
   --  replay impossible at the cost of forbidding legitimate
   --  retries on the same ticket (the server issues new tickets in
   --  the post-handshake NST so the client can resume future
   --  connections regardless).
   procedure Consume
     (Cache : in out Ticket_Store;
      ID    : Byte_Seq)
   with Pre => ID'First = 0 and ID'Length = Ticket_ID_Len;

end SPARKTLS.Ticket_Cache;
