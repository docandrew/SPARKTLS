--  Server-side session ticket cache operations.
--  Types are defined in parent package SPARKTLS.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Ticket_Cache with
   SPARK_Mode => On
is
   --  Store a new ticket, returns the assigned ID.
   procedure Store
     (Cache   : in out Ticket_Store;
      PSK     : Bytes_48;
      PSK_Len : N32;
      Suite   : Unsigned_16;
      Age_Add : Unsigned_32;
      ID_Out  : out Ticket_ID);

   --  Look up a ticket by ID.
   procedure Lookup
     (Cache   : Ticket_Store;
      ID      : Byte_Seq;
      PSK     : out Bytes_48;
      PSK_Len : out N32;
      Suite   : out Unsigned_16;
      Found   : out Boolean)
   with Pre => ID'First = 0 and ID'Length = Ticket_ID_Len;

end SPARKTLS.Ticket_Cache;
