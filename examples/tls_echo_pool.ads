--  Library-level storage for tls_echo_epoll's connection pool.
--
--  Declaring Conns here (rather than inside the main procedure) puts
--  the array in BSS instead of on the main task stack. Each Session
--  is ~290 KB, so 16 of them = ~4.6 MB — fits stack today, but BSS
--  removes the coupling to stack size and is the pattern we want as
--  this grows.

with Interfaces.C; use Interfaces.C;
with SPARKNaCl;    use SPARKNaCl;
with SPARKTLS;

package TLS_Echo_Pool is

   type Conn_State is (Handshaking, Ready, Closing, Closed);

   type Connection is record
      S       : SPARKTLS.Server_Session;
      FD      : int := -1;
      State   : Conn_State := Closed;
      Req_Buf : Byte_Seq (0 .. 4095) := (others => 0);
      Req_Len : N32 := 0;
   end record;

   Max_Conns : constant := 16;
   type Conn_Index is range 0 .. Max_Conns - 1;
   type Conn_Array is array (Conn_Index) of Connection;

   Conns : Conn_Array;

end TLS_Echo_Pool;
