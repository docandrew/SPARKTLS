--  Library-level storage for tls_echo_epoll's connection pool.
--
--  Declaring Conns here (rather than inside the main procedure) puts
--  the array in BSS instead of on the main task stack. Each Session
--  is ~290 KB, so 16 of them = ~4.6 MB — fits stack today, but BSS
--  removes the coupling to stack size and is the pattern we want as
--  this grows.

with Ada.Real_Time;
with Interfaces.C; use Interfaces.C;
with SPARKNaCl;    use SPARKNaCl;
with SPARKTLS;

package TLS_Echo_Pool is

   type Conn_State is (Handshaking, Ready, Sending, Closing, Closed);

   type Body_Access is access all Byte_Seq;

   type Connection is record
      S       : SPARKTLS.Server_Session;
      FD      : int := -1;
      State   : Conn_State := Closed;
      Req_Buf : Byte_Seq (0 .. 4095) := (others => 0);
      Req_Len : N32 := 0;
      --  Monotonic clock stamps for the deadlines (see tls_web_epoll):
      --  when the socket was accepted, and when bytes last arrived on it.
      Opened_At     : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Last_Activity : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      --  Response in flight (tls_web_epoll): the body by reference and how
      --  much of it has been handed to the session; ciphertext the socket
      --  has not accepted yet; whether close_notify has been queued; and
      --  whether EPOLLOUT is armed. Non-blocking write(2) may take part of
      --  a buffer, so the remainder waits here for the socket to drain.
      Body_Ref     : Body_Access := null;
      Body_Off     : N32 := 0;
      Out_Buf      : Byte_Seq (0 .. 16639) := (others => 0);
      Out_Len      : N32 := 0;
      Out_Sent     : N32 := 0;
      Close_Queued : Boolean := False;
      Want_Out     : Boolean := False;
   end record;

   Max_Conns : constant := 16;
   type Conn_Index is range 0 .. Max_Conns - 1;
   type Conn_Array is array (Conn_Index) of Connection;

   Conns : Conn_Array;

end TLS_Echo_Pool;
