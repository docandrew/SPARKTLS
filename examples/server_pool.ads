--  The example servers' handshake pool: up to 64 handshakes in flight at
--  once (see SPARKTLS.Handshake_Pool). A package-level object, so the slots
--  are static storage rather than main's stack.
with SPARKTLS;

package Server_Pool is
   Handshakes : SPARKTLS.Handshake_Pool (Size => 64);
end Server_Pool;
