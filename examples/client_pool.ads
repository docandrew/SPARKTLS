--  The example clients' handshake pool (see SPARKTLS.Handshake_Pool). A
--  client drives one handshake at a time; a few slots leave room for a
--  resumption test's second connection while the first is being dropped.
--  A package-level object, so the slots are static storage rather than
--  main's stack.
with SPARKTLS;

package Client_Pool is
   Handshakes : SPARKTLS.Handshake_Pool (Size => 4);
end Client_Pool;
