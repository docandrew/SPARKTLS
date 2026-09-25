--  The handshake pool for unit tests and the BoGo shim (see
--  SPARKTLS.Handshake_Pool): 16 slots, the size the library used to fix.
--  A package-level object, so the slots are static storage rather than a
--  test's stack.
with SPARKTLS;

package Test_Pool is
   Handshakes : SPARKTLS.Handshake_Pool (Size => 16);
end Test_Pool;
