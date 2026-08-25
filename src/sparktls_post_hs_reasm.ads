with SPARKTLS_Reassembly_G;

pragma Elaborate_All (SPARKTLS_Reassembly_G);

--  16 KB instance of the reassembly ADT (#90): post-handshake messages
--  (KeyUpdate, NewSessionTicket) are handshake-framed and never exceed
--  one record's plaintext in this design. Same proven body as the
--  128 KB handshake instance.
--
--  A LIBRARY-LEVEL instance, exactly like SPARKTLS_Reassembly, so its
--  generic-body proofs run in a tiny context: instantiated inside the
--  2000-line SPARKTLS root spec, the same Append postcondition VC was
--  a hard timeout; standalone it proves in seconds (measured 2026-08-24
--  on the 128 KB sibling, then confirmed here).
package SPARKTLS_Post_HS_Reasm is new SPARKTLS_Reassembly_G
  (Capacity => 16_384);
