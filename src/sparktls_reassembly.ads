with SPARKTLS_Reassembly_G;
pragma Elaborate_All (SPARKTLS_Reassembly_G);

--  The historical 128 KB handshake-reassembly instance (#90 carve split
--  the ADT into SPARKTLS_Reassembly_G). Same name, same operations, same
--  proofs -- existing users are textually unchanged.

--  32 KB: every accepted handshake message is already bounded by the
--  Transcript_Capacity policy checks at the record layer (client.adb,
--  server.adb, server-tls13.adb), so a larger buffer only weakened what
--  the Message_Index type could promise. Kept equal to Transcript_Capacity
--  by a Compile_Time_Error in sparktls.ads (this unit cannot with SPARKTLS).
package SPARKTLS_Reassembly is new SPARKTLS_Reassembly_G (Capacity => 32_768);
