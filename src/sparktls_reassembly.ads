with SPARKTLS_Reassembly_G;
pragma Elaborate_All (SPARKTLS_Reassembly_G);

--  The historical 128 KB handshake-reassembly instance (#90 carve split
--  the ADT into SPARKTLS_Reassembly_G). Same name, same operations, same
--  proofs -- existing users are textually unchanged.

package SPARKTLS_Reassembly is new SPARKTLS_Reassembly_G (Capacity => 131_072);
