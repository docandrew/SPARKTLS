--  Pools for Test_HS_Pool, at library level like any Handshake_Pool.
with SPARKTLS;

package Test_HS_Pool_Pools is
   Small : SPARKTLS.Handshake_Pool (Size => 2);
   Other : SPARKTLS.Handshake_Pool (Size => 1);
end Test_HS_Pool_Pools;
