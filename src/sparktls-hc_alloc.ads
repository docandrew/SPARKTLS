--  Heap allocation wrapper for Handshake_Context.
--  The spec is SPARK-visible so verified callers can rely on the boundary
--  contract. The body remains SPARK_Mode Off because it uses
--  new/Unchecked_Deallocation.

package SPARKTLS.HC_Alloc with
   SPARK_Mode => On
is
   function Allocate return Handshake_Context_Access;

   --  Frees the context and sets Ptr to null.
   procedure Free (Ptr : in out Handshake_Context_Access)
   with Post => Ptr = null;

end SPARKTLS.HC_Alloc;
