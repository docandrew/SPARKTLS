--  Heap allocation wrapper for Handshake_Context.
--  SPARK_Mode Off: uses new/Unchecked_Deallocation.

package SPARKTLS.HC_Alloc with
   SPARK_Mode => Off
is
   function Allocate return Handshake_Context_Access;

   procedure Free (Ptr : in out Handshake_Context_Access);
   --  Frees the context and sets Ptr to null.

end SPARKTLS.HC_Alloc;
