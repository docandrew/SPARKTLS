with Ada.Unchecked_Deallocation;

package body SPARKTLS.HC_Alloc with
   SPARK_Mode => Off
is
   procedure Dealloc is new Ada.Unchecked_Deallocation
     (Object => HC_Box,
      Name   => Handshake_Context_Access);

   function Allocate return Handshake_Context_Access is
   begin
      return new HC_Box;
   end Allocate;

   procedure Free (Ptr : in out Handshake_Context_Access) is
   begin
      if Ptr /= null then
         Dealloc (Ptr);
      end if;
   end Free;

end SPARKTLS.HC_Alloc;
