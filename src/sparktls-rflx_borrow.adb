with System; use type System.Address;
with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;

package body SPARKTLS.RFLX_Borrow with SPARK_Mode => Off is

   --  GNAT fat pointer for an access-to-unconstrained-array: (data, bounds).
   type Fat is record
      P_ARRAY  : System.Address;
      P_BOUNDS : System.Address;
   end record;

   function To_Ptr is new Ada.Unchecked_Conversion (Fat, RBT.Bytes_Ptr);
   function To_Fat is new Ada.Unchecked_Conversion (RBT.Bytes_Ptr, Fat);

   ----------------------------------------------------------------------------
   procedure Borrow
     (Storage     : in out RBT.Bytes;
      First, Last : RBT.Index;
      Holder      : aliased in out Bounds_Holder;
      P           : out RBT.Bytes_Ptr) is
   begin
      Holder := (F => First, L => Last);
      P := To_Ptr (Fat'(P_ARRAY  => Storage (First)'Address,
                        P_BOUNDS => Holder'Address));
   end Borrow;

   ----------------------------------------------------------------------------
   procedure Discard (P : in out RBT.Bytes_Ptr) is
   begin
      P := null;  --  never Free: the target is inline, not heap
   end Discard;

   ----------------------------------------------------------------------------
   function Layout_Verified return Boolean is
      procedure Free is new Ada.Unchecked_Deallocation (RBT.Bytes, RBT.Bytes_Ptr);
      H  : RBT.Bytes_Ptr := new RBT.Bytes'(3 .. 9 => 0);
      F  : constant Fat := To_Fat (H);
      B  : Bounds_Holder with Import, Address => F.P_BOUNDS;
      OK : constant Boolean :=
        Fat'Size = RBT.Bytes_Ptr'Size
        and then F.P_ARRAY = H.all'Address
        and then B.F = 3 and then B.L = 9;
   begin
      Free (H);
      return OK;
   end Layout_Verified;

begin
   --  Elaboration-time guard: runs once, the moment any unit that uses Borrow
   --  pulls this package into the closure. Fails loudly on a layout change.
   if not Layout_Verified then
      raise Program_Error
        with "SPARKTLS.RFLX_Borrow: fat-pointer layout assumption violated";
   end if;
end SPARKTLS.RFLX_Borrow;
