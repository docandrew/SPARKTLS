--  ===========================================================================
--  SPARKTLS.RFLX_Borrow  --  the one sanctioned representation-level primitive
--  ===========================================================================
--
--  In-place RecordFlux on the connection's INLINE storage. RecordFlux drives
--  every message on a buffer it OWNS through a Bytes_Ptr; to build or parse a
--  message directly inside S.Input.Storage / S.Output.Storage (no heap, no
--  copy) we must hand a context a pointer INTO that inline array. SPARK cannot
--  produce it (taking 'Access of a component and storing it is forbidden), so
--  Borrow does, in a SPARK_Mode Off body.
--
--  It is NOT a same-representation cast. RecordFlux's Bytes_Ptr designates an
--  unconstrained array, so it is a GNAT "fat" pointer (data address + a bounds
--  record); an inline array component yields only a "thin" 'Access. Borrow
--  therefore CONSTRUCTS the fat pointer: data = Storage (First)'Address, bounds
--  = a caller-owned Holder set to (First, Last). Discard drops the pointer
--  WITHOUT freeing (the target is not heap). Layout_Verified checks the fat-
--  pointer format against a real heap pointer and is raised on at elaboration
--  (see the body), so a future compiler that changes the layout fails loudly
--  at startup rather than corrupting memory.
--
--  Usage discipline (the soundness obligation SPARK cannot see):
--    * declare Holder aliased in the SAME scope as the context and keep it
--      alive until Discard -- RecordFlux reads the bounds through the whole
--      context lifetime;
--    * never read or write Storage while a borrow of it is live;
--    * never pass a borrowed pointer to Free / RFLX_Free -- Discard only.
--
--  User-approved 2026-09-05 (inline + Borrow, zero-copy) after being shown it
--  exceeds a plain cast. See memory rflx-byte-unified-conversion-rules and the
--  reproducer tls_proj/exp_conv/.

with RFLX.RFLX_Builtin_Types;
package SPARKTLS.RFLX_Borrow with SPARK_Mode is

   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Bytes_Ptr;
   use type RBT.Index;

   --  Persistent window-bounds storage. Declare one aliased per concurrently
   --  live borrow, in the scope that holds the context.
   type Bounds_Holder is limited private;

   --  Hand out a Bytes_Ptr to the window Storage (First .. Last). Storage is
   --  passed by reference (arrays are); no 'aliased' on the formal, so any
   --  buffer subtype fits without a static-match constraint.
   procedure Borrow
     (Storage     : in out RBT.Bytes;
      First, Last : RBT.Index;
      Holder      : aliased in out Bounds_Holder;
      P           : out RBT.Bytes_Ptr)
   with
     Pre  => First >= Storage'First and then Last <= Storage'Last
             and then First <= Last,
     Post => P /= null and then P'First = First and then P'Last = Last;

   --  Drop a borrowed pointer. Never frees -- the target is inline storage.
   procedure Discard (P : in out RBT.Bytes_Ptr)
   with Post => P = null;

   --  True iff the fabricated fat-pointer layout matches the compiler's. The
   --  body raises Program_Error at elaboration if this is ever False.
   function Layout_Verified return Boolean;

private
   type Bounds_Holder is record
      F, L : RBT.Index := 1;
   end record;
end SPARKTLS.RFLX_Borrow;
