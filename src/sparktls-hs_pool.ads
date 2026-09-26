--  Operations on a handshake pool (#106).
--
--  The handshake context splits in two: the small control-plane record
--  (secrets, transcript contexts, negotiation state -- a few KB) lives
--  INLINE in the Session, where a Session predicate can finally state
--  the state<->phase and version<->suite couplings over one object.
--  The jumbo data-plane components (HS_Data, in the parent) live in a
--  Handshake_Pool the application declares with Size slots:
--
--    * bounded handshake memory: Size x HS_Data, independent of session
--      count -- completed/idle sessions hold NO slot;
--    * admission control: pool exhausted => the handshake is refused
--      before any allocation, instead of the process growing;
--    * zero access types: the leak and borrow obligations of the old
--      heap box are structurally unrepresentable.
--
--  Slots hold no secrets by design (secrets are control-plane), but
--  Release wipes anyway: peer certificates and reassembly bytes are
--  peer-visible data, not key material, yet stale cross-connection
--  reads would still be a confidentiality bug.
--
--  SPARK note: no type predicate references a pool -- a Session and the
--  pool it draws from are separate objects. All pooled data is
--  deliberately invariant-free; every proof-carrying fact stays in the
--  Session.

package SPARKTLS.HS_Pool
  with SPARK_Mode => On
is

   --  The pool types live in the parent (SPARKTLS.Handshake_Pool etc.):
   --  Session and Drop must name them, and a parent spec cannot with its
   --  child. The handlers name the data-plane record through this subtype.
   subtype HS_Data is SPARKTLS.HS_Data;

   --  Admission control. Slot = No_Slot means the pool is exhausted and
   --  the handshake must be refused (the caller maps this to a clean
   --  connection rejection, never a crash).
   procedure Acquire (Pool : in out Handshake_Pool; Slot : out Slot_Count)
   with Post => (if Slot /= No_Slot then Slot <= Pool.Size and then Pool.In_Use (Slot));

   --  Wipe and free. Total over the pool's slots and idempotent: a Pre
   --  demanding In_Use would tie Session.Slot to pool state -- exactly the
   --  cross-object obligation this carve exists to eliminate. Wiping a
   --  free slot is harmless; the wipe is unconditional either way.
   procedure Release (Pool : in out Handshake_Pool; Slot : Slot_Index)
   with Pre  => Slot <= Pool.Size,
        Post => not Pool.In_Use (Slot);

end SPARKTLS.HS_Pool;
