--  Bounded pool for handshake DATA-PLANE state (#106).
--
--  The handshake context splits in two: the small control-plane record
--  (secrets, transcript contexts, negotiation state -- a few KB) lives
--  INLINE in the Session, where a Session predicate can finally state
--  the state<->phase and version<->suite couplings over one object.
--  The three jumbo components below (~236 KB together) live here, in a
--  fixed pool of Max_Inflight slots:
--
--    * bounded handshake memory: Max_Inflight x HS_Data, independent of
--      session count -- completed/idle sessions hold NO slot;
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
--  SPARK note: no type predicate references this package's state --
--  predicates cannot read globals. All pooled data is deliberately
--  invariant-free; every proof-carrying fact stays in the Session.
package SPARKTLS.HS_Pool with
   SPARK_Mode => On
is

   Max_Inflight : constant := 16;

   type Slot_Count is range 0 .. Max_Inflight;
   subtype Slot_Index is Slot_Count range 1 .. Max_Inflight;
   No_Slot : constant Slot_Count := 0;

   --  The data-plane: everything a handshake needs that is too big to
   --  carry per-session for the session's whole lifetime.
   type HS_Data is record
      Reasm      : SPARKTLS_Reassembly.Buffer;
      Peer_Leaf  : Pool_Entry;
      Peer_Ints  : Cert_Pool;
   end record;

   type Slot_Array is array (Slot_Index) of HS_Data;
   type Use_Map    is array (Slot_Index) of Boolean;

   --  Public by design: handlers receive Slots (S.Slot) as an explicit
   --  `in out HS_Data` parameter from the dispatch layer -- three
   --  distinct objects (S, S.HC view, D) means no aliasing and no
   --  Global-annotation cascade through the handler tree.
   Slots  : Slot_Array;
   In_Use : Use_Map := (others => False);

   --  Admission control. Slot = No_Slot means the pool is exhausted and
   --  the handshake must be refused (the caller maps this to a clean
   --  connection rejection, never a crash).
   procedure Acquire (Slot : out Slot_Count)
   with Post => (if Slot /= No_Slot then In_Use (Slot));

   --  Wipe and free. Idempotence is not offered: releasing a free slot
   --  is a caller bug the Pre makes unrepresentable in proved code.
   procedure Release (Slot : Slot_Index)
   with Pre  => In_Use (Slot),
        Post => not In_Use (Slot);

end SPARKTLS.HS_Pool;
