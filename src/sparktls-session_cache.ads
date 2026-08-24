--  Reference thread-safe implementation of the ticket-storage callbacks.
--
--  SPARKTLS itself holds no ticket storage: Config carries callbacks
--  (Store_Session / Lookup_Session / Get_Active_TEK / Get_TEK_By_Id) and the
--  application supplies them. That keeps the core free of global state and of
--  owning pointers, and leaves concurrency policy where only the application
--  can decide it.
--
--  This package is that decision made for you, for the common case: a
--  single-process server, possibly multi-threaded, that wants resumption to
--  work without writing any of it. It is a CHILD package, so the Ada tasking
--  runtime is linked only if you actually reference it -- an embedded caller
--  that leaves the callbacks null pays nothing.
--
--  Usage:
--
--     SPARKTLS.Session_Cache.Initialize
--       (Random => My_RNG'Access, Clock => My_Clock'Access);
--
--     SPARKTLS.Server.Configure
--       (S              => S,
--        Local          => Ident'Unchecked_Access,
--        Random         => My_RNG'Access,
--        Store_Session  => SPARKTLS.Session_Cache.Store_Session'Access,
--        Lookup_Session => SPARKTLS.Session_Cache.Lookup_Session'Access,
--        Get_Active_TEK => SPARKTLS.Session_Cache.Get_Active_TEK'Access,
--        Get_TEK_By_Id  => SPARKTLS.Session_Cache.Get_TEK_By_Id'Access);
--
--  Call Initialize once at startup. It installs a first ticket key and turns
--  on rotation (every 24h by default); the library itself no longer rotates
--  keys, because it no longer holds them. Before Initialize there is no key,
--  so TLS 1.2 tickets are not issued and clients do full handshakes.
--
--  DEPLOYMENT SHAPES this does and does not cover:
--
--    * EMBEDDED / single connection at a time — you do not need this. Leave
--      the callbacks null; resumption is disabled and nothing here is linked.
--
--    * MULTI-THREADED, ONE PROCESS — this package. The protected object
--      serialises access, so any number of tasks may drive sessions
--      concurrently against one cache.
--
--    * MULTI-PROCESS — NOT covered. Workers in separate address spaces would
--      each get their own copy, so a ticket issued by one is unknown to the
--      others (clients simply re-handshake). Sharing across processes needs
--      shared memory or a key/ticket file, which is environment-specific;
--      implement the four callbacks over whatever your platform provides.
--
--    * MULTI-NODE / DISTRIBUTED — NOT covered. Needs an external store
--      (Redis, memcached, a database). Implement the callbacks against it,
--      and note the contract below: DO NOT BLOCK. A lookup that cannot answer
--      quickly should report Found => False and let the handshake proceed in
--      full; that is always safe, whereas stalling blocks the state machine.
--
--  SPARK_Mode is ON here, including the protected object.
--
--  That takes one piece of scaffolding. SPARK refuses to analyse any tasking
--  construct unless the partition commits to a concurrency profile (SPARK RM
--  9(2)), and a protected object is a tasking construct even when the program
--  contains no tasks at all. So proving this unit needs
--
--     pragma Profile (Jorvik);
--     pragma Partition_Elaboration_Policy (Sequential);
--
--  which live in ci/proof.adc and are passed to gnatprove alone, via
--  -cargs -gnatec=. They are deliberately NOT in sparktls.gpr: pragma Profile
--  is partition-wide, so in the project file it would force Ravenscar/Jorvik
--  onto every application linking this library, for the sake of one optional
--  child package. `alr build` therefore never sees them, and consumers get an
--  ordinary protected object with ordinary Ada semantics and no added
--  ordering or runtime cost.
--
--  Be precise about what the proof covers. Absence of runtime errors in the
--  protected bodies -- ranges, indices, overflow -- is profile-independent
--  and holds however the final partition is built. Freedom from data races
--  likewise comes from Ada's protected-object semantics, not from SPARK.
--  What DOES rest on the profile holding at link time is SPARK's
--  scheduling-level reasoning: priority-ceiling correctness and deadlock
--  freedom. A consumer building without Ravenscar/Jorvik does not inherit
--  those two. Since this package has no entries, no delays and no blocking
--  operations, there is nothing here to deadlock on -- but the guarantee is
--  weaker than the rest of the library's, and is stated rather than implied.

with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;

package SPARKTLS.Session_Cache with
   SPARK_Mode => On
is

   ----------------------------------------------------------------------
   --  Setup
   ----------------------------------------------------------------------

   --  Seed the cache and start rotating ticket keys.
   --
   --  Installs a first sealing key immediately, then rotates whenever the
   --  active key reaches Rotation_Interval seconds. Rotation is lazy: the
   --  age is checked when a key is next needed, so there is no timer task
   --  and an idle server does no work. Key generation happens OUTSIDE the
   --  protected object's lock, so a slow CSPRNG cannot stall other tasks.
   --
   --  Rotation is ON BY DEFAULT because a ticket key that never changes
   --  undermines the forward secrecy tickets are supposed to preserve.
   --  Pass Rotation_Interval => 0 to turn it off and drive Rotate_TEK
   --  yourself -- appropriate when keys come from an HSM, or when a fleet
   --  is kept in sync by an orchestrator pushing the same key to every
   --  node (independent per-node rotation would break cross-node resume).
   --
   --  Until this is called there is no key, so no TLS 1.2 tickets are
   --  issued and clients simply perform full handshakes.
   procedure Initialize
     (Random            : Random_Bytes_Fn;
      Clock             : Get_Time_Fn;
      Rotation_Interval : Unsigned_32 := 24 * 3600);

   ----------------------------------------------------------------------
   --  Callbacks — pass these to Configure/Init via 'Access.
   ----------------------------------------------------------------------

   --  Persist a resumption PSK and return the identity to put on the wire.
   procedure Store_Session
     (PSK     : Bytes_48;
      PSK_Len : PSK_Length;
      Suite   : Unsigned_16;
      Age_Add : Unsigned_32;
      ID_Out  : out Ticket_ID)
   with Pre => PSK_Len in 32 | 48;

   --  Retrieve a PSK by identity. Found => False for a miss, a cipher-suite
   --  mismatch, or anything else -- all mean "do a full handshake".
   procedure Lookup_Session
     (ID         : Byte_Seq;
      Want_Suite : Unsigned_16;
      PSK        : out Bytes_48;
      PSK_Len    : out N32;
      Suite      : out Unsigned_16;
      Found      : out Boolean)
   with Pre  => ID'First = 0 and then ID'Length = Ticket_ID_Len,
        Post => (if Found then Suite = Want_Suite
                             and then PSK_Len in 32 | 48);

   --  The key that seals new TLS 1.2 tickets. Found => False before any
   --  Rotate_TEK call, which simply means no ticket is issued.
   procedure Get_Active_TEK
     (Key_ID : out Byte_Seq;
      TEK    : out Byte_Seq;
      Found  : out Boolean)
   with Pre => Key_ID'Length = 4 and then TEK'Length = 32;

   --  The key a presented ticket names. Older keys stay usable until they
   --  age out of the ring, so tickets issued before a rotation still resume.
   procedure Get_TEK_By_Id
     (Key_ID : Byte_Seq;
      TEK    : out Byte_Seq;
      Found  : out Boolean)
   with Pre => TEK'Length = 32;

   ----------------------------------------------------------------------
   --  Key management — the application's job now, on its own schedule.
   ----------------------------------------------------------------------

   --  Install a new sealing key explicitly. Normally unnecessary when
   --  Initialize enabled rotation; use it for HSM- or orchestrator-supplied
   --  keys, or when Rotation_Interval => 0 puts you in manual control.
   --  The previous keys remain valid for
   --  decryption until pushed out of the ring, so in-flight tickets keep
   --  resuming across a rotation. Generate Key_ID/TEK from your CSPRNG,
   --  or fetch them from an HSM or orchestrator.
   procedure Rotate_TEK
     (New_Key_ID : Byte_Seq;
      New_TEK    : Byte_Seq;
      Now_Secs   : Unsigned_64);

   --  Age of the active key in seconds, for callers driving their own
   --  rotation timer. Returns Now_Secs if no key has been installed.
   --
   --  Declared Volatile_Function because it reads state another task may be
   --  changing: two calls can legitimately differ. SPARK callers must bind
   --  the result to a local rather than use it inside a larger expression
   --  (write "A := Active_Key_Age (Now); if A > Limit then", not
   --  "if Active_Key_Age (Now) > Limit then"). That is not a nuisance rule
   --  -- it is the compiler insisting you decide on one observation.
   function Active_Key_Age (Now_Secs : Unsigned_64) return Unsigned_64
   with Volatile_Function;

   --  Drop every cached PSK and key. Intended for tests and for shutdown.
   procedure Reset;

end SPARKTLS.Session_Cache;
