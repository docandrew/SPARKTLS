--  io_uring for the examples, in Ada, with no liburing and no C.
--
--  The kernel ABI from linux/io_uring.h (the records below carry the
--  header's byte offsets in their representation clauses), the three system
--  calls, and a minimal submission/completion ring: just what an event-driven
--  TLS server needs. The oldest kernel it runs on is 6.4, for the repeating
--  timeout (IORING_TIMEOUT_MULTISHOT); the rest needs 6.0 at most
--  (IORING_SETUP_SINGLE_ISSUER), and it was written on 6.8.
--  Record and constant names follow docandrew/liburing-ada, a 2022 binding of
--  liburing; unlike that binding this one talks to the kernel directly.
--
--  Memory: the rings are mmap'd from the kernel and charged to the process's
--  memory cgroup (Linux 5.12 and later), and data moves through ordinary
--  application buffers, so nothing needs RLIMIT_MEMLOCK.
--
--  No provided buffer rings (IORING_REGISTER_PBUF_RING, Linux 5.19): they
--  let the kernel pick a receive buffer from a shared pool when data
--  arrives, which saves memory across many idle connections. The examples
--  keep memory fixed at start-up instead -- each connection receives into
--  its own buffer, with one receive in flight -- which needs nothing from
--  the kernel beyond plain IORING_OP_RECV.
--
--  Not task-safe: a Ring belongs to the task that set it up (the server gives
--  each worker its own), which is also what IORING_SETUP_SINGLE_ISSUER tells
--  the kernel.

with Interfaces;   use Interfaces;
with Interfaces.C;
with System;

package IO_Uring is

   ----------------------------------------------------------------------------
   --  Kernel ABI
   ----------------------------------------------------------------------------

   --  Opcodes (enum io_uring_op; only those the examples use).
   IORING_OP_NOP          : constant := 0;
   IORING_OP_TIMEOUT      : constant := 11;
   IORING_OP_ACCEPT       : constant := 13;
   IORING_OP_ASYNC_CANCEL : constant := 14;
   IORING_OP_CLOSE        : constant := 19;
   IORING_OP_SEND         : constant := 26;
   IORING_OP_RECV         : constant := 27;
   IORING_OP_SHUTDOWN     : constant := 34;

   --  sqe->timeout_flags
   IORING_TIMEOUT_MULTISHOT : constant := 2#100_0000#;   --  1 << 6

   --  sqe->cancel_flags
   IORING_ASYNC_CANCEL_ALL : constant := 2#00_0001#;
   IORING_ASYNC_CANCEL_FD  : constant := 2#00_0010#;

   --  cqe->flags
   IORING_CQE_F_MORE : constant := 2#0010#;   --  the request stays armed (multishot)

   --  shutdown(2) how
   SHUT_RDWR : constant := 2;

   --  io_uring_setup flags
   IORING_SETUP_CLAMP          : constant := 2#1_0000#;           --  1 << 4
   IORING_SETUP_SUBMIT_ALL     : constant := 2#1000_0000#;        --  1 << 7
   IORING_SETUP_COOP_TASKRUN   : constant := 2#1_0000_0000#;      --  1 << 8
   IORING_SETUP_SINGLE_ISSUER  : constant := 2#1_0000_0000_0000#; --  1 << 12

   --  io_uring_params->features
   IORING_FEAT_SINGLE_MMAP : constant := 2#0001#;
   IORING_FEAT_NODROP      : constant := 2#0010#;

   --  io_uring_enter flags
   IORING_ENTER_GETEVENTS : constant := 2#0001#;

   --  mmap offsets
   IORING_OFF_SQ_RING : constant := 16#0000_0000#;
   IORING_OFF_CQ_RING : constant := 16#0800_0000#;
   IORING_OFF_SQES    : constant := 16#1000_0000#;

   --  struct io_uring_sqe, 64 bytes. Of each union, the member the examples
   --  use gives the component its name.
   type SQE is record
      Opcode      : Unsigned_8  := 0;
      Flags       : Unsigned_8  := 0;
      Ioprio      : Unsigned_16 := 0;   --  accept / recv flags
      FD          : Integer_32  := -1;
      Off         : Unsigned_64 := 0;   --  off / addr2
      Addr        : Unsigned_64 := 0;   --  buffer, timespec, or cancel key
      Len         : Unsigned_32 := 0;
      Op_Flags    : Unsigned_32 := 0;   --  msg_flags / timeout_flags / cancel_flags / accept_flags
      User_Data   : Unsigned_64 := 0;
      Buf_Group   : Unsigned_16 := 0;   --  buf_index / buf_group
      Personality : Unsigned_16 := 0;
      File_Index  : Unsigned_32 := 0;   --  splice_fd_in / file_index / optlen
      Addr3       : Unsigned_64 := 0;
      Pad2        : Unsigned_64 := 0;
   end record
     with Convention => C, Size => 64 * 8;
   for SQE use record
      Opcode      at  0 range 0 ..  7;
      Flags       at  1 range 0 ..  7;
      Ioprio      at  2 range 0 .. 15;
      FD          at  4 range 0 .. 31;
      Off         at  8 range 0 .. 63;
      Addr        at 16 range 0 .. 63;
      Len         at 24 range 0 .. 31;
      Op_Flags    at 28 range 0 .. 31;
      User_Data   at 32 range 0 .. 63;
      Buf_Group   at 40 range 0 .. 15;
      Personality at 42 range 0 .. 15;
      File_Index  at 44 range 0 .. 31;
      Addr3       at 48 range 0 .. 63;
      Pad2        at 56 range 0 .. 63;
   end record;

   --  struct io_uring_cqe, 16 bytes (no IORING_SETUP_CQE32).
   type CQE is record
      User_Data : Unsigned_64 := 0;
      Res       : Integer_32  := 0;
      Flags     : Unsigned_32 := 0;
   end record
     with Convention => C, Size => 16 * 8;
   for CQE use record
      User_Data at  0 range 0 .. 63;
      Res       at  8 range 0 .. 31;
      Flags     at 12 range 0 .. 31;
   end record;

   --  struct io_sqring_offsets / io_cqring_offsets, 40 bytes each.
   type SQ_Offsets is record
      Head, Tail, Ring_Mask, Ring_Entries, Flags, Dropped, Array_Off, Resv1 : Unsigned_32 := 0;
      User_Addr : Unsigned_64 := 0;
   end record
     with Convention => C, Size => 40 * 8;
   for SQ_Offsets use record
      Head         at  0 range 0 .. 31;
      Tail         at  4 range 0 .. 31;
      Ring_Mask    at  8 range 0 .. 31;
      Ring_Entries at 12 range 0 .. 31;
      Flags        at 16 range 0 .. 31;
      Dropped      at 20 range 0 .. 31;
      Array_Off    at 24 range 0 .. 31;
      Resv1        at 28 range 0 .. 31;
      User_Addr    at 32 range 0 .. 63;
   end record;

   type CQ_Offsets is record
      Head, Tail, Ring_Mask, Ring_Entries, Overflow, CQEs, Flags, Resv1 : Unsigned_32 := 0;
      User_Addr : Unsigned_64 := 0;
   end record
     with Convention => C, Size => 40 * 8;
   for CQ_Offsets use record
      Head         at  0 range 0 .. 31;
      Tail         at  4 range 0 .. 31;
      Ring_Mask    at  8 range 0 .. 31;
      Ring_Entries at 12 range 0 .. 31;
      Overflow     at 16 range 0 .. 31;
      CQEs         at 20 range 0 .. 31;
      Flags        at 24 range 0 .. 31;
      Resv1        at 28 range 0 .. 31;
      User_Addr    at 32 range 0 .. 63;
   end record;

   type Resv3 is array (1 .. 3) of Unsigned_32 with Convention => C;

   --  struct io_uring_params, 120 bytes.
   type Params is record
      SQ_Entries     : Unsigned_32 := 0;
      CQ_Entries     : Unsigned_32 := 0;
      Flags          : Unsigned_32 := 0;
      SQ_Thread_CPU  : Unsigned_32 := 0;
      SQ_Thread_Idle : Unsigned_32 := 0;
      Features       : Unsigned_32 := 0;
      WQ_FD          : Unsigned_32 := 0;
      Resv           : Resv3 := [others => 0];
      SQ_Off         : SQ_Offsets;
      CQ_Off         : CQ_Offsets;
   end record
     with Convention => C, Size => 120 * 8;
   for Params use record
      SQ_Entries     at  0 range 0 .. 31;
      CQ_Entries     at  4 range 0 .. 31;
      Flags          at  8 range 0 .. 31;
      SQ_Thread_CPU  at 12 range 0 .. 31;
      SQ_Thread_Idle at 16 range 0 .. 31;
      Features       at 20 range 0 .. 31;
      WQ_FD          at 24 range 0 .. 31;
      Resv           at 28 range 0 .. 95;
      SQ_Off         at 40 range 0 .. 319;
      CQ_Off         at 80 range 0 .. 319;
   end record;

   --  struct __kernel_timespec, for IORING_OP_TIMEOUT.
   type Kernel_Timespec is record
      Sec  : Integer_64 := 0;
      Nsec : Integer_64 := 0;
   end record
     with Convention => C;

   ----------------------------------------------------------------------------
   --  A ring
   ----------------------------------------------------------------------------

   type Ring is limited private;

   --  Set up a ring of at least Entries submission entries (a power of two;
   --  the kernel clamps it) and twice as many completion entries. Flags are
   --  IORING_SETUP_* bits beyond the CLAMP this always sets. OK = False if
   --  the kernel refuses (no io_uring, or it is disabled by sysctl).
   procedure Setup (R : in out Ring; Entries : Unsigned_32; Flags : Unsigned_32; OK : out Boolean);

   function Is_Set_Up (R : Ring) return Boolean;
   function FD (R : Ring) return Interfaces.C.int;

   --  The next free submission entry, zeroed, or null when the queue is
   --  full (submit first). Fill it with one of the Prep_ procedures; it is
   --  sent on the next Submit.
   type SQE_Access is access all SQE;
   function Get_SQE (R : in out Ring) return SQE_Access;

   --  Hand the prepared entries to the kernel and, if Wait_Nr > 0, block
   --  until at least that many completions are ready. Result is the number
   --  submitted, or a negative errno (-EINTR when a signal cut the wait
   --  short, which is harmless).
   procedure Submit (R : in out Ring; Wait_Nr : Unsigned_32; Result : out Integer);

   --  Take the next completion, if any. A taken completion is consumed:
   --  its slot goes back to the kernel at once.
   procedure Next_CQE (R : in out Ring; C : out CQE; Found : out Boolean);

   procedure Close (R : in out Ring);

   ----------------------------------------------------------------------------
   --  Preparing entries
   ----------------------------------------------------------------------------

   --  Accept one connection: Res = its fd. A server that submits one only
   --  while it has room for another connection admits exactly what it can
   --  serve (a multishot accept would keep accepting after it filled up).
   procedure Prep_Accept (E : SQE_Access; Listen_FD : Interfaces.C.int; Data : Unsigned_64);

   --  shutdown(2) on Sock (How = SHUT_RDWR etc.): requests in flight on it
   --  complete, a receive with Res = 0.
   procedure Prep_Shutdown (E : SQE_Access; Sock : Interfaces.C.int; How : Unsigned_32; Data : Unsigned_64);

   --  Receive up to Len bytes into Buf. The memory must stay put until the
   --  CQE arrives; Res = bytes received (0 = end of stream).
   procedure Prep_Recv
     (E : SQE_Access; Sock : Interfaces.C.int; Buf : System.Address; Len : Unsigned_32;
      Data : Unsigned_64);

   --  Send Len bytes starting at Buf. The memory must stay put until the
   --  CQE arrives; Res = bytes sent (possibly fewer than Len).
   procedure Prep_Send
     (E : SQE_Access; Sock : Interfaces.C.int; Buf : System.Address; Len : Unsigned_32;
      Data : Unsigned_64);

   --  Cancel every request on Sock (e.g. its multishot receive).
   procedure Prep_Cancel_FD (E : SQE_Access; Sock : Interfaces.C.int; Data : Unsigned_64);

   --  Cancel the request submitted with user data Target.
   procedure Prep_Cancel (E : SQE_Access; Target : Unsigned_64; Data : Unsigned_64);

   --  A timeout that completes every TS (multishot: Count = 0 repeats until
   --  cancelled). TS must stay put while the timeout is armed.
   procedure Prep_Periodic_Timeout (E : SQE_Access; TS : access constant Kernel_Timespec; Data : Unsigned_64);

private

   use type Interfaces.C.int;

   type Ring is limited record
      Ring_FD   : Interfaces.C.int := -1;
      --  Mapped regions: the SQ ring (which is also the CQ ring with
      --  FEAT_SINGLE_MMAP), the CQ ring when separate, and the SQE array.
      SQ_Map, CQ_Map, SQE_Map       : System.Address := System.Null_Address;
      SQ_Map_Len, CQ_Map_Len, SQE_Map_Len : Interfaces.C.size_t := 0;
      --  Kernel-shared words and arrays inside the maps.
      SQ_Head, SQ_Tail, SQ_Mask, SQ_Array : System.Address := System.Null_Address;
      CQ_Head, CQ_Tail, CQ_Mask, CQ_CQEs  : System.Address := System.Null_Address;
      SQEs      : System.Address := System.Null_Address;
      SQ_Size   : Unsigned_32 := 0;
      --  Our side of the SQ: entries handed out by Get_SQE but not yet
      --  published to the kernel's tail.
      Local_Tail : Unsigned_32 := 0;
      Published  : Unsigned_32 := 0;   --  the tail the kernel has been given
   end record;

end IO_Uring;
