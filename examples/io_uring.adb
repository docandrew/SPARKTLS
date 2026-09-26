with System.Address_To_Access_Conversions;
with System.Storage_Elements; use System.Storage_Elements;

package body IO_Uring is

   use type System.Address;
   use type Interfaces.C.long;
   use type Interfaces.C.size_t;

   ----------------------------------------------------------------------------
   --  System calls and memory
   ----------------------------------------------------------------------------

   NR_io_uring_setup : constant := 425;   --  x86_64 and aarch64 share these
   NR_io_uring_enter : constant := 426;

   --  glibc's syscall(2) is variadic: C_Variadic_1 passes the arguments after
   --  the first the way a variadic callee expects them.
   function Syscall
     (Number : Interfaces.C.long;
      A1, A2, A3, A4, A5, A6 : Interfaces.C.long := 0) return Interfaces.C.long
     with Import, Convention => C_Variadic_1, External_Name => "syscall";

   function Errno_Location return access Interfaces.C.int
     with Import, Convention => C, External_Name => "__errno_location";

   --  syscall(2) returns -1 and sets errno; the kernel's own convention,
   --  -errno, is simpler to pass on.
   function Checked (Ret : Interfaces.C.long) return Interfaces.C.long is
     (if Ret = -1 then -Interfaces.C.long (Errno_Location.all) else Ret);

   function Mmap
     (Addr : System.Address; Len : Interfaces.C.size_t; Prot, Flags : Interfaces.C.int;
      FD : Interfaces.C.int; Off : Interfaces.C.long) return System.Address
     with Import, Convention => C, External_Name => "mmap";

   function Munmap (Addr : System.Address; Len : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C, External_Name => "munmap";

   function C_Close (FD : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "close";

   PROT_READ     : constant := 1;
   PROT_WRITE    : constant := 2;
   MAP_SHARED    : constant := 16#01#;
   MAP_POPULATE  : constant := 16#8000#;
   MAP_FAILED    : constant System.Address := To_Address (Integer_Address'Last);   --  (void *) -1

   ----------------------------------------------------------------------------
   --  Ordering. The kernel reads what we write to the rings, and we read what
   --  it writes, from other CPUs. An index we publish (SQ tail, CQ head) is
   --  a release store, so the entries it covers are visible first; an index the kernel publishes (SQ head, CQ tail) is an
   --  acquire load, so the entries it covers are read after it. These are
   --  GCC's __atomic builtins with memory models 2 (acquire) and 3 (release).
   ----------------------------------------------------------------------------

   Acquire : constant := 2;
   Release : constant := 3;

   function Load_32 (Ptr : System.Address; Model : Integer) return Unsigned_32
     with Import, Convention => Intrinsic, External_Name => "__atomic_load_4";
   procedure Store_32 (Ptr : System.Address; Val : Unsigned_32; Model : Integer)
     with Import, Convention => Intrinsic, External_Name => "__atomic_store_4";

   --  Plain access to kernel-shared words and entries.
   package U32_Conv is new System.Address_To_Access_Conversions (Unsigned_32);
   package SQE_Conv is new System.Address_To_Access_Conversions (SQE);
   package CQE_Conv is new System.Address_To_Access_Conversions (CQE);

   function Word (A : System.Address) return Unsigned_32 is (U32_Conv.To_Pointer (A).all);

   ----------------------------------------------------------------------------
   --  Ring
   ----------------------------------------------------------------------------

   procedure Setup (R : in out Ring; Entries : Unsigned_32; Flags : Unsigned_32; OK : out Boolean) is
      P      : aliased Params;
      Ret    : Interfaces.C.long;
      SQ_Len, CQ_Len : Interfaces.C.size_t;
   begin
      OK := False;
      P.Flags := IORING_SETUP_CLAMP or Flags;
      Ret := Checked (Syscall (NR_io_uring_setup, Interfaces.C.long (Entries),
                               Interfaces.C.long (To_Integer (P'Address))));
      if Ret < 0 then
         return;
      end if;
      R.Ring_FD := Interfaces.C.int (Ret);

      --  The SQ ring ends with the index array, the CQ ring with the CQEs.
      SQ_Len := Interfaces.C.size_t (P.SQ_Off.Array_Off) + Interfaces.C.size_t (P.SQ_Entries) * 4;
      CQ_Len := Interfaces.C.size_t (P.CQ_Off.CQEs) + Interfaces.C.size_t (P.CQ_Entries) * 16;
      if (P.Features and IORING_FEAT_SINGLE_MMAP) /= 0 then
         SQ_Len := Interfaces.C.size_t'Max (SQ_Len, CQ_Len);
      end if;

      R.SQ_Map := Mmap (System.Null_Address, SQ_Len, PROT_READ + PROT_WRITE,
                        MAP_SHARED + MAP_POPULATE, R.Ring_FD, IORING_OFF_SQ_RING);
      if R.SQ_Map = MAP_FAILED then
         R.SQ_Map := System.Null_Address;
         Close (R);
         return;
      end if;
      R.SQ_Map_Len := SQ_Len;

      if (P.Features and IORING_FEAT_SINGLE_MMAP) /= 0 then
         R.CQ_Map := R.SQ_Map;
      else
         R.CQ_Map := Mmap (System.Null_Address, CQ_Len, PROT_READ + PROT_WRITE,
                           MAP_SHARED + MAP_POPULATE, R.Ring_FD, IORING_OFF_CQ_RING);
         if R.CQ_Map = MAP_FAILED then
            R.CQ_Map := System.Null_Address;
            Close (R);
            return;
         end if;
         R.CQ_Map_Len := CQ_Len;
      end if;

      R.SQE_Map_Len := Interfaces.C.size_t (P.SQ_Entries) * 64;
      R.SQE_Map := Mmap (System.Null_Address, R.SQE_Map_Len, PROT_READ + PROT_WRITE,
                         MAP_SHARED + MAP_POPULATE, R.Ring_FD, IORING_OFF_SQES);
      if R.SQE_Map = MAP_FAILED then
         R.SQE_Map := System.Null_Address;
         Close (R);
         return;
      end if;

      R.SQ_Head  := R.SQ_Map + Storage_Offset (P.SQ_Off.Head);
      R.SQ_Tail  := R.SQ_Map + Storage_Offset (P.SQ_Off.Tail);
      R.SQ_Mask  := R.SQ_Map + Storage_Offset (P.SQ_Off.Ring_Mask);
      R.SQ_Array := R.SQ_Map + Storage_Offset (P.SQ_Off.Array_Off);
      R.CQ_Head  := R.CQ_Map + Storage_Offset (P.CQ_Off.Head);
      R.CQ_Tail  := R.CQ_Map + Storage_Offset (P.CQ_Off.Tail);
      R.CQ_Mask  := R.CQ_Map + Storage_Offset (P.CQ_Off.Ring_Mask);
      R.CQ_CQEs  := R.CQ_Map + Storage_Offset (P.CQ_Off.CQEs);
      R.SQEs     := R.SQE_Map;
      R.SQ_Size  := P.SQ_Entries;
      R.Local_Tail := Word (R.SQ_Tail);
      R.Published  := R.Local_Tail;

      --  The index array maps ring position to SQE; SQE i always sits at
      --  position i here, so the identity map is written once.
      for I in 0 .. P.SQ_Entries - 1 loop
         U32_Conv.To_Pointer (R.SQ_Array + Storage_Offset (I * 4)).all := I;
      end loop;
      OK := True;
   end Setup;

   function Is_Set_Up (R : Ring) return Boolean is (R.Ring_FD >= 0);
   function FD (R : Ring) return Interfaces.C.int is (R.Ring_FD);

   function Get_SQE (R : in out Ring) return SQE_Access is
      Head : constant Unsigned_32 := Load_32 (R.SQ_Head, Acquire);
   begin
      if R.Local_Tail - Head >= R.SQ_Size then
         return null;
      end if;
      declare
         Index : constant Unsigned_32 := R.Local_Tail and Word (R.SQ_Mask);
         E     : constant SQE_Access :=
           SQE_Access (SQE_Conv.To_Pointer (R.SQEs + Storage_Offset (Index * 64)));
      begin
         E.all := (others => <>);
         R.Local_Tail := R.Local_Tail + 1;
         return E;
      end;
   end Get_SQE;

   procedure Submit (R : in out Ring; Wait_Nr : Unsigned_32; Result : out Integer) is
      To_Submit : constant Unsigned_32 := R.Local_Tail - R.Published;
      Ret       : Interfaces.C.long;
   begin
      if To_Submit > 0 then
         Store_32 (R.SQ_Tail, R.Local_Tail, Release);
         R.Published := R.Local_Tail;
      end if;
      if To_Submit = 0 and then Wait_Nr = 0 then
         Result := 0;
         return;
      end if;
      Ret := Checked (Syscall (NR_io_uring_enter, Interfaces.C.long (R.Ring_FD),
                               Interfaces.C.long (To_Submit), Interfaces.C.long (Wait_Nr),
                               (if Wait_Nr > 0 then IORING_ENTER_GETEVENTS else 0), 0, 0));
      Result := Integer (Ret);
   end Submit;

   procedure Next_CQE (R : in out Ring; C : out CQE; Found : out Boolean) is
      Head : constant Unsigned_32 := Word (R.CQ_Head);
      Tail : constant Unsigned_32 := Load_32 (R.CQ_Tail, Acquire);
   begin
      if Head = Tail then
         C := (others => <>);
         Found := False;
         return;
      end if;
      C := CQE_Conv.To_Pointer (R.CQ_CQEs + Storage_Offset ((Head and Word (R.CQ_Mask)) * 16)).all;
      Store_32 (R.CQ_Head, Head + 1, Release);
      Found := True;
   end Next_CQE;

   procedure Close (R : in out Ring) is
      Dummy : Interfaces.C.int;
   begin
      if R.SQE_Map /= System.Null_Address then
         Dummy := Munmap (R.SQE_Map, R.SQE_Map_Len);
      end if;
      if R.CQ_Map /= System.Null_Address and then R.CQ_Map /= R.SQ_Map then
         Dummy := Munmap (R.CQ_Map, R.CQ_Map_Len);
      end if;
      if R.SQ_Map /= System.Null_Address then
         Dummy := Munmap (R.SQ_Map, R.SQ_Map_Len);
      end if;
      if R.Ring_FD >= 0 then
         Dummy := C_Close (R.Ring_FD);
      end if;
      R.Ring_FD := -1;
      R.SQ_Map := System.Null_Address;
      R.CQ_Map := System.Null_Address;
      R.SQE_Map := System.Null_Address;
      R.SQ_Map_Len := 0;
      R.CQ_Map_Len := 0;
      R.SQE_Map_Len := 0;
      R.SQ_Size := 0;
      R.Local_Tail := 0;
      R.Published := 0;
   end Close;

   ----------------------------------------------------------------------------
   --  Preparing entries
   ----------------------------------------------------------------------------

   procedure Prep_Accept (E : SQE_Access; Listen_FD : Interfaces.C.int; Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_ACCEPT;
      E.FD        := Integer_32 (Listen_FD);
      E.User_Data := Data;
   end Prep_Accept;

   procedure Prep_Shutdown (E : SQE_Access; Sock : Interfaces.C.int; How : Unsigned_32; Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_SHUTDOWN;
      E.FD        := Integer_32 (Sock);
      E.Len       := How;
      E.User_Data := Data;
   end Prep_Shutdown;

   procedure Prep_Recv
     (E : SQE_Access; Sock : Interfaces.C.int; Buf : System.Address; Len : Unsigned_32;
      Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_RECV;
      E.FD        := Integer_32 (Sock);
      E.Addr      := Unsigned_64 (To_Integer (Buf));
      E.Len       := Len;
      E.User_Data := Data;
   end Prep_Recv;

   procedure Prep_Send
     (E : SQE_Access; Sock : Interfaces.C.int; Buf : System.Address; Len : Unsigned_32;
      Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_SEND;
      E.FD        := Integer_32 (Sock);
      E.Addr      := Unsigned_64 (To_Integer (Buf));
      E.Len       := Len;
      E.User_Data := Data;
   end Prep_Send;

   procedure Prep_Cancel_FD (E : SQE_Access; Sock : Interfaces.C.int; Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_ASYNC_CANCEL;
      E.FD        := Integer_32 (Sock);
      E.Op_Flags  := IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_ALL;
      E.User_Data := Data;
   end Prep_Cancel_FD;

   procedure Prep_Cancel (E : SQE_Access; Target : Unsigned_64; Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_ASYNC_CANCEL;
      E.Addr      := Target;
      E.User_Data := Data;
   end Prep_Cancel;

   procedure Prep_Periodic_Timeout (E : SQE_Access; TS : access constant Kernel_Timespec; Data : Unsigned_64) is
   begin
      E.Opcode    := IORING_OP_TIMEOUT;
      E.Addr      := Unsigned_64 (To_Integer (TS.all'Address));
      E.Len       := 1;
      E.Off       := 0;   --  completion count: 0 = repeat until cancelled
      E.Op_Flags  := IORING_TIMEOUT_MULTISHOT;
      E.User_Data := Data;
   end Prep_Periodic_Timeout;

end IO_Uring;
