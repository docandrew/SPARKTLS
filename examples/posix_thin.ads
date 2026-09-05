--  Thin POSIX bindings for socket/epoll operations.
--  Used by the async TLS examples. Not SPARK.

with System;
with Interfaces.C;       use Interfaces.C;

package POSIX_Thin is
   pragma Preelaborate;

   --  Socket constants
   AF_INET        : constant := 2;
   SOCK_STREAM    : constant := 1;
   SOCK_NONBLOCK  : constant := 2048;
   SOL_SOCKET     : constant := 1;
   SO_REUSEADDR   : constant := 2;
   IPPROTO_TCP    : constant := 6;

   --  epoll constants
   EPOLLIN        : constant := 16#001#;
   EPOLLOUT       : constant := 16#004#;
   EPOLLET        : constant := 16#80000000#;
   EPOLL_CTL_ADD  : constant := 1;
   EPOLL_CTL_DEL  : constant := 2;
   EPOLL_CTL_MOD  : constant := 3;

   --  sockaddr_in (IPv4)
   type Sockaddr_In is record
      Sin_Family : unsigned_short := unsigned_short (AF_INET);
      Sin_Port   : unsigned_short := 0;
      Sin_Addr   : unsigned       := 0;
      Sin_Zero   : String (1 .. 8) := (others => ASCII.NUL);
   end record;
   pragma Convention (C, Sockaddr_In);

   --  epoll_event
   --  The C epoll_data_t is an 8-byte union (u64/ptr/etc.). We only
   --  use the fd member but must occupy the full 8 bytes or the array
   --  stride will mismatch the kernel's and we'll read garbage after
   --  index 0 (and the kernel will write past our Events array).
   type Epoll_Data is record
      FD      : int := 0;
      Padding : int := 0;
   end record;
   pragma Convention (C, Epoll_Data);

   --  On x86_64 glibc, struct epoll_event is __attribute__((packed))
   --  so the total size is 12 bytes (4 events + 8 data), not 16.
   type Epoll_Event is record
      Events : unsigned := 0;
      Data   : Epoll_Data;
   end record;
   pragma Convention (C, Epoll_Event);
   pragma Pack (Epoll_Event);

   type Epoll_Event_Array is array (Natural range <>) of Epoll_Event;
   pragma Convention (C, Epoll_Event_Array);

   --  Socket functions
   function C_Socket (Domain, Typ, Protocol : int) return int;
   pragma Import (C, C_Socket, "socket");

   function C_Bind (FD : int; Addr : access Sockaddr_In;
                    Len : int) return int;
   pragma Import (C, C_Bind, "bind");

   function C_Listen (FD : int; Backlog : int) return int;
   pragma Import (C, C_Listen, "listen");

   function C_Accept4 (FD : int; Addr : access Sockaddr_In;
                       Len : access int; Flags : int) return int;
   pragma Import (C, C_Accept4, "accept4");

   function C_Setsockopt (FD, Level, Opt : int;
                          Val : access int; Len : int) return int;
   pragma Import (C, C_Setsockopt, "setsockopt");

   function C_Read (FD : int; Buf : System.Address;
                    Count : size_t) return long;
   pragma Import (C, C_Read, "read");

   function C_Write (FD : int; Buf : System.Address;
                     Count : size_t) return long;
   pragma Import (C, C_Write, "write");

   function C_Close (FD : int) return int;
   pragma Import (C, C_Close, "close");

   --  glibc exposes errno via a thread-local int pointer.
   type Int_Ptr is access all int;
   function Errno_Location return Int_Ptr;
   pragma Import (C, Errno_Location, "__errno_location");

   --  Byte order
   function Htons (X : unsigned_short) return unsigned_short;
   pragma Import (C, Htons, "htons");

   --  epoll functions
   function Epoll_Create1 (Flags : int) return int;
   pragma Import (C, Epoll_Create1, "epoll_create1");

   function Epoll_Ctl (Epfd : int; Op : int; FD : int;
                       Event : access Epoll_Event) return int;
   pragma Import (C, Epoll_Ctl, "epoll_ctl");

   function Epoll_Wait (Epfd : int; Events : access Epoll_Event;
                        Max : int; Timeout : int) return int;
   pragma Import (C, Epoll_Wait, "epoll_wait");

   --  fcntl for non-blocking
   F_GETFL : constant := 3;
   F_SETFL : constant := 4;
   O_NONBLOCK : constant := 2048;

   function Fcntl2 (FD : int; Cmd : int) return int;
   pragma Import (C, Fcntl2, "fcntl");

   function Fcntl3 (FD : int; Cmd : int; Arg : int) return int;
   pragma Import (C, Fcntl3, "fcntl");

end POSIX_Thin;
