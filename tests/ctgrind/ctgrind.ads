--  Ada wrapper around the Valgrind client-request shim in
--  ctgrind_helpers.c. See that file for the design rationale.
--
--  Workflow:
--     1. Allocate a buffer holding key material on the stack.
--     2. Mark it via Make_Undefined.
--     3. Call the crypto primitive that reads the buffer.
--     4. Pass the public output through Use_Output so the optimizer
--        can't eliminate the call as dead code.
--     5. Run the test binary under "valgrind --tool=memcheck
--        --error-exitcode=1". A non-zero exit means valgrind found
--        a secret-dependent branch or memory access — i.e. a
--        constant-time bug.
--
--  Outside of valgrind these calls are essentially no-ops (the
--  Valgrind macros short-circuit when running on bare metal), so
--  the harness can be run as a regular test too.

with Interfaces.C;
with System;

package Ctgrind is

   procedure Make_Undefined
     (Addr : System.Address;
      Size : Interfaces.C.size_t)
     with Import, Convention => C,
          External_Name => "ctgrind_make_undefined";

   procedure Make_Defined
     (Addr : System.Address;
      Size : Interfaces.C.size_t)
     with Import, Convention => C,
          External_Name => "ctgrind_make_defined";

   procedure Use_Output
     (Addr : System.Address;
      Size : Interfaces.C.size_t)
     with Import, Convention => C,
          External_Name => "ctgrind_use";

end Ctgrind;
