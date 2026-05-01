--  Negative control / harness self-test.
--
--  Deliberately writes a function with a SECRET-DEPENDENT BRANCH:
--    if Key (0) > 127 then ... else ... end if;
--  Marks Key as undefined and calls the function. Valgrind/memcheck
--  MUST report a "use of uninitialised value" error. If it doesn't,
--  our harness plumbing is broken (Make_Undefined isn't taking
--  effect, or the compiler optimized the branch away).
--
--  Use this whenever changing the harness or build flags to confirm
--  the analysis machinery is still wired up correctly.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with SPARKNaCl;   use SPARKNaCl;
with Ctgrind;

procedure Ct_Negative_Control is
   Key  : Bytes_32 := (others => 16#42#);
   Sink : Natural  := 0;

   --  Deliberately leaky: secret-dependent branch AND secret-
   --  dependent array index. Either should trip memcheck. The array
   --  lookup is harder for the compiler to eliminate via conditional-
   --  move, so it's the more reliable canary.
   Lookup_Table : constant array (0 .. 255) of Natural :=
     (others => 7);  -- contents don't matter

   procedure Leaky (K : Bytes_32; Sink : in out Natural) is
      Idx : constant Natural := Natural (K (0));
   begin
      if Interfaces.">" (K (0), 127) then
         Sink := Sink + 1;
      else
         Sink := Sink + 2;
      end if;
      Sink := Sink + Lookup_Table (Idx);
   end Leaky;

begin
   Ctgrind.Make_Undefined
     (Key'Address, Interfaces.C.size_t (Key'Length));

   Leaky (Key, Sink);

   Ctgrind.Make_Defined
     (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));
   Ctgrind.Use_Output
     (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));

   --  This program SHOULD trigger a memcheck error. If valgrind
   --  reports 0 errors here, the harness is broken.
   Put_Line ("ct_negative_control: ran leaky function (sink=" & Sink'Image
             & ")");
   Put_Line ("  EXPECTED: 'use of uninitialised value' error from valgrind.");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Negative_Control;
