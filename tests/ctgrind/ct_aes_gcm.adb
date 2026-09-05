--  Constant-time check for AES-128-GCM and AES-256-GCM.
--
--  Under the ctgrind build the AES-NI / AVX-512 dispatch flags are
--  off (CPUID lies under valgrind), so this exercises the SCALAR
--  software AES + GHASH paths in SPARKNaCl. Those are the highest
--  side-channel risk (T-table style scalar AES famously leaks
--  through cache-timing). The asm-only paths are constant-time by
--  construction (branch-free, no data-dependent loads) and don't
--  run under valgrind, so they're vetted by inspection.
--
--  Marks the AES key as undefined and runs the encrypt path. Any
--  branch / memory access whose target depends on the key trips
--  memcheck.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;
with Ctgrind;

procedure Ct_AES_GCM is
   M  : Byte_Seq (0 .. 1023) := (others => 16#AA#);
   AAD : constant Byte_Seq (0 .. 15) := (others => 16#BB#);
   N  : constant Bytes_12 :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
      16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);

   --  AES-128 path
   K128_Bytes : Bytes_16 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#);
   K128       : SPARKNaCl.AES.AES128_Key;
   C128       : Byte_Seq (0 .. 1023);
   Tag128     : Bytes_16;

   --  AES-256 path
   K256_Bytes : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
   K256       : SPARKNaCl.AES.AES256_Key;
   C256       : Byte_Seq (0 .. 1023);
   Tag256     : Bytes_16;
begin
   --  AES-128-GCM
   Ctgrind.Make_Undefined
     (K128_Bytes'Address, Interfaces.C.size_t (K128_Bytes'Length));
   SPARKNaCl.AES.Construct (K128, K128_Bytes);
   SPARKTLSCrypto.AES_GCM.Encrypt
     (C => C128, Tag => Tag128, M => M, N => N, K => K128, AAD => AAD);
   Ctgrind.Make_Defined (C128'Address, Interfaces.C.size_t (C128'Length));
   Ctgrind.Make_Defined (Tag128'Address, Interfaces.C.size_t (Tag128'Length));
   Ctgrind.Use_Output (C128'Address, Interfaces.C.size_t (C128'Length));
   Ctgrind.Use_Output (Tag128'Address, Interfaces.C.size_t (Tag128'Length));

   --  AES-256-GCM
   Ctgrind.Make_Undefined
     (K256_Bytes'Address, Interfaces.C.size_t (K256_Bytes'Length));
   SPARKNaCl.AES.Construct (K256, K256_Bytes);
   SPARKTLSCrypto.AES_GCM.Encrypt_256
     (C => C256, Tag => Tag256, M => M, N => N, K => K256, AAD => AAD);
   Ctgrind.Make_Defined (C256'Address, Interfaces.C.size_t (C256'Length));
   Ctgrind.Make_Defined (Tag256'Address, Interfaces.C.size_t (Tag256'Length));
   Ctgrind.Use_Output (C256'Address, Interfaces.C.size_t (C256'Length));
   Ctgrind.Use_Output (Tag256'Address, Interfaces.C.size_t (Tag256'Length));

   Put_Line ("ct_aes_gcm: AES-128 and AES-256 GCM Encrypt completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_AES_GCM;
