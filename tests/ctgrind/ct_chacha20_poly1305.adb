--  Constant-time check for ChaCha20-Poly1305 AEAD.
--
--  Marks the ChaCha20 key as "uninitialised" via Valgrind, then
--  encrypts a fixed plaintext. Under "valgrind --tool=memcheck" any
--  branch or memory access whose target depends on the key bytes
--  will raise "use of uninitialised value", indicating a constant-
--  time bug somewhere in the chain (Onetimeauth, AVX-512 ChaCha20,
--  Gen_Auth_Msg, or the AEAD glue).
--
--  Outside valgrind the Make_Undefined / Use_Output calls are
--  effective no-ops, so this also runs as a smoke test of the
--  encryption path.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Core;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with Ctgrind;

procedure Ct_Chacha20_Poly1305 is
   --  Plaintext and AAD are fixed/non-secret.
   M       : Byte_Seq (0 .. 1023) := (others => 16#AA#);
   AAD     : Byte_Seq (0 .. 15)   := (others => 16#BB#);

   --  Nonce is public.
   Nonce_Bytes : constant Bytes_12 :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
      16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);
   Nonce : SPARKNaCl.Core.ChaCha20_IETF_Nonce := Nonce_Bytes;

   --  Key is the SECRET. We mark it undefined for valgrind, then
   --  call the AEAD with it.
   K_Bytes : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
   K : SPARKNaCl.Core.ChaCha20_Key;

   C   : Byte_Seq (0 .. 1023);
   Tag : Bytes_16;
begin
   --  Mark key bytes as undefined (= "secret") for memcheck.
   Ctgrind.Make_Undefined
     (K_Bytes'Address, Interfaces.C.size_t (K_Bytes'Length));
   SPARKNaCl.Core.Construct (K, K_Bytes);

   SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
     (C => C, Tag => Tag, M => M, N => Nonce, K => K, AAD => AAD);

   --  The output IS public — re-mark as defined so we can read it
   --  without tripping memcheck on legitimate output use.
   Ctgrind.Make_Defined (C'Address, Interfaces.C.size_t (C'Length));
   Ctgrind.Make_Defined (Tag'Address, Interfaces.C.size_t (Tag'Length));

   --  Force the optimizer to keep the call.
   Ctgrind.Use_Output (C'Address, Interfaces.C.size_t (C'Length));
   Ctgrind.Use_Output (Tag'Address, Interfaces.C.size_t (Tag'Length));

   Put_Line ("ct_chacha20_poly1305: encryption completed");
   Put_Line ("  (run under valgrind --tool=memcheck to check for"
             & " secret-dependent branches)");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Chacha20_Poly1305;
