--  dudect timing-test on the AEAD encrypt path.
--
--  Built against the OPTIMIZE library, so this exercises the actual
--  production asm: AVX-512 ChaCha20 + IFMA Poly1305 (or AES-NI +
--  PCLMULQDQ for AES-GCM). ctgrind doesn't see those paths because
--  CPUID lies in ctgrind-mode build. dudect against optimize is the
--  only mechanical way to catch a CT regression in the asm itself.
--
--  Expectation: |t| < 4.5. The asm is branch-free SIMD math by
--  inspection so this should hold easily, but proving it with a
--  test is the right hygiene.

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Core;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with Dudect_Helpers;

procedure Dudect_AEAD is
   M     : aliased Byte_Seq (0 .. 4095) := (others => 16#AA#);
   AAD   : aliased Byte_Seq (0 .. 15)   := (others => 16#BB#);
   N_Bytes : constant Bytes_12 :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
      16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);
   Nonce : SPARKNaCl.Core.ChaCha20_IETF_Nonce := N_Bytes;

   --  Two distinct keys to compare timing across.
   K0_Bytes : constant Bytes_32 := (others => 16#00#);
   K1_Bytes : constant Bytes_32 := (others => 16#FF#);
   K0, K1   : SPARKNaCl.Core.ChaCha20_Key;

   C   : aliased Byte_Seq (0 .. 4095);
   Tag : Bytes_16;

   procedure Sub_0 is
   begin
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
        (C => C, Tag => Tag, M => M, N => Nonce, K => K0, AAD => AAD);
   end Sub_0;

   procedure Sub_1 is
   begin
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
        (C => C, Tag => Tag, M => M, N => Nonce, K => K1, AAD => AAD);
   end Sub_1;
begin
   SPARKNaCl.Core.Construct (K0, K0_Bytes);
   SPARKNaCl.Core.Construct (K1, K1_Bytes);
   Dudect_Helpers.Time_Test
     (Name      =>
        "ChaCha20-Poly1305 Encrypt 4KiB (K=zeros vs K=ones, opt build)",
      Subject_0 => Sub_0'Access,
      Subject_1 => Sub_1'Access,
      N         => 2_000);
end Dudect_AEAD;
