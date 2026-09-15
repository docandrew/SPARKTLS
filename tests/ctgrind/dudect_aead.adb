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

with Interfaces;      use type Interfaces.Unsigned_8;
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

   C   : aliased Byte_Seq (0 .. 4095);
   Tag : Bytes_16;

   --  dudect shape (see Dudect_Helpers): Prepare selects the class's
   --  key into the shared Cur buffer untimed, and the timed Subject is
   --  one subprogram reading one address for both classes. The class
   --  Boolean is consumed as a mask, never branched on, so the two
   --  classes run one instruction stream on one set of addresses and
   --  only the key bytes differ. That matters at this subject's cost:
   --  ~5K cycles per call at n = 20K puts the standard error near 0.3
   --  cycles, and two subject closures (two code addresses, two key
   --  objects) read t up to ~12 with IDENTICAL keys on a quiet box.
   Cur : SPARKNaCl.Core.ChaCha20_Key;
   procedure Prep (Second : Boolean) is
      Mask : constant Byte := Byte (Boolean'Pos (Second)) * Byte'Last;
      KB   : Bytes_32;
   begin
      for I in KB'Range loop
         KB (I) := (K0_Bytes (I) and not Mask) or (K1_Bytes (I) and Mask);
      end loop;
      SPARKNaCl.Core.Construct (Cur, KB);
   end Prep;
   procedure Encrypt_Cur is
   begin
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
        (C => C, Tag => Tag, M => M, N => Nonce, K => Cur, AAD => AAD);
   end Encrypt_Cur;
begin
   Dudect_Helpers.Time_Test
     (Name      =>
        "ChaCha20-Poly1305 Encrypt 4KiB (K=zeros vs K=ones, opt build)",
      Prepare   => Prep'Access,
      Subject   => Encrypt_Cur'Access,
      N         => 20_000);   --  ~5 us per call: 10x the sample of the EC harnesses
end Dudect_AEAD;
