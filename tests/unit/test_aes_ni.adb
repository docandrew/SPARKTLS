--  AES-NI hardware path: NIST KAT vectors + equivalence with the
--  formally-proven SPARKNaCl software AES.
--
--  Test 1: FIPS 197 Appendix C.1 (AES-128) and C.3 (AES-256)
--          known-answer vectors.
--  Test 2: 1024 random key/plaintext pairs — confirm AES_NI.Cipher
--          and AES.Cipher (software) produce byte-identical output.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;

procedure Test_AES_NI is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
      else
         Fail := Fail + 1;
         Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   function Hex (B : Byte) return String is
      H : constant String := "0123456789abcdef";
      Hi : constant Natural := Natural (Shift_Right (Unsigned_8 (B), 4));
      Lo : constant Natural := Natural (Unsigned_8 (B) and 16#0F#);
   begin
      return H (Hi + 1) & H (Lo + 1);
   end Hex;

   function Hex (X : Bytes_16) return String is
      R : String (1 .. 32);
      P : Natural := 1;
   begin
      for I in X'Range loop
         R (P .. P + 1) := Hex (X (I));
         P := P + 2;
      end loop;
      return R;
   end Hex;

   --  Trivial xorshift PRNG so the equivalence test is deterministic
   --  but sweeps a wide input space.
   State : Unsigned_64 := 16#1234_5678_9abc_def0#;
   function Rand_Byte return Byte is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 7);
      State := State xor Shift_Left (State, 17);
      return Byte (State and 16#FF#);
   end Rand_Byte;

   procedure Fill_16 (B : out Bytes_16) is
   begin
      for I in B'Range loop B (I) := Rand_Byte; end loop;
   end Fill_16;
   procedure Fill_32 (B : out Bytes_32) is
   begin
      for I in B'Range loop B (I) := Rand_Byte; end loop;
   end Fill_32;

begin
   Put_Line ("AES-NI tests");
   Put_Line ("============");
   Put ("CPUID AES-NI: ");
   Put_Line (Boolean'Image (SPARKTLSCrypto.AES_NI.Has_AESNI));

   if not SPARKTLSCrypto.AES_NI.Has_AESNI then
      Put_Line ("SKIP: this CPU does not advertise AES-NI");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   --================================================================
   --  Test 1: FIPS 197 Appendix C.1 (AES-128)
   --================================================================
   declare
      Key : constant Bytes_16 :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#);
      PT : constant Bytes_16 :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#aa#, 16#bb#, 16#cc#, 16#dd#, 16#ee#, 16#ff#);
      Want : constant Bytes_16 :=
        (16#69#, 16#c4#, 16#e0#, 16#d8#, 16#6a#, 16#7b#, 16#04#, 16#30#,
         16#d8#, 16#cd#, 16#b7#, 16#80#, 16#70#, 16#b4#, 16#c5#, 16#5a#);
      AES_K : constant SPARKNaCl.AES.AES128_Key :=
                  SPARKNaCl.AES.Construct (Key);
      RK    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                  SPARKNaCl.AES.Key_Expansion (AES_K);
      Got   : Bytes_16;
   begin
      SPARKTLSCrypto.AES_NI.Cipher_128 (Got, PT, RK);
      Check ("FIPS 197 C.1 (AES-128)", Got = Want);
      if Got /= Want then
         Put_Line ("    want: " & Hex (Want));
         Put_Line ("    got:  " & Hex (Got));
      end if;
   end;

   --================================================================
   --  Test 2: FIPS 197 Appendix C.3 (AES-256)
   --================================================================
   declare
      Key : constant Bytes_32 :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1a#, 16#1b#, 16#1c#, 16#1d#, 16#1e#, 16#1f#);
      PT : constant Bytes_16 :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#aa#, 16#bb#, 16#cc#, 16#dd#, 16#ee#, 16#ff#);
      Want : constant Bytes_16 :=
        (16#8e#, 16#a2#, 16#b7#, 16#ca#, 16#51#, 16#67#, 16#45#, 16#bf#,
         16#ea#, 16#fc#, 16#49#, 16#90#, 16#4b#, 16#49#, 16#60#, 16#89#);
      AES_K : constant SPARKNaCl.AES.AES256_Key :=
                  SPARKNaCl.AES.Construct (Key);
      RK    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                  SPARKNaCl.AES.Key_Expansion (AES_K);
      Got   : Bytes_16;
   begin
      SPARKTLSCrypto.AES_NI.Cipher_256 (Got, PT, RK);
      Check ("FIPS 197 C.3 (AES-256)", Got = Want);
      if Got /= Want then
         Put_Line ("    want: " & Hex (Want));
         Put_Line ("    got:  " & Hex (Got));
      end if;
   end;

   --================================================================
   --  Test 3: 1024 random AES-128 cases — equivalence with software
   --================================================================
   declare
      Bad : Natural := 0;
   begin
      for Trial in 1 .. 1024 loop
         declare
            Key : Bytes_16; PT : Bytes_16;
            CT_HW, CT_SW : Bytes_16;
         begin
            Fill_16 (Key);
            Fill_16 (PT);
            declare
               AES_K : constant SPARKNaCl.AES.AES128_Key :=
                          SPARKNaCl.AES.Construct (Key);
               RK    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                          SPARKNaCl.AES.Key_Expansion (AES_K);
            begin
               SPARKNaCl.AES.Cipher (CT_SW, PT, RK);
               SPARKTLSCrypto.AES_NI.Cipher_128 (CT_HW, PT, RK);
            end;
            if CT_HW /= CT_SW then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image
                            & ": SW=" & Hex (CT_SW)
                            & " HW=" & Hex (CT_HW));
               end if;
            end if;
         end;
      end loop;
      Check ("AES-128 SW/HW equivalence over 1024 random cases", Bad = 0);
   end;

   --================================================================
   --  Test 4: 1024 random AES-256 cases — equivalence
   --================================================================
   declare
      Bad : Natural := 0;
   begin
      for Trial in 1 .. 1024 loop
         declare
            Key : Bytes_32; PT : Bytes_16;
            CT_HW, CT_SW : Bytes_16;
         begin
            Fill_32 (Key);
            Fill_16 (PT);
            declare
               AES_K : constant SPARKNaCl.AES.AES256_Key :=
                          SPARKNaCl.AES.Construct (Key);
               RK    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                          SPARKNaCl.AES.Key_Expansion (AES_K);
            begin
               SPARKNaCl.AES.Cipher (CT_SW, PT, RK);
               SPARKTLSCrypto.AES_NI.Cipher_256 (CT_HW, PT, RK);
            end;
            if CT_HW /= CT_SW then
               Bad := Bad + 1;
            end if;
         end;
      end loop;
      Check ("AES-256 SW/HW equivalence over 1024 random cases", Bad = 0);
   end;

   --================================================================
   --  Test 5: Pre-swapped round-key path — Cipher_*_PreSw must match
   --  Cipher_* (which itself matches SPARKNaCl). Tests the byteswap
   --  optimization used by AES_CTR_*_InPlace.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32; PT : Bytes_16;
            CT_Slow_128, CT_Fast_128 : Bytes_16;
            CT_Slow_256, CT_Fast_256 : Bytes_16;
         begin
            Fill_16 (K128); Fill_32 (K256); Fill_16 (PT);
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
            begin
               SPARKTLSCrypto.AES_NI.Cipher_128 (CT_Slow_128, PT, RK128);
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_NI.Cipher_128_PreSw
                 (CT_Fast_128, PT, Pre_128);
               if CT_Slow_128 /= CT_Fast_128 then Bad_128 := Bad_128 + 1; end if;

               SPARKTLSCrypto.AES_NI.Cipher_256 (CT_Slow_256, PT, RK256);
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_NI.Cipher_256_PreSw
                 (CT_Fast_256, PT, Pre_256);
               if CT_Slow_256 /= CT_Fast_256 then Bad_256 := Bad_256 + 1; end if;
            end;
         end;
      end loop;
      Check ("AES-128 PreSw == Cipher_128 over 256 random cases",
             Bad_128 = 0);
      Check ("AES-256 PreSw == Cipher_256 over 256 random cases",
             Bad_256 = 0);
   end;

   --================================================================
   --  Test 6: 4-way pipelined Cipher_4x_*_PreSw must produce 4 blocks
   --  matching 4 individual Cipher_*_PreSw calls. Tests the AESENC
   --  pipeline optimization used by AES_CTR_*_InPlace.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            PT_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
            CT_4x_128, CT_4x_256 : SPARKTLSCrypto.AES_NI.Bytes_64;
            CT_Ref : Bytes_16;
         begin
            Fill_16 (K128); Fill_32 (K256);
            for I in PT_Buf'Range loop PT_Buf (I) := Rand_Byte; end loop;
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);

               SPARKTLSCrypto.AES_NI.Cipher_4x_128_PreSw
                 (CT_4x_128, PT_Buf, Pre_128);
               SPARKTLSCrypto.AES_NI.Cipher_4x_256_PreSw
                 (CT_4x_256, PT_Buf, Pre_256);

               for B in 0 .. 3 loop
                  declare
                     PT_Block : Bytes_16;
                  begin
                     for I in 0 .. 15 loop
                        PT_Block (N32 (I)) := PT_Buf (N32 (B * 16 + I));
                     end loop;
                     SPARKTLSCrypto.AES_NI.Cipher_128_PreSw
                       (CT_Ref, PT_Block, Pre_128);
                     for I in 0 .. 15 loop
                        if CT_4x_128 (N32 (B * 16 + I)) /= CT_Ref (N32 (I)) then
                           Bad_128 := Bad_128 + 1;
                        end if;
                     end loop;
                     SPARKTLSCrypto.AES_NI.Cipher_256_PreSw
                       (CT_Ref, PT_Block, Pre_256);
                     for I in 0 .. 15 loop
                        if CT_4x_256 (N32 (B * 16 + I)) /= CT_Ref (N32 (I)) then
                           Bad_256 := Bad_256 + 1;
                        end if;
                     end loop;
                  end;
               end loop;
            end;
         end;
      end loop;
      Check ("AES-128 4x_PreSw matches 4× Cipher_128_PreSw over 256 random cases",
             Bad_128 = 0);
      Check ("AES-256 4x_PreSw matches 4× Cipher_256_PreSw over 256 random cases",
             Bad_256 = 0);
   end;

   --================================================================
   --  Test 7: Fused Cipher_4x_*_PreSw_XOR == 4-way keystream + XOR
   --  with the buffer. Tests the in-place fused encrypt path used by
   --  AES_CTR_*_InPlace.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            Ctr_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
            KS_Buf  : SPARKTLSCrypto.AES_NI.Bytes_64;
            Buf_Ref, Buf_Fast : Byte_Seq (0 .. 63);
         begin
            Fill_16 (K128); Fill_32 (K256);
            for I in Ctr_Buf'Range loop Ctr_Buf (I) := Rand_Byte; end loop;
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
            begin
               --  AES-128: reference = generate keystream, manually XOR.
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_NI.Cipher_4x_128_PreSw
                 (KS_Buf, Ctr_Buf, Pre_128);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS_Buf (N32 (I));
               end loop;
               SPARKTLSCrypto.AES_NI.Cipher_4x_128_PreSw_XOR
                 (Buf_Fast, Ctr_Buf, Pre_128);
               if Buf_Fast /= Buf_Ref then Bad_128 := Bad_128 + 1; end if;

               --  Reset for AES-256 trial (use same Buf_Ref/Buf_Fast pattern).
               for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
               Buf_Fast := Buf_Ref;
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_NI.Cipher_4x_256_PreSw
                 (KS_Buf, Ctr_Buf, Pre_256);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS_Buf (N32 (I));
               end loop;
               SPARKTLSCrypto.AES_NI.Cipher_4x_256_PreSw_XOR
                 (Buf_Fast, Ctr_Buf, Pre_256);
               if Buf_Fast /= Buf_Ref then Bad_256 := Bad_256 + 1; end if;
            end;
         end;
      end loop;
      Check ("AES-128 PreSw_XOR == keystream + XOR over 256 random cases",
             Bad_128 = 0);
      Check ("AES-256 PreSw_XOR == keystream + XOR over 256 random cases",
             Bad_256 = 0);
   end;

   --================================================================
   --  Test 8: Fully-fused Encrypt_GCM_Stripe_4 (AES + XOR + 4-block
   --  aggregated GHASH in one asm) must match the unfused sequence
   --  (AES_CTR + separate GHASH) for both buffer and S accumulator.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            H    : Bytes_16;
            S0   : Bytes_16;
            Ctr  : SPARKTLSCrypto.AES_NI.Bytes_64;
            Buf_Ref, Buf_Fast : Byte_Seq (0 .. 63);
            S_Ref, S_Fast : Bytes_16;
            KS   : SPARKTLSCrypto.AES_NI.Bytes_64;
         begin
            Fill_16 (K128); Fill_32 (K256);
            Fill_16 (H); Fill_16 (S0);
            for I in Ctr'Range loop Ctr (I) := Rand_Byte; end loop;
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;

            --  AES-128 path
            Buf_Fast := Buf_Ref;
            S_Ref := S0; S_Fast := S0;
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
               HP       : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
            begin
               --  Reference: encrypt then GHASH_4_Blocks separately.
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_NI.Cipher_4x_128_PreSw (KS, Ctr, Pre_128);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS (N32 (I));
               end loop;
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks (S_Ref, Buf_Ref, HP);

               --  Fused stripe.
               SPARKTLSCrypto.AES_NI.Encrypt_GCM_Stripe_4_128
                 (Buf_Fast, S_Fast, Ctr, Pre_128, HP);

               if Buf_Fast /= Buf_Ref or else S_Fast /= S_Ref then
                  Bad_128 := Bad_128 + 1;
                  if Bad_128 <= 3 then
                     Put_Line ("    trial" & Trial'Image
                               & " buf_eq=" & Boolean'Image (Buf_Fast = Buf_Ref)
                               & " s_eq=" & Boolean'Image (S_Fast = S_Ref));
                  end if;
               end if;
            end;

            --  AES-256 path (fresh inputs)
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            S_Ref := S0; S_Fast := S0;
            declare
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
               HP       : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_NI.Cipher_4x_256_PreSw (KS, Ctr, Pre_256);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS (N32 (I));
               end loop;
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks (S_Ref, Buf_Ref, HP);

               SPARKTLSCrypto.AES_NI.Encrypt_GCM_Stripe_4_256
                 (Buf_Fast, S_Fast, Ctr, Pre_256, HP);

               if Buf_Fast /= Buf_Ref or else S_Fast /= S_Ref then
                  Bad_256 := Bad_256 + 1;
               end if;
            end;
         end;
      end loop;
      Check ("AES-128 GCM fused stripe == unfused over 256 random cases",
             Bad_128 = 0);
      Check ("AES-256 GCM fused stripe == unfused over 256 random cases",
             Bad_256 = 0);
   end;

   --================================================================
   --  Test 9: 2-stripe pipelined Encrypt_GHASH_Pipelined_4 must
   --  produce the same (ciphertext, S) as separate AES + GHASH
   --  primitives on each stripe.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            H : Bytes_16; S0 : Bytes_16;
            Ctr_New : SPARKTLSCrypto.AES_NI.Bytes_64;
            --  128-byte sliding window: [0..63] = prev ct (GHASH input,
            --  unmodified), [64..127] = new plaintext encrypted in place.
            Buf_Ref, Buf_Fast : Byte_Seq (0 .. 127);
            S_Ref, S_Fast : Bytes_16;
            KS : SPARKTLSCrypto.AES_NI.Bytes_64;
         begin
            Fill_16 (K128); Fill_32 (K256);
            Fill_16 (H); Fill_16 (S0);
            for I in Ctr_New'Range loop Ctr_New (I) := Rand_Byte; end loop;
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            S_Ref := S0; S_Fast := S0;

            --  AES-128 path
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
               HP       : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
            begin
               --  Reference: GHASH the prev-ct half, then AES-encrypt the
               --  new-pt half via separate primitives.
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
                 (S_Ref, Buf_Ref (0 .. 63), HP);
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_NI.Cipher_4x_128_PreSw (KS, Ctr_New, Pre_128);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (64 + I)) :=
                     Buf_Ref (N32 (64 + I)) xor KS (N32 (I));
               end loop;

               --  Pipelined call.
               SPARKTLSCrypto.AES_NI.Encrypt_GHASH_Pipelined_4_128
                 (Buf_Fast, S_Fast, Ctr_New, Pre_128, HP);

               if Buf_Fast /= Buf_Ref or else S_Fast /= S_Ref then
                  Bad_128 := Bad_128 + 1;
                  if Bad_128 <= 3 then
                     Put_Line ("    trial" & Trial'Image
                               & " buf_eq=" & Boolean'Image
                                 (Buf_Fast = Buf_Ref)
                               & " s_eq=" & Boolean'Image
                                 (S_Fast = S_Ref));
                  end if;
               end if;
            end;

            --  AES-256 path (fresh randoms).
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            S_Ref := S0; S_Fast := S0;
            declare
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
               HP       : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
            begin
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
                 (S_Ref, Buf_Ref (0 .. 63), HP);
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_NI.Cipher_4x_256_PreSw (KS, Ctr_New, Pre_256);
               for I in 0 .. 63 loop
                  Buf_Ref (N32 (64 + I)) :=
                     Buf_Ref (N32 (64 + I)) xor KS (N32 (I));
               end loop;
               SPARKTLSCrypto.AES_NI.Encrypt_GHASH_Pipelined_4_256
                 (Buf_Fast, S_Fast, Ctr_New, Pre_256, HP);
               if Buf_Fast /= Buf_Ref or else S_Fast /= S_Ref then
                  Bad_256 := Bad_256 + 1;
               end if;
            end;
         end;
      end loop;
      Check ("AES-128 GCM 2-stripe pipelined matches reference (256 cases)",
             Bad_128 = 0);
      Check ("AES-256 GCM 2-stripe pipelined matches reference (256 cases)",
             Bad_256 = 0);
   end;

   --================================================================
   --  Test 10: Build_Ctr_Block_4 must produce the same 4 counter
   --  blocks (and same updated CB) as the equivalent Ada loop using
   --  the existing Increment_Counter helper.
   --================================================================
   declare
      --  Mirror the SPARKNaCl-style BE u32 counter increment used in
      --  the Ada path so we have a self-contained reference here.
      procedure Inc_Ref (CB : in out Bytes_16) is
         Val : Unsigned_32 :=
            Unsigned_32 (CB (12)) * 2**24 +
            Unsigned_32 (CB (13)) * 2**16 +
            Unsigned_32 (CB (14)) * 2**8 +
            Unsigned_32 (CB (15));
      begin
         Val := Val + 1;
         CB (12) := Byte (Shift_Right (Val, 24) and 16#FF#);
         CB (13) := Byte (Shift_Right (Val, 16) and 16#FF#);
         CB (14) := Byte (Shift_Right (Val, 8) and 16#FF#);
         CB (15) := Byte (Val and 16#FF#);
      end Inc_Ref;

      Bad : Natural := 0;
   begin
      for Trial in 1 .. 1024 loop
         declare
            CB_Ref, CB_Fast : Bytes_16;
            Ctr_Ref         : SPARKTLSCrypto.AES_NI.Bytes_64;
            Ctr_Fast        : SPARKTLSCrypto.AES_NI.Bytes_64;
         begin
            Fill_16 (CB_Ref);
            CB_Fast := CB_Ref;

            --  Reference: Ada-side 4-block counter setup.
            for B in 0 .. 3 loop
               for I in 0 .. 15 loop
                  Ctr_Ref (N32 (B * 16 + I)) := CB_Ref (N32 (I));
               end loop;
               Inc_Ref (CB_Ref);
            end loop;

            --  Asm primitive.
            SPARKTLSCrypto.AES_NI.Build_Ctr_Block_4 (CB_Fast, Ctr_Fast);

            if Ctr_Fast /= Ctr_Ref or else CB_Fast /= CB_Ref then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image
                            & " ctr_eq=" & Boolean'Image (Ctr_Fast = Ctr_Ref)
                            & " cb_eq=" & Boolean'Image (CB_Fast = CB_Ref));
               end if;
            end if;
         end;
      end loop;
      Check ("Build_Ctr_Block_4 matches Ada Increment_Counter loop (1024 cases)",
             Bad = 0);
   end;

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " / " & Total'Image);
   if Fail > 0 then
      Put_Line ("FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("PASS");
   end if;
end Test_AES_NI;
