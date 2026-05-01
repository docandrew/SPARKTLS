--  AVX-512 VAES correctness gate: 16-block VAES Cipher matches the
--  AES-NI single-block Cipher repeated 16 times, which itself is
--  validated against SPARKNaCl's formally-proven software AES.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.GHASH_NI;

procedure Test_VAES is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1;
      else Fail := Fail + 1; Put_Line ("FAIL: " & Name); end if;
   end Check;

   State : Unsigned_64 := 16#FACE_F00D_BABE_BEEF#;
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

   function Hex (B : Byte) return String is
      H  : constant String := "0123456789abcdef";
      Hi : constant Natural := Natural (Shift_Right (Unsigned_8 (B), 4));
      Lo : constant Natural := Natural (Unsigned_8 (B) and 16#0F#);
   begin
      return H (Hi + 1) & H (Lo + 1);
   end Hex;
   function Hex (X : Bytes_16) return String is
      R : String (1 .. 32); P : Natural := 1;
   begin
      for I in X'Range loop
         R (P .. P + 1) := Hex (X (I)); P := P + 2;
      end loop;
      return R;
   end Hex;
begin
   Put_Line ("VAES (AVX-512) tests");
   Put_Line ("====================");
   Put ("CPUID AVX-512 + VAES + VPCLMULQDQ: ");
   Put_Line (Boolean'Image
              (SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM));

   if not SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM then
      Put_Line ("SKIP: this CPU does not advertise AVX-512+VAES+VPCLMULQDQ");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   --================================================================
   --  16-block VAES Cipher must match 16 calls to AES-NI's single-
   --  block Cipher_*_PreSw (which is itself validated against the
   --  formally-proven SPARKNaCl reference).
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            Inp  : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
            Out_VAES : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
            Block_In  : Bytes_16;
            Block_Ref : Bytes_16;
         begin
            Fill_16 (K128); Fill_32 (K256);
            for I in Inp'Range loop Inp (I) := Rand_Byte; end loop;

            --  AES-128
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_128_VAES
                 (Out_VAES, Inp, Pre_128);
               for B in 0 .. 15 loop
                  for I in 0 .. 15 loop
                     Block_In (N32 (I)) := Inp (N32 (B * 16 + I));
                  end loop;
                  SPARKTLSCrypto.AES_NI.Cipher_128_PreSw
                    (Block_Ref, Block_In, Pre_128);
                  for I in 0 .. 15 loop
                     if Out_VAES (N32 (B * 16 + I)) /= Block_Ref (N32 (I))
                     then
                        Bad_128 := Bad_128 + 1;
                     end if;
                  end loop;
               end loop;
            end;

            --  AES-256
            for I in Inp'Range loop Inp (I) := Rand_Byte; end loop;
            declare
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_256_VAES
                 (Out_VAES, Inp, Pre_256);
               for B in 0 .. 15 loop
                  for I in 0 .. 15 loop
                     Block_In (N32 (I)) := Inp (N32 (B * 16 + I));
                  end loop;
                  SPARKTLSCrypto.AES_NI.Cipher_256_PreSw
                    (Block_Ref, Block_In, Pre_256);
                  for I in 0 .. 15 loop
                     if Out_VAES (N32 (B * 16 + I)) /= Block_Ref (N32 (I))
                     then
                        Bad_256 := Bad_256 + 1;
                     end if;
                  end loop;
               end loop;
            end;
         end;
      end loop;
      Check ("AES-128 VAES Cipher_16x == 16 × Cipher_128_PreSw (256 cases)",
             Bad_128 = 0);
      Check ("AES-256 VAES Cipher_16x == 16 × Cipher_256_PreSw (256 cases)",
             Bad_256 = 0);
   end;

   --================================================================
   --  Build_Ctr_Block_16 must produce 16 sequential CTR blocks and
   --  advance CB by 16, matching a reference Ada loop.
   --================================================================
   declare
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
            Ctr_Ref  : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
            Ctr_Fast : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
         begin
            Fill_16 (CB_Ref);
            CB_Fast := CB_Ref;
            for B in 0 .. 15 loop
               for I in 0 .. 15 loop
                  Ctr_Ref (N32 (B * 16 + I)) := CB_Ref (N32 (I));
               end loop;
               Inc_Ref (CB_Ref);
            end loop;
            SPARKTLSCrypto.AES_GCM_AVX512.Build_Ctr_Block_16
              (CB_Fast, Ctr_Fast);
            if Ctr_Fast /= Ctr_Ref or else CB_Fast /= CB_Ref then
               Bad := Bad + 1;
            end if;
         end;
      end loop;
      Check ("Build_Ctr_Block_16 matches Ada reference (1024 cases)",
             Bad = 0);
   end;

   --================================================================
   --  Cipher_16x_*_VAES_XOR (CTR-mode keystream + XOR with buf)
   --  matches the unfused sequence of Cipher_16x_*_VAES + Ada XOR.
   --================================================================
   declare
      Bad_128 : Natural := 0;
      Bad_256 : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            K128 : Bytes_16; K256 : Bytes_32;
            Ctr  : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
            Buf_Ref, Buf_Fast : Byte_Seq (0 .. 255);
            KS   : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
         begin
            Fill_16 (K128); Fill_32 (K256);
            for I in Ctr'Range loop Ctr (I) := Rand_Byte; end loop;
            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            declare
               AES_K128 : constant SPARKNaCl.AES.AES128_Key :=
                             SPARKNaCl.AES.Construct (K128);
               RK128    : constant SPARKNaCl.AES.AES128_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K128);
               Pre_128  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_128 (RK128, Pre_128);
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_128_VAES
                 (KS, Ctr, Pre_128);
               for I in 0 .. 255 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS (N32 (I));
               end loop;
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_128_VAES_XOR
                 (Buf_Fast, Ctr, Pre_128);
               if Buf_Fast /= Buf_Ref then Bad_128 := Bad_128 + 1; end if;
            end;

            for I in Buf_Ref'Range loop Buf_Ref (I) := Rand_Byte; end loop;
            Buf_Fast := Buf_Ref;
            declare
               AES_K256 : constant SPARKNaCl.AES.AES256_Key :=
                             SPARKNaCl.AES.Construct (K256);
               RK256    : constant SPARKNaCl.AES.AES256_Round_Keys :=
                             SPARKNaCl.AES.Key_Expansion (AES_K256);
               Pre_256  : SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256;
            begin
               SPARKTLSCrypto.AES_NI.Pre_Swap_RKs_256 (RK256, Pre_256);
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_256_VAES
                 (KS, Ctr, Pre_256);
               for I in 0 .. 255 loop
                  Buf_Ref (N32 (I)) := Buf_Ref (N32 (I)) xor KS (N32 (I));
               end loop;
               SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_256_VAES_XOR
                 (Buf_Fast, Ctr, Pre_256);
               if Buf_Fast /= Buf_Ref then Bad_256 := Bad_256 + 1; end if;
            end;
         end;
      end loop;
      Check ("AES-128 VAES_XOR matches keystream + XOR (256 cases)",
             Bad_128 = 0);
      Check ("AES-256 VAES_XOR matches keystream + XOR (256 cases)",
             Bad_256 = 0);
   end;

   --================================================================
   --  16-block VPCLMULQDQ-zmm aggregated GHASH must match the same
   --  result as 4 sequential calls to the existing 4-block GHASH.
   --================================================================
   declare
      Bad : Natural := 0;
   begin
      for Trial in 1 .. 256 loop
         declare
            H : Bytes_16; S0 : Bytes_16;
            Blocks : Byte_Seq (0 .. 255);
            S_Ref, S_Fast : Bytes_16;
            HP_4   : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
            HP_16  : SPARKTLSCrypto.AES_GCM_AVX512.Pre_H_Powers_16;
         begin
            Fill_16 (H); Fill_16 (S0);
            for I in Blocks'Range loop Blocks (I) := Rand_Byte; end loop;

            --  Reference: 4 calls to the existing 4-block aggregated path.
            S_Ref := S0;
            SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP_4);
            SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
              (S_Ref, Blocks (0 .. 63), HP_4);
            SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
              (S_Ref, Blocks (64 .. 127), HP_4);
            SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
              (S_Ref, Blocks (128 .. 191), HP_4);
            SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
              (S_Ref, Blocks (192 .. 255), HP_4);

            --  Fast: 16-block VPCLMULQDQ-zmm.
            S_Fast := S0;
            SPARKTLSCrypto.AES_GCM_AVX512.Compute_H_Powers_16 (H, HP_16);
            SPARKTLSCrypto.AES_GCM_AVX512.GHASH_16_Blocks
              (S_Fast, Blocks, HP_16);

            if S_Fast /= S_Ref then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image);
                  Put_Line ("      ref=" & Hex (S_Ref));
                  Put_Line ("      vp=" & Hex (S_Fast));
               end if;
            end if;
         end;
      end loop;
      Check ("GHASH_16_Blocks matches 4× GHASH_4_Blocks (256 cases)",
             Bad = 0);
   end;

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " /" & Total'Image);
   if Fail > 0 then
      Put_Line ("FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("PASS");
   end if;
end Test_VAES;
