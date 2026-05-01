--  AVX-512 ChaCha20 correctness gate: 16 blocks of keystream from
--  Encrypt_1024_InPlace must match 16 separate calls to SPARKNaCl's
--  scalar ChaCha20_IETF (counters i, i+1, ..., i+15) XOR'd against
--  the same input buffer.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKNaCl.Core;
with SPARKNaCl.Stream;
with SPARKTLSCrypto.ChaCha20_AVX512;

procedure Test_ChaCha20_AVX512 is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1;
      else Fail := Fail + 1; Put_Line ("FAIL: " & Name); end if;
   end Check;

   State : Unsigned_64 := 16#FACE_B00C_DEAD_BEEF#;
   function Rand_Byte return Byte is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 7);
      State := State xor Shift_Left (State, 17);
      return Byte (State and 16#FF#);
   end Rand_Byte;

begin
   Put_Line ("AVX-512 ChaCha20 tests");
   Put_Line ("======================");
   Put ("CPUID AVX-512F: ");
   Put_Line (Boolean'Image
               (SPARKTLSCrypto.ChaCha20_AVX512.Has_AVX512_ChaCha20));

   if not SPARKTLSCrypto.ChaCha20_AVX512.Has_AVX512_ChaCha20 then
      Put_Line ("SKIP: this CPU does not advertise AVX-512F");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   --================================================================
   --  16-block batch must match 16 sequential scalar ChaCha20 blocks
   --  XOR'd against the same input.
   --================================================================
   declare
      Bad : Natural := 0;
   begin
      for Trial in 1 .. 64 loop
         declare
            K_Bytes : Bytes_32;
            N_Bytes : Bytes_12;
            Counter : constant Unsigned_32 := Unsigned_32 (Trial * 17);

            Buf_Ref  : Byte_Seq (0 .. 1023);
            Buf_Fast : Byte_Seq (0 .. 1023);

            K     : SPARKNaCl.Core.ChaCha20_Key;
            Nonce : SPARKNaCl.Core.ChaCha20_IETF_Nonce;
         begin
            for I in K_Bytes'Range loop K_Bytes (I) := Rand_Byte; end loop;
            for I in N_Bytes'Range loop N_Bytes (I) := Rand_Byte; end loop;
            for I in Buf_Ref'Range loop
               Buf_Ref (I) := Rand_Byte;
            end loop;
            Buf_Fast := Buf_Ref;

            SPARKNaCl.Core.Construct (K, K_Bytes);
            Nonce := SPARKNaCl.Core.ChaCha20_IETF_Nonce (N_Bytes);

            --  Reference: 16 scalar ChaCha20 keystream blocks XOR'd
            --  against the input.
            declare
               KS : Byte_Seq (0 .. 1023);
            begin
               SPARKNaCl.Stream.ChaCha20_IETF
                 (C => KS, N => Nonce, K => K, Counter => Counter);
               for I in KS'Range loop
                  Buf_Ref (I) := Buf_Ref (I) xor KS (I);
               end loop;
            end;

            --  Fast path.
            SPARKTLSCrypto.ChaCha20_AVX512.Encrypt_1024_InPlace
              (Buf => Buf_Fast, K => K_Bytes, N => N_Bytes,
               Counter => Counter);

            if Buf_Fast /= Buf_Ref then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image
                            & " counter=" & Counter'Image
                            & " — first byte: ref="
                            & Buf_Ref (0)'Image & " fast="
                            & Buf_Fast (0)'Image);
                  --  Diff first 16 bytes of each block.
                  for B in 0 .. 15 loop
                     declare
                        Off : constant N32 := N32 (B) * 64;
                        Match : Boolean := True;
                     begin
                        for I in 0 .. 63 loop
                           if Buf_Ref (Off + N32 (I))
                              /= Buf_Fast (Off + N32 (I))
                           then
                              Match := False;
                              exit;
                           end if;
                        end loop;
                        if not Match then
                           Put_Line ("      block" & B'Image & " mismatches");
                        end if;
                     end;
                  end loop;
               end if;
            end if;
         end;
      end loop;
      Check ("AVX-512 16-block matches scalar over 64 random cases",
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
end Test_ChaCha20_AVX512;
