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

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " / " & Total'Image);
   if Fail > 0 then
      Put_Line ("FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("PASS");
   end if;
end Test_AES_NI;
