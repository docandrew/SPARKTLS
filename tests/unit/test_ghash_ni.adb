--  GHASH_NI hardware path: NIST SP 800-38D KAT + equivalence with the
--  bit-by-bit reference in SPARKTLSCrypto.AES_GCM.
--
--  We can't import AES_GCM.GF128_Mul (it's package-body-private), so
--  we mirror the reference implementation here as Reference_GF128_Mul
--  and check the hardware path against it.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKTLSCrypto.GHASH_NI;

procedure Test_GHASH_NI is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1;
      else
         Fail := Fail + 1; Put_Line ("FAIL: " & Name);
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
      R : String (1 .. 32); P : Natural := 1;
   begin
      for I in X'Range loop
         R (P .. P + 1) := Hex (X (I)); P := P + 2;
      end loop;
      return R;
   end Hex;

   --  Reference bit-by-bit GF(2^128) multiplication, mirroring the
   --  AES_GCM.GF128_Mul private implementation.
   function Ref_GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16 is
      Z : Bytes_16 := (others => 0);
      V : Bytes_16 := X;
      LSB : Byte;

      procedure Shift_Right_1 (W : in out Bytes_16) is
         Carry : Byte := 0;
         Next_Carry : Byte;
      begin
         for I in 0 .. 15 loop
            Next_Carry := W (N32 (I)) and 1;
            W (N32 (I)) := Byte (Shift_Right (Unsigned_8 (W (N32 (I))), 1))
                            or Byte (Shift_Left (Unsigned_8 (Carry), 7));
            Carry := Next_Carry;
         end loop;
      end Shift_Right_1;
   begin
      for I in 0 .. 127 loop
         if (Y (N32 (I / 8)) and
             Byte (Shift_Right (Unsigned_8 (16#80#), I mod 8))) /= 0
         then
            for J in 0 .. 15 loop
               Z (N32 (J)) := Z (N32 (J)) xor V (N32 (J));
            end loop;
         end if;
         LSB := V (15) and 1;
         Shift_Right_1 (V);
         if LSB /= 0 then
            V (0) := V (0) xor 16#E1#;
         end if;
      end loop;
      return Z;
   end Ref_GF128_Mul;

   --  xorshift64* for deterministic random inputs
   State : Unsigned_64 := 16#C0FFEE_DEADBEEF#;
   function Rand_Byte return Byte is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 7);
      State := State xor Shift_Left (State, 17);
      return Byte (State and 16#FF#);
   end Rand_Byte;

   procedure Fill (B : out Bytes_16) is
   begin
      for I in B'Range loop B (I) := Rand_Byte; end loop;
   end Fill;

begin
   Put_Line ("GHASH_NI tests");
   Put_Line ("==============");
   Put ("CPUID PCLMULQDQ: ");
   Put_Line (Boolean'Image (SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ));

   if not SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ then
      Put_Line ("SKIP: this CPU does not advertise PCLMULQDQ");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   --================================================================
   --  KAT: zero inputs -> zero output
   --================================================================
   declare
      Z : constant Bytes_16 := (others => 0);
      Got : constant Bytes_16 := SPARKTLSCrypto.GHASH_NI.GF128_Mul (Z, Z);
   begin
      Check ("0 * 0 = 0", Got = Z);
   end;

   --================================================================
   --  KAT: 1 * 1 — in NIST GHASH bit numbering (SP 800-38D §6.2),
   --  the multiplicative identity "1" = u^0 = MSB of byte 0 = 0x80,
   --  with all other bytes zero. 1 * 1 = 1 in any field.
   --================================================================
   declare
      One : Bytes_16 := (others => 0);
      Got : Bytes_16;
   begin
      One (0) := 16#80#;
      Got := SPARKTLSCrypto.GHASH_NI.GF128_Mul (One, One);
      Check ("1 * 1 = 1", Got = One);
   end;

   --================================================================
   --  Equivalence: 1024 random inputs vs the bit-by-bit reference.
   --================================================================
   declare
      Bad : Natural := 0;
   begin
      for Trial in 1 .. 1024 loop
         declare
            X, Y : Bytes_16;
            Got_HW, Got_SW : Bytes_16;
         begin
            Fill (X); Fill (Y);
            Got_SW := Ref_GF128_Mul (X, Y);
            Got_HW := SPARKTLSCrypto.GHASH_NI.GF128_Mul (X, Y);
            if Got_HW /= Got_SW then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image
                            & " X=" & Hex (X) & " Y=" & Hex (Y));
                  Put_Line ("      SW=" & Hex (Got_SW));
                  Put_Line ("      HW=" & Hex (Got_HW));
               end if;
            end if;
         end;
      end loop;
      Check ("HW/SW equivalence over 1024 random pairs", Bad = 0);
   end;

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " /" & Total'Image);
   if Fail > 0 then
      Put_Line ("FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("PASS");
   end if;
end Test_GHASH_NI;
