--  Fast Poly1305 correctness gate: SPARKTLSCrypto.Poly1305.Onetimeauth
--  must produce byte-identical output to the formally-proven
--  SPARKNaCl.MAC.Onetimeauth across random key + message inputs.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKNaCl.MAC;
with SPARKTLSCrypto.Poly1305;

procedure Test_Poly1305 is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
      else
         Fail := Fail + 1; Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   --  Deterministic xorshift64* PRNG for reproducibility.
   State : Unsigned_64 := 16#1234_5678_9ABC_DEF0#;
   function Rand_Byte return Byte is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 7);
      State := State xor Shift_Left (State, 17);
      return Byte (State and 16#FF#);
   end Rand_Byte;

   function Hex (B : Byte) return String is
      Hd : constant String := "0123456789abcdef";
      Hi : constant Natural := Natural (Shift_Right (Unsigned_8 (B), 4));
      Lo : constant Natural := Natural (Unsigned_8 (B) and 16#0F#);
   begin
      return Hd (Hi + 1) & Hd (Lo + 1);
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
   Put_Line ("Fast Poly1305 tests");
   Put_Line ("===================");

   --================================================================
   --  RFC 8439 §2.5.2 KAT: a known answer with a fixed key + message.
   --  This is the canonical test vector.
   --================================================================
   declare
      K_Bytes : constant Bytes_32 :=
        (16#85#, 16#d6#, 16#be#, 16#78#, 16#57#, 16#55#, 16#6d#, 16#33#,
         16#7f#, 16#44#, 16#52#, 16#fe#, 16#42#, 16#d5#, 16#06#, 16#a8#,
         16#01#, 16#03#, 16#80#, 16#8a#, 16#fb#, 16#0d#, 16#b2#, 16#fd#,
         16#4a#, 16#bf#, 16#f6#, 16#af#, 16#41#, 16#49#, 16#f5#, 16#1b#);
      Msg : Byte_Seq (0 .. 33) :=
        (16#43#, 16#72#, 16#79#, 16#70#, 16#74#, 16#6f#, 16#67#, 16#72#,
         16#61#, 16#70#, 16#68#, 16#69#, 16#63#, 16#20#, 16#46#, 16#6f#,
         16#72#, 16#75#, 16#6d#, 16#20#, 16#52#, 16#65#, 16#73#, 16#65#,
         16#61#, 16#72#, 16#63#, 16#68#, 16#20#, 16#47#, 16#72#, 16#6f#,
         16#75#, 16#70#);
      Want : constant Bytes_16 :=
        (16#a8#, 16#06#, 16#1d#, 16#c1#, 16#30#, 16#51#, 16#36#, 16#c6#,
         16#c2#, 16#2b#, 16#8b#, 16#af#, 16#0c#, 16#01#, 16#27#, 16#a9#);
      K : SPARKNaCl.MAC.Poly_1305_Key;
      Got : Bytes_16;
   begin
      SPARKNaCl.MAC.Construct (K, K_Bytes);
      SPARKTLSCrypto.Poly1305.Onetimeauth (Got, Msg, K);
      Check ("RFC 8439 §2.5.2 KAT", Got = Want);
      if Got /= Want then
         Put_Line ("    want: " & Hex (Want));
         Put_Line ("    got:  " & Hex (Got));
      end if;
   end;

   --================================================================
   --  Equivalence: 256 random (key, message) pairs across a range of
   --  message lengths, including non-multiple-of-16 lengths.
   --================================================================
   declare
      Bad : Natural := 0;
      Lengths : constant array (1 .. 8) of N32 :=
        (0, 1, 15, 16, 17, 64, 1024, 4096);
   begin
      for Trial in 1 .. 256 loop
         declare
            Idx     : constant Positive :=
              ((Trial - 1) mod Lengths'Length) + 1;
            Len     : constant N32 := Lengths (Idx);
            K_Bytes : Bytes_32;
            K       : SPARKNaCl.MAC.Poly_1305_Key;
            T_Ref   : Bytes_16;
            T_Fast  : Bytes_16;
         begin
            for I in K_Bytes'Range loop K_Bytes (I) := Rand_Byte; end loop;
            SPARKNaCl.MAC.Construct (K, K_Bytes);

            if Len = 0 then
               declare
                  M : constant Byte_Seq (1 .. 0) := (others => 0);
               begin
                  SPARKNaCl.MAC.Onetimeauth (T_Ref, M, K);
                  SPARKTLSCrypto.Poly1305.Onetimeauth (T_Fast, M, K);
               end;
            else
               declare
                  M : Byte_Seq (0 .. Len - 1);
               begin
                  for I in M'Range loop M (I) := Rand_Byte; end loop;
                  SPARKNaCl.MAC.Onetimeauth (T_Ref, M, K);
                  SPARKTLSCrypto.Poly1305.Onetimeauth (T_Fast, M, K);
               end;
            end if;

            if T_Ref /= T_Fast then
               Bad := Bad + 1;
               if Bad <= 3 then
                  Put_Line ("    trial" & Trial'Image
                            & " len=" & Len'Image
                            & " ref=" & Hex (T_Ref)
                            & " fast=" & Hex (T_Fast));
               end if;
            end if;
         end;
      end loop;
      Check ("Fast == SPARKNaCl ref over 256 random cases (mixed lengths)",
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
end Test_Poly1305;
