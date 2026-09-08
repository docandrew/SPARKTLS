--  NIST FIPS 180-4 known-answer tests for the streaming SHA-384 unit
--  (sparktlscrypto-hashing-sha384, written 2026-08-25 for the
--  streaming-transcript carve). The KATs arbitrate the constant
--  tables; the split-point sweep arbitrates the streaming buffer
--  logic; SPARKNaCl.Hashing.SHA384 is the independent reference.

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;
with SPARKNaCl;     use SPARKNaCl;
use type Interfaces.Unsigned_8;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA512;

procedure Test_SHA384_Streaming_KAT is

   package S renames SPARKTLSCrypto.Hashing.SHA384;

   Pass : Natural := 0;
   Fail : Natural := 0;

   procedure Check (Name : String; Ok : Boolean) is
   begin
      if Ok then
         Pass := Pass + 1;
      else
         Fail := Fail + 1;
         Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   function Hx (C : Character) return Byte is
     (case C is
        when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
        when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
        when others     => 0);

   function From_Hex (H : String) return Bytes_48 is
      R : Bytes_48;
   begin
      for I in 0 .. 47 loop
         R (N32 (I)) :=
           Hx (H (H'First + 2 * I)) * 16 + Hx (H (H'First + 2 * I + 1));
      end loop;
      return R;
   end From_Hex;

   --  NIST FIPS 180-4 / CAVP vectors.
   KAT_Empty : constant Bytes_48 := From_Hex
     ("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
      & "274edebfe76f65fbd51ad2f14898b95b");
   KAT_ABC : constant Bytes_48 := From_Hex
     ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      & "8086072ba1e7cc2358baeca134c825a7");
   KAT_896 : constant Bytes_48 := From_Hex   --  two-block message
     ("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
      & "fcc7c71a557e2db966c3e9fa91746039");

   Empty : constant Byte_Seq (1 .. 0) := (others => 0);
   ABC   : constant Byte_Seq (0 .. 2) := (16#61#, 16#62#, 16#63#);
   M896  : Byte_Seq (0 .. 111);   --  "abcdefgh..." per FIPS 180-4

begin
   declare
      T : constant String :=
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        & "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
   begin
      for I in T'Range loop
         M896 (N32 (I - T'First)) := Character'Pos (T (I));
      end loop;
   end;

   --  1. One-shot against NIST.
   Check ("one-shot: empty", S.Hash (Empty) = S.Digest (KAT_Empty));
   Check ("one-shot: abc", S.Hash (ABC) = S.Digest (KAT_ABC));
   Check ("one-shot: 896-bit two-block", S.Hash (M896) = S.Digest (KAT_896));

   --  2. One-shot against the independent SPARKNaCl implementation.
   Check ("cross: abc matches SPARKNaCl",
          Byte_Seq (S.Hash (ABC)) =
            Byte_Seq (SPARKNaCl.Hashing.SHA384.Hash (ABC)));
   Check ("cross: 896-bit matches SPARKNaCl",
          Byte_Seq (S.Hash (M896)) =
            Byte_Seq (SPARKNaCl.Hashing.SHA384.Hash (M896)));

   --  3. Streaming = one-shot at every split point of the two-block
   --     message (exercises partial-buffer fill, exact-block boundary,
   --     and buffered-remainder paths).
   declare
      All_Match : Boolean := True;
      Ref       : constant S.Digest := S.Hash (M896);
   begin
      for Split in 0 .. 112 loop
         declare
            Ctx : S.Context;
            D   : S.Digest;
         begin
            S.Init (Ctx);
            if Split > 0 then
               S.Update (Ctx, M896 (0 .. N32 (Split - 1)));
            end if;
            if Split < 112 then
               S.Update (Ctx, M896 (N32 (Split) .. 111));
            end if;
            S.Final (Ctx, D);
            if D /= Ref then
               All_Match := False;
            end if;
         end;
      end loop;
      Check ("streaming: all 113 split points match one-shot", All_Match);
   end;

   --  4. Multi-block streaming: 5 updates of 100 bytes each (crosses
   --     three block boundaries mid-update).
   declare
      Big : Byte_Seq (0 .. 499);
      Ctx : S.Context;
      D1, D2 : S.Digest;
   begin
      for I in 0 .. 499 loop
         Big (N32 (I)) := Byte (I mod 251);
      end loop;
      S.Init (Ctx);
      for Chunk in 0 .. 4 loop
         S.Update (Ctx, Big (N32 (Chunk * 100) .. N32 (Chunk * 100 + 99)));
      end loop;
      S.Final (Ctx, D1);
      D2 := S.Hash (Big);
      Check ("streaming: 5x100-byte chunks match one-shot", D1 = D2);
      Check ("cross: 500-byte matches SPARKNaCl",
             Byte_Seq (D2) =
               Byte_Seq (SPARKNaCl.Hashing.SHA384.Hash (Big)));
   end;

   --  5. SHA-512 instantiation (added with the generic refactor): the
   --     same machine under the 5.3.5 IV must produce SHA-512.
   declare
      package S512 renames SPARKTLSCrypto.Hashing.SHA512;
      function From_Hex_64 (H : String) return Byte_Seq is
         R : Byte_Seq (0 .. 63);
      begin
         for I in 0 .. 63 loop
            R (N32 (I)) :=
              Hx (H (H'First + 2 * I)) * 16 + Hx (H (H'First + 2 * I + 1));
         end loop;
         return R;
      end From_Hex_64;
      KAT512_ABC : constant Byte_Seq := From_Hex_64
        ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
         & "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
      KAT512_Empty : constant Byte_Seq := From_Hex_64
        ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
         & "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
      Ctx : S512.Context;
      D   : S512.Digest;
   begin
      Check ("SHA-512: abc", Byte_Seq (S512.Hash (ABC)) = KAT512_ABC);
      Check ("SHA-512: empty", Byte_Seq (S512.Hash (Empty)) = KAT512_Empty);
      S512.Init (Ctx);
      S512.Update (Ctx, ABC (0 .. 0));
      S512.Update (Ctx, ABC (1 .. 2));
      S512.Final (Ctx, D);
      Check ("SHA-512: split streaming matches", Byte_Seq (D) = KAT512_ABC);
   end;

   Put_Line ("=== SHA-384/512 streaming KAT:" & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_SHA384_Streaming_KAT;
