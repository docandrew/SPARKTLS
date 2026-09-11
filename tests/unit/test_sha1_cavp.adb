--  NIST CAVP SHAVS known-answer tests for SPARKTLSCrypto.Hashing.SHA1
--  (the OCSP identifier-hash unit; see its spec for the scope rule).
--
--  Runs the byte-oriented SHA-1 vector files from NIST's
--  shabytetestvectors.zip (tests/cavp/SHA1ShortMsg.rsp, SHA1LongMsg.rsp,
--  SHA1Monte.rsp): every ShortMsg / LongMsg vector one-shot AND streamed
--  through Update in 1-, 7- and 64-byte chunks, plus the 100-checkpoint
--  Monte Carlo sequence of SHAVS 6.4. Set SPARKTLS_CAVP_DIR to point at
--  another vector directory.

with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Exceptions;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Interfaces;
with SPARKNaCl;        use SPARKNaCl;
use type Interfaces.Integer_32;
use type SPARKNaCl.Byte;
with SPARKTLSCrypto.Hashing.SHA1;

procedure Test_SHA1_CAVP is

   package S renames SPARKTLSCrypto.Hashing.SHA1;

   Pass : Natural := 0;
   Fail : Natural := 0;

   function Hx (C : Character) return Byte is
     (case C is
        when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
        when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
        when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
        when others     => 0);

   function From_Hex (H : String) return Byte_Seq is
      R : Byte_Seq (0 .. I32 (H'Length / 2) - 1);
   begin
      for I in R'Range loop
         R (I) := Hx (H (H'First + 2 * Integer (I))) * 16
                  + Hx (H (H'First + 2 * Integer (I) + 1));
      end loop;
      return R;
   end From_Hex;

   function Digest_Of_Hex (H : String) return S.Digest is
      B : constant Byte_Seq := From_Hex (H);
      D : S.Digest := (others => 0);
   begin
      if B'Length = 20 then
         D := B;
      end if;
      return D;
   end Digest_Of_Hex;

   --  Streamed hash with a fixed chunk size
   function Streamed (M : Byte_Seq; Chunk : N32) return S.Digest is
      Ctx : S.Context;
      D   : S.Digest;
      P   : N32 := M'First;
   begin
      S.Init (Ctx);
      while P <= M'Last loop
         declare
            Last : constant N32 := N32'Min (M'Last, P + Chunk - 1);
         begin
            S.Update (Ctx, M (P .. Last));
            P := Last + 1;
         end;
      end loop;
      S.Final (Ctx, D);
      return D;
   end Streamed;

   --  Value after "Name = " on a line, or "" when the line is not that
   --  field. The NIST files use CRLF line endings: strip the CR too.
   function Field (Line : String; Name : String) return String is
      use Ada.Strings.Fixed;
      Key  : constant String := Name & " = ";
      Last : Natural := Line'Last;
   begin
      while Last >= Line'First and then Character'Pos (Line (Last)) < 32 loop
         Last := Last - 1;
      end loop;
      if Last - Line'First + 1 >= Key'Length
        and then Line (Line'First .. Line'First + Key'Length - 1) = Key
      then
         return Trim (Line (Line'First + Key'Length .. Last), Ada.Strings.Both);
      end if;
      return "";
   end Field;

   Dir : constant String :=
     (if Ada.Environment_Variables.Exists ("SPARKTLS_CAVP_DIR")
      then Ada.Environment_Variables.Value ("SPARKTLS_CAVP_DIR")
      else "tests/cavp");

   ----------------------------------------------------------------------------
   --  ShortMsg / LongMsg: Len = bits, Msg = hex, MD = hex
   ----------------------------------------------------------------------------

   procedure Run_Msg_File (Name : String) is
      F        : File_Type;
      Len_Bits : Natural := 0;
      Have_Len : Boolean := False;
      Count    : Natural := 0;
      Bad      : Natural := 0;
   begin
      Open (F, In_File, Dir & "/" & Name);
      declare
         Msg_Hex : String (1 .. 1_000_000);
         Msg_Len : Natural := 0;
      begin
         while not End_Of_File (F) loop
            declare
               Line : constant String := Get_Line (F);
            begin
               if Field (Line, "Len") /= "" then
                  Len_Bits := Natural'Value (Field (Line, "Len"));
                  Have_Len := True;
               elsif Field (Line, "Msg") /= "" then
                  declare
                     V : constant String := Field (Line, "Msg");
                  begin
                     Msg_Len := V'Length;
                     Msg_Hex (1 .. Msg_Len) := V;
                  end;
               elsif Field (Line, "MD") /= "" and then Have_Len then
                  declare
                     Want  : constant S.Digest := Digest_Of_Hex (Field (Line, "MD"));
                     --  Len = 0 vectors carry "Msg = 00" but mean the empty message
                     Hex   : constant String :=
                       (if Len_Bits = 0 then "" else Msg_Hex (1 .. Msg_Len));
                     M     : constant Byte_Seq := From_Hex (Hex);
                     Got   : S.Digest;
                     OK    : Boolean;
                  begin
                     Count := Count + 1;
                     if Natural (M'Length) * 8 /= Len_Bits then
                        Put_Line ("FAIL: " & Name & " Len=" & Len_Bits'Image
                                  & " message length mismatch");
                        Bad := Bad + 1;
                     else
                        S.Hash (Got, M);
                        OK := Got = Want;
                        if OK and then M'Length > 0 then
                           OK := Streamed (M, 1) = Want
                             and then Streamed (M, 7) = Want
                             and then Streamed (M, 64) = Want;
                        end if;
                        if not OK then
                           Put_Line ("FAIL: " & Name & " Len=" & Len_Bits'Image);
                           Bad := Bad + 1;
                        end if;
                     end if;
                     Have_Len := False;
                  end;
               end if;
            end;
         end loop;
      end;
      Close (F);
      if Bad = 0 and then Count > 0 then
         Put_Line ("PASS: " & Name & " (" & Count'Image & " vectors, one-shot + streamed)");
         Pass := Pass + 1;
      else
         Put_Line ("FAIL: " & Name & " (" & Bad'Image & " of" & Count'Image & " failed)");
         Fail := Fail + 1;
      end if;
   exception
      when Name_Error =>
         Put_Line ("SKIP: " & Name & " (no " & Dir & "/" & Name
                   & "; run tests/cavp/fetch_sha.sh)");
      when E : others =>
         Put_Line ("FAIL: " & Name & " (error reading " & Dir & "/" & Name & ": "
                   & Ada.Exceptions.Exception_Information (E) & ")");
         Fail := Fail + 1;
   end Run_Msg_File;

   ----------------------------------------------------------------------------
   --  Monte Carlo (SHAVS 6.4): 100 checkpoints of 1000 chained hashes
   ----------------------------------------------------------------------------

   procedure Run_Monte (Name : String) is
      F         : File_Type;
      Seed      : S.Digest := (others => 0);
      Have_Seed : Boolean := False;
      Count     : Natural := 0;
      Bad       : Natural := 0;
   begin
      Open (F, In_File, Dir & "/" & Name);
      while not End_Of_File (F) loop
         declare
            Line : constant String := Get_Line (F);
         begin
            if Field (Line, "Seed") /= "" then
               Seed := Digest_Of_Hex (Field (Line, "Seed"));
               Have_Seed := True;
            elsif Field (Line, "MD") /= "" and then Have_Seed then
               declare
                  Want : constant S.Digest := Digest_Of_Hex (Field (Line, "MD"));
                  MD0, MD1, MD2, MDi : S.Digest;
                  Mi : Byte_Seq (0 .. 59);
               begin
                  MD0 := Seed; MD1 := Seed; MD2 := Seed;
                  MDi := Seed;
                  for I in 3 .. 1002 loop
                     Mi (0 .. 19)  := MD0;
                     Mi (20 .. 39) := MD1;
                     Mi (40 .. 59) := MD2;
                     S.Hash (MDi, Mi);
                     MD0 := MD1; MD1 := MD2; MD2 := MDi;
                  end loop;
                  Count := Count + 1;
                  if MDi /= Want then
                     Put_Line ("FAIL: " & Name & " COUNT=" & Natural'Image (Count - 1));
                     Bad := Bad + 1;
                  end if;
                  Seed := MDi;
               end;
            end if;
         end;
      end loop;
      Close (F);
      if Bad = 0 and then Count = 100 then
         Put_Line ("PASS: " & Name & " (100 checkpoints)");
         Pass := Pass + 1;
      else
         Put_Line ("FAIL: " & Name & " (" & Bad'Image & " bad," & Count'Image & " checkpoints)");
         Fail := Fail + 1;
      end if;
   exception
      when Name_Error =>
         Put_Line ("SKIP: " & Name & " (no " & Dir & "/" & Name
                   & "; run tests/cavp/fetch_sha.sh)");
      when E : others =>
         Put_Line ("FAIL: " & Name & " (error reading " & Dir & "/" & Name & ": "
                   & Ada.Exceptions.Exception_Information (E) & ")");
         Fail := Fail + 1;
   end Run_Monte;

   --  FIPS 180-4 / RFC 3174 sanity vectors, independent of the files
   procedure Run_Fixed is
      ABC : constant Byte_Seq := From_Hex ("616263");
      D   : S.Digest;
   begin
      S.Hash (D, ABC);
      if D = Digest_Of_Hex ("a9993e364706816aba3e25717850c26c9cd0d89d") then
         Put_Line ("PASS: sha1(""abc"")");
         Pass := Pass + 1;
      else
         Put_Line ("FAIL: sha1(""abc"")");
         Fail := Fail + 1;
      end if;
      declare
         Empty : constant Byte_Seq (1 .. 0) := (others => 0);
      begin
         S.Hash (D, Empty);
         if D = Digest_Of_Hex ("da39a3ee5e6b4b0d3255bfef95601890afd80709") then
            Put_Line ("PASS: sha1("""")");
            Pass := Pass + 1;
         else
            Put_Line ("FAIL: sha1("""")");
            Fail := Fail + 1;
         end if;
      end;
   end Run_Fixed;

begin
   Run_Fixed;
   Run_Msg_File ("SHA1ShortMsg.rsp");
   Run_Msg_File ("SHA1LongMsg.rsp");
   Run_Monte ("SHA1Monte.rsp");
   Put_Line ("SHA-1 CAVP:" & Pass'Image & " passed," & Fail'Image & " failed");
end Test_SHA1_CAVP;
