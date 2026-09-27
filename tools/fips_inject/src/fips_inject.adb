--  fips_inject: write the module integrity MACs into a linked executable.
--
--  Usage: fips_inject <executable>
--
--  The library's linker script (ld/sparktls_fips.ld) gathers the module's
--  code into the section .fips_text and its read-only data into
--  .fips_rodata. At start-up SPARKTLS.Integrity recomputes HMAC-SHA-256
--  (zero key) over both, as loaded, and compares them with the 64 bytes in
--  .fips_hmac. This tool computes the same two MACs from the file and
--  writes them into .fips_hmac. It finds all three by section name, so it
--  works before or after strip(1), which removes the symbol table.
--
--  It refuses the binary if any dynamic relocation (RELA or RELR) lands in
--  a hashed range: the loader would rewrite those bytes and the check could
--  never pass. Exit status 0 on success, 1 on any error.
--
--  ELF64 little-endian only (x86-64 Linux).

with Ada.Command_Line;  use Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;       use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;       use Ada.Text_IO;
with Interfaces;        use Interfaces;
with SPARKNaCl;
with SPARKNaCl.MAC;
with SPARKNaCl.Hashing.SHA256;

procedure FIPS_Inject is

   Tool_Error : exception;

   procedure Fail (Msg : String) is
   begin
      Put_Line (Standard_Error, "fips_inject: " & Msg);
      raise Tool_Error;
   end Fail;

   type Bytes is array (Unsigned_64 range <>) of Unsigned_8;
   type Bytes_Access is access Bytes;

   Image : Bytes_Access;

   --  Little-endian readers over the file image, bounds-checked.
   function U (Off : Unsigned_64; Len : Unsigned_64) return Unsigned_64 is
      R : Unsigned_64 := 0;
   begin
      if Off + Len > Image'Length then
         Fail ("truncated ELF file");
      end if;
      for I in reverse 0 .. Len - 1 loop
         R := Shift_Left (R, 8) or Unsigned_64 (Image (Off + I));
      end loop;
      return R;
   end U;

   function U16 (Off : Unsigned_64) return Unsigned_64 is (U (Off, 2));
   function U32 (Off : Unsigned_64) return Unsigned_64 is (U (Off, 4));
   function U64 (Off : Unsigned_64) return Unsigned_64 is (U (Off, 8));

   SHT_SYMTAB : constant := 2;
   SHT_RELA   : constant := 4;
   SHT_RELR   : constant := 19;
   SHF_ALLOC  : constant := 2;

   type Section is record
      Name_Off, Kind, Flags, Addr, Offset, Size, Link, Entsize : Unsigned_64;
   end record;

   type Section_Array is array (Unsigned_64 range <>) of Section;
   type Section_Array_Access is access Section_Array;
   Sections : Section_Array_Access;
   Shstrndx : Unsigned_64;

   function C_String (Off : Unsigned_64) return String is
      Last : Unsigned_64 := Off;
   begin
      while Last < Image'Length and then Image (Last) /= 0 loop
         Last := Last + 1;
      end loop;
      declare
         S : String (1 .. Natural (Last - Off));
      begin
         for I in S'Range loop
            S (I) := Character'Val (Image (Off + Unsigned_64 (I) - 1));
         end loop;
         return S;
      end;
   end C_String;

   function Section_Name (S : Section) return String is
     (C_String (Sections (Shstrndx).Offset + S.Name_Off));

   procedure Read_File (Path : String) is
      F    : Ada.Streams.Stream_IO.File_Type;
      Size : constant Unsigned_64 := Unsigned_64 (Ada.Directories.Size (Path));
      Buf  : Stream_Element_Array (1 .. Stream_Element_Offset (Size));
      Last : Stream_Element_Offset;
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
      Ada.Streams.Stream_IO.Read (F, Buf, Last);
      Ada.Streams.Stream_IO.Close (F);
      if Last /= Buf'Last then
         Fail ("short read");
      end if;
      Image := new Bytes (0 .. Size - 1);
      for I in Buf'Range loop
         Image (Unsigned_64 (I - 1)) := Unsigned_8 (Buf (I));
      end loop;
   end Read_File;

   procedure Write_File (Path : String) is
      F   : Ada.Streams.Stream_IO.File_Type;
      Buf : Stream_Element_Array (1 .. Stream_Element_Offset (Image'Length));
   begin
      for I in Buf'Range loop
         Buf (I) := Stream_Element (Image (Unsigned_64 (I - 1)));
      end loop;
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.Out_File, Path);
      Ada.Streams.Stream_IO.Write (F, Buf);
      Ada.Streams.Stream_IO.Close (F);
   end Write_File;

   procedure Parse_Sections is
      Shoff     : constant Unsigned_64 := U64 (16#28#);
      Shentsize : constant Unsigned_64 := U16 (16#3A#);
      Shnum     : constant Unsigned_64 := U16 (16#3C#);
   begin
      if Image'Length < 64
        or else Image (0 .. 3) /= (16#7F#, Character'Pos ('E'), Character'Pos ('L'), Character'Pos ('F'))
      then
         Fail ("not an ELF file");
      end if;
      if Image (4) /= 2 or else Image (5) /= 1 then
         Fail ("only ELF64 little-endian is supported");
      end if;
      if Shentsize /= 64 or else Shnum = 0 then
         Fail ("unexpected section header table");
      end if;
      Shstrndx := U16 (16#3E#);
      Sections := new Section_Array (0 .. Shnum - 1);
      for I in Sections'Range loop
         declare
            H : constant Unsigned_64 := Shoff + I * Shentsize;
         begin
            Sections (I) :=
              (Name_Off => U32 (H),      Kind   => U32 (H + 4),
               Flags    => U64 (H + 8),  Addr   => U64 (H + 16),
               Offset   => U64 (H + 24), Size   => U64 (H + 32),
               Link     => U32 (H + 40), Entsize => U64 (H + 56));
         end;
      end loop;
      if Shstrndx > Sections'Last then
         Fail ("bad section name table index");
      end if;
   end Parse_Sections;

   --  The allocated section called Name; fails if absent.
   function Find_Section (Name : String) return Section is
   begin
      for S of Sections.all loop
         if (S.Flags and SHF_ALLOC) /= 0 and then Section_Name (S) = Name then
            return S;
         end if;
      end loop;
      Fail ("section " & Name & " not found (was the library's linker script used?)");
      return Sections (0);
   end Find_Section;

   --  File offset of a virtual address inside an allocated section.
   function File_Offset (Addr : Unsigned_64; Len : Unsigned_64) return Unsigned_64 is
   begin
      for S of Sections.all loop
         if (S.Flags and SHF_ALLOC) /= 0 and then S.Addr /= 0
           and then Addr >= S.Addr and then Addr + Len <= S.Addr + S.Size
         then
            return S.Offset + (Addr - S.Addr);
         end if;
      end loop;
      Fail ("range" & Addr'Image & " +" & Len'Image & " is not inside one section");
      return 0;
   end File_Offset;

   --  Every address the dynamic loader will write must be outside [Lo, Hi).
   procedure Check_No_Relocations (Lo, Hi : Unsigned_64; What : String) is
      procedure Hit (Where : Unsigned_64) is
      begin
         if Where >= Lo and then Where < Hi then
            Fail ("dynamic relocation at" & Where'Image & " inside the module's " & What);
         end if;
      end Hit;
   begin
      for S of Sections.all loop
         if (S.Flags and SHF_ALLOC) = 0 then
            null;
         elsif S.Kind = SHT_RELA and then S.Entsize = 24 then
            for I in 0 .. S.Size / 24 - 1 loop
               Hit (U64 (S.Offset + I * 24));
            end loop;
         elsif S.Kind = SHT_RELR and then S.Size > 0 then
            --  RELR (packed relative relocations): an even entry is an
            --  address; an odd entry is a bitmap for the 63 words after
            --  the previous run.
            declare
               Next : Unsigned_64 := 0;
            begin
               for I in 0 .. S.Size / 8 - 1 loop
                  declare
                     E : constant Unsigned_64 := U64 (S.Offset + I * 8);
                  begin
                     if (E and 1) = 0 then
                        Hit (E);
                        Next := E + 8;
                     else
                        for B in 1 .. 63 loop
                           if (Shift_Right (E, B) and 1) = 1 then
                              Hit (Next + Unsigned_64 (B - 1) * 8);
                           end if;
                        end loop;
                        Next := Next + 63 * 8;
                     end if;
                  end;
               end loop;
            end;
         end if;
      end loop;
   end Check_No_Relocations;

   --  HMAC-SHA-256 with a zero key over [Lo, Hi) as it sits in the file,
   --  the same computation SPARKTLS.Integrity makes over loaded memory.
   function Range_MAC (Lo, Hi : Unsigned_64; What : String) return SPARKNaCl.Byte_Seq is
      use SPARKNaCl;
      Len : constant Unsigned_64 := Hi - Lo;
      Off : Unsigned_64;
      Key : constant Byte_Seq (0 .. 31) := (others => 0);
      D   : Hashing.SHA256.Digest;
   begin
      if Hi <= Lo then
         Fail ("empty " & What & " range");
      end if;
      Check_No_Relocations (Lo, Hi, What);
      Off := File_Offset (Lo, Len);
      declare
         M : Byte_Seq (0 .. N32 (Len) - 1);
      begin
         for I in M'Range loop
            M (I) := Byte (Image (Off + Unsigned_64 (I)));
         end loop;
         MAC.HMAC_SHA_256 (D, M, Key);
      end;
      Put_Line (What & ":" & Len'Image & " bytes hashed");
      return Byte_Seq (D);
   end Range_MAC;

begin
   if Argument_Count /= 1 then
      Put_Line (Standard_Error, "usage: fips_inject <executable>");
      Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Read_File (Argument (1));
   Parse_Sections;
   declare
      use SPARKNaCl;
      Text   : constant Section := Find_Section (".fips_text");
      Rodata : constant Section := Find_Section (".fips_rodata");
      Slot_S : constant Section := Find_Section (".fips_hmac");
      Code_MAC : constant Byte_Seq := Range_MAC (Text.Addr, Text.Addr + Text.Size, "code");
      Data_MAC : constant Byte_Seq :=
        Range_MAC (Rodata.Addr, Rodata.Addr + Rodata.Size, "read-only data");
      MACs : constant Byte_Seq := Code_MAC & Data_MAC;
      Slot : Unsigned_64;
   begin
      if Slot_S.Size /= 64 then
         Fail (".fips_hmac is" & Slot_S.Size'Image & " bytes, expected 64");
      end if;
      Slot := File_Offset (Slot_S.Addr, 64);
      for I in MACs'Range loop
         Image (Slot + Unsigned_64 (I)) := Unsigned_8 (MACs (I));
      end loop;
   end;
   Write_File (Argument (1));
   Put_Line ("integrity MACs written to " & Argument (1));
exception
   when Tool_Error =>
      Set_Exit_Status (Ada.Command_Line.Failure);
end FIPS_Inject;
