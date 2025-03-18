with Ada.Text_IO; use Ada.Text_IO;
with Ada.Assertions; use Ada.Assertions;
with Interfaces; use Interfaces;

with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;

with Test_SPARKTLS_Extensions; use Test_SPARKTLS_Extensions;

procedure Test_SPARKTLS is

   procedure Test_To_Byte_Seq is
      U : U16 := 258;
      Result : SPARKTLS.Bytes_2;
   begin
      Result := SPARKTLS.To_Byte_Seq(U);
      Put_Line("Test_To_Byte_Seq: " & Result(0)'Image & ", " & Result(1)'Image);
      pragma Assert(Result(0) = 1 and Result(1) = 2);
   end Test_To_Byte_Seq;

   procedure Test_To_Byte_Seq_3 is
      U : U24 := 65793; -- 0x010101
      Result : SPARKTLS.Bytes_3;
   begin
      Result := SPARKTLS.To_Byte_Seq_3(U);
      Put_Line("Test_To_Byte_Seq_3: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image);
      pragma Assert(Result(0) = 1 and Result(1) = 1 and Result(2) = 1);
   end Test_To_Byte_Seq_3;

   procedure Test_To_U16 is
      I : Bytes_2 := (2, 1);
      Result : U16;
   begin
      Result := To_U16(I);
      Put_Line("Test_To_U16: " & U16'Image(Result));
      pragma Assert(Result = 513);
   end Test_To_U16;

   procedure Test_To_U32 is
      I : Bytes_3 := (1, 1, 1);
      Result : U32;
   begin
      Result := To_U32(I);
      Put_Line("Test_To_U32: " & U32'Image(Result));
      pragma Assert(Result = 65793);
   end Test_To_U32;

   procedure Test_TLV is
      Tag : Tag_8 := 1;
      Msg : Byte_Seq := (2, 3, 4);
      Result : Byte_Seq := TLV (Tag, Msg);
   begin
      Put_Line("Test_TLV: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image);
      pragma Assert(Result = (1, 0, 3, 2, 3, 4));
   end Test_TLV;

   procedure Test_TLV_2 is
      Tag : Tag_16 := 258;
      Msg : Byte_Seq := (2, 3, 4);
      Result : Byte_Seq := TLV (Tag, Msg);
   begin
      Put_Line("Test_TLV_2: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " & Result(5)'Image);
      pragma Assert(Result = (1, 2, 0, 3, 2, 3, 4));
   end Test_TLV_2;

   procedure Test_TLV_String is
      Tag : Tag_8 := 1;
      Msg : String := "abc";
      Result : Byte_Seq := TLV (Tag, Msg);
   begin
      Put_Line("Test_TLV_String: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " & Result(5)'Image);
      pragma Assert(Result = (1, 0, 3, Character'Pos('a'), Character'Pos('b'), Character'Pos('c')));
   end Test_TLV_String;

   procedure Test_TLV_Handshake is
      Tag : Tag_8 := 1;
      Msg : Byte_Seq := (2, 3, 4);
      Result : Byte_Seq := TLV_Handshake (Tag, Msg);
   begin
      Put_Line("Test_TLV_Handshake: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image);
      pragma Assert(Result = (1, 0, 3, 2, 3, 4));
   end Test_TLV_Handshake;

   procedure Test_TLV_Record is
      Tag : Tag_8 := 1;
      Msg : Byte_Seq := (2, 3, 4);
      Result : Byte_Seq := TLV_Record (Tag, Msg);
   begin
      Put_Line("Test_TLV_Record: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image);
      pragma Assert(Result = (1, 0, 3, 2, 3, 4));
   end Test_TLV_Record;

   procedure Test_LV is
      Msg : Byte_Seq := (2, 3, 4);
      Result : Byte_Seq := LV (Msg);
   begin
      Put_Line("Test_LV: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image);
      pragma Assert(Result = (0, 3, 2, 3, 4));
   end Test_LV;

begin
   -- Basic type and conversion tests
   Test_To_Byte_Seq;
   Test_To_Byte_Seq_3;
   Test_To_U16;
   Test_To_U32;
   Test_TLV;
   Test_TLV_2;
   Test_TLV_String;
   Test_TLV_Handshake;
   Test_TLV_Record;
   Test_LV;

   Test_SPARKTLS_Extensions.Run_Tests;

end Test_SPARKTLS;