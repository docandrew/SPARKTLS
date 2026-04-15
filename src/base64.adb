with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

package body Base64 
   with SPARK_Mode
is

   --  Lookup table from RFC 4648 for Decoding Base 64
   type Decode_Table_Type is array (Character) of Unsigned_8;

   Decode_Table : constant Decode_Table_Type := (
      'A' => 0,
      'B' => 1,
      'C' => 2,
      'D' => 3,
      'E' => 4,
      'F' => 5,
      'G' => 6,
      'H' => 7,
      'I' => 8,
      'J' => 9,
      'K' => 10,
      'L' => 11,
      'M' => 12,
      'N' => 13,
      'O' => 14,
      'P' => 15,
      'Q' => 16,
      'R' => 17,
      'S' => 18,
      'T' => 19,
      'U' => 20,
      'V' => 21,
      'W' => 22,
      'X' => 23,
      'Y' => 24,
      'Z' => 25,
      'a' => 26,
      'b' => 27,
      'c' => 28,
      'd' => 29,
      'e' => 30,
      'f' => 31,
      'g' => 32,
      'h' => 33,
      'i' => 34,
      'j' => 35,
      'k' => 36,
      'l' => 37,
      'm' => 38,
      'n' => 39,
      'o' => 40,
      'p' => 41,
      'q' => 42,
      'r' => 43,
      's' => 44,
      't' => 45,
      'u' => 46,
      'v' => 47,
      'w' => 48,
      'x' => 49,
      'y' => 50,
      'z' => 51,
      '0' => 52,
      '1' => 53,
      '2' => 54,
      '3' => 55,
      '4' => 56,
      '5' => 57,
      '6' => 58,
      '7' => 59,
      '8' => 60,
      '9' => 61,
      '+' => 62,
      '/' => 63,
      '=' => 0,   -- Padding byte
      others => 255
   );

   --  Reverse lookup table for encoding
   type Unsigned_6 is new Unsigned_8 range 0 .. 63;

   type Encode_Table_Type is array (Unsigned_6) of Character;

   Encode_Table : constant Encode_Table_Type := (
      0  => 'A',
      1  => 'B',
      2  => 'C',
      3  => 'D',
      4  => 'E',
      5  => 'F',
      6  => 'G',
      7  => 'H',
      8  => 'I',
      9  => 'J',
      10 => 'K',
      11 => 'L',
      12 => 'M',
      13 => 'N',
      14 => 'O',
      15 => 'P',
      16 => 'Q',
      17 => 'R',
      18 => 'S',
      19 => 'T',
      20 => 'U',
      21 => 'V',
      22 => 'W',
      23 => 'X',
      24 => 'Y',
      25 => 'Z',
      26 => 'a',
      27 => 'b',
      28 => 'c',
      29 => 'd',
      30 => 'e',
      31 => 'f',
      32 => 'g',
      33 => 'h',
      34 => 'i',
      35 => 'j',
      36 => 'k',
      37 => 'l',
      38 => 'm',
      39 => 'n',
      40 => 'o',
      41 => 'p',
      42 => 'q',
      43 => 'r',
      44 => 's',
      45 => 't',
      46 => 'u',
      47 => 'v',
      48 => 'w',
      49 => 'x',
      50 => 'y',
      51 => 'z',
      52 => '0',
      53 => '1',
      54 => '2',
      55 => '3',
      56 => '4',
      57 => '5',
      58 => '6',
      59 => '7',
      60 => '8',
      61 => '9',
      62 => '+',
      63 => '/'
   );

   function Validate (Input : String) return Boolean is
   begin
      if ((Input'Length mod 4 = 0) and
         (for all C of Input =>
            C in 'a'..'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '/' | '=') and
         (for all I in Input'Range =>
            (if Input (I) = '=' then
               (I = Input'Last or
                I = Input'Last - 1))) and
         (if Input'Length > 2 and then
            Input (Input'Last - 1) = '=' then
            Input (Input'Last) = '=') and
         (Input'First = 1)) or Input'Length = 0 then

         return True;
      else
         return False;
      end if;
   end Validate;

   function Construct (Input : String) return Base64_String is
   begin
      return Base64_String (Input);
   end Construct;

   function To_String (Input : Base64_String) return String is
   begin
      return String (Input);
   end To_String;

   function Encode (Plain : String) return Base64_String is

      --  Fwd declare & contract
      function Encoded_Length (P : String) return Natural
         with Pre => Long_Long_Integer (P'Length * 4) <
                        Long_Long_Integer (Positive'Last),
              Post => Encoded_Length'Result <= P'Length * 4 / 3 + 3 and
                      (if P'Length = 0 then Encoded_Length'Result = 0) and
                      (if P'Length > 0 then Encoded_Length'Result >= 4) and
                      Encoded_Length'Result mod 4 = 0;

      --  Every 3 input chars will have 4 output chars, rounded up to next 4
      function Encoded_Length (P : String) return Natural is
         Unpadded  : Natural := (P'Length * 4) / 3;
         Remainder : Natural := Unpadded mod 4;
      begin
         if P'Length = 0 then
            return 0;
         end if;

         if Remainder = 0 then
            return Unpadded;
         else
            return Unpadded + 4 - Remainder;
         end if;
      end Encoded_Length;

      --  Assignment needed to abide by type predicate
      Result  : Base64_String (1 .. Encoded_Length (Plain)) := (others => 'A');
      In_Idx  : Natural := Plain'First;
      Out_Idx : Natural := Result'First;

      B1 : Unsigned_8;
      B2 : Unsigned_8;
      B3 : Unsigned_8;

      S1 : Unsigned_6;
      S2 : Unsigned_6;
      S3 : Unsigned_6;
      S4 : Unsigned_6;
   begin
      if Plain'Length = 0 then
         return Construct ("");
      end if;

      loop
         B1 := Character'Pos (Plain (In_Idx));

         B2 := (if In_Idx + 1 > Plain'Last then 0 else
                  Character'Pos (Plain (In_Idx + 1)));

         B3 := (if In_Idx + 2 > Plain'Last then 0 else
                  Character'Pos (Plain (In_Idx + 2)));

         S1 := Unsigned_6 (Shift_Right (B1, 2));
         S2 := Unsigned_6 ((Shift_Left (B1, 4) or Shift_Right (B2, 4))
                           and 16#3F#);
         S3 := Unsigned_6 ((Shift_Left (B2, 2) or Shift_Right (B3, 6)) 
                           and 16#3F#);
         S4 := Unsigned_6 (B3 and 16#3F#);

         Result (Out_Idx)     := Encode_Table (S1);
         Result (Out_Idx + 1) := Encode_Table (S2);
         Result (Out_Idx + 2) := Encode_Table (S3);
         Result (Out_Idx + 3) := Encode_Table (S4);

         In_Idx  := In_Idx + 3;
         Out_Idx := Out_Idx + 4;

         exit when In_Idx > Plain'Last or Out_Idx + 3 > Result'Last;

         --  pragma Loop_Invariant (In_Idx in Plain'Range);
         pragma Loop_Invariant (In_Idx in Plain'Range and then
                                Out_Idx in Result'Range and then
                                Out_Idx + 3 in Result'Range);
      end loop;

      --  Replace last 2 chars with padding if warranted
      if Plain'Length mod 3 = 1 then
         Result (Result'Last - 1 .. Result'Last) := "==";
      elsif Plain'Length mod 3 = 2 then
         Result (Result'Last) := '=';
      end if;

      -- Put_Line ("Result: " & To_String (Result));
      return Result;
   end Encode;

   function Decode (Encoded : Base64_String) return String is

      --  Fwd declare
      function Decoded_Length (S : Base64_String) return Natural with
         Post => Decoded_Length'Result <= (S'Length / 4) * 3;

      --  Determine the length of the output string. We need this because
      --  we're going to stack allocate the return value.
      function Decoded_Length (S : Base64_String) return Natural is
         Padding_Bytes : Natural := 0;
         
         --  Every 4 Encoded characters is 3 output bytes.
         Output_Len : Natural := (S'Length / 4) * 3;
      begin
         if S'Length = 0 then
            return 0;
         end if;

         --  Subtract padding bytes
         if S (S'Last) = '=' then
            Padding_Bytes := Padding_Bytes + 1;
         end if;

         if S (S'Last - 1) = '=' then
            Padding_Bytes := Padding_Bytes + 1;
         end if;

         return Output_Len - Padding_Bytes;
      end Decoded_Length;

      --  Reserve a byte for every encoded char/sextet
      type BArr is array (Encoded'Range) of Unsigned_8;

      Sextets : BArr;
      Result  : String (1 .. Decoded_Length (Encoded));

      In_Idx  : Natural := Sextets'First;
      SHL     : Natural;
      SHR     : Natural;
   begin
      if Encoded'Length = 0 then
         return "";
      end if;

      for I in Sextets'Range loop
         Sextets (I) := Decode_Table (Encoded (I));
      end loop;

      for I in Result'Range loop
         SHL := (if I mod 3 = 0 then 6 elsif I mod 3 = 1 then 2 else 4);
         SHR := 6 - SHL;

         Result (I) := Character'Val (Shift_Left  (Sextets (In_Idx), SHL) or
                                      Shift_Right (Sextets (In_Idx + 1), SHR));

         -- Every 3 bytes, jump to the next set of 4 input sextets.
         In_Idx := (if I mod 3 = 0 then In_Idx + 2 else In_Idx + 1);

         pragma Loop_Invariant (I <= (Encoded'Last / 4) * 3);
         pragma Loop_Invariant (Long_Long_Integer (In_Idx) <= 
                                  Long_Long_Integer (I) * 4 / 3 + 1);
         pragma Loop_Invariant (In_Idx >= I);
         pragma Loop_Invariant (I in Result'Range);
      end loop;

      return Result;
   end Decode;

end Base64;
