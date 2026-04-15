---------------------------------------------------------------------------
--  @summary
--  Base64 Encoding and Decoding Routines
--
--  @description
--  This package contains routines for encoding and decoding byte-oriented
--  messages to/from Base64 format.
---------------------------------------------------------------------------
package Base64
   with SPARK_Mode
is

   type Base64_String is new String
      with Dynamic_Predicate =>
         --  Require padding to make encoded length divisible by 4
         Base64_String'Length mod 4 = 0 and
         --  Only RFC 4648 allowed characters
         (for all I in Base64_String'Range =>
            Base64_String (I) in 'a'..'z' | 'A' .. 'Z' | 
                                 '0' .. '9' | '+' | '/' | '=') and
         --  Padding characters can only appear at the last 2 positions
         (for all I in Base64_String'Range =>
            (if Base64_String (I) = '=' then
               (I = Base64_String'Last or
                I = Base64_String'Last - 1))) and
         --  If the penultimate char is padding, then the last must be also
         (if Base64_String'Length > 2 and then
            Base64_String (Base64_String'Last - 1) = '=' then
            Base64_String (Base64_String'Last) = '=') and
         --  Only positive indices
         Base64_String'First = 1;

   ---------------------------------------------------------------------------
   -- Given an input string, determine whether it represents a valid Base64
   -- encoded message
   -- @param Input A String which may or may not be a Base64-encoded message
   -- @return True if Input is valid Base64, False otherwise
   ---------------------------------------------------------------------------
   function Validate (Input : String) return Boolean
      with Post =>
         (if ((Input'Length mod 4 = 0) and
         (for all C of Input =>
            C in 'a'..'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '/' | '=') and
         (for all I in Input'Range =>
            (if Input (I) = '=' then
               (I = Input'Last or
                I = Input'Last - 1))) and
         (if Input'Length > 2 and then
            Input (Input'Last - 1) = '=' then
            Input (Input'Last) = '=') and
         (Input'First = 1)) or
         (Input'Length = 0) then Validate'Result = True);

   ---------------------------------------------------------------------------
   -- Cast a String to a Base64_String type.
   -- @param Input A String containing only Base64 characters and padding
   -- @return The same string as a Base64_String type
   ---------------------------------------------------------------------------
   function Construct (Input : String) return Base64_String
      with Pre =>          
         --  Require padding to make encoded length divisible by 4
         Input'Length mod 4 = 0 and
         --  Only RFC 4648 allowed characters
         (for all C of Input =>
            C in 'a'..'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '/' | '=') and
         --  Padding characters can only appear at the last 2 positions
         (for all I in Input'Range =>
            (if Input (I) = '=' then
               (I = Input'Last or
                I = Input'Last - 1))) and
         --  If the penultimate char is padding, then the last must be also
         (if Input'Length > 2 and then
            Input (Input'Last - 1) = '=' then
            Input (Input'Last) = '=') and
         --  No negative indices
         Input'First = 1;

   ---------------------------------------------------------------------------
   -- Cast a Base64_String to a normal String type for printing, etc.
   -- @param Input A Base64_String
   -- @return The same Base64 characters as a String type
   ---------------------------------------------------------------------------   
   function To_String (Input : Base64_String) return String;

   ---------------------------------------------------------------------------
   -- Encode a string in Base 64 format
   -- @param Plain A string. This can contain non-printable characters.
   -- @return The Base64 encoded version of the input
   ---------------------------------------------------------------------------
   function Encode (Plain : String) return Base64_String
      with Pre => Long_Long_Integer (Plain'Length * 4) < 
                     Long_Long_Integer (Positive'Last) and
                  Plain'First = 1;

   ---------------------------------------------------------------------------
   -- Decode a Base64-encoded string
   -- @param Encoded A Base64 encoded piece of data
   -- @return The bytes (represented as a String) represented by the encoding
   ---------------------------------------------------------------------------
   function Decode (Encoded : Base64_String) return String;

end Base64;
