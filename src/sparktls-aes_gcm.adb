with Interfaces; use Interfaces;

package body SPARKTLS.AES_GCM with
   SPARK_Mode => Off  --  TODO: enable incrementally
is
   --================================================================
   --  GF(2^128) multiplication for GHASH (NIST SP 800-38D)
   --
   --  Elements are 128 bits stored as 16 bytes, big-endian bit order:
   --  bit 0 of the field element is the MSB of byte 0.
   --  Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
   --  Reduction constant R = 0xE1 in the high byte.
   --================================================================

   --  Right-shift a 128-bit value by 1 bit (big-endian byte order)
   procedure Shift_Right_1 (V : in out Bytes_16) is
      Carry : Byte := 0;
      Next_Carry : Byte;
   begin
      for I in 0 .. 15 loop
         Next_Carry := V (N32 (I)) and 1;
         V (N32 (I)) := Byte (Shift_Right (Unsigned_8 (V (N32 (I))), 1))
                         or Byte (Shift_Left (Unsigned_8 (Carry), 7));
         Carry := Next_Carry;
      end loop;
   end Shift_Right_1;

   --  Multiply two elements in GF(2^128)
   procedure GF128_Mul (Result : out Bytes_16;
                        X      : in  Bytes_16;
                        Y      : in  Bytes_16)
   is
      Z : Bytes_16 := (others => 0);
      V : Bytes_16 := X;
      LSB : Byte;
   begin
      for I in 0 .. 127 loop
         --  If bit I of Y is set (MSB-first ordering)
         if (Y (N32 (I / 8)) and
             Byte (Shift_Right (Unsigned_8 (16#80#), I mod 8))) /= 0
         then
            for J in 0 .. 15 loop
               Z (N32 (J)) := Z (N32 (J)) xor V (N32 (J));
            end loop;
         end if;

         --  Check LSB of V (bit 127 in big-endian bit numbering)
         LSB := V (15) and 1;

         --  Shift V right by 1
         Shift_Right_1 (V);

         --  If LSB was set, XOR with reduction polynomial
         --  R = 0xE1 || 0^120
         if LSB /= 0 then
            V (0) := V (0) xor 16#E1#;
         end if;
      end loop;

      Result := Z;
   end GF128_Mul;

   --================================================================
   --  GHASH: hash AAD and ciphertext for authentication
   --
   --  GHASH(H, A, C) where H is the hash subkey,
   --  A is additional data, C is ciphertext.
   --================================================================

   --  XOR a 16-byte block: Dst := Dst XOR Src
   procedure XOR_Block (Dst : in out Bytes_16;
                        Src : in     Bytes_16) is
   begin
      for I in 0 .. 15 loop
         Dst (N32 (I)) := Dst (N32 (I)) xor Src (N32 (I));
      end loop;
   end XOR_Block;

   procedure GHASH
     (Tag   :    out Bytes_16;
      H     : in     Bytes_16;
      AAD   : in     Byte_Seq;
      C     : in     Byte_Seq)
   is
      Y     : Bytes_16 := (others => 0);
      Block : Bytes_16;
      Pos   : N32;
      Remaining : N32;
   begin
      --  Process AAD in 16-byte blocks
      Pos := 0;
      while Pos + 16 <= N32 (AAD'Length) loop
         Block := Bytes_16 (AAD (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial AAD block (zero-padded)
      Remaining := N32 (AAD'Length) - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in 0 .. N32 (Remaining) - 1 loop
            Block (I) := AAD (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
      end if;

      --  Process ciphertext in 16-byte blocks
      Pos := 0;
      while Pos + 16 <= N32 (C'Length) loop
         Block := Bytes_16 (C (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial ciphertext block (zero-padded)
      Remaining := N32 (C'Length) - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in 0 .. N32 (Remaining) - 1 loop
            Block (I) := C (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
      end if;

      --  Final block: len(A) || len(C) in bits, as 64-bit big-endian
      Block := (others => 0);
      declare
         A_Bits : constant Unsigned_64 := Unsigned_64 (AAD'Length) * 8;
         C_Bits : constant Unsigned_64 := Unsigned_64 (C'Length) * 8;
      begin
         for I in 0 .. 7 loop
            Block (N32 (I)) :=
               Byte (Shift_Right (A_Bits, (7 - I) * 8) and 16#FF#);
            Block (N32 (8 + I)) :=
               Byte (Shift_Right (C_Bits, (7 - I) * 8) and 16#FF#);
         end loop;
      end;
      XOR_Block (Y, Block);
      GF128_Mul (Y, Y, H);

      Tag := Y;
   end GHASH;

   --  Increment the 32-bit counter in bytes 12..15 of a counter block
   procedure Increment_Counter (CB : in out Bytes_16) is
      Val : Unsigned_32;
   begin
      Val := Unsigned_32 (CB (12)) * 2**24 +
             Unsigned_32 (CB (13)) * 2**16 +
             Unsigned_32 (CB (14)) * 2**8 +
             Unsigned_32 (CB (15));
      Val := Val + 1;
      CB (12) := Byte (Shift_Right (Val, 24) and 16#FF#);
      CB (13) := Byte (Shift_Right (Val, 16) and 16#FF#);
      CB (14) := Byte (Shift_Right (Val, 8) and 16#FF#);
      CB (15) := Byte (Val and 16#FF#);
   end Increment_Counter;

   --================================================================
   --  AES-CTR: encrypt/decrypt using AES in counter mode
   --
   --  Counter block: Nonce (12 bytes) || Counter (4 bytes big-endian)
   --  Initial counter value is provided by caller.
   --================================================================

   procedure AES_CTR_128
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES128_Round_Keys;
      ICB     : in     Bytes_16)
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
   begin
      Output := (others => 0);

      while Pos + 16 <= N32 (Input'Length) loop
         --  Encrypt counter block
         AES.Cipher (Keystream, CB, K);

         --  XOR with input
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;

         --  Increment 32-bit counter (bytes 12..15, big-endian)
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      --  Handle final partial block
      Remaining := N32 (Input'Length) - Pos;
      if Remaining > 0 then
         AES.Cipher (Keystream, CB, K);
         for I in 0 .. N32 (Remaining) - 1 loop
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_128;

   --================================================================
   --  GCM Encrypt
   --================================================================

   procedure Encrypt
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
   begin
      --  Step 1: Compute hash subkey H = AES_K(0^128)
      AES.Cipher (H, Bytes_16'(others => 0), RK);

      --  Step 2: Build initial counter block J0 = Nonce || 0x00000001
      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      --  Step 3: Encrypt J0 for final tag XOR
      AES.Cipher (EJ0, J0, RK);

      --  Step 4: Encrypt plaintext with CTR starting at J0 + 1
      Increment_Counter (J0);
      AES_CTR_128 (C, M, RK, J0);

      --  Step 5: Compute GHASH over AAD and ciphertext
      GHASH (S, H, AAD, C);

      --  Step 6: Tag = GHASH XOR E(K, J0)
      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt;

   --================================================================
   --  GCM Decrypt
   --================================================================

   procedure Decrypt
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      M := (others => 0);
      Status := False;

      --  Step 1: Compute hash subkey H = AES_K(0^128)
      AES.Cipher (H, Bytes_16'(others => 0), RK);

      --  Step 2: Build initial counter block J0 = Nonce || 0x00000001
      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      --  Step 3: Encrypt J0 for tag verification
      AES.Cipher (EJ0, J0, RK);

      --  Step 4: Compute GHASH over AAD and ciphertext
      GHASH (S, H, AAD, C);

      --  Step 5: Compute expected tag
      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      --  Step 6: Constant-time tag comparison
      if not Equal (Computed_Tag, Tag) then
         return;
      end if;

      --  Step 7: Decrypt ciphertext
      Increment_Counter (J0);
      AES_CTR_128 (M, C, RK, J0);
      Status := True;
   end Decrypt;

   --================================================================
   --  AES-256-CTR
   --================================================================

   procedure AES_CTR_256
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES256_Round_Keys;
      ICB     : in     Bytes_16)
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
   begin
      Output := (others => 0);

      while Pos + 16 <= N32 (Input'Length) loop
         AES.Cipher (Keystream, CB, K);
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := N32 (Input'Length) - Pos;
      if Remaining > 0 then
         AES.Cipher (Keystream, CB, K);
         for I in 0 .. N32 (Remaining) - 1 loop
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_256;

   --================================================================
   --  AES-256-GCM Encrypt
   --================================================================

   procedure Encrypt_256
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
   begin
      AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      AES.Cipher (EJ0, J0, RK);

      Increment_Counter (J0);
      AES_CTR_256 (C, M, RK, J0);

      GHASH (S, H, AAD, C);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt_256;

   --================================================================
   --  AES-256-GCM Decrypt
   --================================================================

   procedure Decrypt_256
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      M := (others => 0);
      Status := False;

      AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      AES.Cipher (EJ0, J0, RK);

      GHASH (S, H, AAD, C);

      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      if not Equal (Computed_Tag, Tag) then
         return;
      end if;

      Increment_Counter (J0);
      AES_CTR_256 (M, C, RK, J0);
      Status := True;
   end Decrypt_256;

end SPARKTLS.AES_GCM;
