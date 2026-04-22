with Interfaces; use Interfaces;

package body SPARKTLS.AES_GCM with
   SPARK_Mode => On
is
   --================================================================
   --  GF(2^128) multiplication for GHASH (NIST SP 800-38D)
   --  Bit-by-bit method: 128 iterations.
   --  Profiling shows GHASH is ~2% of handshake time — not a bottleneck.
   --================================================================

   procedure GF128_Mul (Result : out Bytes_16;
                        X      : in  Bytes_16;
                        Y      : in  Bytes_16)
   is
      --  Bit-by-bit GF(2^128) multiplication (simple, correct reference).
      --  TODO: Replace with 4-bit table method after validating with test vectors.
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

      Result := Z;
   end GF128_Mul;

   --================================================================
   --  GHASH
   --================================================================

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
   with Pre => AAD'First = 0 and AAD'Last < N32'Last and
               C'First = 0 and C'Last < N32'Last
   is
      Y     : Bytes_16 := (others => 0);
      Block : Bytes_16 := (others => 0);
      Pos   : N32;
      Remaining : N32;
      AAD_Len : constant N32 := N32 (AAD'Length);
      C_Len   : constant N32 := N32 (C'Length);
   begin
      --  Process AAD in 16-byte blocks
      Pos := 0;
      while AAD_Len >= 16 and then Pos <= AAD_Len - 16 loop
         pragma Loop_Invariant (Pos <= AAD_Len - 16 and Pos mod 16 = 0);
         Block := Bytes_16 (AAD (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial AAD block (zero-padded)
      Remaining := AAD_Len - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= AAD'Last);
            Block (I) := AAD (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
      end if;

      --  Process ciphertext in 16-byte blocks
      Pos := 0;
      while C_Len >= 16 and then Pos <= C_Len - 16 loop
         pragma Loop_Invariant (Pos <= C_Len - 16 and Pos mod 16 = 0);
         Block := Bytes_16 (C (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial ciphertext block (zero-padded)
      Remaining := C_Len - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= C'Last);
            Block (I) := C (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         GF128_Mul (Y, Y, H);
      end if;

      --  Final block: len(A) || len(C) in bits, as 64-bit big-endian
      Block := (others => 0);
      declare
         A_Bits : constant Unsigned_64 := Unsigned_64 (AAD_Len) * 8;
         C_Bits : constant Unsigned_64 := Unsigned_64 (C_Len) * 8;
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
   --  AES-CTR
   --================================================================

   procedure AES_CTR_128
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES128_Round_Keys;
      ICB     : in     Bytes_16)
   with Pre => Output'First = 0 and Input'First = 0 and
               Output'Last = Input'Last and
               Input'Last < N32'Last
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      In_Len    : constant N32 := N32 (Input'Length);
   begin
      Output := (others => 0);

      while In_Len >= 16 and then Pos <= In_Len - 16 loop
         pragma Loop_Invariant (Pos <= In_Len - 16 and Pos mod 16 = 0);
         AES.Cipher (Keystream, CB, K);
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := In_Len - Pos;
      if Remaining > 0 then
         AES.Cipher (Keystream, CB, K);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= Input'Last);
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_128;

   procedure AES_CTR_256
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES256_Round_Keys;
      ICB     : in     Bytes_16)
   with Pre => Output'First = 0 and Input'First = 0 and
               Output'Last = Input'Last and
               Input'Last < N32'Last
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      In_Len    : constant N32 := N32 (Input'Length);
   begin
      Output := (others => 0);

      while In_Len >= 16 and then Pos <= In_Len - 16 loop
         pragma Loop_Invariant (Pos <= In_Len - 16 and Pos mod 16 = 0);
         AES.Cipher (Keystream, CB, K);
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := In_Len - Pos;
      if Remaining > 0 then
         AES.Cipher (Keystream, CB, K);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= Input'Last);
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_256;

   --================================================================
   --  GCM Encrypt / Decrypt (AES-128)
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
      AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      AES.Cipher (EJ0, J0, RK);

      Increment_Counter (J0);
      AES_CTR_128 (C, M, RK, J0);

      GHASH (S, H, AAD, C);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt;

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

      AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      AES.Cipher (EJ0, J0, RK);

      GHASH (S, H, AAD, C);

      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      --  Constant-time tag comparison (prevents timing oracle
      --  that would allow tag forgery detection)
      if not Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag)) then
         return;
      end if;

      Increment_Counter (J0);
      AES_CTR_128 (M, C, RK, J0);
      Status := True;
   end Decrypt;

   --================================================================
   --  GCM Encrypt / Decrypt (AES-256)
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

      --  Constant-time tag comparison
      if not Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag)) then
         return;
      end if;

      Increment_Counter (J0);
      AES_CTR_256 (M, C, RK, J0);
      Status := True;
   end Decrypt_256;

end SPARKTLS.AES_GCM;
