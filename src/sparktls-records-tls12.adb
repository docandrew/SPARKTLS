with Interfaces;             use Interfaces;
with SPARKNaCl.AES;
with SPARKNaCl.Core;         use SPARKNaCl.Core;
with SPARKNaCl.Secretbox;
with SPARKTLSCrypto.AES_GCM;
use SPARKTLSCrypto;

--  TLS 1.2 Record Layer — AEAD (GCM + ChaCha20-Poly1305)
--
--  Key differences from TLS 1.3 (sparktls-records.adb):
--
--    Nonce:   TLS 1.2 = implicit_IV[4] || seq_num[8]
--             TLS 1.3 = IV[12] XOR counter
--
--    AAD:     TLS 1.2 = seq_num[8] || type[1] || version[2] || plaintext_len[2]
--             TLS 1.3 = record header (type[1] || version[2] || ciphertext_len[2])
--
--    Record:  TLS 1.2 = header[5] || explicit_nonce[8] || ciphertext || tag[16]
--             TLS 1.3 = header[5] || ciphertext || tag[16]
--
--    Content: TLS 1.2 = no inner content type, no zero padding
--             TLS 1.3 = inner content type byte + optional zero padding
package body SPARKTLS.Records.TLS12 with
   SPARK_Mode => On
is
   use SPARKNaCl.AES;

   --  Helper: 2-byte big-endian encoding
   function TS16 (U : Unsigned_16) return Byte_Seq
   with Post => TS16'Result'First = 0 and TS16'Result'Length = 2
   is
      X : Byte_Seq (0 .. 1) := (others => 0);
   begin
      X (0) := Byte (U / 256);
      X (1) := Byte (U mod 256);
      return X;
   end TS16;

   --  Helper: write bytes into output buffer
   procedure Write_To_Output
     (Output : in out IO_Buffer;
      Data   : in     Byte_Seq;
      OK     :    out Boolean)
   with Pre => Data'First = 0 and Data'Last < N32'Last
   is
   begin
      if Data'Length = 0 then
         OK := True;
         return;
      end if;

      declare
         Len : constant N32 := N32 (Data'Length);
      begin
         if Free_Space (Output) >= Len then
            Output.Data (Output.Write_Pos .. Output.Write_Pos + Len - 1) :=
               Data;
            Output.Write_Pos := Output.Write_Pos + Len;
            OK := True;
         else
            OK := False;
         end if;
      end;
   end Write_To_Output;

   --  RFC 5288 §3: Construct 12-byte GCM nonce from 4-byte implicit IV
   --  and 8-byte sequence number (big-endian).
   --  nonce = implicit_IV[4] || seq_num[8]
   function Make_Nonce_12
     (Implicit_IV : Byte_Seq;
      Seq_Num     : Unsigned_64) return Bytes_12
   is
      Nonce : Bytes_12 := (others => 0);
   begin
      --  First 4 bytes: implicit IV (from key expansion)
      Nonce (0) := Implicit_IV (Implicit_IV'First);
      Nonce (1) := Implicit_IV (Implicit_IV'First + 1);
      Nonce (2) := Implicit_IV (Implicit_IV'First + 2);
      Nonce (3) := Implicit_IV (Implicit_IV'First + 3);

      --  Last 8 bytes: sequence number (big-endian)
      for I in 0 .. 7 loop
         Nonce (N32 (4 + I)) :=
            Byte (Shift_Right (Seq_Num, (7 - I) * 8) and 16#FF#);
      end loop;

      return Nonce;
   end Make_Nonce_12;

   --  RFC 5246 §6.2.3.3: Build the 13-byte AAD for AEAD.
   --  additional_data = seq_num[8] || type[1] || version[2] || length[2]
   --  where length = PLAINTEXT length (not ciphertext)
   function Build_AAD
     (Seq_Num       : Unsigned_64;
      Content_Type  : Byte;
      Plaintext_Len : N32) return Byte_Seq
   with Pre  => Plaintext_Len <= Max_Record_Plaintext,
        Post => Build_AAD'Result'First = 0
                and Build_AAD'Result'Last = AAD_Len - 1
   is
      AAD : Byte_Seq (0 .. AAD_Len - 1) := (others => 0);
   begin
      --  Bytes 0..7: sequence number (big-endian)
      for I in 0 .. 7 loop
         AAD (N32 (I)) :=
            Byte (Shift_Right (Seq_Num, (7 - I) * 8) and 16#FF#);
      end loop;

      --  Byte 8: content type
      AAD (8) := Content_Type;

      --  Bytes 9..10: version (0x0303 = TLS 1.2)
      AAD (9)  := TLS12_Version_Major;
      AAD (10) := TLS12_Version_Minor;

      --  Bytes 11..12: plaintext length (big-endian)
      AAD (11) := Byte (Plaintext_Len / 256);
      AAD (12) := Byte (Plaintext_Len mod 256);

      return AAD;
   end Build_AAD;

   --  Encode sequence number as 8-byte big-endian explicit nonce
   function Seq_To_Bytes (Seq : Unsigned_64) return Byte_Seq
   with Post => Seq_To_Bytes'Result'First = 0
                and Seq_To_Bytes'Result'Last = 7;

   function Seq_To_Bytes (Seq : Unsigned_64) return Byte_Seq is
      B : Byte_Seq (0 .. 7) := (others => 0);
   begin
      for I in 0 .. 7 loop
         B (N32 (I)) :=
            Byte (Shift_Right (Seq, (7 - I) * 8) and 16#FF#);
      end loop;
      return B;
   end Seq_To_Bytes;

   ------------------------------------------------------------------
   --  Build_Encrypted_Record_12
   ------------------------------------------------------------------

   procedure Build_Encrypted_Record_12
     (Plaintext    : in     Byte_Seq;
      Content_Type : in     Byte;
      Keys         : in     Traffic_Keys;
      Implicit_IV  : in     Byte_Seq;
      Seq_Num      : in out Unsigned_64;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   is
      pragma Assert (Plaintext'Last < Max_Record_Plaintext);
      PT_Len : constant N32 := N32 (Plaintext'Length);

      --  Output = header[5] + explicit_nonce[8] + ciphertext[PT_Len] + tag[16]
      Total  : constant N32 :=
         Record_Header_Size + Explicit_Nonce_Len + PT_Len + GCM_Tag_Len;

      --  Record header: fragment_length = explicit_nonce + ciphertext + tag
      Frag_Len : constant N32 := Explicit_Nonce_Len + PT_Len + GCM_Tag_Len;

      Nonce      : Bytes_12;
      AAD        : Byte_Seq (0 .. AAD_Len - 1);
      Ciphertext : Byte_Seq (0 .. Plaintext'Last) := (others => 0);
      Tag        : Bytes_16;
      Hdr        : Byte_Seq (0 .. 4) := (others => 0);
      Exp_Nonce  : Byte_Seq (0 .. 7);
      OK         : Boolean;
   begin
      Bytes_Out := 0;

      --  Build 12-byte nonce: implicit_IV[4] || seq_num[8]
      Nonce := Make_Nonce_12 (Implicit_IV, Seq_Num);

      --  Build 13-byte AAD with PLAINTEXT length (not ciphertext!)
      AAD := Build_AAD (Seq_Num, Content_Type, PT_Len);

      pragma Assert (Ciphertext'First = 0);
      pragma Assert (Ciphertext'Last = Plaintext'Last);

      --  Encrypt
      case Keys.Suite is
         when Suite_AES_128_GCM_SHA256 =>
            declare
               AES_Key : constant AES128_Key :=
                  Construct (Keys.Key (0 .. 15));
            begin
               AES_GCM.Encrypt
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Plaintext,
                  N   => Nonce,
                  K   => AES_Key,
                  AAD => AAD);
            end;

         when Suite_AES_256_GCM_SHA384 =>
            declare
               AES_Key : constant AES256_Key := Construct (Keys.Key);
            begin
               AES_GCM.Encrypt_256
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Plaintext,
                  N   => Nonce,
                  K   => AES_Key,
                  AAD => AAD);
            end;

         when others =>
            --  ChaCha20-Poly1305
            declare
               Key : constant ChaCha20_Key := Construct (Keys.Key);
            begin
               SPARKNaCl.Secretbox.Create
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Plaintext,
                  N   => ChaCha20_IETF_Nonce (Nonce),
                  K   => Key,
                  AAD => AAD);
            end;
      end case;

      --  Increment sequence number AFTER using it for nonce
      Seq_Num := Seq_Num + 1;

      --  Build record header: content_type || 0x0303 || fragment_length
      Hdr (0) := Content_Type;
      Hdr (1) := TLS12_Version_Major;
      Hdr (2) := TLS12_Version_Minor;
      Hdr (3 .. 4) := TS16 (Unsigned_16 (Frag_Len));

      --  Write: header || explicit_nonce || ciphertext || tag
      Write_To_Output (Output, Hdr, OK);
      if not OK then return; end if;

      Exp_Nonce := Seq_To_Bytes (Seq_Num - 1);  --  the seq we just used
      Write_To_Output (Output, Exp_Nonce, OK);
      if not OK then return; end if;

      Write_To_Output (Output, Ciphertext, OK);
      if not OK then return; end if;

      Write_To_Output (Output, Tag, OK);
      if not OK then return; end if;

      Bytes_Out := Total;
   end Build_Encrypted_Record_12;

   ------------------------------------------------------------------
   --  Decrypt_Record_12
   ------------------------------------------------------------------

   procedure Decrypt_Record_12
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in     Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
      Seq_Num     : in out Unsigned_64;
      Plaintext   :    out Byte_Seq;
      Plain_Len   :    out N32;
      Valid       :    out Boolean)
   is
      --  Encrypted layout: explicit_nonce[8] || ciphertext[N] || tag[16]
      --  Ciphertext length = total - 8 (nonce) - 16 (tag)
      CT_Len : constant N32 :=
         N32 (Encrypted'Length) - Explicit_Nonce_Len - GCM_Tag_Len;

      --  Extract explicit nonce (first 8 bytes) into 0-based buffer
      Exp_Nonce : Byte_Seq (0 .. 7) := (others => 0);

      Nonce : Bytes_12 := (others => 0);
      AAD   : Byte_Seq (0 .. AAD_Len - 1);
      Tag   : Bytes_16 := (others => 0);

      --  0-based copy of ciphertext for AEAD (requires First = 0)
      CT_Copy   : Byte_Seq (0 .. CT_Len - 1) := (others => 0);
      Decrypted : Byte_Seq (0 .. CT_Len - 1) := (others => 0);
   begin
      Plaintext := (others => 0);
      Plain_Len := 0;
      Valid := False;

      --  Defense-in-depth: verify input is large enough for nonce + tag
      if N32 (Encrypted'Length) < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
         return;
      end if;
      Valid     := False;

      --  Extract explicit nonce, ciphertext, and tag into 0-based buffers
      for I in N32 range 0 .. 7 loop
         Exp_Nonce (I) := Encrypted (I);
      end loop;
      for I in N32 range 0 .. CT_Len - 1 loop
         CT_Copy (I) := Encrypted (Explicit_Nonce_Len + I);
      end loop;
      for I in N32 range 0 .. 15 loop
         Tag (I) := Encrypted (Explicit_Nonce_Len + CT_Len + I);
      end loop;

      --  Build nonce: implicit_IV[4] || explicit_nonce[8]
      --  MUST be after Exp_Nonce extraction above!
      Nonce (0) := Implicit_IV (Implicit_IV'First);
      Nonce (1) := Implicit_IV (Implicit_IV'First + 1);
      Nonce (2) := Implicit_IV (Implicit_IV'First + 2);
      Nonce (3) := Implicit_IV (Implicit_IV'First + 3);
      for I in N32 range 0 .. 7 loop
         Nonce (4 + I) := Exp_Nonce (I);
      end loop;

      --  Build AAD: seq_num || content_type || version || plaintext_length
      --  Content type from record header byte 0
      --  Plaintext length = ciphertext length (no inner type byte in 1.2)
      AAD := Build_AAD (Seq_Num, Record_Hdr (Record_Hdr'First), CT_Len);

      --  Increment seq_num (always, even on failure — RFC 5246 §6.1)
      Seq_Num := Seq_Num + 1;

      --  Decrypt
      case Keys.Suite is
         when Suite_AES_128_GCM_SHA256 =>
            declare
               AES_Key : constant AES128_Key :=
                  Construct (Keys.Key (0 .. 15));
            begin
               AES_GCM.Decrypt
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => CT_Copy,
                  N      => Nonce,
                  K      => AES_Key,
                  AAD    => AAD);
            end;

         when Suite_AES_256_GCM_SHA384 =>
            declare
               AES_Key : constant AES256_Key := Construct (Keys.Key);
            begin
               AES_GCM.Decrypt_256
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => CT_Copy,
                  N      => Nonce,
                  K      => AES_Key,
                  AAD    => AAD);
            end;

         when others =>
            declare
               Key : constant ChaCha20_Key := Construct (Keys.Key);
            begin
               SPARKNaCl.Secretbox.Open
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => CT_Copy,
                  N      => ChaCha20_IETF_Nonce (Nonce),
                  K      => Key,
                  AAD    => AAD);
            end;
      end case;

      if not Valid then
         return;
      end if;

      --  TLS 1.2: no inner content type, no zero padding.
      --  The decrypted data IS the plaintext directly.
      Plain_Len := CT_Len;
      if CT_Len > 0 then
         Plaintext (0 .. CT_Len - 1) := Decrypted;
      end if;
   end Decrypt_Record_12;

   ------------------------------------------------------------------
   --  Build_Alert_Record_12
   ------------------------------------------------------------------

   procedure Build_Alert_Record_12
     (Level       : in     Byte;
      Desc        : in     Byte;
      Keys        : in     Traffic_Keys;
      Implicit_IV : in     Byte_Seq;
      Seq_Num     : in out Unsigned_64;
      Output      : in out IO_Buffer;
      Bytes_Out   :    out N32)
   is
      --  Alert payload: level[1] || description[1] = 2 bytes
      Alert : constant Byte_Seq (0 .. 1) := (0 => Level, 1 => Desc);
   begin
      Build_Encrypted_Record_12
        (Plaintext    => Alert,
         Content_Type => 16#15#,  --  alert
         Keys         => Keys,
         Implicit_IV  => Implicit_IV,
         Seq_Num      => Seq_Num,
         Output       => Output,
         Bytes_Out    => Bytes_Out);
   end Build_Alert_Record_12;

end SPARKTLS.Records.TLS12;
