with Interfaces; use Interfaces;
with SPARKNaCl.AES;
with SPARKTLS.AES_GCM;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.TLS_Record.TLS_Plaintext;
with RFLX.TLS_Record;
with RFLX.TLS_Common;

package body SPARKTLS.Records with
   SPARK_Mode => Off  --  TODO: enable incrementally
is
   --  Helper: 2-byte big-endian encoding (still used by Build_Encrypted_Record)
   function TS16 (U : Unsigned_16) return Byte_Seq is
      X : Byte_Seq (0 .. 1);
   begin
      X (0) := Byte (U / 256);
      X (1) := Byte (U mod 256);
      return X;
   end TS16;

   --  Helper: compute nonce by XOR-ing IV with 64-bit sequence number
   --  (RFC 8446 Section 5.3)
   function Make_Nonce
     (IV      : Bytes_12;
      Counter : Unsigned_64) return Bytes_12
   is
      Nonce : Bytes_12 := IV;
   begin
      --  XOR the 64-bit counter into the last 8 bytes of the 12-byte nonce
      for I in 0 .. 7 loop
         Nonce (N32 (4 + I)) := Nonce (N32 (4 + I)) xor
            Byte (Shift_Right (Counter, (7 - I) * 8) and 16#FF#);
      end loop;
      return Nonce;
   end Make_Nonce;

   --  Write bytes into output buffer
   procedure Write_To_Output
     (Output : in out IO_Buffer;
      Data   : in     Byte_Seq;
      OK     :    out Boolean)
   is
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
   end Write_To_Output;

   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   is
      use RFLX.TLS_Record.TLS_Plaintext;
      use RFLX.TLS_Record;
      use type RBT.Length;
      Frag_Len : N32;
   begin
      Result := (OK => False, others => <>);

      if Avail < Record_Header_Size then
         return;
      end if;

      declare
         Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Avail));
         Buf     : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
         Ctx     : Context;
      begin
         Buf_Arr := To_RFLX (Data (Data'First .. Data'First + N32 (Avail) - 1));
         Initialize (Ctx, Buf,
                     Written_Last => RBT.Bit_Length (RBT.Length (Avail) * 8));
         Verify_Message (Ctx);

         if Well_Formed_Message (Ctx) then
            Frag_Len := N32 (Get_Length (Ctx));

            --  Sanity: fragment must not exceed max record size
            if Frag_Len <= Max_Fragment + 256 and then
               Avail >= Record_Header_Size + Frag_Len
            then
               Result.OK           := True;
               Result.Fragment_Pos := Record_Header_Size;
               Result.Fragment_Len := Frag_Len;
               Result.Record_Len   := Record_Header_Size + Frag_Len;

               case Get_Tag (Ctx) is
                  when Handshake          => Result.Content := Content_Handshake;
                  when Alert              => Result.Content := Content_Alert;
                  when Application_Data   => Result.Content := Content_Application_Data;
                  when Change_Cipher_Spec => Result.Content := Content_Change_Cipher_Spec;
                  when others             => Result.Content := Content_Unknown;
               end case;
            end if;
         end if;

         Take_Buffer (Ctx, Buf);
      end;
   end Parse_Record_Header;

   procedure Build_Handshake_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   is
      use RFLX.TLS_Record.TLS_Plaintext;
      use RFLX.TLS_Record;
      use RFLX.TLS_Common;
      Total   : constant N32 := Record_Header_Size + N32 (Fragment'Length);
      Buf_Arr : aliased RBT.Bytes (1 .. RBT.Index (Total)) := (others => 0);
      Buf     : RBT.Bytes_Ptr := Buf_Arr'Unrestricted_Access;
      Ctx     : Context;
      OK      : Boolean;
   begin
      Bytes_Out := 0;

      Initialize (Ctx, Buf);

      Set_Prefix (Ctx, 0);
      Set_Tag (Ctx, Handshake);
      Set_Legacy_Record_Version (Ctx, TLS_1_0);
      Set_Length (Ctx, Plaintext_Length (Fragment'Length));
      Set_Fragment (Ctx, To_RFLX (Fragment));

      Take_Buffer (Ctx, Buf);
      Write_To_Output (Output, To_NaCl (Buf.all (1 .. RBT.Index (Total))), OK);

      if OK then
         Bytes_Out := Total;
      end if;
   end Build_Handshake_Record;

   procedure Build_Encrypted_Record
     (Plaintext    : in     Byte_Seq;
      Inner_Type   : in     Byte;
      Keys         : in out Traffic_Keys;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   is
      --  Build inner plaintext: payload + content type byte
      Inner_Len  : constant N32 := N32 (Plaintext'Length) + 1;
      Inner      : Byte_Seq (0 .. Inner_Len - 1);
      Ciphertext : Byte_Seq (0 .. Inner_Len - 1);
      Tag        : Bytes_16;
      Nonce      : Bytes_12;

      --  Record header (AAD for AEAD)
      --  Total encrypted record = ciphertext + 16-byte tag
      Enc_Len    : constant N32 := Inner_Len + Tag_Size;
      Hdr        : Byte_Seq (0 .. 4);
      OK         : Boolean;
   begin
      Bytes_Out := 0;

      --  Assemble inner plaintext
      Inner (0 .. N32 (Plaintext'Length) - 1) := Plaintext;
      Inner (Inner'Last) := Inner_Type;

      --  Build record header
      Hdr (0) := 16#17#;  --  application_data
      Hdr (1) := 16#03#;
      Hdr (2) := 16#03#;  --  TLS 1.2 for compatibility
      Hdr (3 .. 4) := TS16 (Unsigned_16 (Enc_Len));

      --  Compute nonce (same construction for all TLS 1.3 cipher suites)
      Nonce := Make_Nonce (Keys.IV, Keys.Counter);
      Keys.Counter := Keys.Counter + 1;

      --  Encrypt with the negotiated AEAD
      case Keys.Suite is
         when Suite_AES_128_GCM_SHA256 =>
            declare
               AES_Key : constant AES.AES128_Key :=
                  AES.Construct (Keys.Key (0 .. 15));
            begin
               AES_GCM.Encrypt
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Inner,
                  N   => Nonce,
                  K   => AES_Key,
                  AAD => Hdr);
            end;

         when Suite_AES_256_GCM_SHA384 =>
            declare
               AES_Key : constant AES.AES256_Key :=
                  AES.Construct (Keys.Key);
            begin
               AES_GCM.Encrypt_256
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Inner,
                  N   => Nonce,
                  K   => AES_Key,
                  AAD => Hdr);
            end;

         when others =>
            --  ChaCha20-Poly1305 (default, 0x1303)
            declare
               Key : constant ChaCha20_Key :=
                  SPARKNaCl.Core.Construct (Keys.Key);
            begin
               SPARKNaCl.Secretbox.Create
                 (C   => Ciphertext,
                  Tag => Tag,
                  M   => Inner,
                  N   => ChaCha20_IETF_Nonce (Nonce),
                  K   => Key,
                  AAD => Hdr);
            end;
      end case;

      --  Write header + ciphertext + tag
      Write_To_Output (Output, Hdr, OK);
      if not OK then return; end if;

      Write_To_Output (Output, Ciphertext, OK);
      if not OK then return; end if;

      Write_To_Output (Output, Tag, OK);
      if not OK then return; end if;

      Bytes_Out := Record_Header_Size + Enc_Len;
   end Build_Encrypted_Record;

   procedure Decrypt_Record
     (Encrypted   : in     Byte_Seq;
      Record_Hdr  : in     Byte_Seq;
      Keys        : in out Traffic_Keys;
      Plaintext   :    out Byte_Seq;
      Plain_Len   :    out N32;
      Inner_Type  :    out Byte;
      Valid       :    out Boolean)
   is
      --  Last 16 bytes are the AEAD tag
      Cipher_Len : constant N32 := N32 (Encrypted'Length) - Tag_Size;
      Tag        : Bytes_16;
      Nonce      : Bytes_12;
      Decrypted  : Byte_Seq (0 .. Cipher_Len - 1);
   begin
      Plaintext  := (others => 0);
      Plain_Len  := 0;
      Inner_Type := 0;
      Valid      := False;

      --  Extract tag (last 16 bytes)
      Tag := Bytes_16 (Encrypted (Cipher_Len .. Cipher_Len + 15));

      --  Compute nonce
      Nonce := Make_Nonce (Keys.IV, Keys.Counter);
      Keys.Counter := Keys.Counter + 1;

      --  Decrypt with the negotiated AEAD
      case Keys.Suite is
         when Suite_AES_128_GCM_SHA256 =>
            declare
               AES_Key : constant AES.AES128_Key :=
                  AES.Construct (Keys.Key (0 .. 15));
            begin
               AES_GCM.Decrypt
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => Encrypted (0 .. Cipher_Len - 1),
                  N      => Nonce,
                  K      => AES_Key,
                  AAD    => Record_Hdr);
            end;

         when Suite_AES_256_GCM_SHA384 =>
            declare
               AES_Key : constant AES.AES256_Key :=
                  AES.Construct (Keys.Key);
            begin
               AES_GCM.Decrypt_256
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => Encrypted (0 .. Cipher_Len - 1),
                  N      => Nonce,
                  K      => AES_Key,
                  AAD    => Record_Hdr);
            end;

         when others =>
            --  ChaCha20-Poly1305 (default, 0x1303)
            declare
               Key : constant ChaCha20_Key :=
                  SPARKNaCl.Core.Construct (Keys.Key);
            begin
               SPARKNaCl.Secretbox.Open
                 (M      => Decrypted,
                  Status => Valid,
                  Tag    => Tag,
                  C      => Encrypted (0 .. Cipher_Len - 1),
                  N      => ChaCha20_IETF_Nonce (Nonce),
                  K      => Key,
                  AAD    => Record_Hdr);
            end;
      end case;

      if not Valid then
         return;
      end if;

      --  Last byte of decrypted content is the inner content type
      --  (RFC 8446 Section 5.2)
      Inner_Type := Decrypted (Decrypted'Last);
      Plain_Len  := Cipher_Len - 1;

      Plaintext (0 .. Plain_Len - 1) := Decrypted (0 .. Plain_Len - 1);
   end Decrypt_Record;

   procedure Build_CCS_Record
     (Output    : in out IO_Buffer;
      Bytes_Out :    out N32)
   is
      CCS : constant Byte_Seq (0 .. 5) :=
         (16#14#, 16#03#, 16#03#, 16#00#, 16#01#, 16#01#);
      OK : Boolean;
   begin
      Write_To_Output (Output, CCS, OK);
      if OK then
         Bytes_Out := 6;
      else
         Bytes_Out := 0;
      end if;
   end Build_CCS_Record;

   procedure Build_Alert_Record
     (Level      : in     Byte;
      Desc       : in     Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   is
      Alert_Plaintext : Byte_Seq (0 .. 1) := (Level, Desc);
   begin
      --  Encrypt alert as application_data record with inner type = alert (21)
      Build_Encrypted_Record
        (Plaintext  => Alert_Plaintext,
         Inner_Type => 16#15#,
         Keys       => Keys,
         Output     => Output,
         Bytes_Out  => Bytes_Out);
   end Build_Alert_Record;

end SPARKTLS.Records;
