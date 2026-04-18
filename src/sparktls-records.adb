with Interfaces; use Interfaces;
with SPARKNaCl.AES;
with SPARKTLS.AES_GCM;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with Ada.Unchecked_Deallocation;
with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.TLS_Alert;
with RFLX.TLS_Alert.Alert;
with RFLX.Tls_Parameters;
with RFLX.TLS_Record.TLS_Plaintext;
with RFLX.TLS_Record;
with RFLX.TLS_Common;

package body SPARKTLS.Records with
   SPARK_Mode => On
is
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

   --  Helper: compute nonce by XOR-ing IV with 64-bit sequence number
   function Make_Nonce
     (IV      : Bytes_12;
      Counter : Unsigned_64) return Bytes_12
   is
      Nonce : Bytes_12 := IV;
   begin
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

   procedure Parse_Record_Header
     (Data   : in     Byte_Seq;
      Avail  : in     N32;
      Result :    out Parse_Result)
   is
      --  TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
      --  Manual parsing replaces RFLX to eliminate 'Unrestricted_Access.
      Frag_Len : N32;
      B        : N32;
   begin
      Result := (OK => False, others => <>);

      if Avail < Record_Header_Size then
         return;
      end if;

      B := Data'First;

      --  Parse 2-byte fragment length (big-endian) from bytes 3..4
      Frag_Len := N32 (Data (B + 3)) * 256 + N32 (Data (B + 4));

      --  Determine content type and per-type length limit.
      --  RFC 8446 §5.1: plaintext fragment ≤ 2^14
      --  RFC 8446 §5.2: encrypted fragment ≤ 2^14 + 256
      declare
         Max_Len : constant N32 :=
           (if Data (B) = 16#17# then Max_Fragment + 256
            else Max_Fragment);
      begin
         if Frag_Len > Max_Len then
            Result.Overflow := True;
            return;
         end if;
      end;

      if Avail < Record_Header_Size + Frag_Len then
         return;  --  need more data
      end if;

      Result.Fragment_Pos := Record_Header_Size;
      Result.Fragment_Len := Frag_Len;
      Result.Record_Len   := Record_Header_Size + Frag_Len;

      case Data (B) is
         when 16#16# => Result.Content := Content_Handshake;
                         Result.OK := True;
         when 16#15# => Result.Content := Content_Alert;
                         Result.OK := True;
         when 16#17# => Result.Content := Content_Application_Data;
                         Result.OK := True;
         when 16#14# => Result.Content := Content_Change_Cipher_Spec;
                         Result.OK := True;
         when others  => null;  --  unknown content type, OK stays False
      end case;
   end Parse_Record_Header;

   procedure Build_Handshake_Record
     (Fragment   : in     Byte_Seq;
      Output     : in out IO_Buffer;
      Bytes_Out  :    out N32)
   is
      --  TLS record: type(1) + version(2) + length(2) + fragment
      --  Manual construction replaces RFLX to eliminate 'Unrestricted_Access.
      Frag_Len : constant N32 := N32 (Fragment'Length);
      Hdr      : Byte_Seq (0 .. 4) := (others => 0);
      OK       : Boolean;
   begin
      Bytes_Out := 0;

      --  Build 5-byte header: Handshake (0x16) + TLS 1.2 (0x0303) + length
      --  RFC 8446 §5.1: SHOULD be 0x0303 for all records after ClientHello.
      --  RFC 5246 §6.2.1: record version = negotiated version (0x0303).
      Hdr (0) := 16#16#;  --  handshake
      Hdr (1) := 16#03#;
      Hdr (2) := 16#03#;  --  TLS 1.2 / 1.3 record layer version
      Hdr (3) := Byte (Frag_Len / 256);
      Hdr (4) := Byte (Frag_Len mod 256);

      Write_To_Output (Output, Hdr, OK);
      if not OK then return; end if;

      Write_To_Output (Output, Fragment, OK);
      if not OK then return; end if;

      Bytes_Out := Record_Header_Size + Frag_Len;
   end Build_Handshake_Record;

   procedure Build_Encrypted_Record
     (Plaintext    : in     Byte_Seq;
      Inner_Type   : in     Byte;
      Keys         : in out Traffic_Keys;
      Output       : in out IO_Buffer;
      Bytes_Out    :    out N32)
   is
      Inner_Len  : constant N32 := N32 (Plaintext'Length) + 1;
      Inner      : Byte_Seq (0 .. Inner_Len - 1) := (others => 0);
      Ciphertext : Byte_Seq (0 .. Inner_Len - 1) := (others => 0);
      Tag        : Bytes_16;
      Nonce      : Bytes_12;

      Enc_Len    : constant N32 := Inner_Len + Tag_Size;
      Hdr        : Byte_Seq (0 .. 4) := (others => 0);
      OK         : Boolean;
   begin
      Bytes_Out := 0;

      --  Assemble inner plaintext
      if Plaintext'Length > 0 then
         Inner (0 .. N32 (Plaintext'Length) - 1) := Plaintext;
      end if;
      Inner (Inner'Last) := Inner_Type;

      --  Build record header
      Hdr (0) := 16#17#;
      Hdr (1) := 16#03#;
      Hdr (2) := 16#03#;
      Hdr (3 .. 4) := TS16 (Unsigned_16 (Enc_Len));

      --  Compute nonce
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
      Cipher_Len : constant N32 := N32 (Encrypted'Length) - Tag_Size;
      Tag        : Bytes_16;
      Nonce      : Bytes_12;
      Decrypted  : Byte_Seq (0 .. Cipher_Len - 1) := (others => 0);
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

      --  RFC 8446 Section 5.4: Strip trailing zero padding, then
      --  extract the content type byte. The remaining bytes are the
      --  actual plaintext. If no non-zero byte is found, the record
      --  is invalid (zero-length inner plaintext).
      --  Constant-time padding removal: scan ALL bytes to find
      --  the last non-zero byte (content type). No early exit —
      --  prevents timing leaks of the padding length.
      declare
         Last_Nonzero : N32 := 0;
         Found        : Boolean := False;
      begin
         for I in N32 range 0 .. Cipher_Len - 1 loop
            if Decrypted (I) /= 0 then
               Last_Nonzero := I;
               Found := True;
            end if;
         end loop;

         if not Found then
            --  All zeros — content type is zero (invalid per RFC 8446 §5.4).
            --  AEAD succeeded but inner plaintext is all zeros.
            --  Return Valid = True, Inner_Type = 0, Plain_Len = 0.
            --  Caller checks Inner_Type and sends unexpected_message.
            Inner_Type := 0;
            Plain_Len := 0;
            --  Copy nothing to Plaintext (Plain_Len = 0)
            return;
         end if;

         Inner_Type := Decrypted (Last_Nonzero);
         Plain_Len  := Last_Nonzero;
         --  Last_Nonzero < Cipher_Len <= Encrypted'Length - Tag_Size
         --  Plaintext has same bounds as Encrypted
         pragma Assert (Plain_Len < Cipher_Len);

         --  RFC 8446 Section 5.4: content type must be valid.
         --  Only alert (0x15), handshake (0x16), and application_data (0x17).
         if Inner_Type not in 16#15# | 16#16# | 16#17# then
            Valid := False;
            return;
         end if;

         if Plain_Len > 0 and then Plain_Len - 1 <= Plaintext'Last then
            Plaintext (0 .. Plain_Len - 1) :=
               Decrypted (0 .. Plain_Len - 1);
         end if;
      end;
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
      Build_Encrypted_Record
        (Plaintext  => Alert_Plaintext,
         Inner_Type => 16#15#,
         Keys       => Keys,
         Output     => Output,
         Bytes_Out  => Bytes_Out);
   end Build_Alert_Record;

   procedure Build_Plaintext_Alert
     (Level     : in     Byte;
      Desc      : in     Byte;
      Output    : in out IO_Buffer;
      Bytes_Out :    out N32)
   is
      use RFLX.TLS_Alert;
      use RFLX.TLS_Alert.Alert;
      use RFLX.Tls_Parameters;
      use type RFLX.RFLX_Types.Bytes_Ptr;
      use type RFLX.RFLX_Types.Bit_Length;

      use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

      procedure RFLX_Free_Alert (Buf : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr)
      with Post => Buf = null;

      procedure RFLX_Free_Alert (Buf : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr)
      with SPARK_Mode => Off
      is
         procedure Dealloc is new Ada.Unchecked_Deallocation
           (Object => RFLX.RFLX_Builtin_Types.Bytes,
            Name   => RFLX.RFLX_Builtin_Types.Bytes_Ptr);
      begin
         Dealloc (Buf);
      end RFLX_Free_Alert;

      Buf_Ptr   : RFLX.RFLX_Builtin_Types.Bytes_Ptr :=
                    new RFLX.RFLX_Builtin_Types.Bytes'(1 .. 2 => 0);
      Ctx       : RFLX.TLS_Alert.Alert.Context;
      Alert_Lvl : RFLX.TLS_Alert.Alert_Level;
      Alert_Desc : RFLX.Tls_Parameters.TLS_Alerts_Enum;
   begin
      Bytes_Out := 0;

      --  Map level byte to RFLX enum
      if Level = 1 then
         Alert_Lvl := Warning;
      else
         Alert_Lvl := Fatal;
      end if;

      --  Map description byte to RFLX enum
      declare
         Base_Val : constant RFLX.RFLX_Types.Base_Integer :=
            RFLX.RFLX_Types.Base_Integer (Desc);
      begin
         if RFLX.Tls_Parameters.Valid_TLS_Alerts (Base_Val) then
            declare
               A : constant RFLX.Tls_Parameters.TLS_Alerts :=
                  RFLX.Tls_Parameters.To_Actual (Base_Val);
            begin
               if A.Known then
                  Alert_Desc := A.Enum;
               else
                  Alert_Desc := RFLX.Tls_Parameters.Internal_Error;
               end if;
            end;
         else
            Alert_Desc := RFLX.Tls_Parameters.Internal_Error;
         end if;
      end;

      --  Build alert payload via RFLX
      Initialize (Ctx, Buf_Ptr);
      Set_Level (Ctx, Alert_Lvl);
      Set_Description (Ctx, Alert_Desc);
      Take_Buffer (Ctx, Buf_Ptr);

      --  Wrap in plaintext TLS record: type(1) + version(2) + length(2) + alert(2)
      if Free_Space (Output) >= 7 and then Buf_Ptr /= null then
         Output.Data (Output.Write_Pos)     := 16#15#;        --  alert
         Output.Data (Output.Write_Pos + 1) := 16#03#;        --  TLS 1.2
         Output.Data (Output.Write_Pos + 2) := 16#03#;
         Output.Data (Output.Write_Pos + 3) := 16#00#;        --  length=2
         Output.Data (Output.Write_Pos + 4) := 16#02#;
         Output.Data (Output.Write_Pos + 5) :=
            Byte (Buf_Ptr.all (1));  --  level
         Output.Data (Output.Write_Pos + 6) :=
            Byte (Buf_Ptr.all (2));  --  description
         Output.Write_Pos := Output.Write_Pos + 7;
         Bytes_Out := 7;
      end if;

      RFLX_Free_Alert (Buf_Ptr);
   end Build_Plaintext_Alert;

end SPARKTLS.Records;
