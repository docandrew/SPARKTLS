with Interfaces;           use Interfaces;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.ChaCha20_Poly1305;
use SPARKTLSCrypto;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.TLS_Alert;
with RFLX.TLS_Alert.Alert;
with RFLX.Tls_Parameters;
with RFLX.TLS_Record.TLS_Record_Header;
with RFLX.TLS_Record;
with RFLX.TLS_Common;

package body SPARKTLS.Records
  with SPARK_Mode => On
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
   function Make_Nonce (IV : Bytes_12; Counter : Unsigned_64) return Bytes_12 is
      Nonce : Bytes_12 := IV;
   begin
      for I in 0 .. 7 loop
         Nonce (N32 (4 + I)) :=
           Nonce (N32 (4 + I)) xor Byte (Shift_Right (Counter, (7 - I) * 8) and 16#FF#);
      end loop;
      return Nonce;
   end Make_Nonce;

   --  Write bytes into output buffer
   procedure Write_To_Output (Output : in out IO_Buffer; Data : in Byte_Seq; OK : out Boolean)
   with
     Pre => Data'First = 0 and Data'Last < N32'Last,
     --  Relates success to the buffer. Without this nothing downstream
     --  can conclude that a successful write left anything pending, so
     --  callers cannot prove Available (Output) > 0 after writing.
     --  Holds on all three paths: empty Data (no change, Length = 0),
     --  successful append (Write_Pos advances by Len, Read_Pos fixed),
     --  and refusal for want of space (no change).
     --  Written as one equation rather than "if OK then ..." so the
     --  'Old is evaluated unconditionally -- a potentially unevaluated
     --  'Old would need its prefix to statically name an entity, which
     --  a function call does not, and would otherwise force either
     --  Unevaluated_Use_Of_Old or an 'Old copy of the whole buffer.
     Post => Available (Output) = Available (Output)'Old + (if OK then N32 (Data'Length) else 0)
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
            Copy_In (Output.Storage (Ix (Output.Write_Pos) .. Ix (Output.Write_Pos + Len - 1)), Data);
            Output.Write_Pos := Output.Write_Pos + Len;
            OK := True;
         else
            OK := False;
         end if;
      end;
   end Write_To_Output;

   procedure Ensure_Header_Buffer (Hdr : in out RBT.Bytes_Ptr) is
   begin
      if Hdr = null then
         Hdr := new RBT.Bytes'(1 .. RBT.Index (Record_Header_Size) => 0);
      end if;
   end Ensure_Header_Buffer;

   procedure Build_Record_Header
     (Hdr_Buf      : in out RBT.Bytes_Ptr;
      Content_Type : in Byte;
      Version      : in N32;
      Length       : in N32;
      Hdr          : out Byte_Seq)
   is
      package RH renames RFLX.TLS_Record.TLS_Record_Header;
      Ctx : RH.Context;
   begin
      Ensure_Header_Buffer (Hdr_Buf);
      --  A build starts from an empty context: the default Written_Last is
      --  exactly right here (a parse must pass it explicitly).
      RH.Initialize (Ctx, Hdr_Buf);
      RH.Set_Content_Type (Ctx, RFLX.TLS_Record.Record_Content_Type_Any (Content_Type));
      RH.Set_Legacy_Record_Version (Ctx, RFLX.TLS_Record.Record_Version_Any (Version));
      RH.Set_Length (Ctx, RFLX.TLS_Record.Record_Length_Any (Length));
      RH.Take_Buffer (Ctx, Hdr_Buf);
      Hdr := To_NaCl (Hdr_Buf.all (1 .. RBT.Index (Record_Header_Size)));
   end Build_Record_Header;

   procedure Parse_Record_Header
     (Data          : in Byte_Seq;
      Avail         : in N32;
      Result        : out Parse_Result;
      Hdr           : in out RBT.Bytes_Ptr;
      Loose_Initial : in Boolean := False)
   is
      --  TLS record header: content_type(1) + version(2) + length(2) = 5
      --  bytes, decoded through the RecordFlux TLS_Record_Header message
      --  from a 5-byte copy in the per-connection Hdr buffer -- never by
      --  aliasing the I/O buffer, which is what forced 'Unrestricted_Access
      --  in the earlier RecordFlux attempt. All three fields are tolerant in
      --  the spec, so the RFC policy below runs in the RFC-mandated order and
      --  each fault keeps its alert: version, then length, then type.
      package RH renames RFLX.TLS_Record.TLS_Record_Header;
      Ctx      : RH.Context;
      B        : N32;
      V        : N32;
      CT       : Byte;
      Major    : Byte;
      Minor    : Byte;
      Frag_Len : N32;
   begin
      Result := (OK => False, others => <>);

      if Avail < Record_Header_Size then
         return;
      end if;

      B := Data'First;

      Ensure_Header_Buffer (Hdr);
      Hdr.all (1 .. RBT.Index (Record_Header_Size)) :=
        To_RFLX (Data (B .. B + Record_Header_Size - 1));

      --  Written_Last is mandatory for a parse: the default (0) means
      --  "nothing written yet" (First - 1), which is right for a build but
      --  leaves a parse context empty. All five header bytes are data.
      RH.Initialize
        (Ctx, Hdr, Written_Last => RBT.Bit_Length (Record_Header_Size * 8));
      RH.Verify_Message (Ctx);
      if not RH.Well_Formed_Message (Ctx) then
         --  Unreachable while Written_Last covers all five bytes (tolerant
         --  fields cannot fail). If it ever fires, EVERY record is rejected
         --  and connections stall with no alert (the 2026-09-05 regression:
         --  a bare Initialize left the context empty). Keep the buffer
         --  discipline and report "not a record" exactly as before.
         RH.Take_Buffer (Ctx, Hdr);
         return;
      end if;
      CT       := Byte (RH.Get_Content_Type (Ctx));
      V        := N32 (RH.Get_Legacy_Record_Version (Ctx));
      Major    := Byte (V / 256);
      Minor    := Byte (V mod 256);
      Frag_Len := N32 (RH.Get_Length (Ctx));
      RH.Take_Buffer (Ctx, Hdr);

      --  RFC 8446 5.1 / RFC 5246 6.2.1: the record-layer version
      --  must encode some TLS version. The major byte must be 0x03;
      --  the minor byte one of 0x01 (TLS 1.0) .. 0x04 (TLS 1.3) for
      --  every record except the very first ClientHello (where
      --  Loose_Initial relaxes the minor-byte check -- RFC 8446 5.1
      --  / RFC 5246 E.1 / BoGo LooseInitialRecordVersion).
      if Major /= 16#03# then
         Result.Bad_Version := True;
         return;
      end if;
      if not Loose_Initial and then Minor not in 16#01# .. 16#04# then
         Result.Bad_Version := True;
         return;
      end if;
      --  Pin the field-level invariant for downstream proofs.
      pragma Assert (Loose_Initial or else Record_Version_Valid_RFC_8446_5_1 (Major, Minor));

      --  RFC 8446 5.1: plaintext fragment <= 2^14
      --  RFC 8446 5.2: encrypted fragment <= 2^14 + 256
      declare
         Max_Len : constant N32 := (if CT = 16#17# then Max_Fragment + 256 else Max_Fragment);
      begin
         if Frag_Len = 0 or else Frag_Len > Max_Len then
            Result.Overflow := True;
            return;
         end if;
      end;

      if Avail < Record_Header_Size + Frag_Len then
         return;  --  need more data
      end if;

      Result.Fragment_Pos := Record_Header_Size;
      Result.Fragment_Len := Frag_Len;
      --  RFC 8446 5.1/5.2: any fragment that survived the length
      --  check above satisfies the per-type max. The pragma pins the
      --  invariant -- a future loosening of Max_Len (e.g., dropping
      --  the type-conditioned cap) would break SPARK proof here.
      pragma Assert (Record_Length_Bound_RFC_8446_5_1 (CT, Result.Fragment_Len));
      Result.Record_Len := Record_Header_Size + Frag_Len;

      case CT is
         when 16#16# =>
            Result.Content := Content_Handshake;
            Result.OK := True;

         when 16#15# =>
            Result.Content := Content_Alert;
            Result.OK := True;

         when 16#17# =>
            Result.Content := Content_Application_Data;
            Result.OK := True;

         when 16#14# =>
            Result.Content := Content_Change_Cipher_Spec;
            Result.OK := True;

         when others =>
            null;  --  unknown content type, OK stays False
      end case;
      --  RFC 8446 5.1: every accepted record matches one of the
      --  RFC-recognized types. Pin the property; a future edit that
      --  added 0x18 or similar must update both the case AND the
      --  predicate, otherwise SPARK proof fails here.
      pragma Assert (if Result.OK then Outer_Content_Type_Valid_RFC_8446_5_1 (CT));
   end Parse_Record_Header;

   procedure Build_Handshake_Record
     (Fragment  : in Byte_Seq;
      Output    : in out IO_Buffer;
      Bytes_Out : out N32;
      Hdr_Buf   : in out RBT.Bytes_Ptr)
   is
      --  TLS record: type(1) + version(2) + length(2) + fragment
      --  Manual construction replaces RFLX to eliminate 'Unrestricted_Access.
      Frag_Len : constant N32 := N32 (Fragment'Length);
      Hdr      : Byte_Seq (0 .. 4) := (others => 0);
      OK       : Boolean;
   begin
      Bytes_Out := 0;

      --  Build 5-byte header: Handshake (0x16) + TLS 1.2 (0x0303) + length
      --  RFC 8446 5.1: SHOULD be 0x0303 for all records after ClientHello.
      --  RFC 5246 6.2.1: record version = negotiated version (0x0303).
      Build_Record_Header (Hdr_Buf, 16#16#, 16#0303#, Frag_Len, Hdr);
      pragma Assert (Record_Version_RFC_8446_5_1 (16#03#, 16#03#));

      Write_To_Output (Output, Hdr, OK);
      if not OK then
         return;
      end if;

      Write_To_Output (Output, Fragment, OK);
      if not OK then
         return;
      end if;

      Bytes_Out := Record_Header_Size + Frag_Len;
   end Build_Handshake_Record;

   procedure Build_Initial_ClientHello_Record
     (Fragment  : in Byte_Seq;
      Output    : in out IO_Buffer;
      Bytes_Out : out N32;
      Hdr_Buf   : in out RBT.Bytes_Ptr)
   is
      Frag_Len : constant N32 := N32 (Fragment'Length);
      Hdr      : Byte_Seq (0 .. 4) := (others => 0);
      OK       : Boolean;
   begin
      Bytes_Out := 0;

      --  RFC 8446 5.1: legacy_record_version = 0x0301 (TLS 1.0) for
      --  the initial ClientHello. Middleboxes more reliably forward
      --  the record when it claims TLS 1.0 than TLS 1.2.
      Build_Record_Header (Hdr_Buf, 16#16#, 16#0301#, Frag_Len, Hdr);

      Write_To_Output (Output, Hdr, OK);
      if not OK then
         return;
      end if;

      Write_To_Output (Output, Fragment, OK);
      if not OK then
         return;
      end if;

      Bytes_Out := Record_Header_Size + Frag_Len;
   end Build_Initial_ClientHello_Record;

   procedure Build_Encrypted_Record
     (Plaintext  : in Byte_Seq;
      Inner_Type : in Byte;
      Keys       : in out Traffic_Keys;
      Output     : in out IO_Buffer;
      Bytes_Out  : out N32;
      Hdr_Buf    : in out RBT.Bytes_Ptr)
   is
      Inner_Len : constant N32 := N32 (Plaintext'Length) + 1;
      Enc_Len   : constant N32 := Inner_Len + Tag_Size;
      Total     : constant N32 := Record_Header_Size + Enc_Len;
      Hdr       : Byte_Seq (0 .. 4) := (others => 0);
      Tag       : Bytes_16;
      Nonce     : Bytes_12;
   begin
      Bytes_Out := 0;

      --  Bail if Output can't fit the whole record (header + ciphertext
      --  + tag). The atomic-flight callers gate on this too, but we
      --  need to know before reserving slice positions below.
      if Free_Space (Output) < Total then
         return;
      end if;

      --  Build TLS record header (5 bytes: type + version + length).
      Build_Record_Header (Hdr_Buf, 16#17#, 16#0303#, Enc_Len, Hdr);
      pragma Assert (Record_Version_RFC_8446_5_1 (16#03#, 16#03#));

      --  RFC 8446 5.3: nonce = IV xor sequence number. Fail closed at the
      --  end of the sequence space rather than wrap. Unsigned_64 is
      --  modular, so without this the increment below would silently reach
      --  zero and restart the nonce sequence under an unchanged key --
      --  nonce reuse, catastrophic for AEAD and invisible in a release
      --  build. Record_Counter excludes 'Last so this branch is what makes
      --  the increment provable.
      --
      --  Unreachable on any healthy connection: KeyUpdate rotates at the
      --  RFC 8446 5.5 AEAD limit, roughly 2**40 times sooner. Bytes_Out
      --  stays 0, which callers already treat as "nothing queued".
      if Keys.Counter >= Record_Counter'Last then
         Bytes_Out := 0;
         return;
      end if;

      Nonce := Make_Nonce (Keys.IV, Keys.Counter);
      Keys.Counter := Keys.Counter + 1;

      declare
         Hdr_Pos : constant N32 := Output.Write_Pos;
         CT_Pos  : constant N32 := Hdr_Pos + Record_Header_Size;
         Tag_Pos : constant N32 := CT_Pos + Inner_Len;
      begin
         --  Header at [Hdr_Pos .. Hdr_Pos + 4]
         for I in 0 .. 4 loop
            Output.Storage (Ix (Hdr_Pos + N32 (I))) := Hdr (N32 (I));
         end loop;

         --  Plaintext + content_type byte at [CT_Pos .. Tag_Pos - 1].
         --  This single Plaintext-into-Output copy is the only data
         --  movement at this layer; the prior code did Plaintext ->
         --  Inner -> Ciphertext -> Output (3 copies, ~48 KB extra
         --  shuffle per 16 KB record).
         if Plaintext'Length > 0 then
            for I in N32 range 0 .. N32 (Plaintext'Length) - 1 loop
               Output.Storage (Ix (CT_Pos + I)) := Plaintext (Plaintext'First + I);
            end loop;
         end if;
         Output.Storage (Ix (Tag_Pos - 1)) := Inner_Type;

         --  Encrypt in place + compute tag, slice-aware.
         case Keys.Suite is
            when Suite_AES_128_GCM_SHA256 =>
               declare
                  AES_Key : constant AES.AES128_Key := AES.Construct (Keys.Key (0 .. 15));
               begin
                  AES_GCM.Encrypt_InPlace
                    (Buf => Byte_Seq (Output.Storage (Ix (CT_Pos) .. Ix (Tag_Pos - 1))),
                     Tag => Tag,
                     N   => Nonce,
                     K   => AES_Key,
                     AAD => Hdr);
               end;

            when Suite_AES_256_GCM_SHA384 =>
               declare
                  AES_Key : constant AES.AES256_Key := AES.Construct (Keys.Key);
               begin
                  AES_GCM.Encrypt_InPlace_256
                    (Buf => Byte_Seq (Output.Storage (Ix (CT_Pos) .. Ix (Tag_Pos - 1))),
                     Tag => Tag,
                     N   => Nonce,
                     K   => AES_Key,
                     AAD => Hdr);
               end;

            when others =>
               --  ChaCha20-Poly1305 fallback path: keep the older
               --  separate-buffer code until we have an in-place
               --  variant for SPARKNaCl.Secretbox.Create. AES suites
               --  carry the bulk of TLS traffic, so the optimization
               --  there is what shows up in benchmarks.
               declare
                  Inner      : Byte_Seq (0 .. Inner_Len - 1) := (others => 0);
                  Ciphertext : Byte_Seq (0 .. Inner_Len - 1);
                  Key        : constant ChaCha20_Key := SPARKNaCl.Core.Construct (Keys.Key);
               begin
                  if Plaintext'Length > 0 then
                     Inner (0 .. N32 (Plaintext'Length) - 1) := Plaintext;
                  end if;
                  Inner (Inner'Last) := Inner_Type;
                  SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
                    (C   => Ciphertext,
                     Tag => Tag,
                     M   => Inner,
                     N   => ChaCha20_IETF_Nonce (Nonce),
                     K   => Key,
                     AAD => Hdr);
                  --  Copy ChaCha20 ciphertext into the destination
                  --  slice we already reserved above.
                  for I in N32 range 0 .. Inner_Len - 1 loop
                     Output.Storage (Ix (CT_Pos + I)) := Ciphertext (I);
                  end loop;
               end;
         end case;

         --  Tag at [Tag_Pos .. Tag_Pos + 15]
         for I in 0 .. 15 loop
            Output.Storage (Ix (Tag_Pos + N32 (I))) := Tag (N32 (I));
         end loop;

         Output.Write_Pos := Output.Write_Pos + Total;
      end;
      Bytes_Out := Total;
   end Build_Encrypted_Record;

   procedure Decrypt_Record
     (Encrypted  : in Byte_Seq;
      Record_Hdr : in Byte_Seq;
      Keys       : in out Traffic_Keys;
      Plaintext  : out Byte_Seq;
      Plain_Len  : out N32;
      Inner_Type : out Byte;
      Valid      : out Boolean)
   is
      Cipher_Len : constant N32 := N32 (Encrypted'Length) - Tag_Size;
      Tag        : Bytes_16;
      Nonce      : Bytes_12;
      Decrypted  : Byte_Seq (0 .. Cipher_Len - 1);
   begin
      Plaintext := (others => 0);
      Plain_Len := 0;
      Inner_Type := 0;
      Valid := False;

      --  Defense-in-depth: verify precondition at runtime.
      --  Encrypted must be at least Tag_Size + 1 bytes.
      if N32 (Encrypted'Length) <= Tag_Size then
         return;
      end if;

      --  Extract tag (last 16 bytes)
      Tag := Bytes_16 (Encrypted (Cipher_Len .. Cipher_Len + 15));

      --  Same fail-closed bound on the receive side. A peer that never
      --  rekeys cannot walk us off the end of the sequence space; Valid
      --  stays False and the caller raises bad_record_mac, which is the
      --  correct outcome -- we genuinely cannot authenticate anything more
      --  under this key.
      if Keys.Counter >= Record_Counter'Last then
         return;
      end if;

      --  Compute nonce
      Nonce := Make_Nonce (Keys.IV, Keys.Counter);
      Keys.Counter := Keys.Counter + 1;

      --  Decrypt with the negotiated AEAD
      case Keys.Suite is
         when Suite_AES_128_GCM_SHA256 =>
            declare
               AES_Key : constant AES.AES128_Key := AES.Construct (Keys.Key (0 .. 15));
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
               AES_Key : constant AES.AES256_Key := AES.Construct (Keys.Key);
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
               Key : constant ChaCha20_Key := SPARKNaCl.Core.Construct (Keys.Key);
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
      --  the last non-zero byte (content type). No early exit
      --  prevents timing leaks of the padding length.
      declare
         Last_Nonzero : N32 := 0;
         Found        : Boolean := False;
      begin
         for I in N32 range 0 .. Cipher_Len - 1 loop
            pragma Loop_Invariant (Last_Nonzero in 0 .. Cipher_Len - 1);
            if Decrypted (I) /= 0 then
               Last_Nonzero := I;
               Found := True;
            end if;
         end loop;

         if not Found then
            --  All zeros  content type is zero (invalid per RFC 8446 5.4).
            --  AEAD succeeded but inner plaintext is all zeros.
            --  Return Valid = True, Inner_Type = 0, Plain_Len = 0.
            --  Caller checks Inner_Type and sends unexpected_message.
            Inner_Type := 0;
            Plain_Len := 0;
            --  Copy nothing to Plaintext (Plain_Len = 0)
            return;
         end if;

         Inner_Type := Decrypted (Last_Nonzero);
         Plain_Len := Last_Nonzero;
         --  Last_Nonzero < Cipher_Len <= Encrypted'Length - Tag_Size
         --  Plaintext has same bounds as Encrypted
         pragma Assert (Plain_Len < Cipher_Len);

         if Plain_Len > 0 and then Plain_Len - 1 <= Plaintext'Last then
            Plaintext (0 .. Plain_Len - 1) := Decrypted (0 .. Plain_Len - 1);
         end if;
      end;
   end Decrypt_Record;

   procedure Build_CCS_Record
     (Output : in out IO_Buffer; Bytes_Out : out N32; Hdr_Buf : in out RBT.Bytes_Ptr)
   is
      CCS : Byte_Seq (0 .. 5) := (others => 0);
      Hdr : Byte_Seq (0 .. 4) := (others => 0);
      OK  : Boolean;
   begin
      --  Header through RecordFlux; the body is the single fixed octet 0x01
      --  (RFC 5246 7.1), the same one-byte class as KeyUpdate.
      Build_Record_Header (Hdr_Buf, 16#14#, 16#0303#, 1, Hdr);
      CCS (0 .. 4) := Hdr;
      CCS (5) := 16#01#;
      Write_To_Output (Output, CCS, OK);
      if OK then
         Bytes_Out := 6;
      else
         Bytes_Out := 0;
      end if;
   end Build_CCS_Record;

   procedure Build_Alert_Record
     (Level     : in Byte;
      Desc      : in Byte;
      Keys      : in out Traffic_Keys;
      Output    : in out IO_Buffer;
      Bytes_Out : out N32;
      Hdr_Buf   : in out RBT.Bytes_Ptr)
   is
      Alert_Plaintext : Byte_Seq (0 .. 1) := (Level, Desc);
   begin
      Build_Encrypted_Record
        (Plaintext  => Alert_Plaintext,
         Inner_Type => 16#15#,
         Keys       => Keys,
         Output     => Output,
         Bytes_Out  => Bytes_Out,
         Hdr_Buf    => Hdr_Buf);
   end Build_Alert_Record;

   procedure Build_Plaintext_Alert
     (Level     : in Byte;
      Desc      : in Byte;
      Output    : in out IO_Buffer;
      Bytes_Out : out N32;
      Hdr_Buf   : in out RBT.Bytes_Ptr)
   is
      use RFLX.TLS_Alert;
      use RFLX.TLS_Alert.Alert;
      use RFLX.Tls_Parameters;
      use type RFLX.RFLX_Types.Bytes_Ptr;
      use type RFLX.RFLX_Types.Bit_Length;

      use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

      --  The alert body and the record header both go through RecordFlux
      --  using the connection's scratch buffer (Hdr_Buf), so this path has no
      --  allocation of its own; the former per-call new/Unchecked_Deallocation
      --  (a SPARK_Mode Off body) is gone.
      Hdr        : Byte_Seq (0 .. 4) := (others => 0);
      Ctx        : RFLX.TLS_Alert.Alert.Context;
      Alert_Lvl  : RFLX.TLS_Alert.Alert_Level;
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
         Base_Val : constant RFLX.RFLX_Types.Base_Integer := RFLX.RFLX_Types.Base_Integer (Desc);
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
      Ensure_Header_Buffer (Hdr_Buf);
      Initialize (Ctx, Hdr_Buf);
      Set_Level (Ctx, Alert_Lvl);
      pragma
        Assert
          (RFLX.Tls_Parameters.Valid_TLS_Alerts (RFLX.Tls_Parameters.To_Base_Integer (Alert_Desc)));
      Set_Description (Ctx, Alert_Desc);
      Take_Buffer (Ctx, Hdr_Buf);

      --  Wrap in plaintext TLS record: type(1) + version(2) + length(2) + alert(2)
      if Free_Space (Output) >= 7 then
         --  Alert body (2 bytes) out of the scratch buffer FIRST: the header
         --  build below reuses the same buffer.
         Output.Storage (Ix (Output.Write_Pos + 5)) := Byte (Hdr_Buf.all (1));  --  level
         Output.Storage (Ix (Output.Write_Pos + 6)) := Byte (Hdr_Buf.all (2));  --  description
         Build_Record_Header (Hdr_Buf, 16#15#, 16#0303#, 2, Hdr);
         Copy_In (Output.Storage (Ix (Output.Write_Pos) .. Ix (Output.Write_Pos + 4)), Hdr);
         Output.Write_Pos := Output.Write_Pos + 7;
         Bytes_Out := 7;
      end if;

   end Build_Plaintext_Alert;

end SPARKTLS.Records;
