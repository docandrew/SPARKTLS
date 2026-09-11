with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;

package body SPARKTLS.Tickets_12
  with SPARK_Mode => On
is

   --  Cumulative days from Jan 1 to the start of each month, non-leap.
   --  Index 1 = Jan (0), 2 = Feb (31), â¦, 12 = Dec (334).
   Days_Before_Month : constant array (1 .. 12) of Unsigned_64 :=
     (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334);

   function Is_Leap (Y : Natural) return Boolean
   is ((Y mod 4 = 0 and Y mod 100 /= 0) or Y mod 400 = 0);

   function To_Unix_Seconds (DT : X509.Date_Time) return Unsigned_64 is
      Y    : constant Natural := DT.Year;
      M    : constant Natural := DT.Month;
      D    : constant Natural := DT.Day;
      Days : Unsigned_64 := 0;
   begin
      if Y < 1970 or M not in 1 .. 12 or D < 1 or D > 31 then
         return 0;
      end if;
      --  Whole years 1970 .. Y - 1
      for Yr in 1970 .. Y - 1 loop
         Days := Days + (if Is_Leap (Yr) then 366 else 365);
      end loop;
      --  Months in the current year
      Days := Days + Days_Before_Month (M);
      if M > 2 and Is_Leap (Y) then
         Days := Days + 1;  --  Feb 29 happened this year

      end if;
      --  Days within the current month
      Days := Days + Unsigned_64 (D - 1);
      return
        Days * 86_400 + Unsigned_64 (DT.Hour) * 3600 + Unsigned_64 (DT.Minute) * 60
        + Unsigned_64 (DT.Second);
   end To_Unix_Seconds;


   --  Plaintext layout helpers (version-neutral).
   Plain_Secret_Off     : constant N32 := 0;   --  secret (48)
   Plain_Secret_Len_Off : constant N32 := 48;  --  secret_len (1)
   Plain_Suite_Off      : constant N32 := 49;  --  suite (2)
   Plain_Created_At_Off : constant N32 := 51;  --  created_at (8)
   Plain_Flags_Off      : constant N32 := 59;  --  flags (1)
   Plain_SID_Len_Off    : constant N32 := 60;  --  sid_len (1)
   Plain_SID_Off        : constant N32 := 61;  --  sid (0 .. 32)
   Plain_Fixed_Len      : constant N32 := 61;

   --  flags bit assignments
   Flag_Client_Auth : constant Byte := 1;
   Flag_EMS         : constant Byte := 2;
   Flag_Kind_TLS13  : constant Byte := 4;
   Flag_Unknown_Mask : constant Byte := 16#F8#;
   --  total = 61 + SID_Len (0 .. 32) -> 61 .. 93 bytes

   --  Encode plaintext into a flat Byte_Seq.
   procedure Encode_Plain (Plain : in Ticket_Plain; Buf : out Byte_Seq; Len : out N32)
   with
     Pre => Buf'First = 0 and then Buf'Last >= Plain_SID_Off + 31
            and then Plain.SID_Len in 0 .. 32 and then Plain.Secret_Len in 32 | 48,
     Post => Len in Plain_Fixed_Len .. Plain_Fixed_Len + 32
   is
      Flags : Byte := 0;
   begin
      Buf := (others => 0);
      --  secret (48 bytes, zero-padded beyond Secret_Len)
      Buf (Plain_Secret_Off .. Plain_Secret_Off + 47) := Plain.Secret;
      --  secret_len (1 byte)
      Buf (Plain_Secret_Len_Off) := Byte (Plain.Secret_Len);
      --  suite (2 bytes, big-endian)
      Buf (Plain_Suite_Off)     := Byte (Shift_Right (Plain.Suite, 8) and 16#FF#);
      Buf (Plain_Suite_Off + 1) := Byte (Plain.Suite and 16#FF#);
      --  created_at (8 bytes, big-endian)
      for I in 0 .. 7 loop
         Buf (Plain_Created_At_Off + N32 (I)) :=
           Byte (Shift_Right (Plain.Created_At, 8 * (7 - I)) and 16#FF#);
      end loop;
      --  flags (1 byte): client_auth | ems | kind
      if Plain.Client_Auth then
         Flags := Flags or Flag_Client_Auth;
      end if;
      if Plain.EMS then
         Flags := Flags or Flag_EMS;
      end if;
      if Plain.Kind = Kind_TLS13 then
         Flags := Flags or Flag_Kind_TLS13;
      end if;
      Buf (Plain_Flags_Off) := Flags;
      --  sid_len (1 byte) + sid (SID_Len bytes, zero-padded out)
      Buf (Plain_SID_Len_Off) := Byte (Plain.SID_Len);
      if Plain.SID_Len > 0 then
         Buf (Plain_SID_Off .. Plain_SID_Off + Plain.SID_Len - 1) :=
           Plain.SID (0 .. Plain.SID_Len - 1);
      end if;
      Len := Plain_Fixed_Len + Plain.SID_Len;
   end Encode_Plain;

   --  Inverse of Encode_Plain. Status = False if shape is wrong or the
   --  decoded Kind does not match Expect_Kind (SR-04).
   procedure Decode_Plain
     (Buf         : in Byte_Seq;
      Len         : in N32;
      Expect_Kind : in Ticket_Kind;
      Plain       : out Ticket_Plain;
      Status      : out Boolean)
   with
     Pre => Buf'First = 0 and then Buf'Last >= Len - 1 and then Len >= 0,
     Post => (if Status then Plain.Kind = Expect_Kind and then Plain.Secret_Len in 32 | 48)
   is
      SID_Len    : N32;
      Secret_Len : N32;
      Flags      : Byte;
      Kind       : Ticket_Kind;
   begin
      Plain := (others => <>);
      Status := False;
      if Len < Plain_Fixed_Len or Len > Plain_Fixed_Len + 32 then
         return;
      end if;
      Secret_Len := N32 (Buf (Plain_Secret_Len_Off));
      if Secret_Len /= 32 and Secret_Len /= 48 then
         return;
      end if;
      Flags := Buf (Plain_Flags_Off);
      if (Flags and Flag_Unknown_Mask) /= 0 then
         return;  --  unknown flag bits set -> reject (our own format)
      end if;
      Kind := (if (Flags and Flag_Kind_TLS13) /= 0 then Kind_TLS13 else Kind_TLS12);
      if Kind /= Expect_Kind then
         return;  --  cross-version ticket (SR-04)
      end if;
      SID_Len := N32 (Buf (Plain_SID_Len_Off));
      if SID_Len > 32 or Plain_Fixed_Len + SID_Len /= Len then
         return;
      end if;
      Plain.Secret := Buf (Plain_Secret_Off .. Plain_Secret_Off + 47);
      Plain.Secret_Len := Secret_Len;
      Plain.Suite :=
        Unsigned_16 (Buf (Plain_Suite_Off)) * 256 + Unsigned_16 (Buf (Plain_Suite_Off + 1));
      Plain.Created_At := 0;
      for I in 0 .. 7 loop
         Plain.Created_At :=
           Shift_Left (Plain.Created_At, 8) or Unsigned_64 (Buf (Plain_Created_At_Off + N32 (I)));
      end loop;
      Plain.Kind := Kind;
      Plain.Client_Auth := (Flags and Flag_Client_Auth) /= 0;
      Plain.EMS := (Flags and Flag_EMS) /= 0;
      Plain.SID_Len := SID_Len;
      if SID_Len > 0 then
         Plain.SID (0 .. SID_Len - 1) := Buf (Plain_SID_Off .. Plain_SID_Off + SID_Len - 1);
      end if;
      Status := True;
   end Decode_Plain;

   ----------------------------------------------------------------
   procedure Encrypt_Ticket
     (Plain      : in Ticket_Plain;
      Key_ID     : in Bytes_4;
      TEK        : in Bytes_32;
      Nonce      : in Bytes_12;
      Ticket     : out Byte_Seq;
      Ticket_Len : out N32)
   is
      use SPARKNaCl.AES;
      Plain_Buf : Byte_Seq (0 .. 92);
      Plain_Len : N32;
      Ct        : Byte_Seq (0 .. 92) := (others => 0);
      Tag       : SPARKNaCl.Bytes_16;
      Key       : AES256_Key;
   begin
      Ticket := (others => 0);

      Encode_Plain (Plain, Plain_Buf, Plain_Len);

      --  AAD = Key_ID (4 bytes). Binding the ticket to its TEK ID
      --  prevents key-confusion if the server later rotates tickets
      --  across different TEKs.
      Construct (Key, SPARKNaCl.Bytes_32 (TEK));
      declare
         PL          : constant N32 := Plain_Len;
         Plain_Slice : constant Byte_Seq := Plain_Buf (0 .. PL - 1);
         Ct_Slice    : Byte_Seq (0 .. PL - 1);
         AAD         : constant Byte_Seq := Byte_Seq (Key_ID);
      begin
         SPARKTLSCrypto.AES_GCM.Encrypt_256
           (C   => Ct_Slice,
            Tag => Tag,
            M   => Plain_Slice,
            N   => SPARKNaCl.Bytes_12 (Nonce),
            K   => Key,
            AAD => AAD);
         Ct (0 .. Plain_Len - 1) := Ct_Slice;
      end;
      pragma Warnings (GNATProve, Off, "statement has no effect");
      Sanitize (Key);
      pragma Warnings (GNATProve, On, "statement has no effect");

      --  Assemble wire: Key_ID (4) | Nonce (12) | Ct (N) | Tag (16)
      Ticket (0 .. 3) := Byte_Seq (Key_ID);
      Ticket (4 .. 15) := Byte_Seq (Nonce);
      Ticket (16 .. 16 + Plain_Len - 1) := Ct (0 .. Plain_Len - 1);
      Ticket (16 + Plain_Len .. 16 + Plain_Len + 15) := Byte_Seq (Tag);
      Ticket_Len := 32 + Plain_Len;
   end Encrypt_Ticket;

   function Ticket_Key_ID (Ticket : Byte_Seq) return Byte_Seq is
      Result : Byte_Seq (0 .. Ticket_Key_ID_Size - 1);
   begin
      Result := Ticket (0 .. Ticket_Key_ID_Size - 1);
      return Result;
   end Ticket_Key_ID;

   procedure Decrypt_Ticket
     (Ticket      : in Byte_Seq;
      TEK         : in Byte_Seq;
      Now         : in Unsigned_64;
      Max_Age     : in Unsigned_32;
      Expect_Kind : in Ticket_Kind;
      Plain       : out Ticket_Plain;
      Status      : out Boolean)
   is
      use SPARKNaCl.AES;
      T_Len     : constant N32 := N32 (Ticket'Length);
      Tag       : SPARKNaCl.Bytes_16;
      Ct_Len    : N32;
      Plain_Buf : Byte_Seq (0 .. 92) := (others => 0);
      Decode_OK : Boolean;
      Key       : AES256_Key;
      AES_OK    : Boolean;
   begin
      Plain := (others => <>);
      Status := False;

      --  Minimum wire = 4 (id) + 12 (nonce) + 61 (plain min) + 16 (tag) = 93
      if T_Len < 93 or T_Len > 256 then
         return;
      end if;
      Ct_Len := T_Len - 32;  --  ciphertext length
      if Ct_Len > 93 then
         return;
      end if;

      --  Extract tag from end, ciphertext from middle.
      Tag := SPARKNaCl.Bytes_16 (Ticket (T_Len - 16 .. T_Len - 1));
      declare
         CL           : constant N32 := Ct_Len;
         --  Slide to First=0  the Decrypt_256 precondition is
         --  C'First = 0 and AAD'First = 0; slicing Ticket (a..b)
         --  preserves a as 'First, violating the precondition for
         --  a /= 0. Build a copy with origin 0 to satisfy it.
         Ct_Slice_Raw : constant Byte_Seq := Ticket (16 .. 16 + CL - 1);
         Ct_Slice     : Byte_Seq (0 .. CL - 1);
         AAD          : Byte_Seq (0 .. 3);
         Pt_Slice     : Byte_Seq (0 .. CL - 1);
         Nonce_B      : SPARKNaCl.Bytes_12;
      begin
         Ct_Slice := Ct_Slice_Raw;
         AAD := Ticket (0 .. 3);
         for I in SPARKNaCl.Index_12 loop
            Nonce_B (I) := Ticket (4 + N32 (I));
         end loop;
         Construct (Key, SPARKNaCl.Bytes_32 (TEK));
         SPARKTLSCrypto.AES_GCM.Decrypt_256
           (M      => Pt_Slice,
            Status => AES_OK,
            Tag    => Tag,
            C      => Ct_Slice,
            N      => Nonce_B,
            K      => Key,
            AAD    => AAD);
         pragma Warnings (GNATProve, Off, "statement has no effect");
         Sanitize (Key);
         pragma Warnings (GNATProve, On, "statement has no effect");
         if not AES_OK then
            return;
         end if;
         Plain_Buf (0 .. Ct_Len - 1) := Pt_Slice;
      end;

      Decode_Plain (Plain_Buf, Ct_Len, Expect_Kind, Plain, Decode_OK);
      if not Decode_OK then
         return;
      end if;

      --  Expiry / clock-skew check.
      if Plain.Created_At > Now then
         --  Ticket from the future  clock skew or forged. Reject.
         return;
      end if;
      if Now - Plain.Created_At > Unsigned_64 (Max_Age) then
         return;
      end if;

      Status := True;
   end Decrypt_Ticket;

end SPARKTLS.Tickets_12;
