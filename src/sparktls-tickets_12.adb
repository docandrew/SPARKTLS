with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;

package body SPARKTLS.Tickets_12 is

   --  Plaintext layout helpers.
   Plain_Master_Secret_Off : constant N32 := 0;
   Plain_Suite_Off         : constant N32 := 48;
   Plain_Created_At_Off    : constant N32 := 50;
   Plain_SID_Len_Off       : constant N32 := 58;
   Plain_SID_Off           : constant N32 := 59;
   --  total = 59 + SID_Len (0 .. 32) → 59 .. 91 bytes

   --  Encode plaintext into a flat Byte_Seq.
   procedure Encode_Plain
     (Plain : in     Ticket_Plain;
      Buf   :    out Byte_Seq;
      Len   :    out N32)
   with Pre  => Buf'First = 0
                and then Buf'Last >= 90
                and then Plain.SID_Len in 0 .. 32,
        Post => Len in 59 .. 91
   is
   begin
      Buf := (others => 0);
      --  master_secret (48 bytes)
      Buf (0 .. 47) := Plain.Master_Secret;
      --  suite (2 bytes, big-endian)
      Buf (48) := Byte (Shift_Right (Plain.Suite, 8) and 16#FF#);
      Buf (49) := Byte (Plain.Suite and 16#FF#);
      --  created_at (8 bytes, big-endian)
      for I in 0 .. 7 loop
         Buf (50 + N32 (I)) :=
            Byte (Shift_Right (Plain.Created_At, 8 * (7 - I)) and 16#FF#);
      end loop;
      --  sid_len (1 byte) + sid (SID_Len bytes, zero-padded out)
      Buf (58) := Byte (Plain.SID_Len);
      if Plain.SID_Len > 0 then
         Buf (59 .. 59 + Plain.SID_Len - 1) :=
            Plain.SID (0 .. Plain.SID_Len - 1);
      end if;
      Len := 59 + Plain.SID_Len;
   end Encode_Plain;

   --  Inverse of Encode_Plain. Status = False if shape is wrong.
   procedure Decode_Plain
     (Buf    : in     Byte_Seq;
      Len    : in     N32;
      Plain  :    out Ticket_Plain;
      Status :    out Boolean)
   with Pre  => Buf'First = 0
                and then Buf'Last >= Len - 1
                and then Len >= 0
   is
      SID_Len : N32;
   begin
      Plain := (others => <>);
      Status := False;
      if Len < 59 or Len > 91 then
         return;
      end if;
      SID_Len := N32 (Buf (58));
      if SID_Len > 32 or 59 + SID_Len /= Len then
         return;
      end if;
      Plain.Master_Secret := Buf (0 .. 47);
      Plain.Suite := Unsigned_16 (Buf (48)) * 256
                     + Unsigned_16 (Buf (49));
      Plain.Created_At := 0;
      for I in 0 .. 7 loop
         Plain.Created_At := Shift_Left (Plain.Created_At, 8)
                             or Unsigned_64 (Buf (50 + N32 (I)));
      end loop;
      Plain.SID_Len := SID_Len;
      if SID_Len > 0 then
         Plain.SID (0 .. SID_Len - 1) := Buf (59 .. 59 + SID_Len - 1);
      end if;
      Status := True;
   end Decode_Plain;

   ----------------------------------------------------------------
   procedure Encrypt_Ticket
     (Plain      : in     Ticket_Plain;
      Key_ID     : in     Bytes_4;
      TEK        : in     Bytes_32;
      Nonce      : in     Bytes_12;
      Ticket     :    out Byte_Seq;
      Ticket_Len :    out N32)
   is
      use SPARKNaCl.AES;
      Plain_Buf : Byte_Seq (0 .. 90) := (others => 0);
      Plain_Len : N32;
      Ct        : Byte_Seq (0 .. 90) := (others => 0);
      Tag       : SPARKNaCl.Bytes_16;
      Key       : AES256_Key;
   begin
      Ticket := (others => 0);
      Ticket_Len := 0;

      Encode_Plain (Plain, Plain_Buf, Plain_Len);

      --  AAD = Key_ID (4 bytes). Binding the ticket to its TEK ID
      --  prevents key-confusion if the server later rotates tickets
      --  across different TEKs.
      Construct (Key, SPARKNaCl.Bytes_32 (TEK));
      declare
         Plain_Slice : constant Byte_Seq := Plain_Buf (0 .. Plain_Len - 1);
         Ct_Slice    : Byte_Seq (0 .. Plain_Len - 1) := (others => 0);
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
      Sanitize (Key);

      --  Assemble wire: Key_ID (4) | Nonce (12) | Ct (N) | Tag (16)
      Ticket (0 .. 3) := Byte_Seq (Key_ID);
      Ticket (4 .. 15) := Byte_Seq (Nonce);
      Ticket (16 .. 16 + Plain_Len - 1) := Ct (0 .. Plain_Len - 1);
      Ticket (16 + Plain_Len .. 16 + Plain_Len + 15) := Byte_Seq (Tag);
      Ticket_Len := 32 + Plain_Len;
   end Encrypt_Ticket;

   ----------------------------------------------------------------
   --  Helper: find key with matching Key_ID. Returns -1 on miss.
   function Find_Key_Index
     (Keys : TLS12_Ticket_Key_Array;
      ID   : Byte_Seq) return Integer
   is
   begin
      for I in Keys'Range loop
         if Keys (I).Valid and then Keys (I).Key_ID = ID then
            return I;
         end if;
      end loop;
      return -1;
   end Find_Key_Index;

   procedure Decrypt_Ticket
     (Ticket  : in     Byte_Seq;
      Keys    : in     TLS12_Ticket_Key_Array;
      Now     : in     Unsigned_64;
      Max_Age : in     Unsigned_32;
      Plain   :    out Ticket_Plain;
      Status  :    out Boolean)
   is
      use SPARKNaCl.AES;
      T_Len : constant N32 := N32 (Ticket'Length);
      Idx   : Integer;
      Tag   : SPARKNaCl.Bytes_16;
      Ct_Len : N32;
      Plain_Buf : Byte_Seq (0 .. 90) := (others => 0);
      Decode_OK : Boolean;
      Key       : AES256_Key;
      AES_OK    : Boolean;
   begin
      Plain := (others => <>);
      Status := False;

      --  Minimum wire = 4 (id) + 12 (nonce) + 59 (plain min) + 16 (tag) = 91
      if T_Len < 91 or T_Len > 256 then
         return;
      end if;
      Ct_Len := T_Len - 32;  --  ciphertext length
      if Ct_Len > 91 then
         return;
      end if;

      Idx := Find_Key_Index (Keys, Ticket (0 .. 3));
      if Idx < 0 then
         return;
      end if;

      --  Extract tag from end, ciphertext from middle.
      Tag := SPARKNaCl.Bytes_16
               (Ticket (T_Len - 16 .. T_Len - 1));
      declare
         --  Slide to First=0 — the Decrypt_256 precondition is
         --  C'First = 0 and AAD'First = 0; slicing Ticket (a..b)
         --  preserves a as 'First, violating the precondition for
         --  a /= 0. Build a copy with origin 0 to satisfy it.
         Ct_Slice_Raw : constant Byte_Seq :=
                          Ticket (16 .. 16 + Ct_Len - 1);
         Ct_Slice : Byte_Seq (0 .. Ct_Len - 1);
         AAD : Byte_Seq (0 .. 3);
         Pt_Slice : Byte_Seq (0 .. Ct_Len - 1) := (others => 0);
         Nonce_B  : SPARKNaCl.Bytes_12;
      begin
         Ct_Slice := Ct_Slice_Raw;
         AAD := Ticket (0 .. 3);
         for I in SPARKNaCl.Index_12 loop
            Nonce_B (I) := Ticket (4 + N32 (I));
         end loop;
         Construct (Key, SPARKNaCl.Bytes_32 (Keys (Idx).TEK));
         SPARKTLSCrypto.AES_GCM.Decrypt_256
           (M      => Pt_Slice,
            Status => AES_OK,
            Tag    => Tag,
            C      => Ct_Slice,
            N      => Nonce_B,
            K      => Key,
            AAD    => AAD);
         Sanitize (Key);
         if not AES_OK then
            return;
         end if;
         Plain_Buf (0 .. Ct_Len - 1) := Pt_Slice;
      end;

      Decode_Plain (Plain_Buf, Ct_Len, Plain, Decode_OK);
      if not Decode_OK then
         return;
      end if;

      --  Expiry / clock-skew check.
      if Plain.Created_At > Now then
         --  Ticket from the future — clock skew or forged. Reject.
         return;
      end if;
      if Now - Plain.Created_At > Unsigned_64 (Max_Age) then
         return;
      end if;

      Status := True;
   end Decrypt_Ticket;

end SPARKTLS.Tickets_12;
