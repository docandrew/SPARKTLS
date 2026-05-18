with Ada.Unchecked_Deallocation;
with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Cert_Verify;       use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;
with X509;
use type X509.Algorithm_ID;

with SPARKTLS.RFLX_Bridge;       use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.TLS_Handshake.TLS_1_2_Certificate;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;

package body SPARKTLS.Client.TLS12 with
   SPARK_Mode => On
is
   use Handshake.TLS12;

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Records.Build_Plaintext_Alert (2, Alert_Desc (Err), S.Output, Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Alert_And_Error;

   procedure Append_Transcript (HC : in out Handshake_Context; Data : Byte_Seq)
   --  RFC 5246 §7.4.9 transcript-monotonicity: bytes already
   --  appended cannot be removed. The Post pins this; a future
   --  edit that resets HC.Transcript_Len in this proc would fail.
   with Post => HC.Transcript_Len >= HC.Transcript_Len'Old
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len + Len <= HC.Transcript'Length then
         HC.Transcript (HC.Transcript_Len ..
                          HC.Transcript_Len + Len - 1) := Data;
         HC.Transcript_Len := HC.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   --  Derive TLS 1.2 keys (same as server, shared secret → master → expand)
   --  Derive AEAD keys from an already-set HC.Master_Secret_12. Used
   --  by RFC 5077 abbreviated client handshake: master_secret was
   --  cached from the previous full handshake and copied into HC by
   --  the SH-parse resume-detection branch; we just need to expand
   --  it into traffic keys + IVs for this connection's randoms.
   procedure Derive_Keys_Resumed_12
     (S : in out Session; HC : in out Handshake_Context)
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
          then 16 else 32);
      IV_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_CHACHA20_SHA256
                                 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
          then 12 else 4);
      CK : Byte_Seq (0 .. Key_Len - 1);
      SK : Byte_Seq (0 .. Key_Len - 1);
      CI : Byte_Seq (0 .. 11) := (others => 0);
      SI : Byte_Seq (0 .. 11) := (others => 0);
   begin
      Expand_Keys_12 (CK, SK, CI, SI, HC.Master_Secret_12,
                       HC.Server_Random, HC.Client_Random,
                       Key_Len, IV_Len, Use_384);
      declare
         Int_Suite : constant Unsigned_16 :=
           (case S.Negotiated_Suite is
               when Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                     Suite_AES_128_GCM_SHA256,
               when Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                     Suite_AES_256_GCM_SHA384,
               when others => Suite_CHACHA20_POLY1305_SHA256);
      begin
         S.Client_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;
      HC.Client_Write_IV_12 := CI;
      HC.Server_Write_IV_12 := SI;
      HC.Client_Seq_12 := 0;
      HC.Server_Seq_12 := 0;
   end Derive_Keys_Resumed_12;

   procedure Derive_Keys_12 (S : in out Session; HC : in out Handshake_Context)
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
          then 16 else 32);
      --  RFC 5288 §3: AES-GCM IV salt is 4 bytes.
      --  RFC 7905 §2: ChaCha20-Poly1305 IV is 12 bytes.
      IV_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_CHACHA20_SHA256
                                 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
          then 12 else 4);
      CK : Byte_Seq (0 .. Key_Len - 1);
      SK : Byte_Seq (0 .. Key_Len - 1);
      CI : Byte_Seq (0 .. 11) := (others => 0);
      SI : Byte_Seq (0 .. 11) := (others => 0);
      Shared_Len : constant N32 :=
         (if HC.Selected_Group = Group_Secp384r1 then 48 else 32);
   begin
      --  Master secret derivation
      --  Verify EMS label consistency at compile/prove time
      pragma Assert
        (EMS_Label_Consistent (True, "extended master secret"));
      pragma Assert
        (EMS_Label_Consistent (False, "master secret"));

      if HC.Use_EMS then
         --  RFC 7627: Extended Master Secret
         --  master_secret = PRF(pms, "extended master secret", Hash(hs_msgs))
         declare
            TH     : Digest;
            TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         begin
            if Use_384 then
               SPARKNaCl.Hashing.SHA384.Hash
                 (TH_384, HC.Transcript (0 .. HC.Transcript_Len - 1));
               PRF_SHA384 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "extended master secret", Byte_Seq (TH_384));
            else
               Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
               PRF_SHA256 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "extended master secret", Byte_Seq (TH));
            end if;
         end;
         HC.MS_Derivation := Extended;
      else
         --  RFC 5246 §8.1: Standard master secret
         --  master_secret = PRF(pms, "master secret", CR || SR)
         Key_Schedule_12.Derive_Master_Secret_12
           (HC.Master_Secret_12,
            HC.Shared_Secret (0 .. Shared_Len - 1),
            HC.Client_Random, HC.Server_Random, Use_384);
         HC.MS_Derivation := Legacy;
      end if;

      Expand_Keys_12 (CK, SK, CI, SI, HC.Master_Secret_12,
                       HC.Server_Random, HC.Client_Random,
                       Key_Len, IV_Len, Use_384);

      declare
         Int_Suite : constant Unsigned_16 :=
           (case S.Negotiated_Suite is
               when Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                     Suite_AES_128_GCM_SHA256,
               when Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                     Suite_AES_256_GCM_SHA384,
               when others => Suite_CHACHA20_POLY1305_SHA256);
         pragma Assert
           (Int_Suite = Handshake.TLS12.Internal_Suite_For
                          (S.Negotiated_Suite));
      begin
         S.Client_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;

      HC.Client_Write_IV_12 := CI;
      HC.Server_Write_IV_12 := SI;
      HC.Client_Seq_12 := 0;
      HC.Server_Seq_12 := 0;
   end Derive_Keys_12;

   ------------------------------------------------------------------
   --  Process_Server_Flight: parse Cert + SKE + SHD, then send CKE+CCS+Fin
   ------------------------------------------------------------------

   procedure Process_Server_Flight
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre  => Reasm_Coherent (HC),
        Post => Reasm_Coherent (HC);

   procedure Process_Server_Flight
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Rec : Records.Parse_Result;
      Have_Leftover_Msg : constant Boolean :=
        HC.Reasm_Buf /= null
        and then HC.Reasm_Need > 0
        and then not HC.Reasm_Hdr_Pending
        and then HC.Reasm_Len >= HC.Reasm_Need;
   begin
      --  Fast path: leftover from a prior PackHandshake record already
      --  contains a complete HS message. Skip the record read and
      --  jump straight into dispatch.
      if not Have_Leftover_Msg then
         if Input_Available (S) = 0 then
            Result := Need_Input; return;
         end if;

         Records.Parse_Record_Header
           (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
            Available (S.Input), Rec);

         if Rec.Bad_Version then
            S.Last_Error := Protocol_Version;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         if not Rec.OK then
            Result := Need_Input; return;
         end if;

         if Rec.Content = Records.Content_Alert then
            --  Handshake-time alerts (plaintext, before keys derived).
            --  Warning-level (1) other than close_notify (desc 0) is
            --  ignorable (RFC 5246 §7.2.2), but RFC 8446 §6.1 caps
            --  the rate to defend against DoS: more than 4 warnings
            --  during a handshake → fatal decode_error (BoGo
            --  SendWarningAlerts-TooMany). Fatal alerts close the
            --  connection.
            declare
               AS  : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               ALen : constant N32 := Rec.Fragment_Len;
               Lvl : constant Byte :=
                  (if ALen >= 1 then S.Input.Data (AS) else 0);
               Dsc : constant Byte :=
                  (if ALen >= 2 then S.Input.Data (AS + 1) else 0);
            begin
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               if Lvl = 1 and Dsc /= 0 then
                  S.Warning_Alerts_Recvd :=
                     S.Warning_Alerts_Recvd + 1;
                  if S.Warning_Alerts_Recvd >= 5 then
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  Result := OK; return;
               elsif Lvl = 2 then
                  --  Peer-fatal: close without reply.
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert; return;
               else
                  --  close_notify or malformed: shutdown / skip.
                  Result := OK; return;
               end if;
            end;
         end if;

         if Rec.Content /= Records.Content_Handshake then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK; return;
         end if;
      end if;

      declare
         FS       : constant N32 :=
           (if Have_Leftover_Msg then 0
            else S.Input.Read_Pos + Rec.Fragment_Pos);
         Frag_Len : constant N32 :=
           (if Have_Leftover_Msg then 0 else Rec.Fragment_Len);
         Msg_Type : Byte; Msg_Len : N32; Parse_OK : Boolean;
         Max_HS_Msg : constant N32 := 131072;
      begin
         if Have_Leftover_Msg then
            --  Leftover Reasm_Buf already has a complete message at
            --  offset 0 with size HC.Reasm_Need. Decode header and
            --  fall through to dispatch (skip reassembly branches).
            Handshake.Parse_Handshake_Header
              (HC.Reasm_Buf (0 .. HC.Reasm_Need - 1),
               Msg_Type, Msg_Len, Parse_OK);
            if not Parse_OK then
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;

         --  If reassembly in progress, append this fragment
         elsif HC.Reasm_Need > 0 and then HC.Reasm_Buf /= null then
            declare
               Remaining : constant N32 := HC.Reasm_Need - HC.Reasm_Len;
               Copy_Len  : constant N32 := N32'Min (Frag_Len, Remaining);
            begin
               if HC.Reasm_Len + Copy_Len <=
                     N32 (HC.Reasm_Buf'Length)
               then
                  HC.Reasm_Buf (HC.Reasm_Len ..
                                HC.Reasm_Len + Copy_Len - 1) :=
                     S.Input.Data (FS .. FS + Copy_Len - 1);
                  HC.Reasm_Len := HC.Reasm_Len + Copy_Len;
               end if;
            end;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            --  Header-pending sentinel (BoGo MaxHandshakeRecordLength=1
            --  splits the 4-byte HS header itself across records).
            --  Once 4 bytes are present, decode the real HS_Total
            --  and upgrade Reasm_Need.
            if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
               declare
                  HS_Total : constant N32 :=
                     N32 (HC.Reasm_Buf (1)) * 65536
                     + N32 (HC.Reasm_Buf (2)) * 256
                     + N32 (HC.Reasm_Buf (3)) + 4;
               begin
                  HC.Reasm_Hdr_Pending := False;
                  if HS_Total < 4 or HS_Total > Max_HS_Msg then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  HC.Reasm_Need := HS_Total;
               end;
            end if;

            if HC.Reasm_Len < HC.Reasm_Need then
               Result := OK; return;  --  need more fragments
            end if;

            --  Full message reassembled — parse the handshake header
            --  from the reassembled buffer and fall through to
            --  the normal message dispatch below.
            Handshake.Parse_Handshake_Header
              (HC.Reasm_Buf (0 .. HC.Reasm_Need - 1), Msg_Type, Msg_Len, Parse_OK);
            if not Parse_OK then
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;
         else
            --  Fresh record. Frag_Len < 4 means the server fragmented
            --  the 4-byte HS header itself (BoGo SplitHandshakeRecords
            --  with MaxHandshakeRecordLength=1). Start reassembly with
            --  the header-pending sentinel; once 4 bytes are gathered
            --  the upper branch will decode the real HS_Total.
            if Frag_Len < 4 then
               if Frag_Len = 0 then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
               HC.Reasm_Need := 4;
               HC.Reasm_Hdr_Pending := True;
               HC.Reasm_Len := Frag_Len;
               HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                  S.Input.Data (FS .. FS + Frag_Len - 1);
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               pragma Assert (Reasm_Coherent (HC));
               Result := OK; return;
            end if;

            --  Fresh record — parse handshake header
            declare
               Frag : Byte_Seq renames
                  S.Input.Data (FS .. FS + Frag_Len - 1);
            begin
               Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);
            end;
            if not Parse_OK then
               --  Distinguish unknown-msg-type from malformed shape so
               --  BoGo WrongMessageType-* and TrailingMessageData-*
               --  get the right alert. Unknown type → unexpected_message.
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               declare
                  Raw_Type : constant Byte :=
                     (if Frag_Len >= 1 then S.Input.Data (FS) else 0);
                  Is_Known : constant Boolean :=
                     Raw_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                                 16#0B# | 16#0C# | 16#0D# | 16#0E# |
                                 16#0F# | 16#10# | 16#14#;
               begin
                  if Is_Known then
                     Send_Alert_And_Error (S, Decode_Error, Result);
                  else
                     Send_Alert_And_Error
                       (S, Unexpected_Message, Result);
                  end if;
               end;
               return;
            end if;

            --  Check if message spans multiple records
            if Msg_Len + 4 > Frag_Len then
               if Msg_Len + 4 > Max_HS_Msg then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result); return;
               end if;
               --  Start reassembly
               HC.Reasm_Buf := new Byte_Seq'(0 .. Msg_Len + 3 => 0);
               HC.Reasm_Need := Msg_Len + 4;
               HC.Reasm_Len := Frag_Len;
               HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                  S.Input.Data (FS .. FS + Frag_Len - 1);
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               pragma Assert (Reasm_Coherent (HC));
               Result := OK; return;  --  need more fragments
            end if;
         end if;

         --  At this point we have a complete handshake message.
         --  For single-record messages, copy the WHOLE record fragment
         --  into Reasm_Buf (could be multiple HS msgs packed per BoGo
         --  PackHandshakeFlight). Set Reasm_Need to just the first
         --  message size so the case body sees one message at a time;
         --  the post-dispatch loop below shifts and re-dispatches any
         --  trailing packed messages.
         if HC.Reasm_Buf = null or HC.Reasm_Need = 0 then
            HC.Reasm_Buf := new Byte_Seq'(0 .. Frag_Len - 1 => 0);
            HC.Reasm_Buf.all :=
               S.Input.Data (FS .. FS + Frag_Len - 1);
            HC.Reasm_Need := Msg_Len + 4;
            HC.Reasm_Len := Frag_Len;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         end if;
         pragma Assert (Reasm_Coherent (HC));

         declare
            More_Packed : Boolean := True;
         begin
         while More_Packed loop
            pragma Loop_Variant
              (Decreases => HC.Reasm_Len);
            pragma Loop_Invariant
              (HC.Reasm_Buf /= null
               and then HC.Reasm_Need > 0
               and then HC.Reasm_Need <= HC.Reasm_Len
               and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
            More_Packed := False;
         declare
            RN : constant N32 := HC.Reasm_Need;
            Frag : constant Byte_Seq :=
               HC.Reasm_Buf (0 .. RN - 1);
         begin

         case Msg_Type is
            when 16#0B# =>
               --  Certificate (RFC 5246 §7.4.2) — parsed via RFLX
               --  TLS_1_2_Certificate. The wire format is
               --  cert_list_len(3) || {cert_len(3) || cert}* with no
               --  context byte and no per-cert extensions. The RFLX
               --  schema enforces all length-field invariants
               --  (cert_list_len matches the entries sequence size;
               --  each entry's cert_len matches its cert_data size).
               --  Trailing bytes raise Decode_Error here, matching
               --  BoGo TrailingMessageData-ServerCertificate.
               declare
                  package C12 renames
                    RFLX.TLS_Handshake.TLS_1_2_Certificate;
                  package C12_Entries renames
                    RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
                  package C12_Entry renames
                    RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;
                  package RBT renames RFLX.RFLX_Builtin_Types;
                  procedure RFLX_Free_Local is new
                    Ada.Unchecked_Deallocation
                      (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
                  Buf : RBT.Bytes_Ptr;
                  Ctx : C12.Context;
                  B   : constant N32 := Frag'First + 4;
                  Body_Bytes : Byte_Seq (0 .. Msg_Len - 1);
                  Cert_Idx : Natural := 0;
               begin
                  HC.Peer_Cert_Valid := False;
                  HC.Peer_Int_Count := 0;

                  if Msg_Len < 3 then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;

                  Body_Bytes := Frag (B .. B + Msg_Len - 1);

                  Buf := new RBT.Bytes'
                          (1 .. RBT.Index (Msg_Len) => 0);
                  Buf.all := To_RFLX (Body_Bytes);
                  C12.Initialize
                    (Ctx, Buf,
                     Written_Last => RBT.Bit_Length (Msg_Len * 8));
                  C12.Verify_Message (Ctx);

                  if not C12.Well_Formed_Message (Ctx) then
                     C12.Take_Buffer (Ctx, Buf);
                     RFLX_Free_Local (Buf);
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;

                  declare
                     use type RBT.Bit_Length;
                  begin
                  if C12.Field_Size
                       (Ctx, C12.F_Certificate_List) > 0
                  then
                     declare
                        Entries_Ctx : C12_Entries.Context;
                     begin
                        C12.Switch_To_Certificate_List
                          (Ctx, Entries_Ctx);

                        while C12_Entries.Has_Element (Entries_Ctx)
                          and then Cert_Idx <= Max_Pool_Size
                        loop
                           declare
                              E_Ctx : C12_Entry.Context;
                           begin
                              C12_Entries.Switch (Entries_Ctx, E_Ctx);
                              C12_Entry.Verify_Message (E_Ctx);

                              if C12_Entry.Well_Formed_Message (E_Ctx)
                              then
                                 declare
                                    C_Len : constant N32 :=
                                      N32 (C12_Entry.Get_Cert_Data_Length
                                             (E_Ctx));
                                    Cert_RFLX : RBT.Bytes
                                                  (1 .. RBT.Index (C_Len));
                                 begin
                                    if C_Len > 0
                                      and C_Len <= N32 (Max_Cert_DER)
                                    then
                                       C12_Entry.Get_Cert_Data
                                         (E_Ctx, Cert_RFLX);

                                       if Cert_Idx = 0 then
                                          --  Leaf cert
                                          HC.Peer_Cert_DER_Len := C_Len;
                                          for I in N32 range 0 .. C_Len - 1
                                          loop
                                             HC.Peer_Cert_DER (I) :=
                                               Byte
                                                 (Cert_RFLX
                                                    (RBT.Index (I + 1)));
                                          end loop;
                                          declare
                                             Cert_X : X509.Byte_Seq
                                               (0 .. X509.N32 (C_Len) - 1) :=
                                                 (others => 0);
                                             P_OK : Boolean;
                                          begin
                                             for I in N32 range
                                               0 .. C_Len - 1
                                             loop
                                                Cert_X (X509.N32 (I)) :=
                                                  X509.Byte
                                                    (Cert_RFLX
                                                       (RBT.Index (I + 1)));
                                             end loop;
                                             X509.Parse
                                               (Cert_X, HC.Peer_Cert, P_OK);
                                             HC.Peer_Cert_Valid := P_OK
                                               and then X509.Is_Valid
                                                          (HC.Peer_Cert);
                                          end;
                                       elsif HC.Peer_Int_Count
                                               < Max_Pool_Size
                                       then
                                          --  Intermediate cert
                                          declare
                                             Idx : constant Natural :=
                                               HC.Peer_Int_Count;
                                             Int_X : X509.Byte_Seq
                                               (0 .. X509.N32 (C_Len) - 1) :=
                                                 (others => 0);
                                             C   : X509.Certificate;
                                             P_OK : Boolean;
                                          begin
                                             for I in N32 range
                                               0 .. C_Len - 1
                                             loop
                                                Int_X (X509.N32 (I)) :=
                                                  X509.Byte
                                                    (Cert_RFLX
                                                       (RBT.Index (I + 1)));
                                             end loop;
                                             X509.Parse
                                               (Int_X, C, P_OK);
                                             if P_OK
                                               and then X509.Is_Valid (C)
                                             then
                                                HC.Peer_Ints (Idx).Cert := C;
                                                for I in X509.N32 range
                                                  0 .. X509.N32 (C_Len) - 1
                                                loop
                                                   HC.Peer_Ints (Idx).DER (I)
                                                     :=
                                                       X509.Byte
                                                         (Cert_RFLX
                                                            (RBT.Index
                                                               (N32 (I) + 1)));
                                                end loop;
                                                HC.Peer_Ints (Idx).DER_Len :=
                                                  X509.N32 (C_Len);
                                                HC.Peer_Ints (Idx).Present :=
                                                  True;
                                                HC.Peer_Int_Count :=
                                                  HC.Peer_Int_Count + 1;
                                             end if;
                                          end;
                                       end if;
                                       Cert_Idx := Cert_Idx + 1;
                                    end if;
                                 end;
                              end if;

                              C12_Entries.Update (Entries_Ctx, E_Ctx);
                           end;
                        end loop;

                        C12.Update_Certificate_List
                          (Ctx, Entries_Ctx);
                     end;
                  end if;
                  end;

                  C12.Take_Buffer (Ctx, Buf);
                  RFLX_Free_Local (Buf);
               end;

               --  Wire-format gate: the leaf must parse cleanly even
               --  in Skip_Verify mode (parseability is independent
               --  of chain validation). BoGo's
               --  GarbageCertificate-Client-TLS12 sends "GARBAGE" as
               --  the cert and expects decode_error.
               if not HC.Peer_Cert_Valid then
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;

               --  RFC 5246 §7.4.2: leaf keyUsage must include
               --  digitalSignature for ECDHE-* suites (we sign SKE
               --  with it). Run independently of chain validation
               --  for the same reasons noted on the TLS 1.3 side.
               --  BoGo's {RSA,ECDSA}KeyUsage-Client-TLS12 cluster.
               if X509.Has_Key_Usage (HC.Peer_Cert)
                 and then not X509.KU_Digital_Signature (HC.Peer_Cert)
               then
                  Send_Alert_And_Error (S, Bad_Certificate, Result);
                  return;
               end if;

               --  RFC 5246 §7.4.2 / RFC 8422 §5.4: the leaf cert's
               --  key type must match the cipher suite's expected
               --  signing algorithm. BoGo CertificateCipherMismatch-*
               --  sends e.g. an RSA cert with TLS_ECDHE_ECDSA suite
               --  advertised; we reject with bad_certificate.
               declare
                  PK : constant X509.Algorithm_ID :=
                     X509.PK_Algorithm (HC.Peer_Cert);
                  Suite_Needs_ECDSA : constant Boolean :=
                     S.Negotiated_Suite in
                       Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                     | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                     | Suite_ECDHE_ECDSA_CHACHA20_SHA256;
                  Suite_Needs_RSA   : constant Boolean :=
                     S.Negotiated_Suite in
                       Suite_ECDHE_RSA_AES128_GCM_SHA256
                     | Suite_ECDHE_RSA_AES256_GCM_SHA384
                     | Suite_ECDHE_RSA_CHACHA20_SHA256;
                  Cert_Is_ECDSA : constant Boolean :=
                     PK = X509.Algo_EC_P256
                     or PK = X509.Algo_EC_P384;
                  Cert_Is_RSA : constant Boolean :=
                     PK = X509.Algo_RSA;
                  Cert_Is_Ed25519 : constant Boolean :=
                     PK = X509.Algo_EC_Ed25519;
               begin
                  if Suite_Needs_ECDSA
                    and then not (Cert_Is_ECDSA or Cert_Is_Ed25519)
                  then
                     Send_Alert_And_Error
                       (S, Bad_Certificate, Result);
                     return;
                  end if;
                  if Suite_Needs_RSA and then not Cert_Is_RSA then
                     Send_Alert_And_Error
                       (S, Bad_Certificate, Result);
                     return;
                  end if;
               end;

               --  Chain validation (if trust store is configured)
               if not HC.Cfg.Skip_Verify
                  and then HC.Cfg.Trust /= null
                  and then HC.Cfg.Get_Time /= null
                  and then HC.Peer_Cert_Valid
               then
                  declare
                     PCDL : constant N32 := HC.Peer_Cert_DER_Len;
                     Cert_X : X509.Byte_Seq
                        (0 .. X509.N32 (PCDL) - 1) := (others => 0);
                     VR : Validation_Result;
                  begin
                     for I in N32 range 0 .. PCDL - 1 loop
                        Cert_X (X509.N32 (I)) :=
                           X509.Byte (HC.Peer_Cert_DER (I));
                     end loop;

                     VR := Validate_Chain
                       (Leaf_DER   => Cert_X,
                        Leaf       => HC.Peer_Cert,
                        Ints       => HC.Peer_Ints,
                        Int_Count  => HC.Peer_Int_Count,
                        Roots      => HC.Cfg.Trust.Roots,
                        Root_Count => HC.Cfg.Trust.Root_Count,
                        Now        => HC.Cfg.Get_Time.all,
                        Hostname   =>
                           HC.Cfg.Server_Name.Data
                             (1 .. HC.Cfg.Server_Name.Len),
                        Purpose    => HC.Cfg.Verify_Purpose,
                        Mode       => HC.Cfg.Verify_Mode);

                     if VR /= Valid then
                        Free_Byte_Seq (HC.Reasm_Buf);
                        HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                        Send_Alert_And_Error (S, Bad_Certificate, Result);
                        return;
                     end if;
                  end;
               end if;

               Append_Transcript (HC, Frag);
               Result := OK;

            when 16#0D# =>
               --  CertificateRequest (RFC 5246 §7.4.4).
               --  Wire shape:
               --    cert_types_len(1) + cert_types[N]
               --    sig_algs_len(2) + sig_algs[2N]   (TLS 1.2 only)
               --    ca_dn_len(2) + ca_dns[N]         (we ignore)
               --  RFC 5246 §7.4.1.4.1 mandates supported_signature_
               --  algorithms is non-empty; empty list = decode_error.
               --  Also verify the message ends exactly at the end of
               --  ca_dns — trailing bytes are decode_error (BoGo
               --  TrailingMessageData-CertificateRequest).
               declare
                  Body_OK : Boolean := False;
                  B : constant N32 := Frag'First + 4;
               begin
                  if B + 1 <= Frag'Last then
                     declare
                        CT_Len_D : constant N32 := N32 (Frag (B));
                        SA_Off_D : constant N32 := B + 1 + CT_Len_D;
                     begin
                        if SA_Off_D + 1 <= Frag'Last then
                           declare
                              SA_Len_D : constant N32 :=
                                 N32 (Frag (SA_Off_D)) * 256
                                 + N32 (Frag (SA_Off_D + 1));
                              CA_Off_D : constant N32 :=
                                 SA_Off_D + 2 + SA_Len_D;
                           begin
                              if CA_Off_D + 1 <= Frag'Last then
                                 declare
                                    CA_Len_D : constant N32 :=
                                       N32 (Frag (CA_Off_D)) * 256
                                       + N32 (Frag (CA_Off_D + 1));
                                    Expected : constant N32 :=
                                       1 + CT_Len_D + 2 + SA_Len_D
                                       + 2 + CA_Len_D;
                                 begin
                                    Body_OK := Msg_Len = Expected;
                                 end;
                              end if;
                           end;
                        end if;
                     end;
                  end if;
                  if not Body_OK then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
               end;
               HC.Cert_Request_Received := True;
               declare
                  Picked   : Unsigned_16 := 0;
                  SA_Empty : Boolean := True;
                  B : constant N32 := Frag'First + 4;
               begin
                  if B + 1 <= Frag'Last then
                     declare
                        CT_Len : constant N32 := N32 (Frag (B));
                        SA_Off : constant N32 := B + 1 + CT_Len;
                     begin
                        if SA_Off + 1 <= Frag'Last then
                           declare
                              SA_Len : constant N32 :=
                                 N32 (Frag (SA_Off)) * 256
                                 + N32 (Frag (SA_Off + 1));
                           begin
                              if SA_Len >= 2
                                and SA_Off + 1 + SA_Len <= Frag'Last
                              then
                                 SA_Empty := False;
                                 if HC.Cfg.Local /= null then
                                    declare
                                       SA_Slice : constant Byte_Seq
                                          (0 .. SA_Len - 1) :=
                                          Frag (SA_Off + 2 ..
                                                SA_Off + 1 + SA_Len);
                                    begin
                                       Picked := Handshake.Pick_Sig_Algo
                                         (SA_Slice,
                                          HC.Cfg.Local.Sign_Algo,
                                          Allow_PKCS1_v1_5 => True);
                                    end;
                                 end if;
                              end if;
                           end;
                        end if;
                     end;
                  end if;
                  if SA_Empty then
                     --  RFC 5246 §7.4.1.4.1: empty list = malformed.
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  if HC.Cfg.Local /= null then
                     if Picked /= 0 then
                        HC.Negotiated_Sig_Algo := Picked;
                     else
                        case HC.Cfg.Local.Sign_Algo is
                           when Sign_RSA_PSS =>
                              HC.Negotiated_Sig_Algo := 16#0804#;
                           when Sign_ECDSA_P256 =>
                              HC.Negotiated_Sig_Algo := 16#0403#;
                           when Sign_ECDSA_P384 =>
                              HC.Negotiated_Sig_Algo := 16#0503#;
                           when Sign_Ed25519 =>
                              HC.Negotiated_Sig_Algo := 16#0807#;
                           when Sign_None =>
                              null;
                        end case;
                     end if;
                  end if;
               end;
               Append_Transcript (HC, Frag);
               Result := OK;

            when HT_Server_Key_Exchange =>
               --  Parse SKE: extract ECDHE params + verify signature.
               if Msg_Len = 0 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               --  Length-validate the body before Parse_SKE so that
               --  trailing bytes raise decode_error rather than
               --  handshake_failure. SKE body layout (RFC 5246
               --  §7.4.3): curve_type(1) + curve(2) + pt_len(1) +
               --  pt(pt_len) + sig_hash(1) + sig_alg(1) + sig_len(2)
               --  + sig(sig_len) = 8 + pt_len + sig_len.
               declare
                  Body_Start : constant N32 := Frag'First + 4;
                  Length_OK  : Boolean := False;
               begin
                  if Msg_Len >= 8 then
                     declare
                        Pt_Len  : constant N32 :=
                           N32 (Frag (Body_Start + 3));
                        Sig_Pos : constant N32 :=
                           Body_Start + 4 + Pt_Len + 2;
                     begin
                        if Sig_Pos + 1 < Frag'First + 4 + Msg_Len then
                           declare
                              Sig_Len : constant N32 :=
                                 N32 (Frag (Sig_Pos)) * 256
                                 + N32 (Frag (Sig_Pos + 1));
                           begin
                              Length_OK :=
                                 Msg_Len = 8 + Pt_Len + Sig_Len;
                           end;
                        end if;
                     end;
                  end if;
                  if not Length_OK then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
               end;
               declare
                  Msg_Len_C : constant N32 := Msg_Len;
                  Body_Start : constant N32 := Frag'First + 4;
                  Body_Data : Byte_Seq (0 .. Msg_Len_C - 1);
                  SKE_OK : Boolean;
               begin
                  Body_Data := Frag (Body_Start .. Body_Start + Msg_Len_C - 1);
                  Parse_Server_Key_Exchange (HC, Body_Data, SKE_OK);
                  if not SKE_OK then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
               Append_Transcript (HC, Frag);
               Result := OK;

            when HT_Server_Hello_Done =>
               --  RFC 5246 §7.4.5: ServerHelloDone has empty body
               --  (length = 0). Reject any trailing bytes with
               --  decode_error (BoGo TrailingMessageData-ServerHelloDone).
               if Msg_Len /= 0 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  HC.Reasm_Hdr_Pending := False;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               --  RFC 5246 §7.4: ServerHelloDone is the last
               --  pre-CCS server handshake message in its record,
               --  so any partial/extra bytes after it are excess
               --  handshake data. BoGo
               --  PartialFinishedWithServerHelloDone /
               --  PartialNewSessionTicketWithServerHelloDone append
               --  one stray byte (typeFinished / typeNewSessionTicket)
               --  to the SHD record; reject as unexpected_message.
               if HC.Reasm_Len > HC.Reasm_Need then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  HC.Reasm_Hdr_Pending := False;
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
                  return;
               end if;
               --  End of server flight. Now:
               --  1. Compute ECDHE shared secret
               --  2. Derive keys
               --  3. Send CKE + CCS + Finished
               Append_Transcript (HC, Frag);

               --  Generate ECDHE keypair + compute shared secret
               declare
                  Gen : constant Random_Bytes_Fn := HC.Cfg.Random;
                  SS_OK  : Boolean    := False;
                  --  RFC 5246 §7.2.2 / RFC 8446 §6.2: invalid peer
                  --  share is illegal_parameter; unknown group is
                  --  handshake_failure.
                  SS_Err : Error_Code := Handshake_Failure;
               begin
                  case HC.Selected_Group is
                     when Group_X25519 =>
                        Gen (Byte_Seq (HC.Local_SK));
                        HC.Shared_Secret (0 .. 31) :=
                           SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
                        --  RFC 7748 §6.1: small-subgroup defence.
                        --  Post-condition formally proven by SPARK.
                        SS_OK := Shared_Secret_Is_Acceptable_X25519
                                   (HC.Shared_Secret (0 .. 31));
                        if not SS_OK then
                           SS_Err := Illegal_Parameter;
                        end if;
                     when Group_Secp256r1 =>
                        Gen (Byte_Seq (HC.P256_Local_SK));
                        declare
                           use SPARKTLSCrypto.P256.Point;
                           Pt : P256_Jacobian; V : SPARKNaCl.U32;
                        begin
                           P256_Decode (Pt, HC.P256_Peer_PK, V);
                           if V /= 0 then
                              P256_Mul (Pt, HC.P256_Local_SK, 32);
                              P256_To_Affine (Pt);
                              declare E : Byte_Seq (0 .. 64);
                              begin
                                 P256_Encode (E, Pt);
                                 HC.Shared_Secret := (others => 0);
                                 HC.Shared_Secret (0 .. 31) := E (1 .. 32);
                              end;
                              SS_OK := True;
                           else
                              SS_Err := Illegal_Parameter;
                           end if;
                        end;
                     when Group_Secp384r1 =>
                        Gen (Byte_Seq (HC.P384_Local_SK));
                        declare SS : Bytes_48; OK384 : Boolean;
                        begin
                           SPARKTLSCrypto.P384.Point.P384_ECDHE
                             (SS, OK384, HC.P384_Local_SK, HC.P384_Peer_PK);
                           if OK384 then
                              HC.Shared_Secret := SS; SS_OK := True;
                           else
                              SS_Err := Illegal_Parameter;
                           end if;
                        end;
                     when others => null;
                  end case;

                  if not SS_OK then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, SS_Err, Result);
                     return;
                  end if;
               end;

               --  Atomic flight assembly: build CKE + CCS + encrypted
               --  Finished into Scratch; commit only if the whole
               --  flight fits. The Finished encryption advances
               --  HC.Client_Seq_12, so save it and roll back on commit
               --  failure to keep AEAD nonces in sync with the peer.
               declare
                  use Key_Schedule_12;
                  use Records.TLS12;
                  Scratch : IO_Buffer;
                  CKE : Byte_Seq (0 .. Max_Client_Key_Exchange - 1);
                  CKE_Len : N32;
                  Rec_Out : N32;
                  CCS_Out : N32;
                  FB : Byte_Seq (0 .. Finished_12_Total_Len - 1);
                  FL : N32; EO : N32;
                  TH : Digest;
                  TH4 : SPARKNaCl.Hashing.SHA384.Digest;
                  Use_384 : constant Boolean :=
                     S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                                        | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
                  Saved_Seq : Unsigned_64;
               begin
                  --  Client Certificate (mTLS, RFC 5246 §7.4.6).
                  --  Sent before CKE when the server requested a
                  --  client cert. Empty cert message if we have no
                  --  identity configured — server then decides
                  --  whether to fail (Require) or accept anonymously.
                  if HC.Cert_Request_Received then
                     declare
                        Cert_Buf : Byte_Seq
                          (0 .. 4 + 3 + Max_Cert_DER - 1);
                        Cert_Len : N32;
                     begin
                        if HC.Cfg.Local /= null
                          and then HC.Cfg.Local.Has_Identity
                        then
                           Build_Certificate_Chain_12
                             (HC.Cfg.Local.all, Cert_Buf, Cert_Len);
                        else
                           --  Empty Certificate: type(0x0B) + len(3)=4
                           --  + cert_list_len(3)=0 → 7 bytes total.
                           Cert_Buf := (others => 0);
                           Cert_Buf (0) := 16#0B#;
                           Cert_Buf (3) := 3;  --  body length = 3
                           Cert_Len := 7;
                        end if;
                        if Cert_Len > 0 then
                           Append_Transcript
                             (HC, Cert_Buf (0 .. Cert_Len - 1));
                           Records.Build_Handshake_Record
                             (Cert_Buf (0 .. Cert_Len - 1),
                              Scratch, Rec_Out);
                           if Rec_Out = 0 then
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Len := 0;
                              HC.Reasm_Need := 0;
                              Send_Alert_And_Error
                                (S, Insufficient_Buffer, Result);
                              return;
                           end if;
                        end if;
                     end;
                  end if;

                  --  CKE
                  Build_Client_Key_Exchange (HC, CKE, CKE_Len);
                  if CKE_Len > 0 then
                     Append_Transcript (HC, CKE (0 .. CKE_Len - 1));
                     Records.Build_Handshake_Record
                       (CKE (0 .. CKE_Len - 1), Scratch, Rec_Out);
                     if Rec_Out = 0 then
                        Free_Byte_Seq (HC.Reasm_Buf);
                        HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                        Send_Alert_And_Error
                          (S, Insufficient_Buffer, Result);
                        return;
                     end if;
                  end if;

                  --  CertificateVerify (mTLS, RFC 5246 §7.4.8).
                  --  Signs handshake_messages = ClientHello..CKE.
                  --  Only sent when we presented a non-empty cert.
                  if HC.Cert_Request_Received
                    and then HC.Cfg.Local /= null
                    and then HC.Cfg.Local.Has_Identity
                  then
                     declare
                        --  Build_Certificate_Verify_12 requires
                        --  Result'Last >= 523 (header + RSA-4096 sig).
                        CV_Buf : Byte_Seq (0 .. 523);
                        CV_Len : N32;
                        TH_CV  : Digest;
                        TH4_CV : SPARKNaCl.Hashing.SHA384.Digest;
                        TH5_CV : SPARKNaCl.Hashing.SHA512.Digest;
                        --  RFC 5246 §7.4.8: hash for CV is per the
                        --  chosen signature algorithm. The hash family
                        --  picked here must match the case in
                        --  Build_Certificate_Verify_12. For Ed25519
                        --  (0x0807) we pass the RAW transcript — the
                        --  Ed25519 primitive does SHA-512 internally
                        --  over (dom2 || prefix || message).
                        Use_384_For_CV : constant Boolean :=
                           HC.Negotiated_Sig_Algo in
                             16#0503# | 16#0805# | 16#0501#;
                        Use_512_For_CV : constant Boolean :=
                           HC.Negotiated_Sig_Algo in 16#0806# | 16#0601#;
                        Use_Raw_For_CV : constant Boolean :=
                           HC.Negotiated_Sig_Algo = 16#0807#;
                     begin
                        if Use_Raw_For_CV then
                           Build_Certificate_Verify_12
                             (Transcript_Hash =>
                                HC.Transcript (0 .. HC.Transcript_Len - 1),
                              Id              => HC.Cfg.Local.all,
                              Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                              Random          => HC.Cfg.Random,
                              Result          => CV_Buf,
                              Len             => CV_Len);
                        elsif Use_512_For_CV then
                           SPARKNaCl.Hashing.SHA512.Hash
                             (TH5_CV,
                              HC.Transcript
                                (0 .. HC.Transcript_Len - 1));
                           Build_Certificate_Verify_12
                             (Transcript_Hash => Byte_Seq (TH5_CV),
                              Id              => HC.Cfg.Local.all,
                              Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                              Random          => HC.Cfg.Random,
                              Result          => CV_Buf,
                              Len             => CV_Len);
                        elsif Use_384_For_CV then
                           SPARKNaCl.Hashing.SHA384.Hash
                             (TH4_CV,
                              HC.Transcript
                                (0 .. HC.Transcript_Len - 1));
                           Build_Certificate_Verify_12
                             (Transcript_Hash => Byte_Seq (TH4_CV),
                              Id              => HC.Cfg.Local.all,
                              Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                              Random          => HC.Cfg.Random,
                              Result          => CV_Buf,
                              Len             => CV_Len);
                        else
                           Hash (TH_CV,
                                 HC.Transcript
                                   (0 .. HC.Transcript_Len - 1));
                           Build_Certificate_Verify_12
                             (Transcript_Hash => Byte_Seq (TH_CV),
                              Id              => HC.Cfg.Local.all,
                              Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                              Random          => HC.Cfg.Random,
                              Result          => CV_Buf,
                              Len             => CV_Len);
                        end if;
                        if CV_Len = 0 then
                           Free_Byte_Seq (HC.Reasm_Buf);
                           HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                           Send_Alert_And_Error
                             (S, Internal_Error, Result);
                           return;
                        end if;
                        Append_Transcript
                          (HC, CV_Buf (0 .. CV_Len - 1));
                        Records.Build_Handshake_Record
                          (CV_Buf (0 .. CV_Len - 1),
                           Scratch, Rec_Out);
                        if Rec_Out = 0 then
                           Free_Byte_Seq (HC.Reasm_Buf);
                           HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                           Send_Alert_And_Error
                             (S, Insufficient_Buffer, Result);
                           return;
                        end if;
                     end;
                  end if;

                  --  Derive keys (uses transcript up to CKE/CV)
                  Derive_Keys_12 (S, HC);

                  --  CCS
                  Records.Build_CCS_Record (Scratch, CCS_Out);
                  if CCS_Out = 0 then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error
                       (S, Insufficient_Buffer, Result);
                     return;
                  end if;

                  --  Encrypted Finished (advances HC.Client_Seq_12)
                  if Use_384 then
                     SPARKNaCl.Hashing.SHA384.Hash
                       (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
                     Build_Finished_12 (HC.Master_Secret_12,
                                        Label_Client_Finished,
                                        Byte_Seq (TH4), True, FB, FL);
                  else
                     Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
                     Build_Finished_12 (HC.Master_Secret_12,
                                        Label_Client_Finished,
                                        Byte_Seq (TH), False, FB, FL);
                  end if;

                  --  Add client Finished to transcript
                  Append_Transcript (HC, FB (0 .. FL - 1));

                  Saved_Seq := HC.Client_Seq_12;
                  Build_Encrypted_Record_12
                    (FB (0 .. FL - 1), 16#16#, S.Client_App,
                     HC.Client_Write_IV_12, HC.Client_Seq_12,
                     Scratch, EO);
                  if EO = 0 then
                     HC.Client_Seq_12 := Saved_Seq;
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error
                       (S, Insufficient_Buffer, Result);
                     return;
                  end if;

                  --  Atomic commit
                  if Free_Space (S.Output) < Scratch.Write_Pos then
                     HC.Client_Seq_12 := Saved_Seq;
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error
                       (S, Insufficient_Buffer, Result);
                     return;
                  end if;
                  S.Output.Data
                    (S.Output.Write_Pos ..
                     S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
                     Scratch.Data (0 .. Scratch.Write_Pos - 1);
                  S.Output.Write_Pos :=
                     S.Output.Write_Pos + Scratch.Write_Pos;
               end;

               HC.CKE_Received_12 := True;
               Result := (if Output_Pending (S) > 0
                          then Has_Output else Need_Input);

            when 16#04# =>
               --  RFC 5077 §3.3 NewSessionTicket. Two arrival times:
               --    * Abbreviated handshake (HC.TLS12_Resuming): right
               --      after SH, before server CCS+Finished. Cache it,
               --      append to transcript, derive AEAD keys from the
               --      cached master_secret + this connection's randoms,
               --      and flip CKE_Received_12 := True so the
               --      dispatcher advances to expect server CCS+Finished
               --      (no CKE is ever sent in abbreviated mode).
               --    * Full handshake: after client CKE+CCS+Finished,
               --      before server CCS+Finished. The dispatcher would
               --      route to Process_Server_CCS at this point (not
               --      here) — handled there separately.
               --  Parse via RFLX TLS_1_2_New_Session_Ticket.
               declare
                  B          : constant N32 := Frag'First + 4;
                  NST_Body   : constant Byte_Seq (0 .. Msg_Len - 1) :=
                    Frag (B .. B + Msg_Len - 1);
                  Lifetime   : Unsigned_32;
                  Ticket_Len : N32;
                  Parse_OK   : Boolean;
               begin
                  SPARKTLS.Handshake.TLS12.Parse_New_Session_Ticket_12
                    (NST_Body      => NST_Body,
                     Lifetime_Hint => Lifetime,
                     Ticket_Len    => Ticket_Len,
                     OK            => Parse_OK);
                  if not Parse_OK or Ticket_Len > Max_TLS12_Ticket_Len then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  --  Cache for caller's Get_TLS12_Ticket extraction
                  --  (the bytes are opaque to the client; only the
                  --  server can decrypt). Also save the master_secret +
                  --  suite so the next connection can resume.
                  if Ticket_Len > 0 then
                     S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) :=
                        NST_Body (6 .. 6 + Ticket_Len - 1);
                  end if;
                  S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
                  S.TLS12_New_Ticket.Suite := S.Negotiated_Suite_12;
                  S.TLS12_New_Ticket.Master_Secret :=
                     HC.Master_Secret_12;
                  S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
                  S.TLS12_New_Ticket.Server_Name := HC.Cfg.Server_Name;
                  S.TLS12_New_Ticket.Valid := True;
               end;
               Append_Transcript (HC, Frag);

               if HC.TLS12_Resuming then
                  --  Abbreviated path: derive AEAD keys from the
                  --  cached master_secret + the new randoms, then
                  --  enter the post-CKE state so the dispatcher
                  --  routes the next records to Process_Server_CCS +
                  --  Process_Server_Finished.
                  Derive_Keys_Resumed_12 (S, HC);
                  HC.CKE_Received_12 := True;
               end if;
               Result := OK;

            when others =>
               --  RFC 5246 §7.4: unknown handshake type during the
               --  flight is unexpected_message (BoGo
               --  WrongMessageType-* injects type+42). Pre-CCS so the
               --  alert is plaintext.
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               HC.Reasm_Hdr_Pending := False;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
         end case;
         end;

         --  PackHandshake (BoGo PackHandshakeFlight): one record may
         --  contain multiple back-to-back HS messages. After
         --  dispatching the first, shift trailing bytes to the front
         --  of Reasm_Buf, decode the next message header, and loop.
         --  Stop on error, on Has_Output (handler queued our flight),
         --  or when no more complete message remains.
         if Result = OK
           and HC.Reasm_Len > HC.Reasm_Need
           and HC.Reasm_Buf /= null
         then
            --  Pin facts the prover can't easily re-derive across
            --  the case dispatch: Reasm_Buf is the freshly-allocated
            --  buffer (0 .. Frag_Len-1 or 0 .. Max_HS_Msg-1), and
            --  Reasm_Len <= its length.
            pragma Assert (HC.Reasm_Buf'First = 0);
            pragma Assert
              (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
            declare
               Old_Need : constant N32 := HC.Reasm_Need;
               Leftover : constant N32 := HC.Reasm_Len - Old_Need;
            begin
               pragma Assert
                 (Old_Need + Leftover = HC.Reasm_Len);
               pragma Assert
                 (Old_Need + Leftover <= N32 (HC.Reasm_Buf'Length));
               --  Forward shift via explicit loop: SPARK forbids
               --  potentially-overlapping array-slice assignment.
               for I in N32 range 0 .. Leftover - 1 loop
                  pragma Loop_Invariant
                    (I <= Leftover - 1
                     and HC.Reasm_Buf /= null
                     and HC.Reasm_Buf'First = 0
                     and Old_Need + Leftover <=
                           N32 (HC.Reasm_Buf'Length));
                  HC.Reasm_Buf (I) := HC.Reasm_Buf (Old_Need + I);
               end loop;
               HC.Reasm_Len := Leftover;

               if Leftover < 4 then
                  --  Partial header at tail; defer to next call via
                  --  Hdr_Pending sentinel.
                  HC.Reasm_Need := 4;
                  HC.Reasm_Hdr_Pending := True;
               else
                  pragma Assert (HC.Reasm_Buf'Last >= 3);
                  declare
                     Next_Len : constant N32 :=
                        N32 (HC.Reasm_Buf (1)) * 65536
                        + N32 (HC.Reasm_Buf (2)) * 256
                        + N32 (HC.Reasm_Buf (3));
                     Next_Total : constant N32 := Next_Len + 4;
                  begin
                     if Next_Total > Max_HS_Msg then
                        Free_Byte_Seq (HC.Reasm_Buf);
                        HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                        Send_Alert_And_Error
                          (S, Decode_Error, Result);
                        return;
                     end if;
                     if Leftover >= Next_Total then
                        --  Next message complete; loop to dispatch it.
                        Msg_Type := HC.Reasm_Buf (0);
                        Msg_Len := Next_Len;
                        HC.Reasm_Need := Next_Total;
                        More_Packed := True;
                     else
                        --  Partial body; defer to next call.
                        HC.Reasm_Need := Next_Total;
                     end if;
                  end;
               end if;
            end;
         end if;
         end loop;
         end;

         --  Free the reassembly buffer unless PackHandshake leftover
         --  bytes still need draining on the next call. Leftover
         --  exists when we successfully shifted bytes (Reasm_Len > 0)
         --  AND we still have a current-message size to fill
         --  (Reasm_Len < Reasm_Need or Hdr_Pending awaiting more bytes).
         if HC.Reasm_Buf /= null
           and (HC.Reasm_Len = 0
                or (HC.Reasm_Len >= HC.Reasm_Need
                    and not HC.Reasm_Hdr_Pending))
         then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0;
            HC.Reasm_Need := 0;
            HC.Reasm_Hdr_Pending := False;
         end if;
      end;
   end Process_Server_Flight;

   ------------------------------------------------------------------
   --  Process_Server_CCS: receive CCS, activate server read keys
   ------------------------------------------------------------------

   procedure Process_Server_CCS
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then Result := Need_Input; return; end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         declare
            CCS_Pos    : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_Byte_OK : constant Boolean :=
               Rec.Fragment_Len = 1
               and then S.Input.Data (CCS_Pos) = 16#01#;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if CCS_Byte_OK then
               HC.CCS_Received := True;
               Result := OK;
            else
               --  RFC 5246 §7.1: ChangeCipherSpec payload MUST be the
               --  single byte 0x01. BoGo BadChangeCipherSpec-* sends
               --  other bytes / lengths → unexpected_message.
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
         end;
      elsif Rec.Content = Records.Content_Handshake then
         --  RFC 5077 §3.3 full-handshake NewSessionTicket arrives
         --  AFTER client CCS+Finished but BEFORE server CCS. The
         --  dispatcher routes here (post-client-CKE-flight, waiting
         --  for server CCS) so we need to consume the NST here.
         --  Parse + cache + skip; dispatcher will call us again to
         --  read the actual CCS that follows.
         declare
            FS       : constant N32 :=
              S.Input.Read_Pos + Rec.Fragment_Pos;
            Frag_Len : constant N32 := Rec.Fragment_Len;
         begin
            --  Minimum: HS header(4) + lifetime(4) + ticket_len(2) = 10
            if Frag_Len < 10 then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
            if S.Input.Data (FS) /= 16#04# then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            declare
               Body_Len : constant N32 :=
                  N32 (S.Input.Data (FS + 1)) * 65536
                  + N32 (S.Input.Data (FS + 2)) * 256
                  + N32 (S.Input.Data (FS + 3));
            begin
               if 4 + Body_Len /= Frag_Len then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               declare
                  NST_Body   : constant Byte_Seq (0 .. Body_Len - 1) :=
                    S.Input.Data (FS + 4 .. FS + 4 + Body_Len - 1);
                  Lifetime   : Unsigned_32;
                  Ticket_Len : N32;
                  Parse_OK   : Boolean;
               begin
                  SPARKTLS.Handshake.TLS12.Parse_New_Session_Ticket_12
                    (NST_Body      => NST_Body,
                     Lifetime_Hint => Lifetime,
                     Ticket_Len    => Ticket_Len,
                     OK            => Parse_OK);
                  if not Parse_OK or Ticket_Len > Max_TLS12_Ticket_Len then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  if Ticket_Len > 0 then
                     S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) :=
                        NST_Body (6 .. 6 + Ticket_Len - 1);
                  end if;
                  S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
                  S.TLS12_New_Ticket.Suite := S.Negotiated_Suite_12;
                  S.TLS12_New_Ticket.Master_Secret :=
                     HC.Master_Secret_12;
                  S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
                  S.TLS12_New_Ticket.Server_Name := HC.Cfg.Server_Name;
                  S.TLS12_New_Ticket.Valid := True;

                  --  RFC 5077 §3.3 + RFC 5246 §7.4.9: NST is hashed
                  --  into the handshake transcript before server's
                  --  Finished, so client Finished verify_data uses
                  --  the same hash. Without this, server's Finished
                  --  fails to verify in the full-HS session-ticket
                  --  flow.
                  Append_Transcript
                    (HC, S.Input.Data (FS .. FS + Frag_Len - 1));
               end;
            end;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            --  Dispatcher will call us again to consume the CCS
            --  that follows the NST.
         end;
      else
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
      end if;
   end Process_Server_CCS;

   ------------------------------------------------------------------
   --  Process_Server_Finished: decrypt + verify server Finished
   ------------------------------------------------------------------

   procedure Process_Server_Finished
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre  => Reasm_Building (HC),
        Post => Reasm_Building (HC);

   procedure Process_Server_Finished
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      use Records.TLS12;
      use Key_Schedule_12;
      Rec : Records.Parse_Result;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Max_HS_Msg : constant N32 := 131072;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then Result := Need_Input; return; end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result); return;
      end if;

      --  Decrypt one encrypted record and append its plaintext to
      --  HC.Reasm_Buf. BoGo's MaxHandshakeRecordLength=1 fragments
      --  the encrypted Finished into 16+ tiny records (each
      --  separately AEAD-encrypted with its own seq counter); we
      --  drain them into the same HC reassembly buffer until the
      --  full Finished message is in.
      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted : Byte_Seq (0 .. Frag_Len - 1);
         Hdr : Byte_Seq (0 .. 4);
         Plaintext : Byte_Seq (0 .. Frag_Len - 1);
         PL : N32; DV : Boolean;
      begin
         for I in N32 range 0 .. Frag_Len - 1 loop
            Encrypted (I) := S.Input.Data (FS + I);
         end loop;
         for I in N32 range 0 .. 4 loop
            Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
         end loop;

         declare
            Min_Frag : constant N32 :=
              (if S.Server_App.Suite = Suite_CHACHA20_POLY1305_SHA256
               then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;
         end;

         Decrypt_Record_12 (Encrypted, Hdr, S.Server_App,
                            HC.Server_Write_IV_12, HC.Server_Seq_12,
                            Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Alert_And_Error (S, Bad_Record_MAC, Result); return;
         end if;
         if PL = 0 then
            Send_Alert_And_Error (S, Decode_Error, Result); return;
         end if;

         --  Append decrypted plaintext to HC.Reasm_Buf. Allocate the
         --  buffer on first chunk; size cap is Max_HS_Msg which
         --  trivially holds Finished's 16 bytes. Use Hdr_Pending
         --  while we still need 4 bytes to know the real HS_Total.
         if HC.Reasm_Buf = null then
            HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
            pragma Assert (HC.Reasm_Buf'First = 0);
            pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
            HC.Reasm_Need := 4;
            HC.Reasm_Hdr_Pending := True;
            HC.Reasm_Len := 0;
         end if;
         pragma Assert (Reasm_Building (HC));

         declare
            P_Pos : N32 := 0;  --  bytes consumed from Plaintext
            Take  : N32;
         begin
            --  First-take bounded by current Reasm_Need (which may
            --  still be the Hdr_Pending sentinel of 4).
            Take := N32'Min (PL, HC.Reasm_Need - HC.Reasm_Len);
            if HC.Reasm_Len + Take <=
                  N32 (HC.Reasm_Buf'Length)
            then
               HC.Reasm_Buf
                 (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                 Plaintext (P_Pos .. P_Pos + Take - 1);
               HC.Reasm_Len := HC.Reasm_Len + Take;
               P_Pos := P_Pos + Take;
            end if;

            if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
               declare
                  HS_Total : constant N32 :=
                     N32 (HC.Reasm_Buf (1)) * 65536
                     + N32 (HC.Reasm_Buf (2)) * 256
                     + N32 (HC.Reasm_Buf (3)) + 4;
               begin
                  HC.Reasm_Hdr_Pending := False;
                  if HS_Total < 4 or HS_Total > Max_HS_Msg then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  HC.Reasm_Need := HS_Total;
               end;
               --  Drain remaining plaintext bytes from this same
               --  record (non-split case: full Finished in one record).
               if P_Pos < PL and HC.Reasm_Len < HC.Reasm_Need then
                  declare
                     Need2 : constant N32 :=
                        HC.Reasm_Need - HC.Reasm_Len;
                     Take2 : constant N32 :=
                        N32'Min (Need2, PL - P_Pos);
                  begin
                     if HC.Reasm_Len + Take2 <=
                           N32 (HC.Reasm_Buf'Length)
                     then
                        HC.Reasm_Buf
                          (HC.Reasm_Len ..
                           HC.Reasm_Len + Take2 - 1) :=
                          Plaintext (P_Pos .. P_Pos + Take2 - 1);
                        HC.Reasm_Len := HC.Reasm_Len + Take2;
                        P_Pos := P_Pos + Take2;
                     end if;
                  end;
               end if;

               --  RFC 5246 §7.4.9: server Finished is the last server
               --  handshake message and must be the last thing in its
               --  TLS record. Any leftover plaintext after the Finished
               --  body is fatal unexpected_message (BoGo
               --  TrailingDataWithFinished-Client-TLS12). The alert is
               --  encrypted under client_write_key since we're post-CCS.
               if HC.Reasm_Len = HC.Reasm_Need and P_Pos < PL then
                  declare
                     Saved_Seq : constant Unsigned_64 :=
                        HC.Client_Seq_12;
                     Dummy : N32;
                  begin
                     Records.TLS12.Build_Alert_Record_12
                       (Level       => 2,
                        Desc        => 10,  --  unexpected_message
                        Keys        => S.Client_App,
                        Implicit_IV => HC.Client_Write_IV_12,
                        Seq_Num     => HC.Client_Seq_12,
                        Output      => S.Output,
                        Bytes_Out   => Dummy);
                     if Dummy = 0 then
                        HC.Client_Seq_12 := Saved_Seq;
                     end if;
                  end;
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0
                             then Has_Output else Error_Alert);
                  return;
               end if;
            end if;
         end;

         if HC.Reasm_Len < HC.Reasm_Need then
            Result := OK;
            return;  --  more encrypted records to drain
         end if;

         --  Full Finished plaintext now in HC.Reasm_Buf (0 .. RN-1).
         declare
            RN : constant N32 := HC.Reasm_Need;
            Msg_Type : constant Byte := HC.Reasm_Buf (0);
            Msg_Len : constant N32 :=
               N32 (HC.Reasm_Buf (1)) * 65536
               + N32 (HC.Reasm_Buf (2)) * 256
               + N32 (HC.Reasm_Buf (3));
         begin
            if Msg_Type /= HT_Finished
              or RN < 4 + Finished_Verify_Len
            then
               --  Wrong type or short body. We're post-CCS so the
               --  alert MUST be encrypted (server expects encrypted
               --  records after CCS — sending plaintext yields
               --  bad_record_mac on the peer). BoGo
               --  WrongMessageType-ServerFinished expects
               --  unexpected_message; we treat short body as
               --  decode_error.
               declare
                  Saved_Seq : constant Unsigned_64 := HC.Client_Seq_12;
                  Desc_Code : constant Byte :=
                     (if Msg_Type /= HT_Finished then 10 else 50);
                  Dummy : N32;
               begin
                  Records.TLS12.Build_Alert_Record_12
                    (Level       => 2,
                     Desc        => Desc_Code,
                     Keys        => S.Client_App,
                     Implicit_IV => HC.Client_Write_IV_12,
                     Seq_Num     => HC.Client_Seq_12,
                     Output      => S.Output,
                     Bytes_Out   => Dummy);
                  if Dummy = 0 then
                     HC.Client_Seq_12 := Saved_Seq;
                  end if;
               end;
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               S.Last_Error :=
                 (if Msg_Type /= HT_Finished
                  then Unexpected_Message else Decode_Error);
               Set_State (S, Error_State);
               Result := (if Output_Pending (S) > 0
                          then Has_Output else Error_Alert);
               return;
            end if;
            if Msg_Len /= Finished_Verify_Len then
               --  Length mismatch on Finished — RFC 5246 §7.4.9 +
               --  RFC 8446 §6.2: decrypt_error (alert 51). We're
               --  post-CCS so the alert must be encrypted with our
               --  client_write_key, not plaintext.
               declare
                  Saved_Seq : constant Unsigned_64 := HC.Client_Seq_12;
                  Dummy : N32;
               begin
                  Records.TLS12.Build_Alert_Record_12
                    (Level       => 2,
                     Desc        => 51,  --  decrypt_error
                     Keys        => S.Client_App,
                     Implicit_IV => HC.Client_Write_IV_12,
                     Seq_Num     => HC.Client_Seq_12,
                     Output      => S.Output,
                     Bytes_Out   => Dummy);
                  if Dummy = 0 then
                     HC.Client_Seq_12 := Saved_Seq;
                  end if;
               end;
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               S.Last_Error := Certificate_Verify_Failed;
               Set_State (S, Error_State);
               Result := (if Output_Pending (S) > 0
                          then Has_Output else Error_Alert);
               return;
            end if;

            --  Verify server Finished
            declare
               Exp : Verify_Data_12;
               TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               if Use_384 then
                  SPARKNaCl.Hashing.SHA384.Hash
                    (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Server_Finished,
                                       Byte_Seq (TH4), True);
               else
                  Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Server_Finished,
                                       Byte_Seq (TH), False);
               end if;

               declare
                  Received : constant Verify_Data_12 :=
                     Verify_Data_12
                       (HC.Reasm_Buf
                          (4 .. 4 + Finished_Verify_Len - 1));
               begin
                  if not Equal (Byte_Seq (Received),
                                Byte_Seq (Exp))
                  then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
            end;
         end;

         --  Append server Finished plaintext to transcript so the
         --  client's own Finished verify_data (computed below in the
         --  abbreviated path) covers it.
         Append_Transcript
           (HC,
            HC.Reasm_Buf (0 .. HC.Reasm_Need - 1));

         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
      end;

      --  RFC 5077 §3.3 abbreviated handshake: in the resumed flow the
      --  CLIENT sends CCS+Finished AFTER the server's (inverse of full
      --  HS). In the full-HS case both records were sent before the
      --  server's Finished arrived, so nothing more to send here.
      if HC.TLS12_Resuming then
         declare
            use Records.TLS12;
            Scratch    : IO_Buffer;
            CCS_Out    : N32;
            FB         : Byte_Seq (0 .. Finished_12_Total_Len - 1);
            FL         : N32;
            TH         : Digest;
            TH4        : SPARKNaCl.Hashing.SHA384.Digest;
            EO         : N32;
            Saved_Seq  : Unsigned_64;
         begin
            Records.Build_CCS_Record (Scratch, CCS_Out);
            if CCS_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
            if Use_384 then
               SPARKNaCl.Hashing.SHA384.Hash
                 (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
               Build_Finished_12 (HC.Master_Secret_12,
                                  Label_Client_Finished,
                                  Byte_Seq (TH4), True, FB, FL);
            else
               Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
               Build_Finished_12 (HC.Master_Secret_12,
                                  Label_Client_Finished,
                                  Byte_Seq (TH), False, FB, FL);
            end if;
            Saved_Seq := HC.Client_Seq_12;
            Build_Encrypted_Record_12
              (FB (0 .. FL - 1), 16#16#, S.Client_App,
               HC.Client_Write_IV_12, HC.Client_Seq_12,
               Scratch, EO);
            if EO = 0 then
               HC.Client_Seq_12 := Saved_Seq;
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
            if Free_Space (S.Output) < Scratch.Write_Pos then
               HC.Client_Seq_12 := Saved_Seq;
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
            S.Output.Data
              (S.Output.Write_Pos ..
               S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
               Scratch.Data (0 .. Scratch.Write_Pos - 1);
            S.Output.Write_Pos :=
               S.Output.Write_Pos + Scratch.Write_Pos;
         end;
      end if;

      --  Copy TLS 1.2 state to Session
      S.Negotiated_Version := TLS_1_2;
      S.Client_IV_12 := HC.Client_Write_IV_12;
      S.Server_IV_12 := HC.Server_Write_IV_12;
      S.Client_Seq_12 := HC.Client_Seq_12;
      S.Server_Seq_12 := HC.Server_Seq_12;

      Set_State (S, Connected);
      S.Handshake_Just_Done := True;
      Result := (if Output_Pending (S) > 0 then Has_Output else Handshake_Done);
      if Result = Handshake_Done then S.Handshake_Just_Done := False; end if;
   end Process_Server_Finished;

   ------------------------------------------------------------------
   --  Advance_Handshake_12: dispatch based on internal state
   ------------------------------------------------------------------

   procedure Advance_Handshake_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
   begin
      if Output_Pending (S) > 0 then
         Result := Has_Output;
         return;
      end if;

      if not HC.CKE_Received_12 then
         --  Still processing server flight / sending client flight
         Process_Server_Flight (S, HC, Result);
      elsif not HC.CCS_Received then
         --  Waiting for server CCS
         Process_Server_CCS (S, HC, Result);
      else
         --  Waiting for server Finished
         Process_Server_Finished (S, HC, Result);
      end if;
   end Advance_Handshake_12;

   ------------------------------------------------------------------
   --  Process_Connected_12: identical to Server.TLS12.Process_Connected_12
   ------------------------------------------------------------------

   procedure Process_Connected_12 (S : in out Session; Result : out Action)
   is
      use Records.TLS12;
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input; return;
      end if;

      --  The record length bound below is from Parse_Record_Header's Post
      --  (Record_Len <= Avail = Write_Pos - Read_Pos). Pin it here while
      --  the call's Avail argument is still in syntactic scope, so later
      --  asserts about FS + Frag_Len can chain.
      pragma Assert
        (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      if Rec.Content not in Records.Content_Application_Data
                          | Records.Content_Alert
      then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         --  Reject records exceeding the TLS 1.2 max ciphertext size.
         --  A 16384-byte plaintext encrypts to exactly 16408 bytes
         --  (16384 + 8 explicit nonce + 16 tag), so the bound is
         --  strict-greater-than, not greater-or-equal — and matches
         --  Decrypt_Record_12's Pre (`Encrypted'Last <
         --  Max_Record_Plaintext + TLS12_Record_Overhead`).
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Record_Overflow, Result);
            return;
         end if;
         --  FS + Frag_Len = Read_Pos + Fragment_Pos + Fragment_Len
         --                = Read_Pos + Record_Len   (Post: Record_Len =
         --                                            Fragment_Pos + Fragment_Len)
         --                <= Read_Pos + Avail
         --                = Read_Pos + (Write_Pos - Read_Pos)
         --                = Write_Pos.
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
         declare
            Encrypted : Byte_Seq (0 .. Frag_Len - 1);
            Hdr : Byte_Seq (0 .. 4);
            Plaintext : Byte_Seq (0 .. Frag_Len - 1);
            PL : N32; DV : Boolean;
         begin
            for I in N32 range 0 .. Frag_Len - 1 loop
               Encrypted (I) := S.Input.Data (FS + I);
            end loop;
            for I in N32 range 0 .. 4 loop
               Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
            end loop;

            declare
               Min_Frag : constant N32 :=
                 (if S.Server_App.Suite = Suite_CHACHA20_POLY1305_SHA256
                  then GCM_Tag_Len + 1
                  else Explicit_Nonce_Len + GCM_Tag_Len + 1);
            begin
               if Frag_Len < Min_Frag then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK; return;
               end if;
            end;

            --  RFC 5246 §6.1: "If a TLS implementation would need to
            --  wrap a sequence number, it must renegotiate instead."
            --  AEAD nonce uniqueness in GCM depends on the sequence
            --  number never wrapping; reuse would catastrophically
            --  leak the AEAD key. We don't support renegotiation, so
            --  abort the connection. Decrypt_Record_12's Pre also
            --  requires Seq_Num < Unsigned_64'Last so increment is
            --  safe. 2^64 records is practically unreachable.
            if S.Server_Seq_12 = Unsigned_64'Last then
               Send_Alert_And_Error (S, Internal_Error, Result);
               return;
            end if;

            Decrypt_Record_12 (Encrypted, Hdr, S.Server_App,
                               S.Server_IV_12, S.Server_Seq_12,
                               Plaintext, PL, DV);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if not DV then
               Send_Alert_And_Error (S, Bad_Record_MAC, Result);
               return;
            end if;

            case Rec.Content is
               when Records.Content_Application_Data =>
                  if PL > 0
                    and then S.App_Data_Len <= S.App_Data'Length - PL
                  then
                     S.App_Data
                       (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                        Plaintext (0 .. PL - 1);
                     S.App_Data_Len := S.App_Data_Len + PL;
                     Result := Plaintext_Ready;
                  else
                     Result := OK;
                  end if;
               when Records.Content_Alert =>
                  --  RFC 5246 §7.2: alerts have (level, description).
                  --  - close_notify (desc=0): peer is closing — initiate
                  --    Closing. Required regardless of level by §7.2.1.
                  --  - level=warning (1): MAY ignore. We ignore so BoGo
                  --    SendWarningAlerts-Pass /
                  --    AlternateEmptyRecordsAndWarningAlerts complete.
                  --  - level=fatal (2): connection MUST close. We just
                  --    record the error and stop reading; sending an
                  --    alert back would loop on every fatal we receive.
                  if PL >= 2 and then Plaintext (1) = 0 then
                     --  close_notify
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  elsif PL >= 1 and then Plaintext (0) = 1 then
                     --  warning (non-close_notify) — count + cap.
                     --  RFC 8446 §6.1 / BoGo SendWarningAlerts-TooMany:
                     --  more than 4 in a connection → fatal
                     --  decode_error.
                     S.Warning_Alerts_Recvd :=
                        S.Warning_Alerts_Recvd + 1;
                     if S.Warning_Alerts_Recvd >= 5 then
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        Result := OK;
                     end if;
                  else
                     --  fatal alert from peer — record + close.
                     S.Last_Error := Unexpected_Message;
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  end if;
               when others =>
                  Result := OK;
            end case;
         end;
      end;
   end Process_Connected_12;

end SPARKTLS.Client.TLS12;
