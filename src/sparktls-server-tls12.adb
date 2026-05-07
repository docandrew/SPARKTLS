with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;

package body SPARKTLS.Server.TLS12 with
   SPARK_Mode => On
is
   use Handshake.TLS12;

   function Alert_Desc (E : Error_Code) return Byte is
     (case E is
         when Unexpected_Message    => 10, when Bad_Record_MAC   => 20,
         when Record_Overflow       => 22, when Handshake_Failure => 40,
         when Bad_Certificate       => 42, when Certificate_Expired => 45,
         when Certificate_Verify_Failed => 51, when Decode_Error  => 50,
         when Illegal_Parameter     => 47, when Protocol_Version  => 70,
         when Certificate_Required  => 116,
         when Internal_Error    => 80,
         when Insufficient_Buffer   => 80, when Unsupported_Cipher_Suite => 40,
         when No_Error              => 80);

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and Alert_Desc (Err) /= 0
               and Alert_Desc (Err) /= 90;

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
   --  Body uses Ada slide-assignment, which works for any Data'First.
   --  Frame: only writes HC.Transcript / HC.Transcript_Len. The Cfg
   --  pointer + identity are preserved across the call so callers
   --  don't lose those facts. SPARK forbids equality on access types,
   --  so we restate the specific properties on exit (matching the
   --  Pre bound) rather than HC.Cfg.Local = HC.Cfg.Local'Old.
   with Pre  => Data'Length > 0
                and then Data'Length <= HC.Transcript'Length
                and then HC.Cfg.Local /= null
                and then HC.Cfg.Local.Has_Identity
                and then HC.Cfg.Random /= null,
        Post => HC.Cfg.Local /= null
                and then HC.Cfg.Local.Has_Identity
                and then HC.Cfg.Random /= null
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len <= HC.Transcript'Length - Len then
         HC.Transcript (HC.Transcript_Len ..
                          HC.Transcript_Len + Len - 1) := Data;
         HC.Transcript_Len := HC.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   ------------------------------------------------------------------
   procedure Build_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Gen_Random : constant Random_Bytes_Fn := HC.Cfg.Random;
      Rec_Out    : N32;
      --  Atomic flight assembly: build every record into a scratch buffer
      --  first. We commit to S.Output only when the entire flight has
      --  been built and we know it fits, so the peer never observes a
      --  partial flight. (All four records here are plaintext, so the
      --  AEAD counter doesn't need rolling back on failure.)
      Scratch : IO_Buffer;
   begin
      --  TLS 1.2 uses supported_groups (no key_share extension)
      if HC.Client_Has_X25519 or HC.Client_Supports_X25519 then
         HC.Selected_Group := Group_X25519;
      elsif HC.Client_Has_P256 or HC.Client_Supports_P256 then
         HC.Selected_Group := Group_Secp256r1;
      elsif HC.Client_Has_P384 or HC.Client_Supports_P384 then
         HC.Selected_Group := Group_Secp384r1;
      else
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;

      --  Use the TLS 1.2 suite that the client actually offered
      if S.Negotiated_Suite_12 /= 0 then
         S.Negotiated_Suite := S.Negotiated_Suite_12;
      else
         --  No matching TLS 1.2 ECDHE+AEAD suite
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;

      --  Negotiate signature scheme: pick the first client-offered
      --  scheme that is compatible with our local key's signing
      --  algorithm. RSA-PKCS#1 v1.5 schemes (0x0401/0x0501/0x0601)
      --  would be valid in TLS 1.2 but we don't yet implement
      --  v1.5 *signing* in SPARKTLSCrypto.RSA — only verify — so
      --  we offer PSS only for RSA keys. Verify is supported, so
      --  client cert sigs in v1.5 are still accepted via the
      --  cert_verify path.
      declare
         Negotiated : Unsigned_16 := 0;
      begin
         for I in Natural range 0 .. HC.Peer_Sig_Algo_Count - 1 loop
            declare
               Scheme : constant Unsigned_16 := HC.Peer_Sig_Algos (I);
            begin
               case HC.Cfg.Local.Sign_Algo is
                  when Sign_RSA_PSS =>
                     if Scheme = 16#0804# or Scheme = 16#0805#
                        or Scheme = 16#0806#
                     then
                        Negotiated := Scheme;
                        exit;
                     end if;
                  when Sign_ECDSA_P256 =>
                     if Scheme = 16#0403# then
                        Negotiated := Scheme;
                        exit;
                     end if;
                  when Sign_ECDSA_P384 =>
                     if Scheme = 16#0503# then
                        Negotiated := Scheme;
                        exit;
                     end if;
                  when Sign_Ed25519 =>
                     if Scheme = 16#0807# then
                        Negotiated := Scheme;
                        exit;
                     end if;
                  when Sign_None =>
                     null;
               end case;
            end;
         end loop;
         if Negotiated = 0 then
            Send_Alert_And_Error (S, Handshake_Failure, Result);
            return;
         end if;
         HC.Negotiated_Sig_Algo := Negotiated;
      end;

      case HC.Selected_Group is
         when Group_X25519    => Gen_Random (Byte_Seq (HC.Local_SK));
         when Group_Secp256r1 => Gen_Random (Byte_Seq (HC.P256_Local_SK));
         when Group_Secp384r1 => Gen_Random (Byte_Seq (HC.P384_Local_SK));
         when others => null;
      end case;

      --  1. ServerHello
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1); Hello_Len : N32;
      begin
         Build_Server_Hello_12 (S, HC, Hello_Buf, Hello_Len);
         if Hello_Len = 0 then
            Send_Alert_And_Error (S, Internal_Error, Result); return;
         end if;
         Append_Transcript (HC, Hello_Buf (0 .. Hello_Len - 1));
         Records.Build_Handshake_Record
           (Hello_Buf (0 .. Hello_Len - 1), Scratch, Rec_Out);
         if Rec_Out = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  2. Certificate (TLS 1.2 format)
      declare
         Cert_Buf : Byte_Seq (0 .. 8191); Cert_Len : N32;
      begin
         Build_Certificate_Chain_12 (HC.Cfg.Local.all, Cert_Buf, Cert_Len);
         if Cert_Len > 0 then
            Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Handshake_Record
              (Cert_Buf (0 .. Cert_Len - 1), Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end if;
      end;

      --  3. ServerKeyExchange
      declare
         SKE_Buf : Byte_Seq (0 .. Max_Server_Key_Exchange - 1); SKE_Len : N32;
      begin
         Build_Server_Key_Exchange
           (HC, HC.Cfg.Local.all, Gen_Random, SKE_Buf, SKE_Len);
         if SKE_Len > 0 then
            Append_Transcript (HC, SKE_Buf (0 .. SKE_Len - 1));
            Records.Build_Handshake_Record
              (SKE_Buf (0 .. SKE_Len - 1), Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end if;
      end;

      --  4. ServerHelloDone
      declare
         Done_Buf : Byte_Seq (0 .. 3); Done_Len : N32;
      begin
         Build_Server_Hello_Done (Done_Buf, Done_Len);
         Append_Transcript (HC, Done_Buf (0 .. Done_Len - 1));
         Records.Build_Handshake_Record
           (Done_Buf (0 .. Done_Len - 1), Scratch, Rec_Out);
         if Rec_Out = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  Atomic commit: full flight built. If it fits in S.Output, copy
      --  in one shot; otherwise abort without touching S.Output.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos ..
                     S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
         Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      Set_State (S, Server_Hello_Sent);
      Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
   end Build_Server_Flight_12;

   ------------------------------------------------------------------
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
      CK : Byte_Seq (0 .. Key_Len - 1);
      SK : Byte_Seq (0 .. Key_Len - 1);
      CI : Byte_Seq (0 .. 3);
      SI : Byte_Seq (0 .. 3);
      Shared_Len : constant N32 :=
         (if HC.Selected_Group = Group_Secp384r1 then 48 else 32);
   begin
      --  Server always uses EMS (we signal it in ServerHello)
      pragma Assert (EMS_Label_Consistent (True, "extended master secret"));

      --  RFC 7627: Extended Master Secret
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

      Expand_Keys_12 (CK, SK, CI, SI, HC.Master_Secret_12,
                       HC.Server_Random, HC.Client_Random, Key_Len, Use_384);

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
         --  Verify the mapping matches the ghost function
         pragma Assert
           (Int_Suite = Handshake.TLS12.Internal_Suite_For
                          (S.Negotiated_Suite));

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
   procedure Process_Client_Key_Exchange_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if not Rec.OK then
         if Rec.Overflow then Send_Alert_And_Error (S, Record_Overflow, Result);
         else Result := Need_Input; end if;
         return;
      end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         if Rec.Fragment_Len = 1 and then not HC.CCS_Received then
            HC.CCS_Received := True; Result := OK;
         else Send_Alert_And_Error (S, Unexpected_Message, Result); end if;
         return;
      end if;

      if Rec.Content = Records.Content_Alert then
         --  RFC 5246 §7.2.1: close_notify can arrive at any time
         --  (including mid-handshake before keys are established).
         --  We must reply with close_notify (warning level) and
         --  close. Other plaintext alerts during handshake are
         --  protocol violations — fatal.
         declare
            FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            Alert_Level : Byte := 0;
            Alert_Desc  : Byte := 0;
         begin
            if Rec.Fragment_Len >= 2 then
               Alert_Level := S.Input.Data (FS);
               Alert_Desc  := S.Input.Data (FS + 1);
            end if;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Alert_Desc = 0 then
               --  close_notify — reply in kind (plaintext warning).
               declare
                  A : N32;
               begin
                  Records.Build_Plaintext_Alert
                    (Level     => 1,
                     Desc      => 0,
                     Output    => S.Output,
                     Bytes_Out => A);
               end;
               Set_State (S, Closing);
               if Output_Pending (S) > 0 then
                  Result := Has_Output;
               else
                  Result := Shutdown;
               end if;
            else
               --  Other alert mid-handshake — peer is closing on us
               --  with a fatal condition; just close (no reply).
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               Result := Error_Alert;
            end if;
            pragma Unreferenced (Alert_Level);
            return;
         end;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         --  Slice bound: Parse_Record_Header Post gives Record_Len <= Avail,
         --  i.e., Read_Pos + Record_Len <= Write_Pos <= IO_Buffer_Capacity.
         --  So FS + Frag_Len = Read_Pos + Fragment_Pos + Fragment_Len
         --                  = Read_Pos + Record_Len <= Write_Pos.
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
         declare
            Frag : Byte_Seq renames S.Input.Data (FS .. FS + Frag_Len - 1);
            Msg_Type : Byte; Msg_Len : N32; POK : Boolean;
         begin
            Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, POK);
            if not POK or Msg_Type /= HT_Client_Key_Exchange then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;

            declare
               Msg_Len_Const : constant N32 := Msg_Len;
               BS  : constant N32 := Frag'First + 4;
               Body_Data : Byte_Seq (0 .. Msg_Len_Const - 1);
               CKE_OK : Boolean;
            begin
               --  Min CKE body for ECDHE: 1-byte length + 32-byte X25519
               --  point = 33 bytes. Require at least 4 to satisfy
               --  Parse_Client_Key_Exchange's Pre.
               if Msg_Len >= 4 and then 4 + Msg_Len <= Frag_Len then
                  Body_Data := Frag (BS .. BS + Msg_Len - 1);
                  Parse_Client_Key_Exchange (HC, Body_Data, CKE_OK);
                  if not CKE_OK then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Decode_Error, Result); return;
                  end if;
               else
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result); return;
               end if;
            end;

            Append_Transcript (HC, Frag);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         end;
      end;

      --  Compute ECDHE shared secret
      declare
         SS_OK : Boolean := False;
      begin
         case HC.Selected_Group is
            when Group_X25519 =>
               HC.Shared_Secret (0 .. 31) :=
                  SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
               --  RFC 7748 §6.1 / RFC 8422 §5.10: reject all-zeros
               --  shared secret. X25519 maps small-subgroup peer
               --  public keys (orders 1, 2, 4, 8 — eight specific
               --  byte strings) to a zero shared secret. Accepting
               --  these allows a passive attacker to coerce the
               --  shared secret to a known value (full handshake
               --  break). Constant-time OR-fold across the 32
               --  bytes; SS_OK iff at least one byte non-zero.
               declare
                  Acc : Byte := 0;
               begin
                  for I in N32 range 0 .. 31 loop
                     Acc := Acc or HC.Shared_Secret (I);
                  end loop;
                  SS_OK := Acc /= 0;
               end;
            when Group_Secp256r1 =>
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
                  end if;
               end;
            when Group_Secp384r1 =>
               declare SS : Bytes_48; OK384 : Boolean;
               begin
                  SPARKTLSCrypto.P384.Point.P384_ECDHE
                    (SS, OK384, HC.P384_Local_SK, HC.P384_Peer_PK);
                  if OK384 then HC.Shared_Secret := SS; SS_OK := True; end if;
               end;
            when others => null;
         end case;
         if not SS_OK then
            Send_Alert_And_Error (S, Handshake_Failure, Result); return;
         end if;
      end;

      Derive_Keys_12 (S, HC);
      HC.CKE_Received_12 := True;
      Result := (if Input_Available (S) > 0 then OK else Need_Input);
   end Process_Client_Key_Exchange_12;

   ------------------------------------------------------------------
   procedure Process_Client_CCS_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      pragma Unreferenced (S, HC);
   begin
      --  TODO: implement CCS handling per RFC 5246 §7.1 — activate client
      --  write keys for decrypting subsequent records.
      Result := Error_Alert;
   end Process_Client_CCS_12;

   ------------------------------------------------------------------
   procedure Process_Client_Finished_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      use SPARKTLS.Records.TLS12;
      use Key_Schedule_12;
      Rec : Records.Parse_Result;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);
      if not Rec.OK then
         if Rec.Overflow then Send_Alert_And_Error (S, Record_Overflow, Result);
         else Result := Need_Input; end if;
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result); return;
      end if;

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

         if Frag_Len < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result); return;
         end if;

         Decrypt_Record_12 (Encrypted, Hdr, S.Client_App,
                            HC.Client_Write_IV_12, HC.Client_Seq_12,
                            Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Alert_And_Error (S, Bad_Record_MAC, Result); return;
         end if;
         if PL < 4 then
            Send_Alert_And_Error (S, Decode_Error, Result); return;
         end if;

         declare
            Msg_Type : constant Byte := Plaintext (0);
            Msg_Len : constant N32 := N32 (Plaintext (1)) * 65536 +
                                 N32 (Plaintext (2)) * 256 +
                                 N32 (Plaintext (3));
         begin
            if Msg_Type /= HT_Finished then
               Send_Alert_And_Error (S, Unexpected_Message, Result); return;
            end if;
            if Msg_Len /= Finished_Verify_Len or PL < 4 + Finished_Verify_Len then
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;

            declare
               Exp : Verify_Data_12;
               TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               if Use_384 then
                  SPARKNaCl.Hashing.SHA384.Hash
                    (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Client_Finished,
                                       Byte_Seq (TH4), True);
               else
                  Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Client_Finished,
                                       Byte_Seq (TH), False);
               end if;

               --  Constant-time comparison (prevents timing attacks
               --  on the verify_data). SPARKNaCl.Equal uses XOR
               --  accumulation — no early exit on mismatch.
               declare
                  Received : constant Key_Schedule_12.Verify_Data_12 :=
                     Key_Schedule_12.Verify_Data_12
                       (Plaintext (4 .. 4 + Finished_Verify_Len - 1));
               begin
                  if not Equal (Byte_Seq (Received), Byte_Seq (Exp)) then
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
            end;

            Append_Transcript (HC, Plaintext (0 .. PL - 1));
         end;
      end;

      --  Atomic flight assembly: build CCS + encrypted Finished into a
      --  scratch buffer; commit only if the whole flight fits in
      --  S.Output. The Finished encryption advances HC.Server_Seq_12, so
      --  we save it and roll back on commit failure to keep AEAD nonces
      --  in sync with what the peer actually sees.
      declare
         Scratch       : IO_Buffer;
         CCS_Out       : N32;
         EO            : N32;
         Saved_Seq     : constant Unsigned_64 := HC.Server_Seq_12;
         FB : Byte_Seq (0 .. Finished_12_Total_Len - 1); FL : N32;
         TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
      begin
         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         if Use_384 then
            SPARKNaCl.Hashing.SHA384.Hash
              (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12, Label_Server_Finished,
                               Byte_Seq (TH4), True, FB, FL);
         else
            Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12, Label_Server_Finished,
                               Byte_Seq (TH), False, FB, FL);
         end if;

         Build_Encrypted_Record_12
           (FB (0 .. FL - 1), 16#16#, S.Server_App,
            HC.Server_Write_IV_12, HC.Server_Seq_12, Scratch, EO);
         if EO = 0 then
            HC.Server_Seq_12 := Saved_Seq;  --  Build_Encrypted_Record_12
                                            --  always advances; rollback.
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         --  Atomic commit
         if Free_Space (S.Output) < Scratch.Write_Pos then
            HC.Server_Seq_12 := Saved_Seq;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         S.Output.Data (S.Output.Write_Pos ..
                        S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
            Scratch.Data (0 .. Scratch.Write_Pos - 1);
         S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
      end;

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
   end Process_Client_Finished_12;

   ------------------------------------------------------------------
   procedure Process_Connected_12 (S : in out Session; Result : out Action)
   is
      use SPARKTLS.Records.TLS12;
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Overflow then
         Send_Alert_And_Error (S, Record_Overflow, Result); return;
      end if;
      if not Rec.OK then
         if Rec.Record_Len > 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Unexpected_Message, Result);
         else Result := Need_Input; end if;
         return;
      end if;

      --  TLS 1.2: CCS in Connected is ignored
      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      --  Only app_data and alert are valid encrypted record types
      if Rec.Content not in Records.Content_Application_Data
                          | Records.Content_Alert
      then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result); return;
      end if;

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

         if Frag_Len < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Unexpected_Message, Result); return;
         end if;

         Decrypt_Record_12 (Encrypted, Hdr, S.Client_App,
                            S.Client_IV_12, S.Client_Seq_12,
                            Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Alert_And_Error (S, Bad_Record_MAC, Result); return;
         end if;

         case Rec.Content is
            when Records.Content_Application_Data =>
               if PL > 0
                  and then S.App_Data_Len <= S.App_Data'Length
                  and then PL <= S.App_Data'Length - S.App_Data_Len
               then
                  S.App_Data (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                     Plaintext (0 .. PL - 1);
                  S.App_Data_Len := S.App_Data_Len + PL;
                  Result := Plaintext_Ready;
               else
                  Result := OK;
               end if;

            when Records.Content_Alert =>
               if PL >= 2 and then Plaintext (1) = 0 then
                  --  close_notify received — RFC 5246 §7.2.1 (and
                  --  RFC 8446 §6.1) require a close_notify reply at
                  --  warning level (1) before tearing the
                  --  connection down. Without this TLS-Anvil's
                  --  closeNotify test sees a level-2 alert from us.
                  declare
                     A : N32;
                  begin
                     Records.TLS12.Build_Alert_Record_12
                       (Level       => 1,
                        Desc        => 0,
                        Keys        => S.Server_App,
                        Implicit_IV => S.Server_IV_12,
                        Seq_Num     => S.Server_Seq_12,
                        Output      => S.Output,
                        Bytes_Out   => A);
                  end;
                  Set_State (S, Closing);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Shutdown;
                  end if;
               else
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               end if;

            when others =>
               Result := OK;
         end case;
      end;
   end Process_Connected_12;

end SPARKTLS.Server.TLS12;
