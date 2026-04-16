with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.MAC;              use SPARKNaCl.MAC;
with SPARKNaCl.HKDF;             use SPARKNaCl.HKDF;

with SPARKNaCl.Sign;
with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Key_Schedule;
with SPARKTLS.HC_Alloc;
with X509;
use type X509.Algorithm_ID;
with SPARKTLS.HMAC384;
with SPARKTLS.HKDF384;
with SPARKTLS.Ticket_Cache;

package body SPARKTLS.Server with
   SPARK_Mode => On
is
   --  Forward declarations
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   procedure Build_Server_Flight
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   procedure Process_Client_Auth
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   procedure Process_Client_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   procedure Process_Connected (S : in out Session; Result : out Action);

   procedure Derive_Handshake_Keys
     (S  : in out Session;
      HC : in out Handshake_Context);

   procedure Derive_App_Keys
     (S  : in out Session;
      HC : in out Handshake_Context);

   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16);

   --  Map Error_Code to TLS alert description byte
   function Alert_Desc (E : Error_Code) return Byte is
     (case E is
         when Unexpected_Message    => 10,
         when Bad_Record_MAC        => 20,
         when Record_Overflow       => 22,
         when Handshake_Failure     => 40,
         when Bad_Certificate       => 42,
         when Certificate_Expired   => 45,
         when Certificate_Verify_Failed => 51,
         when Decode_Error          => 50,
         when Illegal_Parameter     => 47,
         when Internal_Error        => 80,
         when Insufficient_Buffer   => 80,
         when Unsupported_Cipher_Suite => 40,
         when No_Error              => 80);

   --  Send a fatal alert and set error state
   procedure Send_Alert_And_Error
     (S      : in out Session;
      Err    : Error_Code;
      Result : out Action)
   is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      S.State := Error_State;
      Result := Error_Alert;
      Records.Build_Plaintext_Alert
        (Level     => 2,  --  fatal
         Desc      => Alert_Desc (Err),
         Output    => S.Output,
         Bytes_Out => Dummy);
   end Send_Alert_And_Error;

   --  Append handshake message bytes to the transcript
   procedure Append_Transcript
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq)
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len + Len <= HC.Transcript'Length then
         HC.Transcript (HC.Transcript_Len ..
                          HC.Transcript_Len + Len - 1) := Data;
         HC.Transcript_Len := HC.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   function Transcript_Hash_256 (HC : Handshake_Context) return Digest is
      H : Digest;
   begin
      Hash (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (HC : Handshake_Context)
      return SPARKNaCl.Hashing.SHA384.Digest
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKNaCl.Hashing.SHA384.Hash
        (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_384;

   procedure Configure
     (S                   : out Session;
      Local               : Identity_Access;
      Random              : Random_Bytes_Fn;
      Trust               : Trust_Store_Access := null;
      Request_Client_Cert : Boolean := False;
      Tickets             : Ticket_Store_Access := null)
   is
      Cfg : Config;
   begin
      Cfg.Random              := Random;
      Cfg.Local               := Local;
      Cfg.Trust               := Trust;
      Cfg.Request_Client_Cert := Request_Client_Cert;
      Cfg.Ticket_Store        := Tickets;
      Init (S, Cfg);
   end Configure;

   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   with SPARK_Mode => Off
   is
   begin
      S := (State     => Wait_Client_Hello,
            Role => Role_Server,
            others    => <>);

      S.HC_Ptr := HC_Alloc.Allocate;
      if S.HC_Ptr = null then
         S.State := Error_State;
         S.Last_Error := Internal_Error;
         return;
      end if;
      S.HC_Ptr.Cfg := Cfg;
   end Init;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with SPARK_Mode => Off
   is
   begin
      case S.State is
         when Connected =>
            --  Drain pending output first (e.g., NewSessionTicket)
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Process_Connected (S, Result);
            end if;

         when Closing =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.State := Closed;
               Result := Shutdown;
            end if;

         when Error_State =>
            --  Drain any pending alert before reporting error
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;

         when Closed | Idle =>
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;

         when others =>
            if S.HC_Ptr = null then
               S.Last_Error := Internal_Error;
               S.State := Error_State;
               Result := Error_Alert;
               return;
            end if;

            Advance_Handshake (S, S.HC_Ptr.all, Result);

            if S.State in Connected | Error_State | Closed then
               S.Peer_Cert_Valid := S.HC_Ptr.Peer_Cert_Valid;
               HC_Alloc.Free (S.HC_Ptr);
            end if;
      end case;
   end Advance;

   --  Dispatch handshake states to the appropriate handler
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      case S.State is
         when Wait_Client_Hello =>
            if Input_Available (S) = 0 then
               Result := Need_Input;
               return;
            end if;

            --  Parse ClientHello from input
            declare
               Rec : Records.Parse_Result;
            begin
               Records.Parse_Record_Header
                 (Data   => S.Input.Data (S.Input.Read_Pos ..
                                           S.Input.Write_Pos - 1),
                  Avail  => Available (S.Input),
                  Result => Rec);

               if not Rec.OK then
                  Result := Need_Input;
                  return;
               end if;

               if Rec.Content /= Records.Content_Handshake then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK;
                  return;
               end if;

               declare
                  Frag_Start : constant N32 :=
                     S.Input.Read_Pos + Rec.Fragment_Pos;
                  Frag : Byte_Seq renames
                     S.Input.Data (Frag_Start ..
                                    Frag_Start + Rec.Fragment_Len - 1);
                  Parse_OK : Boolean;
               begin
                  Handshake.Parse_Client_Hello (S, HC, Frag, Parse_OK);

                  if not Parse_OK then
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     return;
                  end if;

                  --  Add ClientHello to transcript
                  Append_Transcript (HC, Frag);

                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                  --  Build entire server flight
                  Build_Server_Flight (S, HC, Result);
               end;
            end;

         when Server_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               if HC.Cfg.Request_Client_Cert and not HC.Using_PSK then
                  S.State := Wait_Client_Certificate;
               else
                  S.State := Wait_Client_Finished;
               end if;
               Result := Need_Input;
            end if;

         when Wait_Client_Certificate
            | Wait_Client_Cert_Verify =>
            Process_Client_Auth (S, HC, Result);

         when Wait_Client_Finished =>
            Process_Client_Finished (S, HC, Result);

         when others =>
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
      end case;
   end Advance_Handshake;

   --  Build the entire server handshake flight:
   --  ServerHello (plaintext record) + CCS + encrypted(EE + Cert + CV + Finished)
   procedure Build_Server_Flight
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      SH_Buf  : Byte_Seq (0 .. Handshake.Max_Server_Hello - 1);
      SH_Len  : N32;
      Rec_Out : N32;
      CCS_Out : N32;
   begin
      Result := OK;

      --  Check for PSK resumption (must happen before Build_Server_Hello
      --  so the ServerHello includes the pre_shared_key extension)
      if HC.PSK_Offered and then HC.Cfg.Ticket_Store /= null then
         declare
            PSK     : Bytes_48;
            PSK_Len : N32;
            Suite   : Unsigned_16;
            Found   : Boolean;
         begin
            Ticket_Cache.Lookup
              (HC.Cfg.Ticket_Store.all,
               HC.PSK_Ticket_ID,
               PSK, PSK_Len, Suite, Found);
            if Found and then HC.PSK_Binder_Len > 0 then
               --  Verify the PSK binder before accepting
               --  The binder covers the truncated ClientHello:
               --  everything up to the binders list in pre_shared_key.
               --  The ClientHello is in HC.Transcript at this point.
               --  Binders offset within pre_shared_key extension data
               --  is HC.PSK_Binders_Offset. We need to find the absolute
               --  offset in the ClientHello message.
               --
               --  The pre_shared_key ext is the last extension.
               --  Its data starts at: CH_len - ext_data_len
               --  Binders start at: that + PSK_Binders_Offset
               --  Truncation point: 2 bytes before binders (binders_len field)
               --
               --  For simplicity, accept if binder length is valid.
               --  Full binder verification requires knowing the exact
               --  byte offset, which we'll compute from the transcript.

               declare
                  Binder_OK : Boolean := False;
               begin
                  --  Compute truncated ClientHello hash.
                  --  The binders list is at the end of the transcript.
                  --  binders_list = binders_len(2) + binder_entry(1 + binder)
                  declare
                     Binders_Size : constant N32 :=
                        2 + 1 + HC.PSK_Binder_Len;
                     Trunc_Len    : N32;
                  begin
                     if HC.Transcript_Len > Binders_Size then
                        Trunc_Len := HC.Transcript_Len - Binders_Size;

                        if PSK_Len = 48 then
                           declare
                              use SPARKTLS.HKDF384;
                              Trunc_Hash  : Key_Schedule.Digest_384;
                              Binder_Key  : OKM384_Seq (0 .. 47);
                              Finished_Key : OKM384_Seq (0 .. 47);
                              Expected    : Bytes_48;
                           begin
                              SPARKNaCl.Hashing.SHA384.Hash
                                (Trunc_Hash,
                                 HC.Transcript (0 .. Trunc_Len - 1));
                              Key_Schedule.Derive_Binder_Key_384
                                (Binder_Key, PSK);
                              Key_Schedule.Derive_Finished_Key_384
                                (Finished_Key, Byte_Seq (Binder_Key));
                              HMAC384.HMAC_SHA_384
                                (Output => Expected,
                                 M      => Trunc_Hash,
                                 K      => Byte_Seq (Finished_Key));
                              Binder_OK := Equal
                                (Expected, Bytes_48 (HC.PSK_Binder));
                           end;
                        else
                           declare
                              Trunc_Hash   : Digest;
                              Binder_Key   : OKM_Seq (0 .. 31);
                              Finished_Key : OKM_Seq (0 .. 31);
                              Expected     : Digest;
                           begin
                              SPARKNaCl.Hashing.SHA256.Hash
                                (Trunc_Hash,
                                 HC.Transcript (0 .. Trunc_Len - 1));
                              Key_Schedule.Derive_Binder_Key
                                (Binder_Key,
                                 Bytes_32 (PSK (0 .. 31)));
                              Key_Schedule.Derive_Finished_Key
                                (Finished_Key, Byte_Seq (Binder_Key));
                              HMAC_SHA_256
                                (Output => Expected,
                                 M      => Trunc_Hash,
                                 K      => Byte_Seq (Finished_Key));
                              Binder_OK := Equal
                                (Expected,
                                 Bytes_32 (HC.PSK_Binder (0 .. 31)));
                           end;
                        end if;
                     end if;
                  end;

                  if Binder_OK then
                     HC.Using_PSK := True;
                     HC.PSK_Value := PSK;
                     HC.PSK_Value_Len := PSK_Len;
                  end if;
               end;
            end if;
         end;
      end if;

      --  Build ServerHello
      Handshake.Build_Server_Hello (S, HC, SH_Buf, SH_Len);
      if SH_Len = 0 then
         S.Last_Error := Internal_Error;
         S.State := Error_State;
         Result := Error_Alert;
         return;
      end if;

      --  Add ServerHello to transcript
      Append_Transcript (HC, SH_Buf (0 .. SH_Len - 1));

      --  Write ServerHello record (plaintext)
      Records.Build_Handshake_Record
        (Fragment  => SH_Buf (0 .. SH_Len - 1),
         Output    => S.Output,
         Bytes_Out => Rec_Out);

      if Rec_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         S.State := Error_State;
         Result := Error_Alert;
         return;
      end if;

      --  Derive handshake keys
      Derive_Handshake_Keys (S, HC);

      --  Send CCS for middlebox compatibility
      Records.Build_CCS_Record (S.Output, CCS_Out);

      --  Build EncryptedExtensions (encrypted with server HS keys)
      declare
         EE_Buf : Byte_Seq (0 .. 5);
         EE_Len : N32;
         Enc_Out : N32;
      begin
         Handshake.Build_Encrypted_Extensions (EE_Buf, EE_Len);
         Append_Transcript (HC, EE_Buf (0 .. EE_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => EE_Buf (0 .. EE_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Skip Certificate/CertificateVerify for PSK resumption
      if not HC.Using_PSK then

      --  Build CertificateRequest if mTLS is configured
      if HC.Cfg.Request_Client_Cert then
         declare
            CR_Buf  : Byte_Seq (0 .. 31);
            CR_Len  : N32;
            Enc_Out : N32;
         begin
            Handshake.Build_Certificate_Request (CR_Buf, CR_Len);
            if CR_Len > 0 then
               Append_Transcript (HC, CR_Buf (0 .. CR_Len - 1));
               Records.Build_Encrypted_Record
                 (Plaintext  => CR_Buf (0 .. CR_Len - 1),
                  Inner_Type => 16#16#,
                  Keys       => HC.Server_HS,
                  Output     => S.Output,
                  Bytes_Out  => Enc_Out);
            end if;
         end;
      end if;

      --  Build Certificate chain (leaf + intermediates, encrypted)
      declare
         --  Max: leaf + 8 intermediates, each up to 8 KB + 5 bytes overhead
         Cert_Buf : Byte_Seq (0 .. 9 * (Max_Cert_DER_Len + 5) + 10);
         Cert_Len : N32;
         Enc_Out  : N32;
      begin
         Handshake.Build_Certificate_Chain
           (Id     => HC.Cfg.Local.all,
            Result => Cert_Buf,
            Len    => Cert_Len);

         if Cert_Len = 0 then
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Negotiate signature algorithm
      declare
         Algo_OK : Boolean := False;
      begin
         for I in 0 .. HC.Peer_Sig_Algo_Count - 1 loop
            case HC.Cfg.Local.Sign_Algo is
               when Sign_Ed25519 =>
                  if HC.Peer_Sig_Algos (I) = 16#0807# then
                     HC.Negotiated_Sig_Algo := 16#0807#;
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_ECDSA_P256 =>
                  if HC.Peer_Sig_Algos (I) = 16#0403# then
                     HC.Negotiated_Sig_Algo := 16#0403#;
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_ECDSA_P384 =>
                  if HC.Peer_Sig_Algos (I) = 16#0503# then
                     HC.Negotiated_Sig_Algo := 16#0503#;
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_RSA_PSS =>
                  if HC.Peer_Sig_Algos (I) in
                     16#0804# | 16#0805# | 16#0806#
                  then
                     HC.Negotiated_Sig_Algo := HC.Peer_Sig_Algos (I);
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_None =>
                  null;
            end case;
         end loop;

         if not Algo_OK then
            S.Last_Error := Handshake_Failure;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Build CertificateVerify (encrypted)
      declare
         H_Len   : constant N32 := HC.Hash_Len;
         CV_Hash : Byte_Seq (0 .. H_Len - 1);
         CV_Buf  : Byte_Seq (0 .. 523);
         CV_Len  : N32;
         Enc_Out : N32;
      begin
         case S.Negotiated_Suite is
            when Suite_AES_256_GCM_SHA384 =>
               CV_Hash := Transcript_Hash_384 (HC);
            when others =>
               declare
                  H256 : constant Digest := Transcript_Hash_256 (HC);
               begin
                  CV_Hash := H256;
               end;
         end case;

         Handshake.Build_Certificate_Verify
           (Transcript_Hash => CV_Hash,
            Id              => HC.Cfg.Local.all,
            Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
            Role            => Role_Server,
            Random          => HC.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);

         if CV_Len = 0 then
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (HC, CV_Buf (0 .. CV_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => CV_Buf (0 .. CV_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      end if;  --  not Using_PSK (skip cert/cert_verify for resumption)

      --  Build Finished (encrypted)
      declare
         Enc_Out : N32;
      begin
         case S.Negotiated_Suite is
            when Suite_AES_256_GCM_SHA384 =>
               declare
                  use HKDF384;
                  TS_Hash      : constant Key_Schedule.Digest_384 :=
                     Transcript_Hash_384 (HC);
                  Fin_Key      : OKM384_Seq (0 .. 47);
                  Verify_48    : Bytes_48;
                  Big_Finished : Byte_Seq (0 .. 51);  --  4 + 48
               begin
                  Key_Schedule.Derive_Finished_Key_384
                    (Fin_Key, HC.Server_HS_Secret);
                  HMAC384.HMAC_SHA_384
                    (Output => Verify_48,
                     M      => TS_Hash,
                     K      => Byte_Seq (Fin_Key));

                  Big_Finished (0) := Handshake.HT_Finished;
                  Big_Finished (1) := 16#00#;
                  Big_Finished (2) := 16#00#;
                  Big_Finished (3) := 16#30#;  --  48
                  Big_Finished (4 .. 51) := Verify_48;

                  Append_Transcript (HC, Big_Finished);

                  Records.Build_Encrypted_Record
                    (Plaintext  => Big_Finished,
                     Inner_Type => 16#16#,
                     Keys       => HC.Server_HS,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out);
               end;

            when others =>
               declare
                  TS_Hash     : constant Digest := Transcript_Hash_256 (HC);
                  Fin_Key     : OKM_Seq (0 .. 31);
                  Verify_32   : Digest;
                  Fin_Buf     : Byte_Seq (0 .. 35);
                  Fin_Len     : N32;
               begin
                  Key_Schedule.Derive_Finished_Key
                    (Fin_Key, HC.Server_HS_Secret (0 .. 31));
                  HMAC_SHA_256
                    (Output => Verify_32,
                     M      => TS_Hash,
                     K      => Byte_Seq (Fin_Key));

                  Handshake.Build_Finished (Verify_32, Fin_Buf, Fin_Len);
                  Append_Transcript (HC, Fin_Buf (0 .. Fin_Len - 1));

                  Records.Build_Encrypted_Record
                    (Plaintext  => Fin_Buf (0 .. Fin_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => HC.Server_HS,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out);
               end;
         end case;

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Derive application keys now (using transcript through server Finished)
      Derive_App_Keys (S, HC);

      S.State := Server_Hello_Sent;
      Result := Has_Output;
   end Build_Server_Flight;

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys
     (S  : in out Session;
      HC : in out Handshake_Context)
   is
   begin
      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            Hello_Hash : Key_Schedule.Digest_384 :=
               Transcript_Hash_384 (HC);
            Early      : Key_Schedule.Digest_384;
            HS_Secret  : Key_Schedule.Digest_384;
            No_PSK     : Bytes_48 := (others => 0);
            Client_Sec : OKM384_Seq (0 .. 47);
            Server_Sec : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Early_Secret_384 (Early, HC.PSK_Value);
            Key_Schedule.Derive_Handshake_Secret_384
              (HS_Secret, HC.Shared_Secret (0 .. 31), Early);

            HC.Handshake_Secret := Bytes_48 (HS_Secret);
            HC.Hash_Len := 48;

            Key_Schedule.Derive_HS_Traffic_Secrets_384
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_Sec));
            HC.Server_HS_Secret := Bytes_48 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (HC.Client_HS, HC.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (HC.Server_HS, HC.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      when others =>
         declare
            Hello_Hash : Digest := Transcript_Hash_256 (HC);
            Early      : Digest;
            HS_Secret  : Digest;
            No_PSK     : Bytes_32 := (others => 0);
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret
              (Early, Bytes_32 (HC.PSK_Value (0 .. 31)));
            Key_Schedule.Derive_Handshake_Secret
              (HS_Secret, HC.Shared_Secret (0 .. 31), Early);

            HC.Handshake_Secret := (others => 0);
            HC.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
            HC.Hash_Len := 32;

            Key_Schedule.Derive_HS_Traffic_Secrets
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            HC.Client_HS_Secret := (others => 0);
            HC.Client_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Client_Sec));
            HC.Server_HS_Secret := (others => 0);
            HC.Server_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (HC.Client_HS, HC.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (HC.Server_HS, HC.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      end case;
   end Derive_Handshake_Keys;

   --  Derive application keys from master secret + transcript
   procedure Derive_App_Keys
     (S  : in out Session;
      HC : in out Handshake_Context)
   is
   begin
      case S.Negotiated_Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               TS_Hash        : constant Key_Schedule.Digest_384 :=
                  Transcript_Hash_384 (HC);
               Master         : Key_Schedule.Digest_384;
               Client_App_Sec : OKM384_Seq (0 .. 47);
               Server_App_Sec : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Master_Secret_384
                 (Master, Key_Schedule.Digest_384 (HC.Handshake_Secret));

               Key_Schedule.Derive_App_Traffic_Secrets_384
                 (Client_App_Sec, Server_App_Sec, Master, TS_Hash);

               HC.Master_Secret := Bytes_48 (Master);

               Set_Traffic_Keys (S.Client_App,
                                 Bytes_48 (Byte_Seq (Client_App_Sec)),
                                 S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App,
                                 Bytes_48 (Byte_Seq (Server_App_Sec)),
                                 S.Negotiated_Suite);
            end;

         when others =>
            declare
               TS_Hash        : constant Digest := Transcript_Hash_256 (HC);
               Master         : Digest;
               Client_App_Sec : OKM_Seq (0 .. 31);
               Server_App_Sec : OKM_Seq (0 .. 31);
               CS48           : Bytes_48 := (others => 0);
               SS48           : Bytes_48 := (others => 0);
            begin
               Key_Schedule.Derive_Master_Secret
                 (Master, Digest (HC.Handshake_Secret (0 .. 31)));

               Key_Schedule.Derive_App_Traffic_Secrets
                 (Client_App_Sec, Server_App_Sec,
                  Master, TS_Hash);

               HC.Master_Secret := (others => 0);
               HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));

               CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
               SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
               Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);
            end;
      end case;
   end Derive_App_Keys;

   --  Helper: derive key/IV and set Traffic_Keys based on suite
   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16)
   is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               K384 : HKDF384.OKM384_Seq (0 .. 31);
               IV384 : HKDF384.OKM384_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_256
                 (K384, IV384, Secret);
               TK.Key := Bytes_32 (Byte_Seq (K384));
               TK.IV  := Bytes_12 (Byte_Seq (IV384));
            end;
         when Suite_AES_128_GCM_SHA256 =>
            declare
               K128 : OKM_Seq (0 .. 15);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_128
                 (K128, IV12, Secret (0 .. 31));
               TK.Key := (others => 0);
               TK.Key (0 .. 15) := Bytes_16 (Byte_Seq (K128));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;
         when others =>
            declare
               K32 : OKM_Seq (0 .. 31);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV
                 (K32, IV12, Secret (0 .. 31));
               TK.Key := Bytes_32 (Byte_Seq (K32));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;
      end case;
      TK.Counter := 0;
      TK.Suite := Suite;
   end Set_Traffic_Keys;

   --  Process incoming records while waiting for client Finished
   --================================================================
   --  Process_Client_Auth (mTLS)
   --
   --  Handles encrypted records containing the client's Certificate
   --  and CertificateVerify messages.
   --================================================================
   procedure Process_Client_Auth
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data   => S.Input.Data (S.Input.Read_Pos ..
                                  S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            HC.CCS_Received := True;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;

         when Records.Content_Application_Data =>
            declare
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               Encrypted  : Byte_Seq (0 .. Rec.Fragment_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Rec.Fragment_Len - 1);
               Hdr        : Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Rec.Fragment_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Rec.Fragment_Len <= Records.Tag_Size then
                  S.Last_Error := Decode_Error;
                  S.State := Error_State;
                  Result := Error_Alert;
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  return;
               end if;

               Records.Decrypt_Record
                 (Encrypted  => Encrypted,
                  Record_Hdr => Hdr,
                  Keys       => HC.Client_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  S.Last_Error := Bad_Record_MAC;
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               end if;

               if Inner_Type /= 16#16# then
                  Result := OK;
                  return;
               end if;

               declare
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
                  Data     : Byte_Seq renames Plaintext (0 .. Plain_Len - 1);
               begin
                  Handshake.Parse_Handshake_Header
                    (Data, Msg_Type, Msg_Len, Parse_OK);

                  if not Parse_OK then
                     S.Last_Error := Decode_Error;
                     S.State := Error_State;
                     Result := Error_Alert;
                     return;
                  end if;

                  case S.State is
                     when Wait_Client_Certificate =>
                        if Msg_Type /= Handshake.HT_Certificate then
                           S.Last_Error := Unexpected_Message;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;

                        Append_Transcript (HC, Data);

                        --  Parse client certificate (same logic as client)
                        HC.Peer_Cert_Valid := False;
                        HC.Peer_Int_Count := 0;
                        if Msg_Len > 4 and then
                           N32 (Data'Length) >= 4 + Msg_Len
                        then
                           declare
                              B : constant N32 := 4;
                              Ctx_Len : constant N32 := N32 (Data (B));
                              List_Start : constant N32 := B + 1 + Ctx_Len;
                              Pos : N32;
                           begin
                              if List_Start + 3 <= N32 (Data'Length) then
                                 Pos := List_Start + 3;

                                 --  First cert is the leaf
                                 if Pos + 3 <= N32 (Data'Length) then
                                    declare
                                       C_Len : constant N32 :=
                                          N32 (Data (Pos)) * 65536 +
                                          N32 (Data (Pos + 1)) * 256 +
                                          N32 (Data (Pos + 2));
                                    begin
                                       Pos := Pos + 3;
                                       if C_Len > 0
                                          and then C_Len <= Max_Cert_DER_Len
                                          and then Pos + C_Len <=
                                                      N32 (Data'Length)
                                       then
                                          HC.Peer_Cert_DER_Len := C_Len;
                                          HC.Peer_Cert_DER (0 .. C_Len - 1) :=
                                             Data (Pos .. Pos + C_Len - 1);

                                          declare
                                             Cert_X : X509.Byte_Seq
                                                (0 .. X509.N32 (C_Len) - 1);
                                             P_OK : Boolean;
                                          begin
                                             for I in N32 range
                                                0 .. C_Len - 1
                                             loop
                                                Cert_X (X509.N32 (I)) :=
                                                   X509.Byte (Data (Pos + I));
                                             end loop;
                                             X509.Parse
                                               (Cert_X, HC.Peer_Cert, P_OK);
                                             HC.Peer_Cert_Valid := P_OK
                                                and then
                                                   X509.Is_Valid (HC.Peer_Cert);
                                          end;
                                       end if;
                                    end;
                                 end if;
                              end if;
                           end;
                        end if;

                        --  Empty cert list is OK (client has no cert)
                        if not HC.Peer_Cert_Valid then
                           --  No client cert — skip CertificateVerify
                           S.State := Wait_Client_Finished;
                        else
                           S.State := Wait_Client_Cert_Verify;
                        end if;
                        Result := OK;

                     when Wait_Client_Cert_Verify =>
                        if Msg_Type /= Handshake.HT_Certificate_Verify then
                           S.Last_Error := Unexpected_Message;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;

                        --  Verify client CertificateVerify signature
                        declare
                           H_Len : constant N32 := HC.Hash_Len;
                           CV_Hash : Byte_Seq (0 .. H_Len - 1);
                        begin
                           --  Transcript hash up to (not including) CV
                           case S.Negotiated_Suite is
                              when Suite_AES_256_GCM_SHA384 =>
                                 CV_Hash := Transcript_Hash_384 (HC);
                              when others =>
                                 declare
                                    H : constant Digest :=
                                       Transcript_Hash_256 (HC);
                                 begin
                                    CV_Hash := H;
                                 end;
                           end case;

                           Append_Transcript (HC, Data);

                           --  Build expected signed content
                           declare
                              Ctx_Str : constant String :=
                                 "TLS 1.3, client CertificateVerify";
                              C_Len : constant N32 :=
                                 64 + N32 (Ctx_Str'Length) + 1 + H_Len;
                              Content : Byte_Seq (0 .. C_Len - 1);
                              Verified : Boolean := False;
                           begin
                              Content (0 .. 63) := (others => 16#20#);
                              for I in Ctx_Str'Range loop
                                 Content (64 + N32 (I - Ctx_Str'First)) :=
                                    Byte (Character'Pos (Ctx_Str (I)));
                              end loop;
                              Content (64 + N32 (Ctx_Str'Length)) := 0;
                              Content (64 + N32 (Ctx_Str'Length) + 1 ..
                                       64 + N32 (Ctx_Str'Length) + H_Len) :=
                                 CV_Hash;

                              --  Ed25519 verification
                              if X509.PK_Algorithm (HC.Peer_Cert) =
                                    X509.Algo_EC_Ed25519
                                 and then Msg_Len >= 68
                              then
                                 declare
                                    SM_Len : constant N32 := 64 + C_Len;
                                    SM : Byte_Seq (0 .. SM_Len - 1)
                                       := (others => 0);
                                    M  : Byte_Seq (0 .. SM_Len - 1)
                                       := (others => 0);
                                    PK_Bytes : Bytes_32 := (others => 0);
                                    CV_PK : SPARKNaCl.Sign.Signing_PK;
                                    V_OK : Boolean;
                                    V_Len : I32;
                                 begin
                                    SM (0 .. 63) := Data (8 .. 71);
                                    SM (64 .. SM_Len - 1) := Content;

                                    declare
                                       PK : constant X509.Byte_Seq :=
                                          X509.PK_Data (HC.Peer_Cert);
                                    begin
                                       for I in 0 .. 31 loop
                                          PK_Bytes (N32 (I)) :=
                                             Byte (PK (X509.N32 (I)));
                                       end loop;
                                    end;

                                    SPARKNaCl.Sign.PK_From_Bytes
                                      (PK_Bytes, CV_PK);
                                    SPARKNaCl.Sign.Open
                                      (M, V_OK, V_Len, SM, CV_PK);
                                    Verified := V_OK;
                                 end;
                              end if;

                              --  TODO: ECDSA P-256/P-384 verification

                              if not Verified then
                                 S.Last_Error := Certificate_Verify_Failed;
                                 S.State := Error_State;
                                 Result := Error_Alert;
                                 return;
                              end if;
                           end;
                        end;

                        --  Validate client cert chain if trust store
                        if HC.Cfg.Trust /= null
                           and then HC.Cfg.Get_Time /= null
                           and then HC.Peer_Cert_Valid
                        then
                           declare
                              Cert_X : X509.Byte_Seq
                                 (0 .. X509.N32 (HC.Peer_Cert_DER_Len) - 1);
                              VR : Validation_Result;
                           begin
                              for I in N32 range
                                 0 .. HC.Peer_Cert_DER_Len - 1
                              loop
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
                                 Hostname   => "",
                                 Purpose    => Purpose_Client,
                                 Mode       => HC.Cfg.Verify_Mode);

                              if VR /= Valid then
                                 S.Last_Error := Bad_Certificate;
                                 S.State := Error_State;
                                 Result := Error_Alert;
                                 return;
                              end if;
                           end;
                        end if;

                        S.State := Wait_Client_Finished;
                        Result := OK;

                     when others =>
                        S.Last_Error := Internal_Error;
                        S.State := Error_State;
                        Result := Error_Alert;
                  end case;
               end;
            end;

         when others =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Client_Auth;

   procedure Process_Client_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data   => S.Input.Data (S.Input.Read_Pos ..
                                  S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            --  CCS for middlebox compatibility, ignore
            HC.CCS_Received := True;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;

         when Records.Content_Application_Data =>
            --  Encrypted handshake record (client Finished)
            declare
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               Encrypted  : Byte_Seq (0 .. Rec.Fragment_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Rec.Fragment_Len - 1);
               Hdr        : Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Rec.Fragment_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Rec.Fragment_Len <= Records.Tag_Size then
                  S.Last_Error := Decode_Error;
                  S.State := Error_State;
                  Result := Error_Alert;
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  return;
               end if;

               Records.Decrypt_Record
                 (Encrypted  => Encrypted,
                  Record_Hdr => Hdr,
                  Keys       => HC.Client_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  S.Last_Error := Bad_Record_MAC;
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               end if;

               if Inner_Type = 16#15# and then Plain_Len >= 2 then
                  S.Last_Error := Error_Code'Val
                    (Natural'Min (Natural (Plaintext (1)),
                                  Error_Code'Pos (Error_Code'Last)));
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               elsif Inner_Type /= 16#16# then
                  Result := OK;
                  return;
               end if;

               --  Parse handshake header
               declare
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
               begin
                  Handshake.Parse_Handshake_Header
                    (Plaintext (0 .. Plain_Len - 1),
                     Msg_Type, Msg_Len, Parse_OK);

                  if not Parse_OK or Msg_Type /= Handshake.HT_Finished then
                     S.Last_Error := Unexpected_Message;
                     S.State := Error_State;
                     Result := Error_Alert;
                     return;
                  end if;

                  --  Verify client Finished
                  declare
                     Data     : Byte_Seq renames Plaintext (0 .. Plain_Len - 1);
                     Verified : Boolean := False;
                  begin
                     case S.Negotiated_Suite is
                        when Suite_AES_256_GCM_SHA384 =>
                           declare
                              use HKDF384;
                              Pre_Hash : constant Key_Schedule.Digest_384 :=
                                 Transcript_Hash_384 (HC);
                              Fin_Key  : OKM384_Seq (0 .. 47);
                              Expected : Bytes_48;
                           begin
                              Key_Schedule.Derive_Finished_Key_384
                                (Fin_Key, HC.Client_HS_Secret);
                              HMAC384.HMAC_SHA_384
                                (Output => Expected,
                                 M      => Pre_Hash,
                                 K      => Byte_Seq (Fin_Key));

                              if Msg_Len = 48 and then
                                 N32 (Data'Length) >= 52
                              then
                                 if Equal (Expected,
                                           Bytes_48 (Data (4 .. 51))) then
                                    Verified := True;
                                 end if;
                              end if;
                           end;
                        when others =>
                           declare
                              Pre_Hash : constant Digest :=
                                 Transcript_Hash_256 (HC);
                              Fin_Key  : OKM_Seq (0 .. 31);
                              Expected : Digest;
                           begin
                              Key_Schedule.Derive_Finished_Key
                                (Fin_Key, HC.Client_HS_Secret (0 .. 31));
                              HMAC_SHA_256
                                (Output => Expected,
                                 M      => Pre_Hash,
                                 K      => Byte_Seq (Fin_Key));

                              if Msg_Len = 32 and then
                                 N32 (Data'Length) >= 36
                              then
                                 if Equal (Expected,
                                           Bytes_32 (Data (4 .. 35))) then
                                    Verified := True;
                                 end if;
                              end if;
                           end;
                     end case;

                     if not Verified then
                        S.Last_Error := Handshake_Failure;
                        S.State := Error_State;
                        Result := Error_Alert;
                        return;
                     end if;

                     --  Client Finished verified.
                     --  Append client Finished to transcript for res_master derivation
                     Append_Transcript (HC, Data);

                     --  Derive resumption master secret and send NewSessionTicket
                     declare
                        use SPARKTLS.Ticket_Cache;
                        Nonce    : Byte_Seq (0 .. 1) := (0, 0);
                        TID : Ticket_ID;
                        Enc_Out  : N32;
                     begin
                        case S.Negotiated_Suite is
                           when Suite_AES_256_GCM_SHA384 =>
                              declare
                                 use HKDF384;
                                 Full_Hash : constant Key_Schedule.Digest_384 :=
                                    Transcript_Hash_384 (HC);
                                 Res_Master : OKM384_Seq (0 .. 47);
                                 PSK_Out    : OKM384_Seq (0 .. 47);
                              begin
                                 Key_Schedule.Derive_Resumption_Master_Secret_384
                                   (Res_Master, HC.Master_Secret (0 .. 47), Full_Hash);
                                 Key_Schedule.Derive_PSK_384
                                   (PSK_Out, Byte_Seq (Res_Master), Nonce);
                                 --  Store in cache
                                 if HC.Cfg.Ticket_Store /= null then
                                    Ticket_Cache.Store
                                      (HC.Cfg.Ticket_Store.all,
                                       Bytes_48 (PSK_Out), 48,
                                       S.Negotiated_Suite, 0, TID);
                                 end if;
                                 S.Res_Master := Bytes_48 (Res_Master);
                                 S.Res_Master_Len := 48;
                              end;
                           when others =>
                              declare
                                 Full_Hash : constant Digest :=
                                    Transcript_Hash_256 (HC);
                                 Res_Master : OKM_Seq (0 .. 31);
                                 PSK_Out    : OKM_Seq (0 .. 31);
                              begin
                                 Key_Schedule.Derive_Resumption_Master_Secret
                                   (Res_Master,
                                    Digest (HC.Master_Secret (0 .. 31)),
                                    Full_Hash);
                                 Key_Schedule.Derive_PSK
                                   (PSK_Out, Byte_Seq (Res_Master), Nonce);
                                 if HC.Cfg.Ticket_Store /= null then
                                    declare
                                       PSK_48 : Bytes_48 := (others => 0);
                                    begin
                                       for I in N32 range 0 .. 31 loop
                                          PSK_48 (I) := PSK_Out (I);
                                       end loop;
                                       Ticket_Cache.Store
                                         (HC.Cfg.Ticket_Store.all,
                                          PSK_48, 32,
                                          S.Negotiated_Suite, 0, TID);
                                    end;
                                 end if;
                                 S.Res_Master := (others => 0);
                                 for I in N32 range 0 .. 31 loop
                                    S.Res_Master (I) := Res_Master (I);
                                 end loop;
                                 S.Res_Master_Len := 32;
                              end;
                        end case;

                        --  Build and send NewSessionTicket if we have a cache
                        if HC.Cfg.Ticket_Store /= null then
                           declare
                              --  NST format: type(1) + len(3) + lifetime(4) +
                              --  age_add(4) + nonce_len(1) + nonce(2) +
                              --  ticket_len(2) + ticket(16) + ext_len(2) = 35
                              NST : Byte_Seq (0 .. 34) := (others => 0);
                              P   : N32 := 0;
                           begin
                              --  Handshake type: NewSessionTicket (0x04)
                              NST (0) := 16#04#;
                              --  Length: 31 bytes
                              NST (1) := 0; NST (2) := 0; NST (3) := 31;
                              --  ticket_lifetime: 3600 seconds (1 hour)
                              NST (4) := 0; NST (5) := 0;
                              NST (6) := 16#0E#; NST (7) := 16#10#;
                              --  ticket_age_add: 0 (simplified)
                              NST (8) := 0; NST (9) := 0;
                              NST (10) := 0; NST (11) := 0;
                              --  ticket_nonce_length: 2
                              NST (12) := 2;
                              --  ticket_nonce
                              NST (13) := Nonce (0);
                              NST (14) := Nonce (1);
                              --  ticket_length: 16
                              NST (15) := 0; NST (16) := 16;
                              --  ticket (the cache ID)
                              NST (17 .. 32) := TID;
                              --  extensions_length: 0
                              NST (33) := 0; NST (34) := 0;

                              --  Encrypt and queue as post-handshake record
                              Records.Build_Encrypted_Record
                                (Plaintext  => NST,
                                 Inner_Type => 16#16#,  --  handshake
                                 Keys       => S.Server_App,
                                 Output     => S.Output,
                                 Bytes_Out  => Enc_Out);
                           end;
                        end if;
                     end;

                     S.State := Connected;
                     Result := Handshake_Done;
                  end;
               end;
            end;

         when others =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Client_Finished;

   --  Process records in Connected state
   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         if Output_Pending (S) > 0 then
            Result := Has_Output;
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      Records.Parse_Record_Header
        (Data   => S.Input.Data (S.Input.Read_Pos ..
                                  S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      if Rec.Content /= Records.Content_Application_Data then
         --  In Connected state, only application_data records are valid.
         --  CCS after Finished and other unexpected types get rejected.
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;

      declare
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Rec.Fragment_Len - 1) :=
            S.Input.Data (Frag_Start ..
                           Frag_Start + Rec.Fragment_Len - 1);
         Hdr        : Byte_Seq (0 .. 4) :=
            S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Rec.Fragment_Len <= Records.Tag_Size then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            return;
         end if;

         Records.Decrypt_Record
           (Encrypted  => Encrypted,
            Record_Hdr => Hdr,
            Keys       => S.Client_App,
            Plaintext  => Plaintext,
            Plain_Len  => Plain_Len,
            Inner_Type => Inner_Type,
            Valid      => Dec_Valid);

         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not Dec_Valid then
            S.Last_Error := Bad_Record_MAC;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         case Inner_Type is
            when 16#17# =>
               --  Application data
               if Plain_Len > 0 and then
                  S.App_Data_Len + Plain_Len <= S.App_Data'Length
               then
                  S.App_Data (S.App_Data_Len ..
                               S.App_Data_Len + Plain_Len - 1) :=
                     Plaintext (0 .. Plain_Len - 1);
                  S.App_Data_Len := S.App_Data_Len + Plain_Len;
                  Result := Plaintext_Ready;
               else
                  Result := OK;
               end if;

            when 16#16# =>
               --  Post-handshake message (NewSessionTicket, etc.)
               Result := OK;

            when 16#15# =>
               --  Alert
               if Plain_Len >= 2 and then Plaintext (1) = 0 then
                  S.State := Closing;
                  Result := Shutdown;
               else
                  S.Last_Error := Unexpected_Message;
                  S.State := Error_State;
                  Result := Error_Alert;
               end if;

            when others =>
               Result := OK;
         end case;
      end;
   end Process_Connected;

   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   is
      Enc_Out : N32;
   begin
      Records.Build_Encrypted_Record
        (Plaintext  => Plaintext,
         Inner_Type => 16#17#,
         Keys       => S.Server_App,
         Output     => S.Output,
         Bytes_Out  => Enc_Out);

      if Enc_Out > 0 then
         Bytes_Written := N32 (Plaintext'Length);
      else
         Bytes_Written := 0;
      end if;
   end Write_Plaintext;

   procedure Close_Notify (S : in out Session) is
      Alert_Out : N32;
   begin
      Records.Build_Alert_Record
        (Level     => 1,
         Desc      => 0,
         Keys      => S.Server_App,
         Output    => S.Output,
         Bytes_Out => Alert_Out);
      S.State := Closing;
   end Close_Notify;

end SPARKTLS.Server;
