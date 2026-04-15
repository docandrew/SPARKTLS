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
with X509;
use type X509.Algorithm_ID;
with SPARKTLS.HMAC384;
with SPARKTLS.HKDF384;

package body SPARKTLS.Server with
   SPARK_Mode => On
is
   --  Forward declarations
   procedure Build_Server_Flight (S : in out Session; Result : out Action);
   procedure Process_Client_Auth (S : in out Session; Result : out Action);
   procedure Process_Client_Finished (S : in out Session; Result : out Action);
   procedure Process_Connected (S : in out Session; Result : out Action);
   procedure Derive_Handshake_Keys (S : in out Session);
   procedure Derive_App_Keys (S : in out Session);

   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16);

   --  Append handshake message bytes to the transcript
   procedure Append_Transcript
     (S    : in out Session;
      Data : in     Byte_Seq)
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if S.Transcript_Len + Len <= S.Transcript'Length then
         S.Transcript (S.Transcript_Len ..
                         S.Transcript_Len + Len - 1) := Data;
         S.Transcript_Len := S.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   function Transcript_Hash_256 (S : Session) return Digest is
      H : Digest;
   begin
      Hash (H, S.Transcript (0 .. S.Transcript_Len - 1));
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (S : Session)
      return SPARKNaCl.Hashing.SHA384.Digest
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKNaCl.Hashing.SHA384.Hash
        (H, S.Transcript (0 .. S.Transcript_Len - 1));
      return H;
   end Transcript_Hash_384;

   procedure Configure
     (S                   : out Session;
      Local               : Identity_Access;
      Random              : Random_Bytes_Fn;
      Trust               : Trust_Store_Access := null;
      Request_Client_Cert : Boolean := False)
   is
      Cfg : Config;
   begin
      Cfg.Random              := Random;
      Cfg.Local               := Local;
      Cfg.Trust               := Trust;
      Cfg.Request_Client_Cert := Request_Client_Cert;
      Init (S, Cfg);
   end Configure;

   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   is
   begin
      S := (Cfg       => Cfg,
            State     => Wait_Client_Hello,
            Role => Role_Server,
            others    => <>);
   end Init;

   procedure Advance
     (S      : in out Session;
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
                  Handshake.Parse_Client_Hello (S, Frag, Parse_OK);

                  if not Parse_OK then
                     S.Last_Error := Handshake_Failure;
                     S.State := Error_State;
                     Result := Error_Alert;
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     return;
                  end if;

                  --  Add ClientHello to transcript
                  Append_Transcript (S, Frag);

                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                  --  Build entire server flight
                  Build_Server_Flight (S, Result);
               end;
            end;

         when Server_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               if S.Cfg.Request_Client_Cert then
                  S.State := Wait_Client_Certificate;
               else
                  S.State := Wait_Client_Finished;
               end if;
               Result := Need_Input;
            end if;

         when Wait_Client_Certificate
            | Wait_Client_Cert_Verify =>
            Process_Client_Auth (S, Result);

         when Wait_Client_Finished =>
            Process_Client_Finished (S, Result);

         when Connected =>
            Process_Connected (S, Result);

         when Closing =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.State := Closed;
               Result := Shutdown;
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
      end case;
   end Advance;

   --  Build the entire server handshake flight:
   --  ServerHello (plaintext record) + CCS + encrypted(EE + Cert + CV + Finished)
   procedure Build_Server_Flight (S : in out Session; Result : out Action)
   is
      SH_Buf  : Byte_Seq (0 .. Handshake.Max_Server_Hello - 1);
      SH_Len  : N32;
      Rec_Out : N32;
      CCS_Out : N32;
   begin
      Result := OK;

      --  Build ServerHello
      Handshake.Build_Server_Hello (S, SH_Buf, SH_Len);
      if SH_Len = 0 then
         S.Last_Error := Internal_Error;
         S.State := Error_State;
         Result := Error_Alert;
         return;
      end if;

      --  Add ServerHello to transcript
      Append_Transcript (S, SH_Buf (0 .. SH_Len - 1));

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
      Derive_Handshake_Keys (S);

      --  Send CCS for middlebox compatibility
      Records.Build_CCS_Record (S.Output, CCS_Out);

      --  Build EncryptedExtensions (encrypted with server HS keys)
      declare
         EE_Buf : Byte_Seq (0 .. 5);
         EE_Len : N32;
         Enc_Out : N32;
      begin
         Handshake.Build_Encrypted_Extensions (EE_Buf, EE_Len);
         Append_Transcript (S, EE_Buf (0 .. EE_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => EE_Buf (0 .. EE_Len - 1),
            Inner_Type => 16#16#,
            Keys       => S.Server_HS,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Build CertificateRequest if mTLS is configured
      if S.Cfg.Request_Client_Cert then
         declare
            CR_Buf  : Byte_Seq (0 .. 31);
            CR_Len  : N32;
            Enc_Out : N32;
         begin
            Handshake.Build_Certificate_Request (CR_Buf, CR_Len);
            if CR_Len > 0 then
               Append_Transcript (S, CR_Buf (0 .. CR_Len - 1));
               Records.Build_Encrypted_Record
                 (Plaintext  => CR_Buf (0 .. CR_Len - 1),
                  Inner_Type => 16#16#,
                  Keys       => S.Server_HS,
                  Output     => S.Output,
                  Bytes_Out  => Enc_Out);
            end if;
         end;
      end if;

      --  Build Certificate (encrypted)
      declare
         Cert_Buf : Byte_Seq (0 .. S.Cfg.Local.NaCl_Cert_Len + 15);
         Cert_Len : N32;
         Enc_Out  : N32;
      begin
         Handshake.Build_Certificate
           (Cert_DER => S.Cfg.Local.NaCl_Cert_DER,
            Cert_Len => S.Cfg.Local.NaCl_Cert_Len,
            Result   => Cert_Buf,
            Len      => Cert_Len);

         if Cert_Len = 0 then
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (S, Cert_Buf (0 .. Cert_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
            Inner_Type => 16#16#,
            Keys       => S.Server_HS,
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
         for I in 0 .. S.Peer_Sig_Algo_Count - 1 loop
            case S.Cfg.Local.Sign_Algo is
               when Sign_Ed25519 =>
                  if S.Peer_Sig_Algos (I) = 16#0807# then
                     S.Negotiated_Sig_Algo := 16#0807#;
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_ECDSA_P256 =>
                  if S.Peer_Sig_Algos (I) = 16#0403# then
                     S.Negotiated_Sig_Algo := 16#0403#;
                     Algo_OK := True;
                     exit;
                  end if;
               when Sign_ECDSA_P384 =>
                  if S.Peer_Sig_Algos (I) = 16#0503# then
                     S.Negotiated_Sig_Algo := 16#0503#;
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
         H_Len   : constant N32 := S.Hash_Len;
         CV_Hash : Byte_Seq (0 .. H_Len - 1);
         CV_Buf  : Byte_Seq (0 .. 199);
         CV_Len  : N32;
         Enc_Out : N32;
      begin
         case S.Negotiated_Suite is
            when Suite_AES_256_GCM_SHA384 =>
               CV_Hash := Transcript_Hash_384 (S);
            when others =>
               declare
                  H256 : constant Digest := Transcript_Hash_256 (S);
               begin
                  CV_Hash := H256;
               end;
         end case;

         Handshake.Build_Certificate_Verify
           (Transcript_Hash => CV_Hash,
            Id              => S.Cfg.Local.all,
            Sig_Algo_Wire   => S.Negotiated_Sig_Algo,
            Role            => Role_Server,
            Random          => S.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);

         if CV_Len = 0 then
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (S, CV_Buf (0 .. CV_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => CV_Buf (0 .. CV_Len - 1),
            Inner_Type => 16#16#,
            Keys       => S.Server_HS,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Build Finished (encrypted)
      declare
         Enc_Out : N32;
      begin
         case S.Negotiated_Suite is
            when Suite_AES_256_GCM_SHA384 =>
               declare
                  use HKDF384;
                  TS_Hash      : constant Key_Schedule.Digest_384 :=
                     Transcript_Hash_384 (S);
                  Fin_Key      : OKM384_Seq (0 .. 47);
                  Verify_48    : Bytes_48;
                  Big_Finished : Byte_Seq (0 .. 51);  --  4 + 48
               begin
                  Key_Schedule.Derive_Finished_Key_384
                    (Fin_Key, S.Server_HS_Secret);
                  HMAC384.HMAC_SHA_384
                    (Output => Verify_48,
                     M      => TS_Hash,
                     K      => Byte_Seq (Fin_Key));

                  Big_Finished (0) := Handshake.HT_Finished;
                  Big_Finished (1) := 16#00#;
                  Big_Finished (2) := 16#00#;
                  Big_Finished (3) := 16#30#;  --  48
                  Big_Finished (4 .. 51) := Verify_48;

                  Append_Transcript (S, Big_Finished);

                  Records.Build_Encrypted_Record
                    (Plaintext  => Big_Finished,
                     Inner_Type => 16#16#,
                     Keys       => S.Server_HS,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out);
               end;

            when others =>
               declare
                  TS_Hash     : constant Digest := Transcript_Hash_256 (S);
                  Fin_Key     : OKM_Seq (0 .. 31);
                  Verify_32   : Digest;
                  Fin_Buf     : Byte_Seq (0 .. 35);
                  Fin_Len     : N32;
               begin
                  Key_Schedule.Derive_Finished_Key
                    (Fin_Key, S.Server_HS_Secret (0 .. 31));
                  HMAC_SHA_256
                    (Output => Verify_32,
                     M      => TS_Hash,
                     K      => Byte_Seq (Fin_Key));

                  Handshake.Build_Finished (Verify_32, Fin_Buf, Fin_Len);
                  Append_Transcript (S, Fin_Buf (0 .. Fin_Len - 1));

                  Records.Build_Encrypted_Record
                    (Plaintext  => Fin_Buf (0 .. Fin_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => S.Server_HS,
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
      Derive_App_Keys (S);

      S.State := Server_Hello_Sent;
      Result := Has_Output;
   end Build_Server_Flight;

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys (S : in out Session) is
   begin
      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            Hello_Hash : Key_Schedule.Digest_384 :=
               Transcript_Hash_384 (S);
            Early      : Key_Schedule.Digest_384;
            HS_Secret  : Key_Schedule.Digest_384;
            No_PSK     : Bytes_48 := (others => 0);
            Client_Sec : OKM384_Seq (0 .. 47);
            Server_Sec : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Early_Secret_384 (Early, No_PSK);
            Key_Schedule.Derive_Handshake_Secret_384
              (HS_Secret, S.Shared_Secret (0 .. 31), Early);

            S.Handshake_Secret := Bytes_48 (HS_Secret);
            S.Hash_Len := 48;

            Key_Schedule.Derive_HS_Traffic_Secrets_384
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            S.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_Sec));
            S.Server_HS_Secret := Bytes_48 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (S.Client_HS, S.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_HS, S.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      when others =>
         declare
            Hello_Hash : Digest := Transcript_Hash_256 (S);
            Early      : Digest;
            HS_Secret  : Digest;
            No_PSK     : Bytes_32 := (others => 0);
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret (Early, No_PSK);
            Key_Schedule.Derive_Handshake_Secret
              (HS_Secret, S.Shared_Secret (0 .. 31), Early);

            S.Handshake_Secret := (others => 0);
            S.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
            S.Hash_Len := 32;

            Key_Schedule.Derive_HS_Traffic_Secrets
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            S.Client_HS_Secret := (others => 0);
            S.Client_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Client_Sec));
            S.Server_HS_Secret := (others => 0);
            S.Server_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (S.Client_HS, S.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_HS, S.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      end case;
   end Derive_Handshake_Keys;

   --  Derive application keys from master secret + transcript
   procedure Derive_App_Keys (S : in out Session) is
   begin
      case S.Negotiated_Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               TS_Hash        : constant Key_Schedule.Digest_384 :=
                  Transcript_Hash_384 (S);
               Master         : Key_Schedule.Digest_384;
               Client_App_Sec : OKM384_Seq (0 .. 47);
               Server_App_Sec : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Master_Secret_384
                 (Master, Key_Schedule.Digest_384 (S.Handshake_Secret));

               Key_Schedule.Derive_App_Traffic_Secrets_384
                 (Client_App_Sec, Server_App_Sec, Master, TS_Hash);

               S.Master_Secret := Bytes_48 (Master);

               Set_Traffic_Keys (S.Client_App,
                                 Bytes_48 (Byte_Seq (Client_App_Sec)),
                                 S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App,
                                 Bytes_48 (Byte_Seq (Server_App_Sec)),
                                 S.Negotiated_Suite);
            end;

         when others =>
            declare
               TS_Hash        : constant Digest := Transcript_Hash_256 (S);
               Master         : Digest;
               Client_App_Sec : OKM_Seq (0 .. 31);
               Server_App_Sec : OKM_Seq (0 .. 31);
               CS48           : Bytes_48 := (others => 0);
               SS48           : Bytes_48 := (others => 0);
            begin
               Key_Schedule.Derive_Master_Secret
                 (Master, Digest (S.Handshake_Secret (0 .. 31)));

               Key_Schedule.Derive_App_Traffic_Secrets
                 (Client_App_Sec, Server_App_Sec,
                  Master, TS_Hash);

               S.Master_Secret := (others => 0);
               S.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));

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
            S.CCS_Received := True;
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
                  Keys       => S.Client_HS,
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

                        Append_Transcript (S, Data);

                        --  Parse client certificate (same logic as client)
                        S.Peer_Cert_Valid := False;
                        S.Peer_Int_Count := 0;
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
                                          S.Peer_Cert_DER_Len := C_Len;
                                          S.Peer_Cert_DER (0 .. C_Len - 1) :=
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
                                               (Cert_X, S.Peer_Cert, P_OK);
                                             S.Peer_Cert_Valid := P_OK
                                                and then
                                                   X509.Is_Valid (S.Peer_Cert);
                                          end;
                                       end if;
                                    end;
                                 end if;
                              end if;
                           end;
                        end if;

                        --  Empty cert list is OK (client has no cert)
                        if not S.Peer_Cert_Valid then
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
                           H_Len : constant N32 := S.Hash_Len;
                           CV_Hash : Byte_Seq (0 .. H_Len - 1);
                        begin
                           --  Transcript hash up to (not including) CV
                           case S.Negotiated_Suite is
                              when Suite_AES_256_GCM_SHA384 =>
                                 CV_Hash := Transcript_Hash_384 (S);
                              when others =>
                                 declare
                                    H : constant Digest :=
                                       Transcript_Hash_256 (S);
                                 begin
                                    CV_Hash := H;
                                 end;
                           end case;

                           Append_Transcript (S, Data);

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
                              if X509.PK_Algorithm (S.Peer_Cert) =
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
                                          X509.PK_Data (S.Peer_Cert);
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
                        if S.Cfg.Trust /= null
                           and then S.Cfg.Get_Time /= null
                           and then S.Peer_Cert_Valid
                        then
                           declare
                              Cert_X : X509.Byte_Seq
                                 (0 .. X509.N32 (S.Peer_Cert_DER_Len) - 1);
                              VR : Validation_Result;
                           begin
                              for I in N32 range
                                 0 .. S.Peer_Cert_DER_Len - 1
                              loop
                                 Cert_X (X509.N32 (I)) :=
                                    X509.Byte (S.Peer_Cert_DER (I));
                              end loop;

                              VR := Validate_Chain
                                (Leaf_DER   => Cert_X,
                                 Leaf       => S.Peer_Cert,
                                 Ints       => S.Peer_Ints,
                                 Int_Count  => S.Peer_Int_Count,
                                 Roots      => S.Cfg.Trust.Roots,
                                 Root_Count => S.Cfg.Trust.Root_Count,
                                 Now        => S.Cfg.Get_Time.all,
                                 Hostname   => "",
                                 Purpose    => Purpose_Client,
                                 Mode       => S.Cfg.Verify_Mode);

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
            S.CCS_Received := True;
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
                  Keys       => S.Client_HS,
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
                                 Transcript_Hash_384 (S);
                              Fin_Key  : OKM384_Seq (0 .. 47);
                              Expected : Bytes_48;
                           begin
                              Key_Schedule.Derive_Finished_Key_384
                                (Fin_Key, S.Client_HS_Secret);
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
                                 Transcript_Hash_256 (S);
                              Fin_Key  : OKM_Seq (0 .. 31);
                              Expected : Digest;
                           begin
                              Key_Schedule.Derive_Finished_Key
                                (Fin_Key, S.Client_HS_Secret (0 .. 31));
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

                     --  Client Finished verified. Transition to Connected.
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
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
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
