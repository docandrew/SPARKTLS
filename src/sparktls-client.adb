with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.MAC;              use SPARKNaCl.MAC;
with SPARKNaCl.HKDF;             use SPARKNaCl.HKDF;

with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Client_Msgs;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule;
with SPARKTLS.HMAC384;
with SPARKTLS.HKDF384;
with SPARKTLS.HC_Alloc;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Client.TLS12;

with X509;

package body SPARKTLS.Client with
   SPARK_Mode => On
is
   --  Forward declarations for internal procedures
   procedure Derive_Handshake_Keys
     (S  : in out Session;
      HC : in out Handshake_Context);
   procedure Send_Client_Certificate
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);
   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action);
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);
   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action);
   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16);

   --  Advance the handshake state machine (operates on dereferenced HC).
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

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

   function Transcript_Hash_256 (HC : Handshake_Context) return Digest
   with Pre => HC.Transcript_Len > 0
   is
      H : Digest;
   begin
      Hash (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (HC : Handshake_Context)
      return SPARKNaCl.Hashing.SHA384.Digest
   with Pre => HC.Transcript_Len > 0
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKNaCl.Hashing.SHA384.Hash
        (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_384;

   procedure Configure
     (S        : out Session;
      Hostname : String;
      Trust    : Trust_Store_Access;
      Random   : Random_Bytes_Fn;
      Clock    : Get_Time_Fn;
      Local    : Identity_Access := null)
   is
      Cfg : Config;
   begin
      Cfg.Random      := Random;
      Cfg.Trust       := Trust;
      Cfg.Local       := Local;
      Cfg.Skip_Verify := Trust = null;
      Cfg.Get_Time    := Clock;
      if Hostname'Length > 0
         and then Hostname'Length <= Max_Hostname_Len
      then
         Cfg.Server_Name.Data (1 .. Hostname'Length) := Hostname;
         Cfg.Server_Name.Len := Hostname'Length;
      end if;
      Init (S, Cfg);
   end Configure;

   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   with SPARK_Mode => Off
   is
      CH_Buf    : Byte_Seq (0 .. Handshake.Client_Msgs.Max_Client_Hello - 1);
      CH_Len    : N32;
      Rec_Out   : N32;
   begin
      S := (State     => Client_Hello_Sent,
            Role      => Role_Client,
            others    => <>);

      S.HC_Ptr := HC_Alloc.Allocate;
      if S.HC_Ptr = null then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         return;
      end if;

      S.HC_Ptr.Cfg := Cfg;

      Handshake.Client_Msgs.Build_Client_Hello (S, S.HC_Ptr.all, CH_Buf, CH_Len);

      if CH_Len = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         HC_Alloc.Free (S.HC_Ptr);
         return;
      end if;

      Append_Transcript (S.HC_Ptr.all, CH_Buf (0 .. CH_Len - 1));

      Records.Build_Handshake_Record
        (Fragment  => CH_Buf (0 .. CH_Len - 1),
         Output    => S.Output,
         Bytes_Out => Rec_Out);

      if Rec_Out = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Insufficient_Buffer;
         HC_Alloc.Free (S.HC_Ptr);
      end if;
   end Init;

   --  Process a decrypted handshake message during the handshake
   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
      Msg_Type : Byte;
      Msg_Len  : N32;
      Parse_OK : Boolean;
   begin
      Result := OK;

      Handshake.Parse_Handshake_Header (Data, Msg_Type, Msg_Len, Parse_OK);
      if not Parse_OK then
         S.Last_Error := Decode_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      case Msg_Type is
         when Handshake.HT_Encrypted_Extensions =>
            --  For now, just record in transcript and move on.
            --  TODO: parse and validate extensions
            Append_Transcript (HC, Data);
            Set_State (S, Wait_Certificate);

         when Handshake.HT_Certificate_Request =>
            --  mTLS: server requests a client certificate.
            --  Record in transcript and set flag; we'll send our cert
            --  after the server's Finished message.
            Append_Transcript (HC, Data);
            HC.Cert_Request_Received := True;
            --  Stay in Wait_Certificate (server Certificate comes next)

         when Handshake.HT_Certificate =>
            Append_Transcript (HC, Data);

            --  Parse Certificate message: extract leaf + intermediates.
            --  Format (past HS header at offset 4):
            --    request_context_len(1) + context +
            --    cert_list_len(3) + entries...
            --  Each entry: cert_len(3) + cert_DER + ext_len(2) + exts
            HC.Peer_Cert_Valid := False;
            HC.Peer_Int_Count := 0;
            if Msg_Len > 4 and then N32 (Data'Length) >= 4 + Msg_Len then
               declare
                  B   : constant N32 := 4;  --  past HS header
                  --  Skip request_context (1-byte len + content)
                  Ctx_Len : constant N32 := N32 (Data (B));
                  List_Start : constant N32 := B + 1 + Ctx_Len;
                  Pos : N32;
                  Cert_Idx : Natural := 0;  --  0 = leaf, 1+ = intermediates
               begin
                  if List_Start + 3 <= N32 (Data'Length) then
                     --  cert_list length (3 bytes)
                     Pos := List_Start + 3;

                     --  Walk each certificate entry
                     while Pos + 3 <= N32 (Data'Length)
                        and then Cert_Idx <= Max_Pool_Size
                     loop
                        declare
                           C_Len : constant N32 :=
                              N32 (Data (Pos)) * 65536 +
                              N32 (Data (Pos + 1)) * 256 +
                              N32 (Data (Pos + 2));
                        begin
                           Pos := Pos + 3;
                           exit when C_Len = 0
                              or else C_Len > N32 (Max_Cert_DER)
                              or else Pos + C_Len > N32 (Data'Length);

                           if Cert_Idx = 0 then
                              --  First entry is the leaf
                              HC.Peer_Cert_DER_Len := C_Len;
                              HC.Peer_Cert_DER (0 .. C_Len - 1) :=
                                 Data (Pos .. Pos + C_Len - 1);

                              declare
                                 Cert_X : X509.Byte_Seq
                                    (0 .. X509.N32 (C_Len) - 1);
                                 P_OK : Boolean;
                              begin
                                 for I in N32 range 0 .. C_Len - 1 loop
                                    Cert_X (X509.N32 (I)) :=
                                       X509.Byte (Data (Pos + I));
                                 end loop;
                                 X509.Parse (Cert_X, HC.Peer_Cert, P_OK);
                                 HC.Peer_Cert_Valid := P_OK
                                    and then X509.Is_Valid (HC.Peer_Cert);
                              end;
                           else
                              --  Subsequent entries are intermediates
                              if HC.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx : constant Natural :=
                                       HC.Peer_Int_Count;
                                    Int_X : X509.Byte_Seq
                                       (0 .. X509.N32 (C_Len) - 1);
                                    C   : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    for I in N32 range 0 .. C_Len - 1 loop
                                       Int_X (X509.N32 (I)) :=
                                          X509.Byte (Data (Pos + I));
                                    end loop;
                                    X509.Parse (Int_X, C, P_OK);
                                    if P_OK and then X509.Is_Valid (C) then
                                       HC.Peer_Ints (Idx).Cert := C;
                                       for I in X509.N32 range
                                          0 .. X509.N32 (C_Len) - 1
                                       loop
                                          HC.Peer_Ints (Idx).DER (I) :=
                                             X509.Byte (Data (Pos + N32 (I)));
                                       end loop;
                                       HC.Peer_Ints (Idx).DER_Len :=
                                          X509.N32 (C_Len);
                                       HC.Peer_Ints (Idx).Present := True;
                                       HC.Peer_Int_Count :=
                                          HC.Peer_Int_Count + 1;
                                    end if;
                                 end;
                              end if;
                           end if;

                           Pos := Pos + C_Len;
                           Cert_Idx := Cert_Idx + 1;

                           --  Skip per-cert extensions (2-byte length)
                           exit when Pos + 2 > N32 (Data'Length);
                           declare
                              Ext_Len : constant N32 :=
                                 N32 (Data (Pos)) * 256 +
                                 N32 (Data (Pos + 1));
                           begin
                              Pos := Pos + 2 + Ext_Len;
                           end;
                        end;
                     end loop;
                  end if;
               end;
            end if;

            --  Chain validation (if trust store is configured)
            if not HC.Cfg.Skip_Verify
               and then HC.Cfg.Trust /= null
               and then HC.Cfg.Get_Time /= null
               and then HC.Peer_Cert_Valid
            then
               declare
                  Cert_DER_Len_Const : constant N32 := HC.Peer_Cert_DER_Len;
                  Cert_X : X509.Byte_Seq
                     (0 .. X509.N32 (Cert_DER_Len_Const) - 1);
                  VR : Validation_Result;
               begin
                  --  Copy peer DER to X509.Byte_Seq for Validate_Chain
                  for I in N32 range 0 .. Cert_DER_Len_Const - 1 loop
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
                     S.Last_Error := Bad_Certificate;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                     return;
                  end if;
               end;
            end if;

            Set_State (S, Wait_Certificate_Verify);

         when Handshake.HT_Certificate_Verify =>
            --  Verify CertificateVerify (RFC 8446 Section 4.4.3)
            declare
               --  Hash length depends on suite: 32 for SHA-256, 48 for SHA-384
               H_Len : constant N32 := HC.Hash_Len;
               CV_Hash : Byte_Seq (0 .. H_Len - 1);
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

               Append_Transcript (HC, Data);

               if HC.Cfg.Skip_Verify then
                  --  -k mode: skip all signature verification
                  Set_State (S, Wait_Server_Finished);
                  return;
               end if;

               if not HC.Peer_Cert_Valid then
                  S.Last_Error := Certificate_Verify_Failed;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

               --  Build the signed content (same for all algorithms):
               --  64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + hash
               declare
                  Context_Str : constant String :=
                     "TLS 1.3, server CertificateVerify";
                  Content_Len : constant N32 :=
                     64 + N32 (Context_Str'Length) + 1 + H_Len;
                  Content     : Byte_Seq (0 .. Content_Len - 1);
               begin
                  --  64 spaces
                  Content (0 .. 63) := (others => 16#20#);
                  --  Context string
                  for I in Context_Str'Range loop
                     Content (64 + N32 (I - Context_Str'First)) :=
                        Byte (Character'Pos (Context_Str (I)));
                  end loop;
                  --  Separator
                  Content (64 + N32 (Context_Str'Length)) := 16#00#;
                  --  Transcript hash
                  Content (64 + N32 (Context_Str'Length) + 1 ..
                           64 + N32 (Context_Str'Length) + H_Len) := CV_Hash;

                  --  Extract signature scheme and signature from CV message
                  --  Format: sig_scheme(2) + sig_len(2) + sig(N)
                  --  (past the 4-byte HS header)
                  if Msg_Len >= 8 then
                     declare
                        Sig_Scheme : constant Unsigned_16 :=
                           Unsigned_16 (Data (4)) * 256 +
                           Unsigned_16 (Data (5));
                        Sig_Len : constant N32 :=
                           N32 (Data (6)) * 256 + N32 (Data (7));
                        Sig_Start : constant N32 := 8;
                     begin
                        if Sig_Len > 0
                           and then Sig_Start + Sig_Len <=
                                       N32 (Data'Length)
                        then
                           declare
                              Sig : Byte_Seq (0 .. Sig_Len - 1);
                           begin
                              Sig := Data (Sig_Start ..
                                           Sig_Start + Sig_Len - 1);

                              if not Cert_Verify.Verify_Signature
                                (Data       => Content,
                                 Sig        => Sig,
                                 Cert       => HC.Peer_Cert,
                                 Sig_Scheme => Sig_Scheme)
                              then
                                 S.Last_Error := Certificate_Verify_Failed;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                           end;
                        else
                           S.Last_Error := Certificate_Verify_Failed;
                           Set_State (S, Error_State);
                           Result := Error_Alert;
                           return;
                        end if;
                     end;

                  else
                     S.Last_Error := Certificate_Verify_Failed;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                     return;
                  end if;
               end;
            end;

            Set_State (S, Wait_Server_Finished);

         when Handshake.HT_Finished =>
            --  Verify server Finished (RFC 8446 Section 4.4.4)
            --  verify_data length = Hash.length (32 for SHA-256, 48 for SHA-384)
            declare
               H_Len : constant N32 := HC.Hash_Len;
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
                     Append_Transcript (HC, Data);
                     Key_Schedule.Derive_Finished_Key_384
                       (Fin_Key, HC.Server_HS_Secret);
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
                     Pre_Hash : constant Digest := Transcript_Hash_256 (HC);
                     Fin_Key  : OKM_Seq (0 .. 31);
                     Expected : Digest;
                  begin
                     Append_Transcript (HC, Data);
                     Key_Schedule.Derive_Finished_Key
                       (Fin_Key, HC.Server_HS_Secret (0 .. 31));
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
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;
            end;

            --  Server Finished verified. Now derive application keys
            --  and send Client Finished.
            Derive_App_Keys_And_Send_Finished (S, HC, Result);

         when others =>
            --  Unknown handshake message, skip
            Append_Transcript (HC, Data);
      end case;
   end Process_Handshake_Message;

   --  mTLS: send client Certificate + CertificateVerify if requested.
   --  Called before sending Client Finished.
   procedure Send_Client_Certificate
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Enc_Out : N32;
   begin
      Result := OK;

      if not HC.Cert_Request_Received then
         return;
      end if;

      if HC.Cfg.Local = null or else not HC.Cfg.Local.Has_Identity then
         --  Server requested cert but we have none.
         --  Send empty Certificate message (allowed by RFC 8446 S.4.4.2).
         declare
            Empty_Cert : Byte_Seq (0 .. 7);
         begin
            --  HS header: type=Certificate(0x0B), length=4
            Empty_Cert (0) := Handshake.HT_Certificate;
            Empty_Cert (1) := 0;
            Empty_Cert (2) := 0;
            Empty_Cert (3) := 4;
            --  Body: context_len=0, cert_list_len=0
            Empty_Cert (4) := 0;  --  context length
            Empty_Cert (5) := 0;  --  list length (3 bytes)
            Empty_Cert (6) := 0;
            Empty_Cert (7) := 0;

            Append_Transcript (HC, Empty_Cert);
            Records.Build_Encrypted_Record
              (Plaintext  => Empty_Cert,
               Inner_Type => 16#16#,
               Keys       => HC.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);
         end;
         return;
      end if;

      --  Send our Certificate
      declare
         Nacl_Cert_Len : constant N32 := HC.Cfg.Local.NaCl_Cert_Len;
         Cert_Buf : Byte_Seq (0 .. Nacl_Cert_Len + 15);
         Cert_Len : N32;
      begin
         Handshake.Certs.Build_Certificate
           (Cert_DER => HC.Cfg.Local.NaCl_Cert_DER,
            Cert_Len => HC.Cfg.Local.NaCl_Cert_Len,
            Result   => Cert_Buf,
            Len      => Cert_Len);

         if Cert_Len > 0 then
            Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Encrypted_Record
              (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
               Inner_Type => 16#16#,
               Keys       => HC.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);
         end if;
      end;

      --  Send CertificateVerify
      if HC.Cfg.Local.Sign_Algo = Sign_Ed25519 then
         declare
            H_Len : constant N32 := HC.Hash_Len;
            CV_Hash : Byte_Seq (0 .. H_Len - 1);
         begin
            case S.Negotiated_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  CV_Hash := Transcript_Hash_384 (HC);
               when others =>
                  declare
                     H : constant Digest := Transcript_Hash_256 (HC);
                  begin
                     CV_Hash := H;
                  end;
            end case;

            declare
               CV_Buf : Byte_Seq (0 .. 523);
               CV_Len : N32;
            begin
               Handshake.Certs.Build_Certificate_Verify
                 (Transcript_Hash => CV_Hash,
                  Id              => HC.Cfg.Local.all,
                  Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                  Role            => Role_Client,
                  Random          => HC.Cfg.Random,
                  Result          => CV_Buf,
                  Len             => CV_Len);

               if CV_Len > 0 then
                  Append_Transcript (HC, CV_Buf (0 .. CV_Len - 1));
                  Records.Build_Encrypted_Record
                    (Plaintext  => CV_Buf (0 .. CV_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => HC.Client_HS,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out);
               end if;
            end;
         end;
      end if;
   end Send_Client_Certificate;

   --  After verifying server Finished, derive app keys and send client Finished
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Finished_Buf : Byte_Seq (0 .. 35);
      Finished_Len : N32;
      CCS_Out      : N32;
      Enc_Out      : N32;
      Verify_32    : Bytes_32;
      Cert_Result  : Action;
   begin
      Result := OK;

      --  mTLS: send client certificate before Finished if requested
      Send_Client_Certificate (S, HC, Cert_Result);
      if Cert_Result = Error_Alert then
         Result := Error_Alert;
         return;
      end if;

      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            TS_Hash : constant Key_Schedule.Digest_384 :=
               Transcript_Hash_384 (HC);
            Finished_Key_384 : OKM384_Seq (0 .. 47);
            Verify_48        : Bytes_48;
            Master           : Key_Schedule.Digest_384;
            Client_App_Sec   : OKM384_Seq (0 .. 47);
            Server_App_Sec   : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Finished_Key_384
              (Finished_Key_384, HC.Client_HS_Secret);

            HMAC384.HMAC_SHA_384
              (Output => Verify_48,
               M      => TS_Hash,
               K      => Byte_Seq (Finished_Key_384));

            --  Build Finished: verify_data is 48 bytes for SHA-384
            --  but Build_Finished expects Bytes_32. We need a larger variant.
            --  For now, use only first 32 bytes - wait, that's wrong.
            --  TLS 1.3 finished verify_data length = Hash.length.
            --  For SHA-384, it's 48 bytes. Let me build it manually.
            Finished_Buf := (others => 0);
            Finished_Buf (0) := Handshake.HT_Finished;
            Finished_Buf (1) := 16#00#;
            Finished_Buf (2) := 16#00#;
            Finished_Buf (3) := 16#30#;  --  48 decimal = 0x30
            --  We need a bigger buffer for 48-byte verify data
            declare
               Big_Finished : Byte_Seq (0 .. 51);  -- 4 + 48
            begin
               Big_Finished (0) := Handshake.HT_Finished;
               Big_Finished (1) := 16#00#;
               Big_Finished (2) := 16#00#;
               Big_Finished (3) := 16#30#;  --  48
               Big_Finished (4 .. 51) := Verify_48;

               Records.Build_CCS_Record (S.Output, CCS_Out);
               Records.Build_Encrypted_Record
                 (Plaintext  => Big_Finished,
                  Inner_Type => 16#16#,
                  Keys       => HC.Client_HS,
                  Output     => S.Output,
                  Bytes_Out  => Enc_Out);
            end;

            if Enc_Out = 0 then
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret_384
              (Master, Key_Schedule.Digest_384 (HC.Handshake_Secret));

            Key_Schedule.Derive_App_Traffic_Secrets_384
              (Client_App_Sec, Server_App_Sec, Master, TS_Hash);

            HC.Master_Secret := Bytes_48 (Master);

            --  Set app traffic keys
            HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
            Set_Traffic_Keys (S.Client_App,
                              Bytes_48 (Byte_Seq (Client_App_Sec)),
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_App,
                              Bytes_48 (Byte_Seq (Server_App_Sec)),
                              S.Negotiated_Suite);
         end;
      when others =>
         --  SHA-256 suites
         declare
            TS_Hash : constant Digest := Transcript_Hash_256 (HC);
            Client_Finished_Key : OKM_Seq (0 .. 31);
            Client_Verify       : Digest;
            Master              : Digest;
            Client_App_Sec      : OKM_Seq (0 .. 31);
            Server_App_Sec      : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Finished_Key
              (Client_Finished_Key, HC.Client_HS_Secret (0 .. 31));

            HMAC_SHA_256
              (Output => Client_Verify,
               M      => TS_Hash,
               K      => Byte_Seq (Client_Finished_Key));

            Handshake.Build_Finished
              (Client_Verify, Finished_Buf, Finished_Len);

            Records.Build_CCS_Record (S.Output, CCS_Out);
            Records.Build_Encrypted_Record
              (Plaintext  => Finished_Buf (0 .. Finished_Len - 1),
               Inner_Type => 16#16#,
               Keys       => HC.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);

            if Enc_Out = 0 then
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret
              (Master, Digest (HC.Handshake_Secret (0 .. 31)));

            Key_Schedule.Derive_App_Traffic_Secrets
              (Client_App_Sec, Server_App_Sec,
               Master, TS_Hash);

            HC.Master_Secret := (others => 0);
            HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));

            declare
               CS48 : Bytes_48 := (others => 0);
               SS48 : Bytes_48 := (others => 0);
            begin
               CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
               SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
               Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);
            end;
         end;
      end case;

      Set_State (S, Client_Finished_Sent);
      Result := Has_Output;
   end Derive_App_Keys_And_Send_Finished;

   --  Advance handshake states (called with dereferenced HC_Ptr)
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      case S.State is
         when Client_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Set_State (S, Wait_Server_Hello);
               Result := Need_Input;
            end if;

         when Wait_Server_Hello =>
            if Input_Available (S) = 0 then
               Result := Need_Input;
               return;
            end if;

            --  Parse record from input
            declare
               Rec : Records.Parse_Result;
            begin
               Records.Parse_Record_Header
                 (Data  => S.Input.Data (S.Input.Read_Pos ..
                                          S.Input.Write_Pos - 1),
                  Avail => Available (S.Input),
                  Result => Rec);

               if not Rec.OK then
                  Result := Need_Input;
                  return;
               end if;

               case Rec.Content is
                  when Records.Content_Handshake =>
                     declare
                        Frag_Len : constant N32 := Rec.Fragment_Len;
                        Frag_Start : constant N32 :=
                           S.Input.Read_Pos + Rec.Fragment_Pos;
                        Frag : constant Byte_Seq :=
                           S.Input.Data (Frag_Start ..
                                          Frag_Start + Frag_Len - 1);
                        Parse_OK : Boolean;
                     begin
                        Handshake.Client_Msgs.Parse_Server_Hello (S, HC, Frag, Parse_OK);

                        if not Parse_OK then
                           --  RFLX parser may fail on TLS 1.2 ServerHello
                           --  (empty session_id). Try manual parse.
                           Handshake.TLS12.Parse_Server_Hello_12
                             (S, HC, Frag, Parse_OK);
                        end if;

                        if not Parse_OK then
                           S.Last_Error := Handshake_Failure;
                           Set_State (S, Error_State);
                           Result := Error_Alert;
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           return;
                        end if;

                        --  Add ServerHello to transcript
                        Append_Transcript (HC, Frag);

                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;

                        if HC.Version = TLS_1_3 then
                           --  TLS 1.3: derive handshake keys
                           Derive_Handshake_Keys (S, HC);
                           Set_State (S, Wait_Encrypted_Extensions);
                        else
                           --  TLS 1.2: move to Wait_Server_Finished
                           --  which will be dispatched to
                           --  Client.TLS12.Advance_Handshake_12
                           --  on the next Advance call.
                           Set_State (S, Wait_Server_Finished);
                        end if;
                        Result := OK;
                     end;

                  when others =>
                     --  Skip unexpected record
                     S.Input.Read_Pos :=
                        S.Input.Read_Pos + Rec.Record_Len;
                     Result := OK;
               end case;
            end;

         when Wait_Encrypted_Extensions
            | Wait_Certificate
            | Wait_Certificate_Verify
            | Wait_Server_Finished =>
            --  All these states expect encrypted handshake records
            Process_Encrypted_Handshake (S, HC, Result);

         when Client_Finished_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               --  Derive resumption master secret before HC is freed
               case S.Negotiated_Suite is
                  when Suite_AES_256_GCM_SHA384 =>
                     declare
                        use SPARKTLS.HKDF384;
                        Full_Hash : constant Key_Schedule.Digest_384 :=
                           Transcript_Hash_384 (HC);
                        Res : OKM384_Seq (0 .. 47);
                     begin
                        Key_Schedule.Derive_Resumption_Master_Secret_384
                          (Res, HC.Master_Secret (0 .. 47), Full_Hash);
                        S.Res_Master := Bytes_48 (Res);
                        S.Res_Master_Len := 48;
                     end;
                  when others =>
                     declare
                        Full_Hash : constant Digest :=
                           Transcript_Hash_256 (HC);
                        Res : OKM_Seq (0 .. 31);
                     begin
                        Key_Schedule.Derive_Resumption_Master_Secret
                          (Res,
                           Digest (HC.Master_Secret (0 .. 31)),
                           Full_Hash);
                        S.Res_Master := (others => 0);
                        for I in N32 range 0 .. 31 loop
                           S.Res_Master (I) := Res (I);
                        end loop;
                        S.Res_Master_Len := 32;
                     end;
               end case;

               Set_State (S, Connected);
               Result := Handshake_Done;
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with SPARK_Mode => Off
   is
   begin
      case S.State is
         when Connected =>
            if S.Negotiated_Version = TLS_1_2 then
               SPARKTLS.Client.TLS12.Process_Connected_12 (S, Result);
            else
               Process_Connected (S, Result);
            end if;

         when Closing =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Set_State (S, Closed);
               Result := Shutdown;
            end if;

         when others =>
            if S.HC_Ptr = null then
               S.Last_Error := Internal_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            --  Version dispatch for handshake states.
            --  HC.Version is set after Parse_Server_Hello.
            --  Before ServerHello, Version defaults to TLS_1_3
            --  (ClientHello is version-agnostic).
            if S.HC_Ptr.Version = TLS_1_2
               and S.State /= Client_Hello_Sent
               and S.State /= Wait_Server_Hello
            then
               SPARKTLS.Client.TLS12.Advance_Handshake_12
                 (S, S.HC_Ptr.all, Result);
            else
               Advance_Handshake (S, S.HC_Ptr.all, Result);
            end if;

            if S.State = Connected or S.State = Error_State then
               S.Peer_Cert_Valid := S.HC_Ptr.Peer_Cert_Valid;
               --  Zero key material before freeing HC
               S.HC_Ptr.Shared_Secret := (others => 0);
               S.HC_Ptr.Client_HS_Secret := (others => 0);
               S.HC_Ptr.Server_HS_Secret := (others => 0);
               S.HC_Ptr.Handshake_Secret := (others => 0);
               S.HC_Ptr.Master_Secret := (others => 0);
               S.HC_Ptr.Master_Secret_12 := (others => 0);
               Free_Byte_Seq (S.HC_Ptr.Reasm_Buf);
               HC_Alloc.Free (S.HC_Ptr);
            end if;
      end case;
   end Advance;

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
            --  ChaCha20-Poly1305: 32-byte key
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
            Key_Schedule.Derive_Early_Secret_384 (Early, No_PSK);
            --  Use full 48 bytes if P-384 ECDHE, else first 32
            if HC.Use_P384_KE then
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, Byte_Seq (HC.Shared_Secret), Early);
            else
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, HC.Shared_Secret (0 .. 31), Early);
            end if;

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
         --  SHA-256 suites (0x1301, 0x1303)
         declare
            Hello_Hash : Digest := Transcript_Hash_256 (HC);
            Early      : Digest;
            HS_Secret  : Digest;
            No_PSK     : Bytes_32 := (others => 0);
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret (Early, No_PSK);
            --  Pass full shared secret: 48 bytes for P-384, 32 for others
            if HC.Use_P384_KE then
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, Byte_Seq (HC.Shared_Secret), Early);
            else
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, HC.Shared_Secret (0 .. 31), Early);
            end if;

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

   --  Process encrypted handshake records (post-ServerHello)
   procedure Process_Encrypted_Handshake
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
        (Data  => S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Write_Pos - 1),
         Avail => Available (S.Input),
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
            --  This is an encrypted handshake record
            declare
               Frag_Len : constant N32 := Rec.Fragment_Len;
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               --  Copy to 0-indexed locals (Decrypt_Record requires
               --  0-indexed inputs)
               Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Frag_Len - 1);
               Hdr        : Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Frag_Len <= Records.Tag_Size then
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  return;
               end if;

               Records.Decrypt_Record
                 (Encrypted  => Encrypted,
                  Record_Hdr => Hdr,
                  Keys       => HC.Server_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  S.Last_Error := Bad_Record_MAC;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

               --  Inner type should be handshake (0x16)
               --  A single encrypted record may contain multiple
               --  handshake messages, or a single message may span
               --  multiple records. Use Reasm_Buf for cross-record
               --  reassembly.
               if Inner_Type = 16#16# then
                  declare
                     Pos : N32 := 0;
                     Max_HS_Msg : constant N32 := 131072;
                  begin
                     --  If we have a partial message from a previous
                     --  record, continue filling the reassembly buffer.
                     if HC.Reasm_Need > 0 and HC.Reasm_Buf /= null then
                        declare
                           Remaining : constant N32 :=
                              HC.Reasm_Need - HC.Reasm_Len;
                           Copy_Len  : constant N32 :=
                              N32'Min (Plain_Len, Remaining);
                        begin
                           if HC.Reasm_Len + Copy_Len <=
                                 N32 (HC.Reasm_Buf'Length)
                           then
                              HC.Reasm_Buf
                                (HC.Reasm_Len ..
                                 HC.Reasm_Len + Copy_Len - 1) :=
                                 Plaintext (0 .. Copy_Len - 1);
                              HC.Reasm_Len := HC.Reasm_Len + Copy_Len;
                           end if;
                           Pos := Copy_Len;
                        end;

                        if HC.Reasm_Len >= HC.Reasm_Need then
                           --  Full message reassembled
                           declare
                              Reasm_Need_Const : constant N32 := HC.Reasm_Need;
                              Full : constant Byte_Seq :=
                                 HC.Reasm_Buf (0 .. Reasm_Need_Const - 1);
                           begin
                              Process_Handshake_Message
                                (S, HC, Full, Result);
                           end;
                           Free_Byte_Seq (HC.Reasm_Buf);
                           HC.Reasm_Len := 0;
                           HC.Reasm_Need := 0;
                           if Result = Error_Alert then
                              Pos := Plain_Len;  --  skip rest
                           end if;
                        else
                           --  Still need more data
                           Pos := Plain_Len;  --  consumed all
                        end if;
                     end if;

                     --  Process complete messages in this record
                     while Pos + 4 <= Plain_Len loop
                        declare
                           HS_Len : constant N32 :=
                              N32 (Plaintext (Pos + 1)) * 65536 +
                              N32 (Plaintext (Pos + 2)) * 256 +
                              N32 (Plaintext (Pos + 3));
                           Msg_Total : constant N32 := 4 + HS_Len;
                           Msg_End   : constant N32 := Pos + Msg_Total;
                        begin
                           if Msg_Total > Max_HS_Msg then
                              S.Last_Error := Decode_Error;
                              Set_State (S, Error_State);
                              Result := Error_Alert;
                              exit;
                           end if;

                           if Msg_End > Plain_Len then
                              --  Message spans into next record.
                              --  Start reassembly.
                              HC.Reasm_Buf := new Byte_Seq'
                                 (0 .. Msg_Total - 1 => 0);
                              HC.Reasm_Need := Msg_Total;
                              declare
                                 Avail : constant N32 :=
                                    Plain_Len - Pos;
                              begin
                                 HC.Reasm_Buf (0 .. Avail - 1) :=
                                    Plaintext (Pos .. Plain_Len - 1);
                                 HC.Reasm_Len := Avail;
                              end;
                              exit;  --  wait for next record
                           end if;

                           --  Complete message — process it
                           declare
                              Msg_Copy : Byte_Seq
                                 (0 .. Msg_Total - 1);
                           begin
                              Msg_Copy :=
                                 Plaintext (Pos .. Msg_End - 1);
                              Process_Handshake_Message
                                (S, HC, Msg_Copy, Result);
                           end;
                           if Result = Error_Alert then
                              exit;
                           end if;
                           Pos := Msg_End;
                        end;
                     end loop;
                  end;
               elsif Inner_Type = 16#15# then
                  --  Alert
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               else
                  Result := OK;
               end if;
            end;

         when others =>
            --  Skip unexpected
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Encrypted_Handshake;

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
        (Data  => S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Write_Pos - 1),
         Avail => Available (S.Input),
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
         Frag_Len : constant N32 := Rec.Fragment_Len;
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
            S.Input.Data (Frag_Start ..
                           Frag_Start + Frag_Len - 1);
         Hdr        : Byte_Seq (0 .. 4) :=
            S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Frag_Len <= Records.Tag_Size then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            return;
         end if;

         Records.Decrypt_Record
           (Encrypted  => Encrypted,
            Record_Hdr => Hdr,
            Keys       => S.Server_App,
            Plaintext  => Plaintext,
            Plain_Len  => Plain_Len,
            Inner_Type => Inner_Type,
            Valid      => Dec_Valid);

         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not Dec_Valid then
            S.Last_Error := Bad_Record_MAC;
            Set_State (S, Error_State);
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
               --  Post-handshake message
               if Plain_Len >= 4
                  and then Plaintext (0) = 16#04#  --  NewSessionTicket
               then
                  --  Parse NewSessionTicket:
                  --    type(1) + len(3) + lifetime(4) + age_add(4) +
                  --    nonce_len(1) + nonce(var) + ticket_len(2) + ticket(var)
                  declare
                     P : N32 := 4;  --  skip handshake header
                  begin
                     if Plain_Len >= 15 then
                        declare
                           Lifetime : constant Unsigned_32 :=
                              Unsigned_32 (Plaintext (P)) * 2**24 +
                              Unsigned_32 (Plaintext (P + 1)) * 2**16 +
                              Unsigned_32 (Plaintext (P + 2)) * 2**8 +
                              Unsigned_32 (Plaintext (P + 3));
                           Age_Add  : constant Unsigned_32 :=
                              Unsigned_32 (Plaintext (P + 4)) * 2**24 +
                              Unsigned_32 (Plaintext (P + 5)) * 2**16 +
                              Unsigned_32 (Plaintext (P + 6)) * 2**8 +
                              Unsigned_32 (Plaintext (P + 7));
                           Nonce_Len : constant N32 :=
                              N32 (Plaintext (P + 8));
                        begin
                           P := P + 9;
                           if Nonce_Len > 0
                              and then P + Nonce_Len + 2 <= Plain_Len
                           then
                              declare
                                 Nonce : Byte_Seq (0 .. Nonce_Len - 1);
                                 Tick_Len : N32;
                              begin
                                 Nonce := Plaintext (P .. P + Nonce_Len - 1);
                                 P := P + Nonce_Len;
                                 Tick_Len :=
                                    N32 (Plaintext (P)) * 256 +
                                    N32 (Plaintext (P + 1));
                                 P := P + 2;
                                 if P + Tick_Len <= Plain_Len
                                    and then Tick_Len <= Max_Ticket_Len
                                 then
                                    --  Derive PSK from res_master + nonce
                                    S.Ticket.Ticket (0 .. Tick_Len - 1) :=
                                       Plaintext (P .. P + Tick_Len - 1);
                                    S.Ticket.Ticket_Len := Tick_Len;
                                    S.Ticket.Lifetime := Lifetime;
                                    S.Ticket.Age_Add := Age_Add;
                                    S.Ticket.Suite := S.Negotiated_Suite;

                                    case S.Negotiated_Suite is
                                       when Suite_AES_256_GCM_SHA384 =>
                                          declare
                                             use SPARKTLS.HKDF384;
                                             PSK_Out : OKM384_Seq (0 .. 47);
                                          begin
                                             Key_Schedule.Derive_PSK_384
                                               (PSK_Out,
                                                S.Res_Master,
                                                Nonce);
                                             S.Ticket.PSK :=
                                                Bytes_48 (PSK_Out);
                                             S.Ticket.PSK_Len := 48;
                                          end;
                                       when others =>
                                          declare
                                             PSK_Out : OKM_Seq (0 .. 31);
                                          begin
                                             Key_Schedule.Derive_PSK
                                               (PSK_Out,
                                                S.Res_Master (0 .. 31),
                                                Nonce);
                                             S.Ticket.PSK := (others => 0);
                                             for I in N32 range 0 .. 31 loop
                                                S.Ticket.PSK (I) :=
                                                   PSK_Out (I);
                                             end loop;
                                             S.Ticket.PSK_Len := 32;
                                          end;
                                    end case;

                                    S.Ticket.Valid := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end;
               end if;
               Result := OK;

            when 16#15# =>
               --  Alert
               if Plain_Len >= 2 and then Plaintext (1) = 0 then
                  --  close_notify
                  Set_State (S, Closing);
                  Result := Shutdown;
               else
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
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
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Encrypted_Record_12
           (Plaintext    => Plaintext,
            Content_Type => 16#17#,
            Keys         => S.Client_App,
            Implicit_IV  => S.Client_IV_12,
            Seq_Num      => S.Client_Seq_12,
            Output       => S.Output,
            Bytes_Out    => Enc_Out);
      else
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext,
            Inner_Type => 16#17#,
            Keys       => S.Client_App,
            Output     => S.Output,
            Bytes_Out  => Enc_Out);
      end if;

      if Enc_Out > 0 then
         Bytes_Written := N32 (Plaintext'Length);
      else
         Bytes_Written := 0;
      end if;
   end Write_Plaintext;

   procedure Close_Notify (S : in out Session) is
      Alert_Out : N32;
   begin
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Alert_Record_12
           (Level       => 1,
            Desc        => 0,
            Keys        => S.Client_App,
            Implicit_IV => S.Client_IV_12,
            Seq_Num     => S.Client_Seq_12,
            Output      => S.Output,
            Bytes_Out   => Alert_Out);
      else
         Records.Build_Alert_Record
           (Level     => 1,
            Desc      => 0,
            Keys      => S.Client_App,
            Output    => S.Output,
            Bytes_Out => Alert_Out);
      end if;
      Set_State (S, Closing);
   end Close_Notify;

end SPARKTLS.Client;
