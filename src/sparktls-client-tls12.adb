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
with SPARKTLS.Cert_Verify;       use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;
with X509;
use type X509.Algorithm_ID;

package body SPARKTLS.Client.TLS12 with
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
      else
         --  RFC 5246 §8.1: Standard master secret
         --  master_secret = PRF(pms, "master secret", CR || SR)
         Key_Schedule_12.Derive_Master_Secret_12
           (HC.Master_Secret_12,
            HC.Shared_Secret (0 .. Shared_Len - 1),
            HC.Client_Random, HC.Server_Random, Use_384);
      end if;

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
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input; return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if not Rec.OK then
         Result := Need_Input; return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      declare
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Frag_Len : constant N32 := Rec.Fragment_Len;
         Msg_Type : Byte; Msg_Len : N32; Parse_OK : Boolean;
         Max_HS_Msg : constant N32 := 131072;
      begin
         --  If reassembly in progress, append this fragment
         if HC.Reasm_Need > 0 and then HC.Reasm_Buf /= null then
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
            --  Fresh record — parse handshake header
            declare
               Frag : Byte_Seq renames
                  S.Input.Data (FS .. FS + Frag_Len - 1);
            begin
               Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);
            end;
            if not Parse_OK then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
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
               Result := OK; return;  --  need more fragments
            end if;
         end if;

         --  At this point we have a complete handshake message.
         --  Ensure we have a uniform Reasm_Buf reference:
         --  for single-record messages, move data into Reasm_Buf too.
         if HC.Reasm_Buf = null or HC.Reasm_Need = 0 then
            HC.Reasm_Buf := new Byte_Seq'(0 .. Frag_Len - 1 => 0);
            HC.Reasm_Buf.all :=
               S.Input.Data (FS .. FS + Frag_Len - 1);
            HC.Reasm_Need := Frag_Len;
            HC.Reasm_Len := Frag_Len;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         end if;

         declare
            RN : constant N32 := HC.Reasm_Need;
            Frag : constant Byte_Seq :=
               HC.Reasm_Buf (0 .. RN - 1);
         begin

         case Msg_Type is
            when 16#0B# =>
               --  Certificate (RFC 5246 §7.4.2)
               --  TLS 1.2 format: cert_list_len(3) || {cert_len(3) || cert}*
               --  No context byte, no per-cert extensions.
               HC.Peer_Cert_Valid := False;
               HC.Peer_Int_Count := 0;

               declare
                  B   : constant N32 := Frag'First + 4;  --  past HS header
                  Pos : N32;
                  Cert_Idx : Natural := 0;
               begin
                  if Msg_Len > 3 and then B + 3 <= Frag'Last then
                     Pos := B + 3;  --  skip cert_list_len

                     while Pos + 3 <= Frag'Last
                        and then Cert_Idx <= Max_Pool_Size
                     loop
                        declare
                           C_Len : constant N32 :=
                              N32 (Frag (Pos)) * 65536 +
                              N32 (Frag (Pos + 1)) * 256 +
                              N32 (Frag (Pos + 2));
                        begin
                           Pos := Pos + 3;
                           exit when C_Len = 0
                              or else C_Len > N32 (Max_Cert_DER)
                              or else Pos + C_Len - 1 > Frag'Last;

                           if Cert_Idx = 0 then
                              --  Leaf certificate
                              HC.Peer_Cert_DER_Len := C_Len;
                              for I in N32 range 0 .. C_Len - 1 loop
                                 HC.Peer_Cert_DER (I) := Frag (Pos + I);
                              end loop;
                              declare
                                 Cert_X : X509.Byte_Seq
                                    (0 .. X509.N32 (C_Len) - 1) := (others => 0);
                                 P_OK : Boolean;
                              begin
                                 for I in N32 range 0 .. C_Len - 1 loop
                                    Cert_X (X509.N32 (I)) :=
                                       X509.Byte (Frag (Pos + I));
                                 end loop;
                                 X509.Parse (Cert_X, HC.Peer_Cert, P_OK);
                                 HC.Peer_Cert_Valid := P_OK
                                    and then X509.Is_Valid (HC.Peer_Cert);
                              end;
                           else
                              --  Intermediate certificates
                              if HC.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx : constant Natural :=
                                       HC.Peer_Int_Count;
                                    Int_X : X509.Byte_Seq
                                       (0 .. X509.N32 (C_Len) - 1) := (others => 0);
                                    C   : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    for I in N32 range 0 .. C_Len - 1 loop
                                       Int_X (X509.N32 (I)) :=
                                          X509.Byte (Frag (Pos + I));
                                    end loop;
                                    X509.Parse (Int_X, C, P_OK);
                                    if P_OK and then X509.Is_Valid (C) then
                                       HC.Peer_Ints (Idx).Cert := C;
                                       for I in X509.N32 range
                                          0 .. X509.N32 (C_Len) - 1
                                       loop
                                          HC.Peer_Ints (Idx).DER (I) :=
                                             X509.Byte (Frag (Pos + N32 (I)));
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
                           --  TLS 1.2: no per-cert extensions
                        end;
                     end loop;
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

            when HT_Server_Key_Exchange =>
               --  Parse SKE: extract ECDHE params + verify signature.
               if Msg_Len = 0 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
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
               --  End of server flight. Now:
               --  1. Compute ECDHE shared secret
               --  2. Derive keys
               --  3. Send CKE + CCS + Finished
               Append_Transcript (HC, Frag);

               --  Generate ECDHE keypair + compute shared secret
               declare
                  Gen : constant Random_Bytes_Fn := HC.Cfg.Random;
                  SS_OK : Boolean := False;
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
                           end if;
                        end;
                     when others => null;
                  end case;

                  if not SS_OK then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
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

                  --  Derive keys (uses transcript up to CKE)
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

            when others =>
               --  Unknown message type — skip
               Result := OK;
         end case;

         --  Free the reassembly buffer
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0;
         HC.Reasm_Need := 0;
         end;
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

      if not Rec.OK then Result := Need_Input; return; end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         if Rec.Fragment_Len = 1 then
            HC.CCS_Received := True;
            Result := OK;
         else
            Send_Alert_And_Error (S, Unexpected_Message, Result);
         end if;
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
   is
      use Records.TLS12;
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

      if not Rec.OK then Result := Need_Input; return; end if;

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

         Decrypt_Record_12 (Encrypted, Hdr, S.Server_App,
                            HC.Server_Write_IV_12, HC.Server_Seq_12,
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
            if Msg_Type /= HT_Finished or Msg_Len /= Finished_Verify_Len
               or PL < 4 + Finished_Verify_Len
            then
               Send_Alert_And_Error (S, Decode_Error, Result); return;
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

               --  Constant-time comparison (prevents timing attacks)
               declare
                  Received : constant Verify_Data_12 :=
                     Verify_Data_12
                       (Plaintext (4 .. 4 + Finished_Verify_Len - 1));
               begin
                  if not Equal (Byte_Seq (Received),
                                Byte_Seq (Exp))
                  then
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
            end;
         end;
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
         --  Reject records exceeding the TLS 1.2 max ciphertext size
         --  (matches Decrypt_Record_12's Pre); Parse_Record_Header allows
         --  larger via the looser Max_Record_Overhead bound.
         if Frag_Len >= Max_Record_Plaintext + TLS12_Record_Overhead then
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

            if Frag_Len < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Result := OK; return;
            end if;

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
                  if PL >= 2 and then Plaintext (1) = 0 then
                     --  Runtime check: prover can't carry S.State through
                     --  the prior S-field updates without a much heavier
                     --  contract. Connected→Closing is the only valid
                     --  transition we expect here.
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  else
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  end if;
               when others =>
                  Result := OK;
            end case;
         end;
      end;
   end Process_Connected_12;

end SPARKTLS.Client.TLS12;
