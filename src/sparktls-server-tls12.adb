with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;

package body SPARKTLS.Server.TLS12 with
   SPARK_Mode => Off
is
   use Handshake.TLS12;

   function Alert_Desc (E : Error_Code) return Byte is
     (case E is
         when Unexpected_Message    => 10, when Bad_Record_MAC   => 20,
         when Record_Overflow       => 22, when Handshake_Failure => 40,
         when Bad_Certificate       => 42, when Certificate_Expired => 45,
         when Certificate_Verify_Failed => 51, when Decode_Error  => 50,
         when Illegal_Parameter     => 47, when Protocol_Version  => 70,
         when Internal_Error    => 80,
         when Insufficient_Buffer   => 80, when Unsupported_Cipher_Suite => 40,
         when No_Error              => 80);

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      S.State := Error_State;
      Records.Build_Plaintext_Alert (2, Alert_Desc (Err), S.Output, Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Alert_And_Error;

   procedure Append_Transcript (HC : in out Handshake_Context; Data : Byte_Seq)
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len + Len <= HC.Transcript'Length then
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
      Rec_Out : N32;
   begin
      Result := OK;

      if HC.Client_Has_X25519 then
         HC.Selected_Group := Group_X25519;
      elsif HC.Client_Has_P256 then
         HC.Selected_Group := Group_Secp256r1;
      elsif HC.Client_Has_P384 then
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

      HC.Negotiated_Sig_Algo := 16#0804#;  -- RSA-PSS-SHA256

      case HC.Selected_Group is
         when Group_X25519    => Gen_Random (Byte_Seq (HC.Local_SK));
         when Group_Secp256r1 => Gen_Random (Byte_Seq (HC.P256_Local_SK));
         when Group_Secp384r1 => Gen_Random (Byte_Seq (HC.P384_Local_SK));
         when others => null;
      end case;

      --  1. ServerHello
      declare
         SH : Byte_Seq (0 .. Max_Server_Hello_12 - 1); L : N32;
      begin
         Build_Server_Hello_12 (S, HC, SH, L);
         if L = 0 then
            Send_Alert_And_Error (S, Internal_Error, Result); return;
         end if;
         Append_Transcript (HC, SH (0 .. L - 1));
         Records.Build_Handshake_Record (SH (0 .. L - 1), S.Output, Rec_Out);
      end;

      --  2. Certificate (TLS 1.2 format)
      declare
         CB : Byte_Seq (0 .. 8191); CL : N32;
      begin
         Build_Certificate_Chain_12 (HC.Cfg.Local.all, CB, CL);
         if CL > 0 then
            Append_Transcript (HC, CB (0 .. CL - 1));
            Records.Build_Handshake_Record (CB (0 .. CL - 1), S.Output, Rec_Out);
         end if;
      end;

      --  3. ServerKeyExchange
      declare
         SK : Byte_Seq (0 .. Max_Server_Key_Exchange - 1); SL : N32;
      begin
         Build_Server_Key_Exchange (HC, HC.Cfg.Local.all, Gen_Random, SK, SL);
         if SL > 0 then
            Append_Transcript (HC, SK (0 .. SL - 1));
            Records.Build_Handshake_Record (SK (0 .. SL - 1), S.Output, Rec_Out);
         end if;
      end;

      --  4. ServerHelloDone
      declare
         SD : Byte_Seq (0 .. 3); DL : N32;
      begin
         Build_Server_Hello_Done (SD, DL);
         Append_Transcript (HC, SD (0 .. DL - 1));
         Records.Build_Handshake_Record (SD (0 .. DL - 1), S.Output, Rec_Out);
      end;

      S.State := Server_Hello_Sent;
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
      CK : Byte_Seq (0 .. Key_Len - 1) := (others => 0);
      SK : Byte_Seq (0 .. Key_Len - 1) := (others => 0);
      CI : Byte_Seq (0 .. 3) := (others => 0);
      SI : Byte_Seq (0 .. 3) := (others => 0);
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

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;

      declare
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Frag : Byte_Seq renames S.Input.Data (FS .. FS + Rec.Fragment_Len - 1);
         MT : Byte; ML : N32; POK : Boolean;
      begin
         Handshake.Parse_Handshake_Header (Frag, MT, ML, POK);
         if not POK or MT /= HT_Client_Key_Exchange then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Unexpected_Message, Result);
            return;
         end if;

         declare
            BS : constant N32 := Frag'First + 4;
            Body_Data : Byte_Seq (0 .. ML - 1);
            CKE_OK : Boolean;
         begin
            if ML > 0 and then 4 + ML <= Rec.Fragment_Len then
               Body_Data := Frag (BS .. BS + ML - 1);
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

      --  Compute ECDHE shared secret
      declare
         SS_OK : Boolean := False;
      begin
         case HC.Selected_Group is
            when Group_X25519 =>
               HC.Shared_Secret (0 .. 31) :=
                  SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
               SS_OK := True;
            when Group_Secp256r1 =>
               declare
                  use SPARKTLS.P256.Point;
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
                  SPARKTLS.P384.Point.P384_ECDHE
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
   is begin
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
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         Hdr : Byte_Seq (0 .. 4);
         Plaintext : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         PL : N32; DV : Boolean;
      begin
         for I in N32 range 0 .. Rec.Fragment_Len - 1 loop
            Encrypted (I) := S.Input.Data (FS + I);
         end loop;
         for I in N32 range 0 .. 4 loop
            Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
         end loop;

         if Rec.Fragment_Len < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
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
            MT : constant Byte := Plaintext (0);
            ML : constant N32 := N32 (Plaintext (1)) * 65536 +
                                 N32 (Plaintext (2)) * 256 +
                                 N32 (Plaintext (3));
         begin
            if MT /= HT_Finished then
               Send_Alert_And_Error (S, Unexpected_Message, Result); return;
            end if;
            if ML /= Finished_Verify_Len or PL < 4 + Finished_Verify_Len then
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

      --  Send server CCS
      declare CCS_Out : N32;
      begin Records.Build_CCS_Record (S.Output, CCS_Out); end;

      --  Build and send encrypted server Finished
      declare
         FB : Byte_Seq (0 .. Finished_12_Total_Len - 1); FL : N32;
         TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest; EO : N32;
      begin
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

         Build_Encrypted_Record_12 (FB (0 .. FL - 1), 16#16#, S.Server_App,
                                     HC.Server_Write_IV_12, HC.Server_Seq_12,
                                     S.Output, EO);
      end;

      --  Copy TLS 1.2 state to Session
      S.Negotiated_Version := TLS_1_2;
      S.Client_IV_12 := HC.Client_Write_IV_12;
      S.Server_IV_12 := HC.Server_Write_IV_12;
      S.Client_Seq_12 := HC.Client_Seq_12;
      S.Server_Seq_12 := HC.Server_Seq_12;

      S.State := Connected;
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
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         Hdr : Byte_Seq (0 .. 4);
         Plaintext : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         PL : N32; DV : Boolean;
      begin
         for I in N32 range 0 .. Rec.Fragment_Len - 1 loop
            Encrypted (I) := S.Input.Data (FS + I);
         end loop;
         for I in N32 range 0 .. 4 loop
            Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
         end loop;

         if Rec.Fragment_Len < Explicit_Nonce_Len + GCM_Tag_Len + 1 then
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
               if PL > 0 and then S.App_Data_Len + PL <= S.App_Data'Length then
                  S.App_Data (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                     Plaintext (0 .. PL - 1);
                  S.App_Data_Len := S.App_Data_Len + PL;
                  Result := Plaintext_Ready;
               else
                  Result := OK;
               end if;

            when Records.Content_Alert =>
               if PL >= 2 and then Plaintext (1) = 0 then
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
   end Process_Connected_12;

end SPARKTLS.Server.TLS12;
