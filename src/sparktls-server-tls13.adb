with Interfaces;                    use Interfaces;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256; use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;            use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HKDF;           use SPARKTLSCrypto.HKDF;

with SPARKTLSCrypto.Ed25519;
with SPARKTLS_Reassembly;  use SPARKTLS_Reassembly;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;     use SPARKTLS.Records;
with SPARKTLS.Cert_Verify; use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS13;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Update;
with X509;
use type X509.Algorithm_ID;
use type X509.Certificate;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;
with SPARKTLS.Ticket_Cache;

with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA384;

package body SPARKTLS.Server.TLS13
  with SPARK_Mode => On
is
   pragma Unevaluated_Use_Of_Old (Allow);

   function Server_Active (S : Session) return Boolean
   is (S.Role = Role_Server and then S.State not in Idle | Closing | Closed | Error_State)
   with Ghost;

   procedure Complete_Client_Hello_Retry
     (S                      : in out Session;
      D                      : in out SPARKTLS.HS_Pool.HS_Data;
      Msg                    : in Byte_Seq;
      Consume_Current_Record : in Boolean;
      Record_Len             : in N32;
      Ready_To_Build         : out Boolean;
      Result                 : out Action)
   with
     Pre =>
       Server_Active (S)
       and then S.Version = TLS_1_3
       and then S.State = Wait_Client_Hello_Retry
       and then S.Role = Role_Server
       and then Msg'First = 0
       and then Msg'Last <= N32 (Max_HS_Msg) - 1
       and then (if Consume_Current_Record
                 then
                   Record_Len <= Available (S.Input)
                   and then S.Input.Read_Pos <= N32'Last - Record_Len),
     Post =>
       (if Ready_To_Build
        then
          Server_Active (S)
          and then S.Version = TLS_1_3
          and then S.State = Wait_Client_Hello_Retry
          and then S.Role = Role_Server
          and then Result = OK);

   procedure Validate_Client_Hello_Retry
     (S     : in out Session;
      D     : in out SPARKTLS.HS_Pool.HS_Data;
      Msg   : in Byte_Seq;
      Valid : out Boolean)
   with
     Pre =>
       Server_Active (S)
       and then S.Version = TLS_1_3
       and then S.State = Wait_Client_Hello_Retry
       and then S.Role = Role_Server
       and then Msg'First = 0
       and then Msg'Length > 0
       and then Msg'Last <= N32 (Max_HS_Msg) - 1,
     Post =>
       Server_Active (S)
       and then S.State = Wait_Client_Hello_Retry
       and then S.Role = Role_Server
       and then S.Input.Read_Pos = S.Input.Read_Pos'Old
       and then S.Input.Write_Pos = S.Input.Write_Pos'Old
       and then S.Version = TLS_1_3;

   procedure Build_Server_Flight_After_Client_Hello_Retry
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action)
   with
     Pre =>
       Server_Active (S)
       and then S.Version = TLS_1_3
       and then S.State = Wait_Client_Hello_Retry
       and then S.Role = Role_Server;
   procedure Handle_Client_Hello_Retry
     (S      : in out Server_Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Result : out Action)
      --  Same shape as Handle_Wait_Client_Hello: without a state Pre the
      --  prover knows nothing about S.State on entry, so the eight
      --  Send_Alert_And_Error (S, ...) calls in the body cannot discharge
      --  that callee's one-line state precondition. Discharged by the
      --  "when Wait_Client_Hello_Retry =>" arm of Advance_Handshake.
   with Pre => S.Version = TLS_1_3 and then S.State = Wait_Client_Hello_Retry;

   procedure Build_Hello_Retry_Request
     (S       : in out Session;
      Group   : in ECDHE_Group;
      Built   : out Boolean)
   with
     Pre => Server_Active (S),
     Post =>
       S.State = S.State'Old
       and then (if Built then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Append_And_Encrypt_Server_HS
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Scratch   : in out IO_Buffer;
      Result    : out Action;
      Emitted   : out Boolean)
   with
     Pre =>
       Server_Active
         (S)
         --  transcript-append bound
       and then Plaintext'Last < N32'Last - 256
       and then Plaintext'Length > 0
       and then Plaintext'Length <= Max_Fragment
       and then Plaintext'Length < Transcript_Capacity,
     Post =>
       (if Emitted
        then
          Server_Active (S)
          and then S.State = S.State'Old
          and then S.Role = S.Role'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old
          and then Result = OK)
       and then (if not Emitted then S.State = Error_State and then Result = Error_Alert);

   procedure Append_And_Encrypt_Server_HS_Fragmented
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Scratch   : in out IO_Buffer;
      Result    : out Action;
      Emitted   : out Boolean)
   with
     Pre =>
       Server_Active (S)
       and then Plaintext'First = 0
       and then Plaintext'Last in 0 .. N32 (Transcript_Capacity) - 2
       and then S.HC.Server_HS.Counter <= Unsigned_64'Last - 2,
     Post =>
       (if Emitted
        then
          Server_Active (S)
          and then S.State = S.State'Old
          and then S.Role = S.Role'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old
          and then Result = OK)
       and then (if not Emitted then S.State = Error_State and then Result = Error_Alert);

   --  Cfg is the Ready_Config VIEW of S.HC.Cfg, established once by
   --  Advance_Handshake's membership guard and passed BY COPY (passing
   --  S.HC.Cfg directly alongside `in out HC` would alias). The configured-
   --  server fact rides the subtype; no Server_Configured contract needed
   --  anywhere in this chain.
   procedure Process_Client_Auth
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action);

   procedure Process_Client_Finished
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with Pre => S.Role = Role_Server and then S.State = Wait_Client_Finished;
   procedure Handle_PCF_App_Data
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   with
     Pre =>
       S.State = Wait_Client_Finished
       and then S.Role = Role_Server
       and then Rec.OK
       and then Rec.Content = Records.Content_Application_Data
       and then Free_Space (S.Output) >= Records.Record_Header_Size + 3 + Records.Tag_Size
       and then Rec.Fragment_Len >= 1
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Record_Len >= Rec.Fragment_Pos
       and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
       and then Rec.Record_Len <= Available (S.Input);
   procedure Verify_Client_Finished
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Msg_Len   : in N32;
      Result    : out Action)
   with
     Pre =>
       S.State = Wait_Client_Finished
       and then S.Role = Role_Server
       and then Plaintext'First = 0
       and then Plain_Len > 0
       and then Plaintext'Last < N32'Last
       and then Plain_Len - 1 <= Plaintext'Last;

   procedure Derive_Handshake_Keys
     (S : in out Session; Suite : in TLS13_Suite)
   with
     Post => S.HC.TS = S.HC.TS'Old and S.HC.Server_HS.Counter = 0;

   procedure Derive_App_Keys
     (S : in out Session; Suite : in TLS13_Suite)
   with
     Post =>
       S.HC.TS = S.HC.TS'Old
       and S.State = S.State'Old
       and S.Role = S.Role'Old
       and S.Negotiated_Suite = S.Negotiated_Suite'Old
       and S.Server_App.Counter = 0;

   procedure Set_Traffic_Keys
     (TK : out Traffic_Keys; Secret : in Bytes_48; Suite : in Supported_Suite)
   with Post => TK.Counter = 0 and TK.Suite = Suite;

   --  Alert_Desc / Error_Code mapping is in the parent SPARKTLS
   --  package  child-unit visibility resolves call sites here.

   --  Send a fatal alert and set error state
   procedure Send_Alert_And_Error (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre => S.State not in Idle | Closed | Closing | Error_State,
     Post =>
       S.State = Error_State
       and then S.Last_Error = Err
       and then S.Role = S.Role'Old
       and then Result in Has_Output | Error_Alert
       and then S.Role = S.Role'Old
       and then S.Input.Read_Pos = S.Input.Read_Pos'Old
       and then S.Input.Write_Pos = S.Input.Write_Pos'Old
   is
      Dummy : N32;
   begin
      null; -- debug removed
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Records.Build_Plaintext_Alert
        (Level     => 2,  --  fatal
         Desc      => Alert_Desc (Err),
         Output    => S.Output,
         Bytes_Out => Dummy);
      --  Let caller drain the alert before seeing Error_Alert
      if Output_Pending (S) > 0 then
         Result := Has_Output;
      else
         Result := Error_Alert;
      end if;
   end Send_Alert_And_Error;
   procedure Send_Encrypted_Alert (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre => Alert_Desc (Err) /= 0,
     Post =>
       S.State = Error_State and then S.Last_Error = Err and then Result in Has_Output | Error_Alert
   is
      Dummy       : N32;
      --  Captured before Set_State below, which overwrites S.State.
      Entry_State : constant Connection_State := S.State;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
      --  RFC 8446 5.2 / RFC 5246 7.2.1: an ENCRYPTED alert needs established
      --  application keys. In Idle they do not exist yet; in Closed or
      --  Error_State the session is already torn down. Emitting a record
      --  under unestablished or retired keys is worse than staying silent,
      --  so report the error to the caller without putting bytes on the
      --  wire. This is a RUNTIME guard on purpose: shipped builds compile
      --  without -gnata, so the old precondition enforced nothing here.
      if Entry_State in Idle | Closed | Error_State then
         Result := Error_Alert;
         return;
      end if;
      Records.Build_Alert_Record
        (Level     => 2,
         Desc      => Alert_Desc (Err),
         Keys      => S.Server_App,
         Output    => S.Output,
         Bytes_Out => Dummy);
      if Output_Pending (S) > 0 then
         Result := Has_Output;
      else
         Result := Error_Alert;
      end if;
   end Send_Encrypted_Alert;

   --  Append handshake message bytes to the transcript.
   --  RFC 5246 7.4.9 / RFC 8446 4.4.1: append-only invariant
   --  (transcript drives Finished verify_data).
   procedure Append_Transcript (HC : in out Engaged_Context; Data : in Byte_Seq)
   with
     Post =>
       (if SPARKTLS_Transcript.Started (HC.TS)'Old or else Data'First <= Data'Last
       then SPARKTLS_Transcript.Started (HC.TS))
       and Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
       and HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old,
     Pre => Data'Last < N32'Last - 256
   is
   begin
      SPARKTLS_Transcript.Append (HC.TS, Data);
   end Append_Transcript;

   function Transcript_Hash_256 (HC : Engaged_Context) return Digest is
      H : Digest;
   begin
      SPARKTLS_Transcript.Current_256 (HC.TS, H);
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (HC : Engaged_Context) return SPARKNaCl.Hashing.SHA384.Digest is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKTLS_Transcript.Current_384 (HC.TS, H);
      return H;
   end Transcript_Hash_384;

   procedure Validate_Client_Hello_Retry
     (S     : in out Session;
      D     : in out SPARKTLS.HS_Pool.HS_Data;
      Msg   : in Byte_Seq;
      Valid : out Boolean)
   is
      Parse_OK          : Boolean;
      Candidate_Version : TLS_Version;
      Candidate_12      : Supported_Suite := Suite_None;
      CH1_Hash          : constant Unsigned_32 := S.HC.CH_Ext_Hash;
   begin
      Valid := False;

      --  Reset for CH2 parsing. Seen_Ext_Count + Tags also reset:
      --  duplicate-extension checks are intra-ClientHello, not CH1 vs CH2.
      S.HC.Client_Saw_Key_Share := False;
      S.HC.Client_Has_X25519 := False;
      S.HC.Client_Has_P256 := False;
      S.HC.Client_Has_P384 := False;
      S.HC.Client_Saw_Supported_Groups := False;
      S.HC.Client_Supports_X25519 := False;
      S.HC.Client_Supports_P256 := False;
      S.HC.Client_Supports_P384 := False;
      S.HC.CH_Ext_Hash := 0;
      S.HC.CH_Ext_Count := 0;
      S.HC.Seen_Ext_Count := 0;
      S.HC.Seen_Ext_Tags := (others => 0);
      pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);

      Handshake.Server_Msgs.Parse_Client_Hello
        (S.Negotiated_Suite,
         Candidate_12,
         S.Last_Error,
         S.HC,
         Msg,
         Candidate_Version,
         Parse_OK);

      if not Parse_OK then
         return;
      end if;

      pragma Assert (S.State = Wait_Client_Hello_Retry);
      if Candidate_Version /= TLS_1_3
        or else S.Version /= TLS_1_3
        or else S.Negotiated_Suite not in TLS13_Suite
      then
         return;
      end if;

      --  RFC 8446 4.1.2: CH2 extensions must be in the same order
      --  as CH1. Cookie is excluded from the hash in both messages.
      if S.HC.CH_Ext_Hash /= CH1_Hash then
         return;
      end if;

      Valid := True;
   end Validate_Client_Hello_Retry;

   procedure Complete_Client_Hello_Retry
     (S                      : in out Session;
      D                      : in out SPARKTLS.HS_Pool.HS_Data;
      Msg                    : in Byte_Seq;
      Consume_Current_Record : in Boolean;
      Record_Len             : in N32;
      Ready_To_Build         : out Boolean;
      Result                 : out Action)
   is
      Valid_CH2 : Boolean;

      procedure Consume_Record
      with
        Pre =>
          Server_Active (S)
          and then (if Consume_Current_Record
                    then
                      S.Input.Read_Pos <= N32'Last - Record_Len
                      and then S.Input.Read_Pos + Record_Len <= S.Input.Write_Pos),
        Post =>
          S.State = S.State'Old
          and then S.Role = S.Role'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old
          and then Server_Active (S)
          and then (if Consume_Current_Record
                    then
                      S.Input.Read_Pos = S.Input.Read_Pos'Old + Record_Len
                      and then S.Input.Write_Pos = S.Input.Write_Pos'Old
                    else
                      S.Input.Read_Pos = S.Input.Read_Pos'Old
                      and then S.Input.Write_Pos = S.Input.Write_Pos'Old)
      is
      begin
         if Consume_Current_Record then
            pragma Assert (S.Input.Read_Pos + Record_Len <= S.Input.Write_Pos);
            S.Input.Read_Pos := S.Input.Read_Pos + Record_Len;
         end if;
      end Consume_Record;

      procedure Free_CH2_Reasm
      with
        Post =>
          Used (D.Reasm) = 0
          and then S.HC.Legacy_Session_ID_Len = S.HC.Legacy_Session_ID_Len'Old
      is
      begin
         Reset (D.Reasm);
      end Free_CH2_Reasm;
   begin
      Ready_To_Build := False;
      if Msg'Length = 0 or else N32 (Msg'Length) > Transcript_Capacity then
         Consume_Record;
         Free_CH2_Reasm;
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;

      Validate_Client_Hello_Retry (S, D, Msg, Valid_CH2);
      if not Valid_CH2 then
         --  After HRR, CH2 parse/version/order failures are
         --  illegal_parameter (RFC 8446 4.1.4).
         Consume_Record;
         Free_CH2_Reasm;
         Send_Alert_And_Error (S, Illegal_Parameter, Result);
         return;
      end if;
      pragma Assert (S.State = Wait_Client_Hello_Retry);

      --  Append CH2 to transcript
      pragma Assert (Msg'First <= Msg'Last);
      --  CH2 binder hash: stream holds CH1+HRR;
      --  suffix is CH2 truncated before binders.
      if S.HC.PSK.Offered
        and then S.HC.PSK.Binder_Len > 0
        and then N32 (Msg'Length) > 3 + S.HC.PSK.Binder_Len
      then
         declare
            T : constant N32 := N32 (Msg'Length) - (3 + S.HC.PSK.Binder_Len);
         begin
            SPARKTLS_Transcript.Suffix_256
              (S.HC.TS,
               Msg (Msg'First .. Msg'First + T - 1),
               SPARKTLSCrypto.Hashing.SHA256.Digest (S.HC.PSK.Binder_Hash_256));
            SPARKTLS_Transcript.Suffix_384
              (S.HC.TS,
               Msg (Msg'First .. Msg'First + T - 1),
               SPARKTLSCrypto.Hashing.SHA384.Digest (S.HC.PSK.Binder_Hash_384));
            S.HC.PSK.Binder_Hash_Taken := True;
         end;
      end if;

      Append_Transcript (S.HC, Msg);
      Consume_Record;
      Free_CH2_Reasm;

      if not S.HC.Cfg.Local.Has_Identity
        or else S.HC.Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
        or else S.HC.Cfg.Local.Int_Count > Max_Pool_Size
        or else (for some I in 0 .. Max_Pool_Size - 1
                 => S.HC.Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
        or else (S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                 and then S.HC.Cfg.Local.RSA_Mod_Len not in 64 .. 512)
      then
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;
      pragma Assert (S.State = Wait_Client_Hello_Retry);
      pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
      Result := OK;
      Ready_To_Build := True;
   end Complete_Client_Hello_Retry;

   procedure Build_Server_Flight_After_Client_Hello_Retry
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action) is
   begin
      Build_Server_Flight_13 (S, D, Cfg, Result);
   end Build_Server_Flight_After_Client_Hello_Retry;

   procedure Handle_Client_Hello_Retry
     (S : in out Server_Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      --  After HRR, wait for the client's second ClientHello.
      --  Same parsing as Wait_Client_Hello but we expect the
      --  client to include key_share for our requested group.
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (S.State = Wait_Client_Hello_Retry);
         return;
      end if;

      declare
         Rec : Records.Parse_Result;
      begin
         Records.Parse_Record_Header
           (Data   => S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
            Avail  => Available (S.Input),
            Result => Rec);

         if Rec.Overflow then
            Send_Alert_And_Error (S, Record_Overflow, Result);
            return;
         end if;

         if Rec.Bad_Version then
            --  RFC 8446 5.1: legacy_record_version must lie
            --  in {3,1}..{3,4}. Out-of-band â protocol_version.
            Send_Alert_And_Error (S, Protocol_Version, Result);
            return;
         end if;

         if not Rec.OK then
            if Rec.Record_Len > 0 then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            else
               Result := Need_Input;
               pragma Assert (S.State = Wait_Client_Hello_Retry);
            end if;
            return;
         end if;

         if Rec.Content = Records.Content_Change_Cipher_Spec then
            declare
               CCS_Pos : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               CCS_OK  : constant Boolean :=
                 Rec.Fragment_Len = 1 and then S.Input.Data (CCS_Pos) = 16#01#;
            begin
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               if CCS_OK then
                  Result := OK;
               else
                  --  RFC 5246 7.1 / RFC 8446 5: CCS payload MUST
                  --  be the single byte 0x01 (BoGo
                  --  BadChangeCipherSpec-*).
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
               end if;
            end;
            return;
         end if;

         if Rec.Content /= Records.Content_Handshake then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Unexpected_Message, Result);
            return;
         end if;

         --  Parse second ClientHello. CH2 is allowed to span
         --  multiple records just like CH1, including the
         --  pathological one-byte-record split used by BoGo.
         declare
            Frag_Start   : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            Frag_Len     : constant N32 := Rec.Fragment_Len;
            Rec_Consumed : Boolean := False;

            procedure Consume_Record is
            begin
               if not Rec_Consumed then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Rec_Consumed := True;
               end if;
            end Consume_Record;

            procedure Free_CH2_Reasm is
            begin
               Reset (D.Reasm);
            end Free_CH2_Reasm;


         begin
            if Used (D.Reasm) > 0 then
               --  A COMPLETE message sitting here means the
               --  previous call failed to dispatch it, which
               --  is a genuine protocol/state error. The old
               --  "Phase = Idle" half of this test was the
               --  unreachable contradiction again.
               if Has_Message (D.Reasm) then
                  Consume_Record;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;

               declare
                  Take : constant HS_Msg_Len :=
                    N32'Min (N32'Min (Wanted (D.Reasm), Frag_Len), Free_Space (D.Reasm));
               begin
                  if Take > 0 then
                     Append (D.Reasm, S.Input.Data (Frag_Start .. Frag_Start + Take - 1));
                  end if;
               end;
               Consume_Record;

               if Message_Too_Large (D.Reasm) then
                  Free_CH2_Reasm;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;

               if not Has_Message (D.Reasm) then
                  Result := OK;
                  return;
               end if;

               declare
                  Full_Msg       : constant Byte_Seq := Byte_Seq (Message (D.Reasm));
                  Ready_To_Build : Boolean;
               begin
                  Complete_Client_Hello_Retry (S, D, Full_Msg, False, 0, Ready_To_Build, Result);
                  if Ready_To_Build then
                     if S.HC.Cfg not in Ready_Config then
                        --  Fail closed, as Advance's guard does.
                        S.Last_Error := Internal_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        declare
                           Cfg : constant Ready_Config := S.HC.Cfg;
                        begin
                           Build_Server_Flight_After_Client_Hello_Retry (S, D, Cfg, Result);
                        end;
                     end if;
                  end if;
               end;
            elsif Frag_Len = 0 then
               Consume_Record;
               Send_Alert_And_Error (S, Decode_Error, Result);
            elsif Frag_Len < 4 then
               Reset (D.Reasm);
               Append (D.Reasm, S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1));
               Consume_Record;
               Result := OK;
            else
               declare
                  HS_Msg_Len : constant N32 :=
                    N32 (S.Input.Data (Frag_Start + 1)) * 65536
                    + N32 (S.Input.Data (Frag_Start + 2)) * 256
                    + N32 (S.Input.Data (Frag_Start + 3));
                  HS_Total   : constant N32 := HS_Msg_Len + 4;
               begin
                  if HS_Total > Max_HS_Msg then
                     Consume_Record;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                  elsif HS_Total > Frag_Len then
                     Reset (D.Reasm);
                     Append (D.Reasm, S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1));
                     Consume_Record;
                     Result := OK;
                  else
                     declare
                        Frag           : Byte_Seq (0 .. Frag_Len - 1);
                        Ready_To_Build : Boolean;
                     begin
                        Frag := S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
                        Complete_Client_Hello_Retry
                          (S, D, Frag, True, Rec.Record_Len, Ready_To_Build, Result);
                        if Ready_To_Build then
                           if S.HC.Cfg not in Ready_Config then
                              S.Last_Error := Internal_Error;
                              Set_State (S, Error_State);
                              Result := Error_Alert;
                           else
                              declare
                                 Cfg : constant Ready_Config := S.HC.Cfg;
                              begin
                                 Build_Server_Flight_After_Client_Hello_Retry (S, D, Cfg, Result);
                              end;
                           end if;
                        end if;
                     end;
                  end if;
               end;
            end if;
         end;
      end;
   end Handle_Client_Hello_Retry;

   procedure Build_Hello_Retry_Request
     (S       : in out Session;
      Group   : in ECDHE_Group;
      Built   : out Boolean)
   is
      use SPARKTLSCrypto.Hashing.SHA256;

      --  RFC 8446 4.1.3: SHA-256("HelloRetryRequest")
      HRR_Random : constant Bytes_32 :=
        (16#CF#,
         16#21#,
         16#AD#,
         16#74#,
         16#E5#,
         16#9A#,
         16#61#,
         16#11#,
         16#BE#,
         16#1D#,
         16#8C#,
         16#02#,
         16#1E#,
         16#65#,
         16#B8#,
         16#91#,
         16#C2#,
         16#A2#,
         16#11#,
         16#16#,
         16#7A#,
         16#BB#,
         16#8C#,
         16#5E#,
         16#07#,
         16#9E#,
         16#09#,
         16#E2#,
         16#C8#,
         16#A8#,
         16#33#,
         16#9C#);

      --  Build a minimal ServerHello-shaped message manually.
      --  Format: type(1) + length(3) + body
      --  Body: version(2) + random(32) + session_id_len(1) + session_id(32)
      --        + cipher_suite(2) + compression(1) + extensions_len(2)
      --        + key_share_ext(6) + supported_versions_ext(5)
      --  Total body: 2+32+1+32+2+1+2+6+5 = 83
      --  Total message: 4 + 83 = 87

      Ext_Len  : constant N32 := 12;  --  key_share(6) + supported_versions(6)
      Body_Len : constant N32 := 2 + 32 + 1 + 32 + 2 + 1 + 2 + Ext_Len;
      --  version(2) + random(32) + sid_len(1) + sid(32) + suite(2)
      --  + compression(1) + ext_len(2) + extensions(12) = 84
      Msg_Len  : constant N32 := 4 + Body_Len;

      HRR_Buf : Byte_Seq (0 .. Handshake.TLS13.Max_Server_Hello - 1);
      Rec_Out : N32;
      P       : N32;
   begin
      HRR_Buf := (others => 0);
      Rec_Out := 0;
      Built := False;

      pragma Assert (HRR_Buf'First = 0);
      pragma Assert (HRR_Buf'Last >= Msg_Len - 1);

      --  Handshake header: type=ServerHello(0x02) + length(3)
      HRR_Buf (0) := 16#02#;
      HRR_Buf (1) := 0;
      HRR_Buf (2) := 0;
      HRR_Buf (3) := Byte (Body_Len);
      P := 4;

      --  legacy_version = 0x0303
      HRR_Buf (P) := 16#03#;
      HRR_Buf (P + 1) := 16#03#;
      P := P + 2;

      --  random = HRR magic constant
      HRR_Buf (P .. P + 31) := HRR_Random;
      P := P + 32;

      --  legacy_session_id echo (must match CH1)
      HRR_Buf (P) := 32;
      P := P + 1;
      HRR_Buf (P .. P + 31) := S.HC.Legacy_Session_ID;
      P := P + 32;

      --  cipher_suite (use negotiated suite)
      HRR_Buf (P) := Byte (Wire_Of (S.Negotiated_Suite) / 256);
      HRR_Buf (P + 1) := Byte (Wire_Of (S.Negotiated_Suite) mod 256);
      P := P + 2;

      --  legacy_compression_method = 0
      HRR_Buf (P) := 0;
      P := P + 1;

      --  extensions_length
      HRR_Buf (P) := Byte (Ext_Len / 256);
      HRR_Buf (P + 1) := Byte (Ext_Len mod 256);
      P := P + 2;

      --  key_share extension: type(2) + length(2) + group(2)
      HRR_Buf (P) := 16#00#;
      HRR_Buf (P + 1) := 16#33#;  --  key_share
      HRR_Buf (P + 2) := 16#00#;
      HRR_Buf (P + 3) := 16#02#;  --  2 bytes data
      HRR_Buf (P + 4) := Byte (ECDHE_Group_Wire (Group) / 256);
      HRR_Buf (P + 5) := Byte (ECDHE_Group_Wire (Group) mod 256);
      P := P + 6;

      --  supported_versions extension: type(2) + length(2) + version(2)
      --  but ServerHello format uses 2-byte version (not list)
      HRR_Buf (P) := 16#00#;
      HRR_Buf (P + 1) := 16#2B#;  --  supported_versions
      HRR_Buf (P + 2) := 16#00#;
      HRR_Buf (P + 3) := 16#02#;  --  2 bytes data
      HRR_Buf (P + 4) := 16#03#;
      HRR_Buf (P + 5) := 16#04#;  --  TLS 1.3
      P := P + 6;

      pragma Assert (P = Msg_Len);

      --  RFC 8446 4.4.1 via the streaming ADT: select the digest the
      --  HRR names, then replace the transcript with the synthetic
      --  message_hash of ClientHello1.
      SPARKTLS_Transcript.Select_Hash
        (S.HC.TS,
         (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384 then SPARKTLS_Transcript.Only_384
          else SPARKTLS_Transcript.Only_256));
      SPARKTLS_Transcript.Reset_For_HRR (S.HC.TS);

      --  Append HRR to transcript
      Append_Transcript (S.HC, HRR_Buf (0 .. Msg_Len - 1));
      S.HC.HRR_Selected_Group := Group;

      --  Atomic flight assembly: HRR + CCS into scratch, commit only if
      --  the whole flight fits.
      declare
         Scratch : IO_Buffer;
         CCS_Out : N32;
      begin
         Records.Build_Handshake_Record
           (Fragment => HRR_Buf (0 .. Msg_Len - 1), Output => Scratch, Bytes_Out => Rec_Out);
         if Rec_Out = 0 then
            return;
         end if;

         --  Send CCS for middlebox compatibility
         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            return;
         end if;

         if Free_Space (S.Output) < Scratch.Write_Pos then
            return;
         end if;
         S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
           Scratch.Data (0 .. Scratch.Write_Pos - 1);
         S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
         S.HC.Sent_HRR_CCS := True;
         Built := True;
      end;
   end Build_Hello_Retry_Request;

   --  Build the entire server handshake flight:
   --  ServerHello (plaintext record) + CCS + encrypted(EE + Cert + CV + Finished)
   --  RFC 8446 4.2.11 server-side PSK binder verification. Looks up
   --  the cached PSK by ticket ID, recomputes the binder over the
   --  truncated ClientHello transcript, and either installs the PSK
   --  (S.HC.Using_PSK := True + S.HC.PSK.Value/Len populated) on a hash
   --  match or emits a fatal alert on mismatch (matching BoringSSL's
   --  decrypt_error convention per BoGo Resume-Server-InvalidPSKBinder).
   procedure Verify_PSK_Binder
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg      : in Ready_Config;
      Rejected : out Boolean;
      Result   : out Action)
   with
     Pre =>
       S.State not in
         Idle
         | Closing
         | Closed
         | Error_State
         --  Callback facts on the FORMAL: the caller's guard tests
         --  the same object, so the discharge is local. (The old
         --  S.HC.Cfg form was unprovable across the view copy.)
       and then Cfg.Store_Session /= null
       and then Cfg.Lookup_Session /= null
       and then S.HC.PSK.Binder_Len <= Max_HS_Msg,
     Post =>
       (if not Rejected
        then
          S.State = S.State'Old
          and S.Role = S.Role'Old
          and S.Negotiated_Suite = S.Negotiated_Suite'Old)
       and then (if Rejected then S.State = Error_State);

   procedure Verify_PSK_Binder
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg      : in Ready_Config;
      Rejected : out Boolean;
      Result   : out Action)
   is
      PSK     : Bytes_48;
      PSK_Len : N32;
      Suite   : Unsigned_16;
      Found   : Boolean;
   begin
      Rejected := False;
      Result := OK;
      Cfg.Lookup_Session
        (ID         => S.HC.PSK.Offer_ID,
         Want_Suite => Wire_Of (S.Negotiated_Suite),
         PSK        => PSK,
         PSK_Len    => PSK_Len,
         Suite      => Suite,
         Found      => Found);

      --  DEFENCE AGAINST THE CALLBACK, not merely a proof aid.
      --
      --  Lookup_Session is supplied by the application and its access type
      --  cannot carry a postcondition (that is an Ada 2022 feature; this
      --  project builds as Ada 2012), so NOTHING constrains what an
      --  implementation returns. This used to be a bare
      --      pragma Assert (if Found then Suite = Wire_Of (S.Negotiated_Suite));
      --  which is checked only in assertion-enabled builds -- in a release
      --  build a buggy or hostile cache returning Found with a mismatched
      --  suite, or a PSK length other than 32/48, would flow straight into
      --  binder verification and key derivation.
      --
      --  Treat any such answer as a cache miss. RFC 8446 4.2.11 lets us
      --  decline any offered identity, and RFC 5077 3.4 says fall through
      --  to a full handshake -- so downgrading to "not found" is both
      --  safe and spec-legal. It also makes PSK_Len in 32 | 48 available
      --  for the S.HC.PSK.Value_Len assignment below
      --  (PSK_Value_Length is N32 range 0 .. 48).
      if Found and then (Suite /= Wire_Of (S.Negotiated_Suite) or else PSK_Len not in 32 | 48) then
         Found := False;
      end if;
      pragma Assert (if Found then Suite = Wire_Of (S.Negotiated_Suite));
      pragma Assert (if Found then PSK_Len in 32 | 48);
      if not Found or S.HC.PSK.Binder_Len = 0 then
         return;
      end if;

      declare
         Binder_OK    : Boolean := False;
         Binders_Size : constant N32 := 2 + 1 + S.HC.PSK.Binder_Len;
         Trunc_Len    : N32;
      begin
         --  The binder transcript hash was drawn at CH time (before
         --  the CH entered the stream); Binders_Size is retained only
         --  for the wire-shape sanity it encodes.
         if S.HC.PSK.Binder_Hash_Taken and then Binders_Size > 0 then
            Trunc_Len := 0;  --  unused under streaming
            if PSK_Len = 48 then
               declare
                  use SPARKTLSCrypto.HKDF384;
                  Trunc_Hash   : Key_Schedule.Digest_384;
                  Binder_Key   : OKM384_Seq (0 .. 47);
                  Finished_Key : OKM384_Seq (0 .. 47);
                  Expected     : Bytes_48;
               begin
                  Trunc_Hash := Key_Schedule.Digest_384 (S.HC.PSK.Binder_Hash_384);
                  Key_Schedule.Derive_Binder_Key_384 (Binder_Key, PSK);
                  Key_Schedule.Derive_Finished_Key_384 (Finished_Key, Byte_Seq (Binder_Key));
                  HMAC384.HMAC_SHA_384
                    (Output => Expected, M => Trunc_Hash, K => Byte_Seq (Finished_Key));
                  Binder_OK := Equal (Expected, Bytes_48 (S.HC.PSK.Binder));
               end;
            else
               declare
                  Trunc_Hash   : Digest;
                  Binder_Key   : OKM_Seq (0 .. 31);
                  Finished_Key : OKM_Seq (0 .. 31);
                  Expected     : Digest;
               begin
                  Trunc_Hash := Digest (S.HC.PSK.Binder_Hash_256);
                  Key_Schedule.Derive_Binder_Key (Binder_Key, Bytes_32 (PSK (0 .. 31)));
                  Key_Schedule.Derive_Finished_Key (Finished_Key, Byte_Seq (Binder_Key));
                  HMAC_SHA_256 (Output => Expected, M => Trunc_Hash, K => Byte_Seq (Finished_Key));
                  Binder_OK := Equal (Expected, Bytes_32 (S.HC.PSK.Binder (0 .. 31)));
               end;
            end if;
         end if;

         if Binder_OK then
            pragma Assert (PSK_Binder_Validated_RFC_8446_4_2_11_2 (Binder_OK));
            S.HC.Using_PSK := True;
            S.HC.PSK.Value := PSK;
            S.HC.PSK.Value_Len := PSK_Len;
         else
            --  BoringSSL convention: emit decrypt_error (alert 51 =
            --  Certificate_Verify_Failed in our codes) on binder fail.
            Send_Alert_And_Error (S, Certificate_Verify_Failed, Result);
            Rejected := True;
         end if;
      end;
   end Verify_PSK_Binder;

   --  RFC 8446 4.2.3 server-side signature-algorithm negotiation.
   --  Walks S.HC.Peer_Sig_Algos in client-preferred order, picks the
   --  first entry compatible with our local identity's key type, and
   --  stores it in S.HC.Negotiated_Sig_Algo. Emits handshake_failure
   --  on no overlap.
   function Local_Sig_Compatible
     (Scheme : Maybe_Sig_Scheme; Cert : Signing_Algorithm) return Boolean is
   begin
      case Cert is
         when Sign_Ed25519 =>
            return Scheme = Sig_Ed25519;

         when Sign_ECDSA_P256 =>
            return Scheme = Sig_ECDSA_P256_SHA256;

         when Sign_ECDSA_P384 =>
            return Scheme = Sig_ECDSA_P384_SHA384;

         when Sign_RSA_PSS =>
            return Scheme in Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512;

         when Sign_None =>
            return False;
      end case;
   end Local_Sig_Compatible;

   procedure Negotiate_Sig_Algo
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg     : in Ready_Config;
      Algo_OK : out Boolean;
      Result  : out Action)
      --  The identity-bounds conjuncts this contract used to carry (and the
      --  loop invariants restating them in the body) are now FREE: Cfg's
      --  Ready_Config predicate gives Local /= null, and Cfg.Local's own
      --  Valid_Identity_Access predicate carries every bound.
   with
     Pre => S.State not in Idle | Closing | Closed | Error_State,
     Post =>
       (if Algo_OK
        then
          S.State = S.State'Old
          and S.Role = S.Role'Old
          and S.Negotiated_Suite = S.Negotiated_Suite'Old
          and S.HC.Negotiated_Sig_Algo /= Scheme_None
          and Handshake.Sig_Algo_Compatible_With_Cert
                (S.HC.Negotiated_Sig_Algo, Cfg.Local.Sign_Algo))
       and then (if not Algo_OK then S.State = Error_State);

   procedure Negotiate_Sig_Algo
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg     : in Ready_Config;
      Algo_OK : out Boolean;
      Result  : out Action) is
   begin
      Result := OK;
      Algo_OK := False;
      if Cfg.Sign_Sig_Algo_Count > 0 then
         for J in Sig_Algo_Index loop
            pragma Loop_Invariant (S.State = S.State'Loop_Entry);
            pragma Loop_Invariant (S.Role = S.Role'Loop_Entry);
            pragma Loop_Invariant (S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            pragma Loop_Invariant (S.HC.TS = S.HC.TS'Loop_Entry);
            pragma Loop_Invariant (S.HC.Legacy_Session_ID_Len in 0 .. 32);
            pragma
              Loop_Invariant
                (if Algo_OK
                   then
                     S.HC.Negotiated_Sig_Algo /= Scheme_None
                     and then Handshake.Sig_Algo_Compatible_With_Cert
                                (S.HC.Negotiated_Sig_Algo, Cfg.Local.Sign_Algo));
            exit when J >= Cfg.Sign_Sig_Algo_Count;
            if Local_Sig_Compatible (Cfg.Sign_Sig_Algos (J), Cfg.Local.Sign_Algo)
              and then Sig_Scheme_In_List
                         (Cfg.Sign_Sig_Algos (J), S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count)
            then
               S.HC.Negotiated_Sig_Algo := Cfg.Sign_Sig_Algos (J);
               Algo_OK := True;
               exit;
            end if;
         end loop;
      else
         for I in 0 .. S.HC.Peer_Sig_Algo_Count - 1 loop
            pragma Loop_Invariant (S.State = S.State'Loop_Entry);
            pragma Loop_Invariant (S.Role = S.Role'Loop_Entry);
            pragma Loop_Invariant (S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            pragma Loop_Invariant (S.HC.TS = S.HC.TS'Loop_Entry);
            pragma Loop_Invariant (S.HC.Legacy_Session_ID_Len in 0 .. 32);
            pragma
              Loop_Invariant
                (if Algo_OK
                   then
                     S.HC.Negotiated_Sig_Algo /= Scheme_None
                     and then Handshake.Sig_Algo_Compatible_With_Cert
                                (S.HC.Negotiated_Sig_Algo, Cfg.Local.Sign_Algo));
            if Local_Sig_Compatible (S.HC.Peer_Sig_Algos (I), Cfg.Local.Sign_Algo) then
               S.HC.Negotiated_Sig_Algo := S.HC.Peer_Sig_Algos (I);
               Algo_OK := True;
               exit;
            end if;
         end loop;
      end if;
      if not Algo_OK then
         Send_Alert_And_Error (S, Handshake_Failure, Result);
      end if;
   end Negotiate_Sig_Algo;

   procedure Append_And_Encrypt_Server_HS
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Scratch   : in out IO_Buffer;
      Result    : out Action;
      Emitted   : out Boolean)
   is
      Enc_Out : N32;
   begin
      Append_Transcript (S.HC, Plaintext);
      Records.Build_Encrypted_Record
        (Plaintext  => Plaintext,
         Inner_Type => 16#16#,
         Keys       => S.HC.Server_HS,
         Output     => Scratch,
         Bytes_Out  => Enc_Out);

      if Enc_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         Emitted := False;
      else
         Result := OK;
         Emitted := True;
      end if;
   end Append_And_Encrypt_Server_HS;

   procedure Append_And_Encrypt_Server_HS_Fragmented
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Scratch   : in out IO_Buffer;
      Result    : out Action;
      Emitted   : out Boolean)
   is
      Enc_Out : N32;
   begin
      Append_Transcript (S.HC, Plaintext);

      if Plaintext'Length <= Max_Fragment then
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext,
            Inner_Type => 16#16#,
            Keys       => S.HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            Emitted := False;
         else
            Result := OK;
            Emitted := True;
         end if;
      else
         pragma Assert (Plaintext'Last >= N32 (Max_Fragment));
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext (0 .. N32 (Max_Fragment) - 1),
            Inner_Type => 16#16#,
            Keys       => S.HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            Emitted := False;
            return;
         end if;

         pragma Assert (S.HC.Server_HS.Counter <= Unsigned_64'Last - 1);
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext (N32 (Max_Fragment) .. Plaintext'Last),
            Inner_Type => 16#16#,
            Keys       => S.HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            Emitted := False;
         else
            Result := OK;
            Emitted := True;
         end if;
      end if;
   end Append_And_Encrypt_Server_HS_Fragmented;

   --  Certificate message (RFC 8446 4.4.2): leaf + intermediates from the
   --  local identity, encrypted under the server HS keys, fragmented when
   --  the chain exceeds one record. Oversized/unconfigured identities fail
   --  closed with Emitted = False and the error state set.
   procedure Emit_Certificate_Chain
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg     : in Ready_Config;
      Scratch : in out IO_Buffer;
      Result  : out Action;
      Emitted : out Boolean)
   with
     Pre  => Server_Active (S),
     Post =>
       (if Emitted
        then
          Server_Active (S)
          and then S.State = S.State'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old)
   is
      --  Max: leaf + 8 intermediates, each up to 8 KB + 5 bytes overhead
      Cert_Buf : Byte_Seq (0 .. 9 * (Max_Cert_DER_Len + 5) + 10);
      Cert_Len : N32;
   begin
      Emitted := False;
      if Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
        or else Cfg.Local.Int_Count > Max_Pool_Size
        or else (for some I in 0 .. Max_Pool_Size - 1
                 => Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
      then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      Handshake.TLS13.Build_Certificate_Chain
        (Id => Cfg.Local.all, Result => Cert_Buf, Len => Cert_Len);

      if Cert_Len = 0
        or else Cert_Len >= Transcript_Capacity
        or else Cert_Len > 2 * Max_Fragment
      then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      pragma Assert (Cert_Len < Transcript_Capacity);
      pragma Assert (Cert_Len <= 2 * Max_Fragment);
      pragma Assert (S.HC.Server_HS.Counter <= Unsigned_64'Last - 2);
      Append_And_Encrypt_Server_HS_Fragmented
        (S         => S,
         D         => D,
         Plaintext => Cert_Buf (0 .. Cert_Len - 1),
         Scratch   => Scratch,
         Result    => Result,
         Emitted   => Emitted);
   end Emit_Certificate_Chain;

   --  CertificateVerify (RFC 8446 4.4.3): sign the transcript hash with
   --  the negotiated scheme. Hash_Width is the suite hash length (the
   --  #117 type-derived dispatch: 48 selects SHA-384).
   procedure Emit_Cert_Verify
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg        : in Ready_Config;
      Scratch    : in out IO_Buffer;
      Result     : out Action;
      Emitted    : out Boolean)
   with
     Pre  => Server_Active (S),
     Post =>
       (if Emitted
        then
          Server_Active (S)
          and then S.State = S.State'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old)
   is
      --  Derived, not threaded: H_Len from the negotiated suite makes the
      --  width Pre of the chosen transcript hash discharge locally, as the
      --  comment below always claimed.
      H_Len   : constant N32 := Hash_Len (S.HC.Neg);
      CV_Hash : Byte_Seq (0 .. H_Len - 1);
      CV_Buf  : Byte_Seq (0 .. 523);
      CV_Len  : N32;
   begin
      Emitted := False;
      --  Dispatch on the type-derived hash width (#117): H_Len is
      --  Hash_Len (S.HC.Neg) at the call site, so the width Pre of the
      --  chosen hash discharges locally.
      if H_Len = 48 then
         CV_Hash := Transcript_Hash_384 (S.HC);
      else
         declare
            H256 : constant Digest := Transcript_Hash_256 (S.HC);
         begin
            CV_Hash := H256;
         end;
      end if;

      if S.HC.Negotiated_Sig_Algo in Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512
        and then (Cfg.Local.RSA_Mod_Len not in 64 .. 512)
      then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      Handshake.TLS13.Build_Certificate_Verify
        (Transcript_Hash => CV_Hash,
         Id              => Cfg.Local.all,
         Sig_Algo_Wire   => S.HC.Negotiated_Sig_Algo,
         Role            => Role_Server,
         Random          => Cfg.Random,
         Result          => CV_Buf,
         Len             => CV_Len);

      if CV_Len = 0 then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      pragma Assert (CV_Len <= Max_Fragment);
      Append_And_Encrypt_Server_HS
        (S         => S,
         D         => D,
         Plaintext => CV_Buf (0 .. CV_Len - 1),
         Scratch   => Scratch,
         Result    => Result,
         Emitted   => Emitted);
   end Emit_Cert_Verify;

   --  RFC 8446 4.1.4 HelloRetryRequest decision: pick the first mutually
   --  supported group in server preference order; if the client sent no
   --  key_share for it, send HRR requesting that group. Handled is True
   --  when this call fully disposed of the flight (HRR sent, or a fatal
   --  alert) and the caller must return with Result as set; False means
   --  no HRR was needed and the flight build continues.
   procedure Maybe_Send_HRR (S : in out Session; Handled : out Boolean; Result : out Action)
   with
     Pre  => Server_Active (S),
     Post => (if not Handled then Server_Active (S) and then S.State = S.State'Old)
   is
      Need_HRR            : Boolean := False;
      HRR_Group           : Maybe_ECDHE_Group := Group_None;
      Preferred_Has_Share : Boolean := False;
   begin
      Handled := False;
      Result := OK;
      if S.HC.HRR_Sent then
         return;
      end if;

      Handled := True;
      if not S.HC.Client_Saw_Key_Share then
         Send_Alert_And_Error (S, Missing_Extension, Result);
         return;
      end if;

      --  Pick the server-preferred mutually supported group.
      if S.HC.Client_Supports_X25519 then
         HRR_Group := Group_X25519;
         Preferred_Has_Share := S.HC.Client_Has_X25519;
      elsif S.HC.Client_Supports_P256 then
         HRR_Group := Group_Secp256r1;
         Preferred_Has_Share := S.HC.Client_Has_P256;
      elsif S.HC.Client_Supports_P384 then
         HRR_Group := Group_Secp384r1;
         Preferred_Has_Share := S.HC.Client_Has_P384;
      end if;

      if HRR_Group /= Group_None and then not Preferred_Has_Share then
         Need_HRR := True;
      end if;

      if Need_HRR then
         declare
            HRR_Built : Boolean;
         begin
            Build_Hello_Retry_Request (S, HRR_Group, HRR_Built);
            if not HRR_Built then
               if S.State not in Idle | Closed | Closing | Error_State then
                  Send_Alert_And_Error (S, Internal_Error, Result);
               else
                  Result := Error_Alert;
               end if;
               return;
            end if;
         end;
         Set_State (S, Wait_Client_Hello_Retry);
         S.HC.HRR_Sent := True;
         --  RFC 8446 4.1.4: at-most-one-HRR invariant. After
         --  this assignment, the outer `if not S.HC.HRR_Sent`
         --  guard prevents any further HRR from being built
         --  in this connection.
         pragma Assert (HRR_Sent_At_Most_Once_RFC_8446_4_1_4 (S.HC));
         Result := Has_Output;
         return;
      end if;
      Handled := False;
   end Maybe_Send_HRR;

   --  Server Finished (RFC 8446 4.4.4): verify_data = HMAC over the
   --  current transcript hash under the finished key derived from the
   --  server handshake-traffic secret; width follows the suite hash.
   procedure Emit_Server_Finished
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action;
      Emitted : out Boolean)
   with
     Pre  => Server_Active (S),
     Post => (if Emitted then Server_Active (S) and then S.State = S.State'Old)
   is
   begin
      case S.Negotiated_Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               TS_Hash      : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
               Fin_Key      : OKM384_Seq (0 .. 47);
               Verify_48    : Bytes_48;
               Big_Finished : Byte_Seq (0 .. 51) := (others => 0);  --  4 + 48
            begin
               Key_Schedule.Derive_Finished_Key_384 (Fin_Key, S.HC.Server_HS_Secret);
               HMAC384.HMAC_SHA_384 (Output => Verify_48, M => TS_Hash, K => Byte_Seq (Fin_Key));
               --  RFC 8446 4.4.4: TLS 1.3 verify_data length =
               --  Hash.length. SHA-384 â 48 bytes.
               pragma Assert (Verify_Data_Length_TLS13_RFC_8446_4_4_4 (Byte_Seq (Verify_48)));

               Big_Finished (0) := HS_Msg_Wire (HT_Finished);
               Big_Finished (1) := 16#00#;
               Big_Finished (2) := 16#00#;
               Big_Finished (3) := 16#30#;  --  48
               Big_Finished (4 .. 51) := Verify_48;
               Append_And_Encrypt_Server_HS
                 (S         => S,
                  D         => D,
                  Plaintext => Big_Finished,
                  Scratch   => Scratch,
                  Result    => Result,
                  Emitted   => Emitted);
            end;

         when others =>
            declare
               TS_Hash   : constant Digest := Transcript_Hash_256 (S.HC);
               Fin_Key   : OKM_Seq (0 .. 31);
               Verify_32 : Digest;
               Fin_Buf   : Byte_Seq (0 .. 35);
               Fin_Len   : N32;
            begin
               Key_Schedule.Derive_Finished_Key (Fin_Key, S.HC.Server_HS_Secret (0 .. 31));
               HMAC_SHA_256 (Output => Verify_32, M => TS_Hash, K => Byte_Seq (Fin_Key));
               --  RFC 8446 4.4.4: TLS 1.3 verify_data length =
               --  Hash.length. SHA-256 â 32 bytes.
               pragma Assert (Verify_Data_Length_TLS13_RFC_8446_4_4_4 (Byte_Seq (Verify_32)));

               Handshake.TLS13.Build_Finished (Verify_32, Fin_Buf, Fin_Len);
               pragma Assert (Fin_Len <= Max_Fragment);
               Append_And_Encrypt_Server_HS
                 (S         => S,
                  D         => D,
                  Plaintext => Fin_Buf (0 .. Fin_Len - 1),
                  Scratch   => Scratch,
                  Result    => Result,
                  Emitted   => Emitted);
            end;
      end case;
   end Emit_Server_Finished;

   procedure Build_Server_Flight_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action)
   is
      SH_Buf             : Byte_Seq (0 .. Handshake.TLS13.Max_Server_Hello - 1);
      SH_Len             : N32;
      Rec_Out            : N32;
      CCS_Out            : N32;
      --  Atomic flight assembly: every record goes into Scratch first.
      --  We commit to S.Output as one block at the end so the peer never
      --  observes a partial flight. Each Build_Encrypted_Record call
      --  advances S.HC.Server_HS.Counter; if the commit fails we restore
      --  the counter so the next record's AEAD nonce stays in sync with
      --  what the peer actually sees.
      Scratch            : IO_Buffer;
      Flight_Suite       : constant Supported_Suite := S.Negotiated_Suite;
      Flight_Hash_Len    : N32;
   begin
      --  Negotiation has already committed the version. Keep the suite
      --  consistency check local instead of exporting it as a caller VC.
      if Flight_Suite not in TLS13_Suite then
         Send_Alert_And_Error (S, Internal_Error, Result);
         return;
      end if;

      --  PSK resumption: verify binder, install if valid, fatal-alert
      --  on mismatch. Sets S.HC.Using_PSK on success.
      if S.HC.PSK.Offered and then Cfg.Store_Session /= null and then Cfg.Lookup_Session /= null
      then
         declare
            Rejected : Boolean;
         begin
            Verify_PSK_Binder (S, D, Cfg, Rejected, Result);
            if Rejected then
               return;
            end if;
         end;
      end if;

      --  RFC 8446 4.2.3: pick a sig_algorithm compatible with our
      --  local cert. Skipped on PSK resumption (no signature in flight).
      if not S.HC.Using_PSK then
         declare
            Got_It : Boolean;
         begin
            Negotiate_Sig_Algo (S, D, Cfg, Got_It, Result);
            if not Got_It then
               return;
            end if;
         end;
      end if;

      --  Check if HelloRetryRequest is needed.
      --
      --  RFC 8446 4.1.4: choose the first mutually supported group
      --  in server preference order. If the client did not send a
      --  key_share for that selected group, send HRR requesting it.
      declare
         HRR_Handled : Boolean;
      begin
         Maybe_Send_HRR (S, HRR_Handled, Result);
         if HRR_Handled then
            return;
         end if;
      end;

      if Cfg.Require_ALPN and then not Handshake.Server_Msgs.Has_ALPN_Match (S.HC) then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
      end if;

      Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Flight_Suite), S.HC, SH_Buf, SH_Len);

      if SH_Len = 0 then
         --  RFC 7748 6.1: small-subgroup X25519 rejection sets
         --  Ext_Parse_Err := Illegal_Parameter so we don't fold it
         --  into the catch-all handshake_failure.
         if S.HC.Ext_Parse_Err /= No_Error then
            Send_Alert_And_Error (S, S.HC.Ext_Parse_Err, Result);
         else
            Send_Alert_And_Error (S, Handshake_Failure, Result);
         end if;
         return;
      end if;

      --  Add ServerHello to transcript
      Append_Transcript (S.HC, SH_Buf (0 .. SH_Len - 1));

      --  Write ServerHello record (plaintext) into Scratch
      Records.Build_Handshake_Record
        (Fragment => SH_Buf (0 .. SH_Len - 1), Output => Scratch, Bytes_Out => Rec_Out);

      if Rec_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      --  Derive handshake keys
      Derive_Handshake_Keys (S, TLS13_Suite (Flight_Suite));
      Flight_Hash_Len := Hash_Len (S.HC.Neg);
      --  Restored after r67: the length checks downstream consume this
      --  fact; it proves trivially now that Flight_Hash_Len comes from
      --  Hash_Len (S.HC.Neg) (assert on the SAME object, no cross-object).
      pragma
        Assert
          (if S.HC.Neg.Suite = Suite_AES_256_GCM_SHA384 then Flight_Hash_Len = 48
             else Flight_Hash_Len = 32);
      --  Save the AEAD counter snapshot now: every Build_Encrypted_Record
      --  call below advances S.HC.Server_HS.Counter unconditionally
      --  (Post: Keys.Counter = Keys.Counter'Old + 1). If the final
      --  commit fails we restore this so the next record's nonce stays
      --  in sync with whatever the peer last saw.
      pragma Assert (S.HC.Server_HS.Counter = 0);

      --  Send CCS for middlebox compatibility unless HRR already sent it.
      if not S.HC.Sent_HRR_CCS then
         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      end if;

      --  Build EncryptedExtensions (encrypted with server HS keys)
      declare
         EE_Buf  : Byte_Seq (0 .. 271);
         EE_Len  : N32;
         Emitted : Boolean;
      begin
         Handshake.TLS13.Build_Encrypted_Extensions (S, EE_Buf, EE_Len);
         pragma Assert (EE_Len in 6 .. N32 (EE_Buf'Length));
         pragma Assert (EE_Len <= Max_Fragment);
         pragma Assert (S.HC.Server_HS.Counter = 0);
         pragma Assert (S.State not in Idle | Closing | Closed | Error_State);
         pragma Assert (Server_Active (S));
         Append_And_Encrypt_Server_HS
           (S         => S,
            D         => D,
            Plaintext => EE_Buf (0 .. EE_Len - 1),
            Scratch   => Scratch,
            Result    => Result,
            Emitted   => Emitted);
         if not Emitted then
            return;
         end if;
      end;

      --  Skip Certificate/CertificateVerify for PSK resumption
      if not S.HC.Using_PSK then

         --  Build CertificateRequest if mTLS is configured
         if Cfg.Request_Client_Cert then
            declare
               CR_Buf  : Byte_Seq (0 .. 31);
               CR_Len  : N32;
               Emitted : Boolean;
            begin
               Handshake.TLS13.Build_Certificate_Request (CR_Buf, CR_Len);
               if CR_Len > 0 then
                  pragma Assert (CR_Len <= Max_Fragment);
                  Append_And_Encrypt_Server_HS
                    (S         => S,
                     D         => D,
                     Plaintext => CR_Buf (0 .. CR_Len - 1),
                     Scratch   => Scratch,
                     Result    => Result,
                     Emitted   => Emitted);
                  if not Emitted then
                     return;
                  end if;
               end if;
            end;
         end if;

         --  Build Certificate chain (leaf + intermediates, encrypted)
         declare
            Emitted : Boolean;
         begin
            Emit_Certificate_Chain (S, D, Cfg, Scratch, Result, Emitted);
            if not Emitted then
               return;
            end if;
         end;

         --  Build CertificateVerify (encrypted)
         declare
            Emitted : Boolean;
         begin
            Emit_Cert_Verify (S, D, Cfg, Scratch, Result, Emitted);
            if not Emitted then
               return;
            end if;
         end;

      end if;  --  not Using_PSK (skip cert/cert_verify for resumption)

      --  Build Finished (encrypted)
      declare
         Emitted : Boolean;
      begin
         Emit_Server_Finished (S, D, Scratch, Result, Emitted);
         if not Emitted then
            return;
         end if;
      end;

      --  Atomic commit: full flight assembled in Scratch. If S.Output
      --  has room, copy in one shot; otherwise abort and roll the
      --  AEAD counter back so subsequent records (or the alert we may
      --  send) stay nonce-synchronised with the peer.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
        Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      --  Derive application keys now (using transcript through server Finished)
      Derive_App_Keys (S, TLS13_Suite (Flight_Suite));

      Set_State (S, Server_Hello_Sent);
      Result := Has_Output;
   end Build_Server_Flight_13;

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys
     (S : in out Session; Suite : in TLS13_Suite) is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               Hello_Hash : Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
               Early      : Key_Schedule.Digest_384;
               HS_Secret  : Key_Schedule.Digest_384;
               Client_Sec : OKM384_Seq (0 .. 47);
               Server_Sec : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Early_Secret_384 (Early, S.HC.PSK.Value);
               if S.HC.KE.Curve = Group_Secp384r1 then
                  Key_Schedule.Derive_Handshake_Secret_384
                    (HS_Secret, Byte_Seq (S.HC.KE.Shared), Early);
               else
                  Key_Schedule.Derive_Handshake_Secret_384
                    (HS_Secret, S.HC.KE.Shared (0 .. 31), Early);
               end if;

               S.HC.Handshake_Secret := Bytes_48 (HS_Secret);
               S.HC.Neg := (Suite => Suite);

               Key_Schedule.Derive_HS_Traffic_Secrets_384
                 (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

               S.HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_Sec));
               S.HC.Server_HS_Secret := Bytes_48 (Byte_Seq (Server_Sec));

               Set_Traffic_Keys (S.HC.Client_HS, S.HC.Client_HS_Secret, Suite);
               Set_Traffic_Keys (S.HC.Server_HS, S.HC.Server_HS_Secret, Suite);
            end;

         when others =>
            declare
               Hello_Hash : Digest := Transcript_Hash_256 (S.HC);
               Early      : Digest;
               HS_Secret  : Digest;
               Client_Sec : OKM_Seq (0 .. 31);
               Server_Sec : OKM_Seq (0 .. 31);
            begin
               Key_Schedule.Derive_Early_Secret (Early, Bytes_32 (S.HC.PSK.Value (0 .. 31)));
               if S.HC.KE.Curve = Group_Secp384r1 then
                  Key_Schedule.Derive_Handshake_Secret
                    (HS_Secret, Byte_Seq (S.HC.KE.Shared), Early);
               else
                  Key_Schedule.Derive_Handshake_Secret (HS_Secret, S.HC.KE.Shared (0 .. 31), Early);
               end if;

               S.HC.Handshake_Secret := (others => 0);
               S.HC.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
               S.HC.Neg := (Suite => Suite);

               Key_Schedule.Derive_HS_Traffic_Secrets
                 (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

               S.HC.Client_HS_Secret := (others => 0);
               S.HC.Client_HS_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Client_Sec));
               S.HC.Server_HS_Secret := (others => 0);
               S.HC.Server_HS_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Server_Sec));

               Set_Traffic_Keys (S.HC.Client_HS, S.HC.Client_HS_Secret, Suite);
               Set_Traffic_Keys (S.HC.Server_HS, S.HC.Server_HS_Secret, Suite);
            end;
      end case;
   end Derive_Handshake_Keys;

   --  Derive application keys from master secret + transcript
   procedure Derive_App_Keys
     (S : in out Session; Suite : in TLS13_Suite) is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               TS_Hash        : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
               Master         : Key_Schedule.Digest_384;
               Client_App_Sec : OKM384_Seq (0 .. 47);
               Server_App_Sec : OKM384_Seq (0 .. 47);
               Exporter       : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Master_Secret_384
                 (Master, Key_Schedule.Digest_384 (S.HC.Handshake_Secret));

               Key_Schedule.Derive_App_Traffic_Secrets_384
                 (Client_App_Sec, Server_App_Sec, Master, TS_Hash);
               Key_Schedule.Derive_Exporter_Master_Secret_384 (Exporter, Master, TS_Hash);

               S.HC.Master_Secret := Bytes_48 (Master);
               S.Exporter_Secret := Bytes_48 (Exporter);
               S.Exporter_Secret_Len := 48;
               S.Exporter_Client_Random := S.HC.Client_Random;
               S.Exporter_Server_Random := S.HC.Server_Random;

               Set_Traffic_Keys
                 (S.Client_App, Bytes_48 (Byte_Seq (Client_App_Sec)), Suite);
               Set_Traffic_Keys
                 (S.Server_App, Bytes_48 (Byte_Seq (Server_App_Sec)), Suite);

               --  RFC 8446 4.6.3: retain the secrets themselves, not just
               --  the derived key/IV, so KeyUpdate can ratchet forward.
               S.Client_App_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
               S.Server_App_Secret := Bytes_48 (Byte_Seq (Server_App_Sec));
               S.App_Secret_Len := 48;
            end;

         when others =>
            declare
               TS_Hash        : constant Digest := Transcript_Hash_256 (S.HC);
               Master         : Digest;
               Client_App_Sec : OKM_Seq (0 .. 31);
               Server_App_Sec : OKM_Seq (0 .. 31);
               Exporter       : OKM_Seq (0 .. 31);
               CS48           : Bytes_48 := (others => 0);
               SS48           : Bytes_48 := (others => 0);
            begin
               Key_Schedule.Derive_Master_Secret (Master, Digest (S.HC.Handshake_Secret (0 .. 31)));

               Key_Schedule.Derive_App_Traffic_Secrets
                 (Client_App_Sec, Server_App_Sec, Master, TS_Hash);
               Key_Schedule.Derive_Exporter_Master_Secret (Exporter, Master, TS_Hash);

               S.HC.Master_Secret := (others => 0);
               S.HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));
               S.Exporter_Secret := (others => 0);
               S.Exporter_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Exporter));
               S.Exporter_Secret_Len := 32;
               S.Exporter_Client_Random := S.HC.Client_Random;
               S.Exporter_Server_Random := S.HC.Server_Random;

               CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
               SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
               Set_Traffic_Keys (S.Client_App, CS48, Suite);
               Set_Traffic_Keys (S.Server_App, SS48, Suite);

               --  RFC 8446 4.6.3: retain the secrets for the KeyUpdate
               --  ratchet.
               S.Client_App_Secret := CS48;
               S.Server_App_Secret := SS48;
               S.App_Secret_Len := 32;
            end;
      end case;
   end Derive_App_Keys;

   --  Helper: derive key/IV and set Traffic_Keys based on suite
   procedure Set_Traffic_Keys
     (TK : out Traffic_Keys; Secret : in Bytes_48; Suite : in Supported_Suite) is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               K384  : HKDF384.OKM384_Seq (0 .. 31);
               IV384 : HKDF384.OKM384_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_256 (K384, IV384, Secret);
               TK.Key := Bytes_32 (Byte_Seq (K384));
               TK.IV := Bytes_12 (Byte_Seq (IV384));
            end;

         when Suite_AES_128_GCM_SHA256 =>
            declare
               K128 : OKM_Seq (0 .. 15);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV (K128, IV12, Secret (0 .. 31));
               TK.Key := (others => 0);
               TK.Key (0 .. 15) := Bytes_16 (Byte_Seq (K128));
               TK.IV := Bytes_12 (Byte_Seq (IV12));
            end;

         when others =>
            declare
               K32  : OKM_Seq (0 .. 31);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV (K32, IV12, Secret (0 .. 31));
               TK.Key := Bytes_32 (Byte_Seq (K32));
               TK.IV := Bytes_12 (Byte_Seq (IV12));
            end;
      end case;
      TK.Counter := 0;
      TK.Suite := Suite;
   end Set_Traffic_Keys;

   --  Process incoming records while waiting for client Finished
   --  RFC 8446 4.4.2 server-side mTLS Certificate handler. Parses
   --  the client's certificate chain via the shared RFLX-backed
   --  helper, then transitions to Wait_Client_Cert_Verify (cert
   --  present) or Wait_Client_Finished (optional-mode empty cert).
   --  Returns Result = OK on success; otherwise emits the encrypted
   --  alert and sets Result to an Error_* action.
   procedure Handle_Client_Cert_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Data   : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Last >= 3
       and then Data'Last < N32'Last - 4
       and then Data'Last < Transcript_Capacity
       and then S.State = Wait_Client_Certificate;

   procedure Handle_Client_Cert_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Data   : in Byte_Seq;
      Result : out Action)
   is
      Parse_OK  : Boolean;
      Parse_Err : Error_Code;
   begin
      Result := OK;
      Append_Transcript (S.HC, Data);
      Handshake.TLS13.Parse_Certificate_Chain_13
        (HC                     => S.HC,
         D                      => D,
         HS_Msg                 => Data,
         Reject_Cert_Extensions => False,
         OK                     => Parse_OK,
         Err                    => Parse_Err);
      if not Parse_OK then
         Send_Encrypted_Alert (S, Parse_Err, Result);
         return;
      end if;

      if not D.Peer_Leaf.Present then
         if D.Peer_Leaf.DER_Len > 0 then
            Send_Encrypted_Alert (S, Decode_Error, Result);
            return;
         end if;
         if Cfg.Require_Client_Cert then
            --  RFC 8446 6 cert reject after server Finished  keys
            --  are live, MUST be encrypted alert.
            Send_Encrypted_Alert (S, Certificate_Required, Result);
            return;
         end if;
         Set_State (S, Wait_Client_Finished);
      else
         Set_State (S, Wait_Client_Cert_Verify);
      end if;
   end Handle_Client_Cert_13;

   --  RFC 8446 4.4.3 server-side mTLS CertificateVerify handler.
   --  Reconstructs the signed Content (64 spaces || ctx_str || 0x00
   --  || transcript_hash), verifies the client's signature against
   --  its leaf cert, runs trust-store chain validation if a Trust
   --  is configured, and transitions to Wait_Client_Finished on
   --  success.
   procedure Handle_Client_CertVerify_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg     : in Ready_Config;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Last < Transcript_Capacity
       and then X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1);

   procedure Handle_Client_CertVerify_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg     : in Ready_Config;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      H_Len   : constant N32 := Hash_Len (S.HC.Neg);
      CV_Hash : Byte_Seq (0 .. H_Len - 1);
   begin
      pragma Assert (X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
      Result := OK;
      --  Dispatch on the type-derived hash width (#117).
      if H_Len = 48 then
         CV_Hash := Transcript_Hash_384 (S.HC);
      else
         declare
            H : constant Digest := Transcript_Hash_256 (S.HC);
         begin
            CV_Hash := H;
         end;
      end if;

      Append_Transcript (S.HC, Data);

      declare
         Ctx_Str  : constant String := "TLS 1.3, client CertificateVerify";
         C_Len    : constant N32 := 64 + N32 (Ctx_Str'Length) + 1 + H_Len;
         Content  : Byte_Seq (0 .. C_Len - 1) := (others => 0);
         Verified : Boolean := False;
      begin
         Content (0 .. 63) := (others => 16#20#);
         for I in Ctx_Str'Range loop
            Content (64 + N32 (I - Ctx_Str'First)) := Byte (Character'Pos (Ctx_Str (I)));
         end loop;
         Content (64 + N32 (Ctx_Str'Length)) := 0;
         Content (64 + N32 (Ctx_Str'Length) + 1 .. 64 + N32 (Ctx_Str'Length) + H_Len) := CV_Hash;

         if Msg_Len >= 8 and then Data'Length >= 8 then
            declare
               Sig_Scheme : constant Maybe_Sig_Scheme :=
                 Scheme_From_Wire
                   (Unsigned_16 (Data (4)) * 256 + Unsigned_16 (Data (5)));
               Sig_Len    : constant N32 := N32 (Data (6)) * 256 + N32 (Data (7));
               Sig_Start  : constant N32 := 8;
            begin
               --  RFC 8446 4.2.3: rsa_pkcs1_* MUST NOT be used in
               --  TLS 1.3 CV.
               if Sig_Scheme in
                    Sig_RSA_PKCS1_SHA256 | Sig_RSA_PKCS1_SHA384 | Sig_RSA_PKCS1_SHA512
               then
                  Send_Encrypted_Alert (S, Illegal_Parameter, Result);
                  return;
               end if;

               if Cfg.Verify_Sig_Algo_Count > 0
                 and then not Sig_Scheme_In_List
                                (Sig_Scheme, Cfg.Verify_Sig_Algos, Cfg.Verify_Sig_Algo_Count)
               then
                  Send_Encrypted_Alert (S, Illegal_Parameter, Result);
                  return;
               end if;

               if Sig_Len > 0
                 and then Msg_Len = 4 + Sig_Len
                 and then Sig_Start + Sig_Len <= N32 (Data'Length)
               then
                  declare
                     Sig : Byte_Seq (0 .. Sig_Len - 1);
                  begin
                     Sig := Data (Sig_Start .. Sig_Start + Sig_Len - 1);
                     Verified :=
                       Cert_Verify.Verify_Signature
                         (Data       => Content,
                          Sig        => Sig,
                          Cert       => D.Peer_Leaf.Cert,
                          Sig_Scheme => Sig_Scheme);
                  end;
               else
                  Send_Encrypted_Alert (S, Decode_Error, Result);
                  return;
               end if;
            end;
         end if;

         if not Verified then
            Send_Encrypted_Alert (S, Certificate_Verify_Failed, Result);
            pragma Assert (S.Last_Error /= Unexpected_Message);
            return;
         end if;
      end;

      if D.Peer_Leaf.Present then
         declare
            Leaf_Last : constant X509.N32 := D.Peer_Leaf.DER_Len - 1;
            --  DER is X509.Byte_Seq (#101): validators take it directly.
            Cert_X    : X509.Byte_Seq renames D.Peer_Leaf.DER (0 .. Leaf_Last);
            VR        : Validation_Result;
         begin

            pragma Assert (Leaf_Last < X509.N32'Last);
            pragma Assert (D.Peer_Leaf.DER_Len - 1 < X509.N32'Last);

            VR :=
              Validate_Leaf_Policy
                (Leaf     => D.Peer_Leaf.Cert,
                 Leaf_DER => Cert_X (0 .. D.Peer_Leaf.DER_Len - 1),
                 Hostname => "",
                 Purpose  => Purpose_Client,
                 Mode     => Cfg.Verify_Mode);
            if VR /= Valid then
               Send_Encrypted_Alert (S, Bad_Certificate, Result);
               pragma Assert (S.Last_Error /= Unexpected_Message);
               return;
            end if;

            --  Skip_Verify is the explicit "require any client
            --  certificate" mode: enforce leaf policy and proof of
            --  possession, but do not require a trusted issuer chain.
            if not Cfg.Skip_Verify then
               if Cfg.Trust = null or else Cfg.Get_Time = null then
                  Send_Encrypted_Alert (S, Bad_Certificate, Result);
                  pragma Assert (S.Last_Error /= Unexpected_Message);
                  return;
               end if;

               VR :=
                 Validate_Chain
                   (Leaf_DER   => Cert_X (0 .. D.Peer_Leaf.DER_Len - 1),
                    Leaf       => D.Peer_Leaf.Cert,
                    Ints       => D.Peer_Ints,
                    Int_Count  => D.Peer_Int_Count,
                    Roots      => Cfg.Trust.Roots,
                    Root_Count => Cfg.Trust.Root_Count,
                    Now        => Cfg.Get_Time.all,
                    Hostname   => "",
                    Purpose    => Purpose_Client,
                    Mode       => Cfg.Verify_Mode);
               if VR /= Valid then
                  Send_Encrypted_Alert (S, Bad_Certificate, Result);
                  pragma Assert (S.Last_Error /= Unexpected_Message);
                  return;
               end if;
            end if;
         end;
      end if;

      Set_State (S, Wait_Client_Finished);
   end Handle_Client_CertVerify_13;

   ----------------------------------------------------------------------------
   --  Process_Client_Auth (mTLS)
   --
   --  Handles encrypted records containing the client's Certificate
   --  and CertificateVerify messages.
   ----------------------------------------------------------------------------
   procedure Process_Client_Auth
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data   => S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if Rec.Overflow then
         Send_Encrypted_Alert (S, Record_Overflow, Result);
         return;
      end if;

      if not Rec.OK then
         if Rec.Record_Len > 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Rec.Fragment_Len = 1 and then not S.HC.CCS_Received then
               S.HC.CCS_Received := True;
               Result := OK;
            else
               declare
                  Ignored_A : N32;
               begin
                  Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
               end;
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               if Output_Pending (S) > 0 then
                  Result := Has_Output;
               else
                  Result := Error_Alert;
               end if;
            end if;

         when Records.Content_Application_Data =>
            pragma Assert (Rec.Fragment_Len >= 1);
            pragma Assert (Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead);
            pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
            pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
            pragma Assert (Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos);
            pragma Assert (Rec.Record_Len <= Available (S.Input));

            declare
               Frag_Len   : constant N32 := Rec.Fragment_Len;
               Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
                 S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
               Hdr        : constant Byte_Seq (0 .. 4) :=
                 S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Frag_Len < Records.Tag_Size + 1 then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Error_Alert;
                  end if;
                  return;
               end if;

               Records.Decrypt_Record
                 (Encrypted  => Encrypted,
                  Record_Hdr => Hdr,
                  Keys       => S.HC.Client_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Error_Alert;
                  end if;
                  return;
               end if;

               if Inner_Type /= 16#16# then
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Error_Alert;
                  end if;
                  return;
               end if;

               if Plain_Len = 0 then
                  Send_Encrypted_Alert (S, Decode_Error, Result);
                  return;
               end if;

               declare
                  Msg_Type        : Maybe_HS_Msg;
                  Msg_Len         : N32;
                  Parse_OK        : Boolean;
                  Plain_Len_Const : constant N32 := Plain_Len;
                  Data            : constant Byte_Seq := Plaintext (0 .. Plain_Len_Const - 1);
               begin
                  Handshake.Parse_Handshake_Header (Data, Msg_Type, Msg_Len, Parse_OK);

                  if not Parse_OK then
                     --  Unknown handshake type is a state-machine error
                     --  (unexpected_message); malformed shape for a known
                     --  handshake type is decode_error.
                     declare
                        Raw_Type : constant Byte := (if Plain_Len_Const >= 1 then Data (0) else 0);
                        Is_Known : constant Boolean :=
                          Raw_Type in
                            16#01#
                            | 16#02#
                            | 16#04#
                            | 16#08#
                            | 16#0B#
                            | 16#0C#
                            | 16#0D#
                            | 16#0E#
                            | 16#0F#
                            | 16#10#
                            | 16#14#;
                     begin
                        Send_Encrypted_Alert
                          (S, (if Is_Known then Decode_Error else Unexpected_Message), Result);
                     end;
                     return;
                  end if;

                  if Plain_Len_Const < 4 then
                     Send_Encrypted_Alert (S, Decode_Error, Result);
                     return;
                  end if;

                  case S.State is
                     when Wait_Client_Certificate =>
                        if Msg_Type /= HT_Certificate then
                           Send_Encrypted_Alert (S, Unexpected_Message, Result);
                           return;
                        end if;
                        Handle_Client_Cert_13 (S, D, Cfg, Data, Result);

                     when Wait_Client_Cert_Verify =>
                        if Msg_Type /= HT_Certificate_Verify then
                           Send_Encrypted_Alert (S, Unexpected_Message, Result);
                           return;
                        end if;
                        --  RFC 8446 4.4.3: CertificateVerify is only legal
                        --  after a nonempty client Certificate. Fail closed;
                        --  the guard also unlocks Pool_Entry's predicate.
                        if not D.Peer_Leaf.Present then
                           Send_Encrypted_Alert (S, Unexpected_Message, Result);
                           return;
                        end if;
                        --  Lemma step (one hop from the predicate; the callee
                        --  Pre consumes the assumed result -- same pattern as
                        --  Validate_Client_Cert_12).
                        pragma
                          Assert
                            (X509.Spans_Valid
                               (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
                        Handle_Client_CertVerify_13 (S, D, Cfg, Data, Msg_Len, Result);

                     when others =>
                        S.Last_Error := Internal_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                  end case;
               end;
            end;

         when others =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Client_Auth;

   --  Fatal failure under the application/handshake write keys: emit an
   --  encrypted alert with the EXACT wire description Desc (the BoGo-checked
   --  codes here deliberately differ from the Alert_Desc (Err) mapping --
   --  e.g. decrypt_error (51) with Last_Error = Handshake_Failure), set the
   --  error state, and let the caller drain the alert first.
   procedure Fail_With_App_Alert
     (S : in out Session; Desc : in Byte; Err : in Error_Code; Result : out Action)
   --  RFC 8446 6.1: fatal (level 2) alerts exclude close_notify (0) and
   --  user_canceled (90) -- the emission predicate's Level-2 arm.
   with Pre => Desc /= 0 and then Desc /= 90
   is
      Ignored_A : N32;
   begin
      Records.Build_Alert_Record (2, Desc, S.Server_App, S.Output, Ignored_A);
      S.Last_Error := Err;
      Set_State (S, Error_State);
      if Output_Pending (S) > 0 then
         Result := Has_Output;
      else
         Result := Error_Alert;
      end if;
   end Fail_With_App_Alert;

   --  RFC 8446 4.4.4 client Finished check: constant-time compare of the
   --  received verify_data against HMAC (finished_key, transcript hash),
   --  widths following the suite hash.
   function Client_Finished_Verified
     (HC : in Handshake_Context; Suite : in Supported_Suite; Data : in Byte_Seq) return Boolean
   with
     Pre =>
       Data'First = 0
       and then (if Suite = Suite_AES_256_GCM_SHA384
                 then Data'Last >= 51
                 else Data'Last >= 35)
   is
      Verified : Boolean := False;
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               Pre_Hash : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (HC);
               Fin_Key  : OKM384_Seq (0 .. 47);
               Expected : Bytes_48;
            begin
               Key_Schedule.Derive_Finished_Key_384 (Fin_Key, HC.Client_HS_Secret);
               HMAC384.HMAC_SHA_384 (Output => Expected, M => Pre_Hash, K => Byte_Seq (Fin_Key));

               if Equal (Expected, Bytes_48 (Data (4 .. 51))) then
                  Verified := True;
               end if;
            end;

         when others =>
            declare
               Pre_Hash : constant Digest := Transcript_Hash_256 (HC);
               Fin_Key  : OKM_Seq (0 .. 31);
               Expected : Digest;
            begin
               Key_Schedule.Derive_Finished_Key (Fin_Key, HC.Client_HS_Secret (0 .. 31));
               HMAC_SHA_256 (Output => Expected, M => Pre_Hash, K => Byte_Seq (Fin_Key));

               if Equal (Expected, Bytes_32 (Data (4 .. 35))) then
                  Verified := True;
               end if;
            end;
      end case;
      return Verified;
   end Client_Finished_Verified;

   --  Resumption secrets (RFC 8446 7.1): derive res_master over the full
   --  transcript (through client Finished), the PSK from it, store in the
   --  session cache when callbacks are configured, and record res_master
   --  in the Session for later key material.
   procedure Store_Resumption_Secrets
     (S       : in out Session;
      Nonce   : in Byte_Seq;
      Age_Add : in Unsigned_32;
      TID     : out Ticket_ID)
   with Pre => Nonce'First = 0 and then Nonce'Last in 1 .. 254
   is
      use SPARKTLS.Ticket_Cache;
   begin
      TID := (others => 0);
   case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            Full_Hash  : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
            Res_Master : OKM384_Seq (0 .. 47);
            PSK_Out    : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Resumption_Master_Secret_384
              (Res_Master, S.HC.Master_Secret (0 .. 47), Full_Hash);
            Key_Schedule.Derive_PSK_384 (PSK_Out, Byte_Seq (Res_Master), Nonce);
            --  Store in cache
            if S.HC.Cfg.Store_Session /= null and then S.HC.Cfg.Lookup_Session /= null
            then
               pragma Warnings (Off, "value conversion implemented by copy");
               S.HC.Cfg.Store_Session
                 (Bytes_48 (PSK_Out), 48, Wire_Of (S.Negotiated_Suite), Age_Add, TID);
               pragma Warnings (On, "value conversion implemented by copy");
            end if;
            pragma Warnings (Off, "value conversion implemented by copy");
            S.Res_Master := Bytes_48 (Res_Master);
            pragma Warnings (On, "value conversion implemented by copy");
            S.Res_Master_Len := 48;
         end;

      when others =>
         declare
            Full_Hash  : constant Digest := Transcript_Hash_256 (S.HC);
            Res_Master : OKM_Seq (0 .. 31);
            PSK_Out    : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Resumption_Master_Secret
              (Res_Master, Digest (S.HC.Master_Secret (0 .. 31)), Full_Hash);
            Key_Schedule.Derive_PSK (PSK_Out, Byte_Seq (Res_Master), Nonce);
            if S.HC.Cfg.Store_Session /= null and then S.HC.Cfg.Lookup_Session /= null
            then
               declare
                  PSK_48 : Bytes_48 := (others => 0);
               begin
                  for I in N32 range 0 .. 31 loop
                     PSK_48 (I) := PSK_Out (I);
                  end loop;
                  S.HC.Cfg.Store_Session
                    (PSK_48, 32, Wire_Of (S.Negotiated_Suite), Age_Add, TID);
               end;
            end if;
            S.Res_Master := (others => 0);
            for I in N32 range 0 .. 31 loop
               S.Res_Master (I) := Res_Master (I);
            end loop;
            S.Res_Master_Len := 32;
         end;
   end case;
   end Store_Resumption_Secrets;

   --  NewSessionTicket (RFC 8446 4.6.1): issued only when the client
   --  signalled psk_dhe_ke (RFC 8446 4.2.9) and cache callbacks exist.
   --  Best-effort: if S.Output cannot hold it, the record is skipped and
   --  the AEAD counter stays in sync by construction.
   procedure Send_New_Session_Ticket_13
     (S       : in out Session;
      Nonce   : in Byte_Seq;
      Age_Add : in Unsigned_32;
      TID     : in Ticket_ID)
   with Pre => Nonce'First = 0 and then Nonce'Last >= 1
   is
      Enc_Out : N32;
   begin
      --  Build and send NewSessionTicket only if the
      --  client signalled psk_dhe_ke in psk_key_
      --  exchange_modes (RFC 8446 4.6.1 + 4.2.9).
      --  BoGo TLS13-ExpectNoSessionTicketOnBadKE
      --  Mode-Server checks that we DON'T issue NST
      --  when the client only offered psk_ke.
      if S.HC.Cfg.Store_Session /= null
        and then S.HC.Cfg.Lookup_Session /= null
        and then S.HC.PSK.Has_DHE_KE
      then
         declare
            --  NST format: type(1) + len(3) + lifetime(4) +
            --  age_add(4) + nonce_len(1) + nonce(2) +
            --  ticket_len(2) + ticket(16) + ext_len(2) +
            --  GREASE extension(4) + optional
            --  ticket_flags(7) = 39 or 46.
            --  We never emit the early_data extension
            --  0-RTT is intentionally out of scope (see
            --  Cfg.Resume_Ticket comment in sparktls.ads).
            Include_Flags : constant Boolean := S.HC.Cfg.TLS13_Resumption_Across_Names;
            NST_Total     : constant N32 := (if Include_Flags then 46 else 39);
            NST_Body_Len  : constant N32 := NST_Total - 4;
            NST_Ext_Len   : constant N32 := (if Include_Flags then 11 else 4);
            NST           : Byte_Seq (0 .. 45) := (others => 0);
         begin
            --  Handshake type: NewSessionTicket (0x04)
            NST (0) := 16#04#;
            --  Length: 35 or 42 bytes
            NST (1) := 0;
            NST (2) := 0;
            NST (3) := Byte (NST_Body_Len);
            --  ticket_lifetime: 3600 seconds (1 hour)
            NST (4) := 0;
            NST (5) := 0;
            NST (6) := 16#0E#;
            NST (7) := 16#10#;
            --  ticket_age_add
            NST (8) := Byte (Shift_Right (Age_Add, 24));
            NST (9) := Byte (Shift_Right (Age_Add, 16) and 16#FF#);
            NST (10) := Byte (Shift_Right (Age_Add, 8) and 16#FF#);
            NST (11) := Byte (Age_Add and 16#FF#);
            --  ticket_nonce_length: 2
            NST (12) := 2;
            --  ticket_nonce
            NST (13) := Nonce (0);
            NST (14) := Nonce (1);
            --  ticket_length: 16
            NST (15) := 0;
            NST (16) := 16;
            --  ticket (the cache ID)
            NST (17 .. 32) := TID;
            --  extensions_length: 4 or 11
            NST (33) := 0;
            NST (34) := Byte (NST_Ext_Len);
            --  GREASE extension 0x0a0a, empty body.
            NST (35) := 16#0A#;
            NST (36) := 16#0A#;
            NST (37) := 0;
            NST (38) := 0;
            if Include_Flags then
               --  ticket_flags extension (0x003E), body
               --  opaque flags<1..255>. Bit 8
               --  resumption_across_names is encoded as
               --  two minimally-encoded flag bytes: 00 01.
               NST (39) := 0;
               NST (40) := 16#3E#;
               NST (41) := 0;
               NST (42) := 3;
               NST (43) := 2;
               NST (44) := 0;
               NST (45) := 1;
            end if;

            --  NewSessionTicket is a post-handshake
            --  optimisation (RFC 8446 4.6.1); it is
            --  not required for handshake completion.
            --  If S.Output is too full to hold it,
            --  skip silently and roll back the AEAD
            --  counter so the next encrypted record
            --  on these keys keeps its nonce in sync
            --  with what the peer last received.
            --  No save/restore: Build's Post already
            --  guarantees the counter is unchanged when
            --  Bytes_Out = 0 (space checked before seal).
            Records.Build_Encrypted_Record
              (Plaintext  => NST (0 .. NST_Total - 1),
               Inner_Type => 16#16#,  --  handshake
               Keys       => S.Server_App,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);
         end;
      end if;
   end Send_New_Session_Ticket_13;

   procedure Verify_Client_Finished
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Msg_Len   : in N32;
      Result    : out Action) is
   begin
      Result := OK;
      --  Verify client Finished
      declare
         Plain_Len_Const : constant N32 := Plain_Len;
         Data            : constant Byte_Seq := Plaintext (0 .. Plain_Len_Const - 1);
         Expected_Len    : constant N32 :=
           (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384 then 48 else 32);
      begin
         --  Length must match exactly. RFC 8446 4.4.4
         --  Finished is the last handshake message in
         --  the client's first flight; any plaintext
         --  bytes after it in the same record is
         --  excess handshake data  fatal
         --  unexpected_message (BoGo
         --  TrailingDataWithFinished, expected error
         --  ":EXCESS_HANDSHAKE_DATA:" / "remote error:
         --  unexpected message"). Wrong inner Msg_Len
         --  (length declared in handshake header is too
         --  big due to trailing bytes in the message)
         --  is a Finished-verify failure â decrypt_error
         --  (BoGo TrailingMessageData-TLS13-ClientFinished
         --  expects ":DIGEST_CHECK_FAILED:" â alert 51).
         if Msg_Len /= Expected_Len then
            Fail_With_App_Alert (S, AD_Decrypt_Error, Certificate_Verify_Failed, Result);
            return;
         end if;
         if N32 (Data'Length) /= 4 + Expected_Len then
            Fail_With_App_Alert (S, AD_Unexpected_Message, Unexpected_Message, Result);
            return;
         end if;

         --  Length is correct: verify HMAC
         declare
            Verified : constant Boolean :=
              Client_Finished_Verified (S.HC, S.Negotiated_Suite, Data);
         begin
            if not Verified then
               Fail_With_App_Alert (S, AD_Decrypt_Error, Handshake_Failure, Result);
               return;
            end if;
         end;

         --  Client Finished verified.
         --  Append client Finished to transcript for res_master derivation
         Append_Transcript (S.HC, Data);

         --  Derive resumption master secret and send NewSessionTicket.
         --  A session ticket is optional, skipping it on the
         --  impossible branch fails SAFE, not closed.
         declare
            use SPARKTLS.Ticket_Cache;
            Ticket_Random : Byte_Seq (0 .. 5);
            Nonce         : Byte_Seq (0 .. 1);
            Age_Add       : Unsigned_32;
            TID           : Ticket_ID := (others => 0);
         begin
            S.HC.Cfg.Random.all (Ticket_Random);
            Nonce := Ticket_Random (0 .. 1);
            Age_Add :=
              Unsigned_32 (Ticket_Random (2)) * 2 ** 24
                + Unsigned_32 (Ticket_Random (3)) * 2 ** 16
              + Unsigned_32 (Ticket_Random (4)) * 2 ** 8
              + Unsigned_32 (Ticket_Random (5));

            Store_Resumption_Secrets (S, Nonce, Age_Add, TID);

            Send_New_Session_Ticket_13 (S, Nonce, Age_Add, TID);
         end;

         Set_State (S, Connected);
         S.Handshake_Just_Done := True;
         --  If there's pending output (e.g., NewSessionTicket),
         --  return Has_Output first so the caller drains it
         --  BEFORE we process any queued input records.
         if Output_Pending (S) > 0 then
            Result := Has_Output;
         else
            S.Handshake_Just_Done := False;
            Result := Handshake_Done;
         end if;
      end;
   end Verify_Client_Finished;

   procedure Handle_PCF_App_Data
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   is
      procedure Dispatch_Finished_Message (Data : in Byte_Seq; Len : in N32; Result : out Action)
      with
        Pre =>
          S.State = Wait_Client_Finished
          and then S.Role = Role_Server
          and then Data'First = 0
          and then Len > 0
          and then Data'Last < N32'Last
          and then Len - 1 <= Data'Last
      is
         Msg_Type : Maybe_HS_Msg;
         Msg_Len  : N32;
         Parse_OK : Boolean;
      begin
         Handshake.Parse_Handshake_Header (Data (0 .. Len - 1), Msg_Type, Msg_Len, Parse_OK);

         if not Parse_OK then
            --  Distinguish unknown-type (BoGo WrongMessageType injects
            --  type+42) from malformed shape. Unknown type â
            --  unexpected_message; otherwise decode_error.
            declare
               Raw_Type  : constant Byte := (if Len >= 1 then Data (0) else 0);
               Is_Known  : constant Boolean :=
                 Raw_Type in
                   16#01#
                   | 16#02#
                   | 16#04#
                   | 16#08#
                   | 16#0B#
                   | 16#0C#
                   | 16#0D#
                   | 16#0E#
                   | 16#0F#
                   | 16#10#
                   | 16#14#;
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record
                 (2, (if Is_Known then 50 else 10), S.Server_App, S.Output, Ignored_A);
               S.Last_Error := (if Is_Known then Decode_Error else Unexpected_Message);
            end;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         if Msg_Type /= HT_Finished then
            declare
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
            end;
            S.Last_Error := Unexpected_Message;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         Verify_Client_Finished (S, D, Data, Len, Msg_Len, Result);
      end Dispatch_Finished_Message;
   begin
      Result := OK;
      pragma Assert (Rec.Fragment_Len >= 1);
      pragma Assert (Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead);
      pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
      pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
      pragma Assert (Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos);
      pragma Assert (Rec.Record_Len <= Available (S.Input));
      declare
         Frag_Len   : constant N32 := Rec.Fragment_Len;
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
           S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
         Hdr        : constant Byte_Seq (0 .. 4) :=
           S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Frag_Len < Records.Tag_Size + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
            return;
         end if;

         --  RFC 8446 5.4: TLSInnerPlaintext MUST NOT exceed
         --  2^14 + 1 octets. Check before decrypting.
         if Frag_Len - Records.Tag_Size > Records.Max_Fragment + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert (S, Record_Overflow, Result);
            return;
         end if;

         Records.Decrypt_Record
           (Encrypted  => Encrypted,
            Record_Hdr => Hdr,
            Keys       => S.HC.Client_HS,
            Plaintext  => Plaintext,
            Plain_Len  => Plain_Len,
            Inner_Type => Inner_Type,
            Valid      => Dec_Valid);

         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not Dec_Valid then
            --  RFC 8446 4.2.10 / 4.6.1: 0-RTT is intentionally
            --  not supported by this stack. If a client tried
            --  it anyway (Early_Data_Offered set in CH), its
            --  records are encrypted with a key we never
            --  derived and won't decrypt with Client_HS. The
            --  RFC requires the server to silently drop those
            --  records and keep waiting for the client
            --  Finished (which uses Client_HS keys we do have).
            --  Bounded to defend against a buggy/malicious
            --  peer streaming garbage indefinitely.
            if S.HC.Early_Data_Offered and then S.HC.Skipped_Early_Data_Records < 32 then
               S.HC.Skipped_Early_Data_Records := S.HC.Skipped_Early_Data_Records + 1;
               Result := OK;
               return;
            end if;
            --  MAC failure or empty inner plaintext.
            --  Send alert with app keys (client switched to app
            --  keys after receiving our Finished).
            --  RFC 8446 5.2: bad_record_mac (20)
            declare
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record (2, AD_Bad_Record_MAC, S.Server_App, S.Output, Ignored_A);
            end;
            S.Last_Error := Bad_Record_MAC;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         if Inner_Type = 16#15# and then Plain_Len >= 2 then
            --  Peer sent alert
            S.Last_Error :=
              Error_Code'Val
                (Natural'Min (Natural (Plaintext (1)), Error_Code'Pos (Error_Code'Last)));
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         elsif Inner_Type /= 16#16# then
            --  Unexpected inner type during handshake
            declare
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
            end;
            S.Last_Error := Unexpected_Message;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         --  Parse handshake header
         if Plain_Len = 0 then
            Send_Encrypted_Alert (S, Decode_Error, Result);
            return;
         end if;

         if Used (D.Reasm) > 0 then
            declare
               Pos : N32 := 0;
            begin
               if not Has_Message (D.Reasm) then
                  declare
                     Take : constant HS_Msg_Len :=
                       N32'Min (N32'Min (Wanted (D.Reasm), Plain_Len), Free_Space (D.Reasm));
                  begin
                     if Take > 0 then
                        Append (D.Reasm, Plaintext (0 .. Take - 1));
                        Pos := Take;
                     end if;
                  end;
               end if;

               if Message_Too_Large (D.Reasm) then
                  Reset (D.Reasm);
                  Send_Encrypted_Alert (S, Decode_Error, Result);
                  return;
               end if;

               if not Has_Message (D.Reasm) and then Pos < Plain_Len then
                  declare
                     Take : constant HS_Msg_Len :=
                       N32'Min (N32'Min (Wanted (D.Reasm), Plain_Len - Pos), Free_Space (D.Reasm));
                  begin
                     if Take > 0 then
                        Append (D.Reasm, Plaintext (Pos .. Pos + Take - 1));
                        Pos := Pos + Take;
                     end if;
                  end;
               end if;

               if not Has_Message (D.Reasm) then
                  Result := OK;
                  return;
               end if;

               declare
                  Full     : constant Message_Bytes := Message (D.Reasm);
                  Full_Len : constant N32 := Full'Length;
               begin
                  Reset (D.Reasm);
                  Dispatch_Finished_Message (Byte_Seq (Full), Full_Len, Result);
               end;
               return;
            end;
         end if;

         if Plain_Len < 4 then
            Reset (D.Reasm);
            Append (D.Reasm, Plaintext (0 .. Plain_Len - 1));
            Result := OK;
            return;
         end if;

         declare
            HS_Total : constant N32 :=
              N32 (Plaintext (1)) * 65536 + N32 (Plaintext (2)) * 256 + N32 (Plaintext (3)) + 4;
         begin
            if HS_Total > Max_HS_Msg then
               Send_Encrypted_Alert (S, Decode_Error, Result);
               return;
            elsif HS_Total > Plain_Len then
               Reset (D.Reasm);
               Append (D.Reasm, Plaintext (0 .. Plain_Len - 1));
               Result := OK;
               return;
            end if;
         end;

         pragma Assert (Plain_Len > 0);
         pragma Assert (Plaintext'First = 0);
         pragma Assert (Plaintext'Last < N32'Last);
         pragma Assert (Plain_Len - 1 <= Plaintext'Last);
         Dispatch_Finished_Message (Plaintext, Plain_Len, Result);
      end;
   end Handle_PCF_App_Data;

   procedure Process_Client_Finished
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data   => S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if Rec.Overflow then
         Send_Encrypted_Alert (S, Record_Overflow, Result);
         return;
      end if;

      if not Rec.OK then
         if Rec.Record_Len > 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            --  CCS for middlebox compatibility.
            --  RFC 8446 Section 5: MUST be a single byte 0x01.
            --  Only one CCS is allowed per direction.
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Rec.Fragment_Len = 1 and then not S.HC.CCS_Received then
               S.HC.CCS_Received := True;
               Result := OK;
            else
               --  Invalid CCS (wrong length or duplicate)
               declare
                  Ignored_A : N32;
               begin
                  Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
               end;
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               if Output_Pending (S) > 0 then
                  Result := Has_Output;
               else
                  Result := Error_Alert;
               end if;
            end if;

         when Records.Content_Application_Data =>
            --  H_PCF_App_Data may need to emit one encrypted alert. If the
            --  output buffer cannot hold it, have the app drain first: the
            --  record stays buffered (Read_Pos untouched) and we re-enter.
            if Free_Space (S.Output)
              < Records.Record_Header_Size + 3 + Records.Tag_Size
            then
               Result := Has_Output;
            else
               Handle_PCF_App_Data (S, D, Rec, Result);
            end if;

         when others =>
            --  Plaintext handshake/alert records are not allowed here.
            --  RFC 8446 5.1: after ServerHello, all records MUST be
            --  encrypted (content type application_data or CCS).
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if Rec.Content = Records.Content_Alert then
               --  Plaintext alert during post-ServerHello handshake.
               --  Just close  do not respond.
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               Result := Error_Alert;
            else
               --  Send encrypted alert for other unexpected record types.
               Send_Encrypted_Alert (S, Unexpected_Message, Result);
            end if;
      end case;
   end Process_Client_Finished;

   --  Process records in Connected state
   ----------------------------------------------------------------------
   --  Post-handshake handshake messages (RFC 8446 4.6)
   --
   --  Until 2026-08-17 the server silently dropped every post-handshake
   --  handshake record ("when 16#16# => Result := OK;"). That was not
   --  merely a missing feature: a peer sending KeyUpdate would rotate its
   --  write key, the server would never rotate its matching read key, and
   --  every subsequent record failed to decrypt -- surfacing as an opaque
   --  bad_record_mac rather than anything diagnosable.
   --
   --  Messages may be fragmented across records (a hostile peer will split
   --  a 5-byte KeyUpdate deliberately), so this reassembles header-then-body
   --  exactly as the client side does.
   ----------------------------------------------------------------------

   procedure Reset_Post_HS_Reasm (S : in out Session)
   with Post => Post_HS_Reasm.Used (S.Post_HS) = 0;

   procedure Reset_Post_HS_Reasm (S : in out Session) is
   begin
      Post_HS_Reasm.Reset (S.Post_HS);
   end Reset_Post_HS_Reasm;

   --  RFC 8446 4.6.3. The peer's KeyUpdate rotates its WRITE key, which
   --  for a server is S.Client_App (our read direction). A request_update
   --  obliges us to rotate S.Server_App and say so before our next
   --  Application Data record.
   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in Byte_Seq;
      Suite  : in TLS13_Suite;
      Result : out Action)
   with
     Pre =>
       Msg'First = 0
       and then S.App_Secret_Len in 32 | 48;

   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in Byte_Seq;
      Suite  : in TLS13_Suite;
      Result : out Action) is
      Request   : Boolean;
      KU_Status : Key_Update.Parse_Status;
   begin
      Key_Update.Parse_Key_Update (Msg, Request, KU_Status);

      --  Two distinct failures carry two distinct alerts. Exhaustive
      --  case, no `others`: adding a Parse_Status literal must not be
      --  silently absorbed here.
      case KU_Status is
         when Key_Update.Parse_OK =>
            null;

         when Key_Update.Parse_Malformed =>
            --  RFC 8446 6.2: decode_error is "the length of the message
            --  was incorrect" -- a truncated or absent request_update.
            Send_Encrypted_Alert (S, Decode_Error, Result);
            return;

         when Key_Update.Parse_Bad_Value =>
            --  RFC 8446 4.6.3: a well-formed KeyUpdate whose
            --  request_update is outside {0,1} MUST be illegal_parameter.
            Send_Encrypted_Alert (S, Illegal_Parameter, Result);
            return;
      end case;

      --  Leaky bucket, drained by work actually done under the previous
      --  key. S.Client_App.Counter is our READ counter: it counts records
      --  read since the last rotation, so a peer that rekeyed after real
      --  traffic refunds a token here and can rekey indefinitely, while a
      --  peer spamming KeyUpdates back-to-back (counter ~0) refunds
      --  nothing and drains the bucket. See Max_Key_Updates in sparktls.ads
      --  for why a lifetime cap would be an interop bug.
      if S.Client_App.Counter >= Rekey_Refill_Records and then S.Key_Updates_Recvd > 0 then
         S.Key_Updates_Recvd := S.Key_Updates_Recvd - 1;
      end if;

      if S.Key_Updates_Recvd >= Max_Key_Updates then
         Send_Encrypted_Alert (S, Unexpected_Message, Result);
         return;
      end if;
      S.Key_Updates_Recvd := S.Key_Updates_Recvd + 1;

      --  Rotate the read direction; the peer has already switched.
      Key_Update.Update_Secret
        (Secret => S.Client_App_Secret,
         Len    => S.App_Secret_Len,
         TK     => S.Client_App,
         Suite  => Suite);

      if not Request then
         Result := OK;
         return;
      end if;

      --  RFC 8446 4.6.3 requires a reply "prior to sending its next
      --  Application Data record" -- the obligation is per-write, not
      --  per-message. Defer it: a burst of requests collapses to a single
      --  KeyUpdate, which is what the peer expects. Replying inline would
      --  make every reply after the first look unsolicited.
      S.Key_Update_Pending := True;
      Result := OK;
   end Process_Key_Update_Message;

   procedure Dispatch_Post_HS_Message (S : in out Session; Result : out Action)
   with Pre => Post_HS_Reasm.Has_Message (S.Post_HS), Post => Post_HS_Reasm.Used (S.Post_HS) = 0;

   procedure Dispatch_Post_HS_Message (S : in out Session; Result : out Action) is
      Msg_Len : constant N32 := Post_HS_Reasm.Message_Length (S.Post_HS);
      Msg     : constant Byte_Seq (0 .. Msg_Len - 1) :=
        Byte_Seq (Post_HS_Reasm.Message (S.Post_HS));
   begin
      if Msg (0) = Key_Update.HS_Key_Update then
         if S.App_Secret_Len in 32 | 48
           and then S.Client_App.Suite in TLS13_Suite
         then
            Process_Key_Update_Message
              (S, Msg, TLS13_Suite (S.Client_App.Suite), Result);
         else
            --  TLS 1.3 only; a TLS 1.2 session has no retained secret.
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         end if;
      else
         --  RFC 8446 4.6: a server legitimately receives few
         --  post-handshake messages. NewSessionTicket is server-to-client,
         --  and post-handshake client auth is not supported here, so
         --  anything else is unexpected rather than ignorable.
         Send_Encrypted_Alert (S, Unexpected_Message, Result);
      end if;
      Reset_Post_HS_Reasm (S);
   end Dispatch_Post_HS_Message;

   procedure Process_Post_HS_Handshake_Bytes
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
   with
     Pre =>
       S.State in Connected | Closing
       and then Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length);

   procedure Process_Post_HS_Handshake_Bytes
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
   is
      Pos : N32 := 0;
   begin
      Result := OK;

      while Pos < Plain_Len loop
         pragma Loop_Invariant (Pos <= Plain_Len);

         --  Same ADT idiom as the client twin: Wanted/Append derive all
         --  the old Len/Need bookkeeping; the phase flip is structural.
         declare
            use Post_HS_Reasm;
            Take : constant N32 :=
              N32'Min (N32'Min (Wanted (S.Post_HS), Free_Space (S.Post_HS)), Plain_Len - Pos);
         begin
            if Take > 0 then
               Append
                 (S.Post_HS, Plaintext (Plaintext'First + Pos .. Plaintext'First + Pos + Take - 1));
               Pos := Pos + Take;
            end if;

            if Message_Too_Large (S.Post_HS) or else (Take = 0 and then not Has_Message (S.Post_HS))
            then
               Reset (S.Post_HS);
               Send_Encrypted_Alert (S, Decode_Error, Result);
               return;
            end if;

            if Has_Message (S.Post_HS) then
               Dispatch_Post_HS_Message (S, Result);
               if Result /= OK then
                  return;
               end if;
            end if;
         end;
      end loop;
   end Process_Post_HS_Handshake_Bytes;

   procedure Process_Connected_13 (S : in out Session; Result : out Action) is
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
        (Data   => S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Avail  => Available (S.Input),
         Result => Rec);

      if Rec.Overflow then
         Send_Encrypted_Alert (S, Record_Overflow, Result);
         return;
      end if;

      if not Rec.OK then
         if Rec.Record_Len > 0 then
            --  Parsed successfully but unknown content type.
            --  RFC 8446 5: unexpected_message
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      if Rec.Content /= Records.Content_Application_Data then
         --  In Connected state, only application_data records are valid.
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if Rec.Content = Records.Content_Alert then
            --  RFC 8446 5.1: unencrypted alert after handshake.
            --  Just close  do not respond with an alert.
            S.Last_Error := Unexpected_Message;
            Set_State (S, Error_State);
            Result := Error_Alert;
         else
            --  CCS after Finished and other unexpected types get rejected.
            --  Send ENCRYPTED alert (we have application keys).
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         end if;
         return;
      end if;

      pragma Assert (Rec.Fragment_Len >= 1);
      pragma Assert (Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead);
      pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
      pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
      pragma Assert (Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos);
      pragma Assert (Rec.Record_Len <= Available (S.Input));

      declare
         Frag_Len   : constant N32 := Rec.Fragment_Len;
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
           S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
         Hdr        : constant Byte_Seq (0 .. 4) :=
           S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Frag_Len < Records.Tag_Size + 1 then
            --  Too short for AEAD tag + at least 1 byte of ciphertext
            --  (the inner content type byte). RFC 8446 5.4.
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            declare
               Ignored_Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,
                  Desc      => 10,  --  unexpected_message
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Ignored_Alert_Out);
            end;
            S.Last_Error := Unexpected_Message;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         --  RFC 8446 5.4: TLSInnerPlaintext MUST NOT exceed
         --  2^14 + 1 octets. Check before decrypting.
         if Frag_Len - Records.Tag_Size > Records.Max_Fragment + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            declare
               Ignored_Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,
                  Desc      => 22,  --  record_overflow
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Ignored_Alert_Out);
            end;
            S.Last_Error := Record_Overflow;
            Set_State (S, Error_State);
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
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
            --  MAC failure or empty inner plaintext (RFC 8446 5.2/5.4)
            --  Send encrypted bad_record_mac alert
            declare
               Ignored_Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,       --  fatal
                  Desc      => 20,      --  bad_record_mac
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Ignored_Alert_Out);
            end;
            Set_State (S, Error_State);
            S.Last_Error := Bad_Record_MAC;
            --  Return Has_Output to drain the alert before Error_Alert
            if Output_Pending (S) > 0 then
               --  RFC 8446 5.2: AEAD-failure invariant: alert
               --  queued, Error_State entered, Last_Error pinned
               --  to Bad_Record_MAC. No timing oracle leaked.
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
            return;
         end if;

         case Inner_Type is
            when 16#17# =>
               --  Application data
               if Post_HS_Reasm.Used (S.Post_HS) > 0 then
                  --  RFC 8446 5.1: "Handshake messages MUST NOT be
                  --  interleaved with other record types." A
                  --  post-handshake handshake message is mid-reassembly
                  --  (Post_HS_Need > 0), so an application_data record
                  --  arriving now splits it. Reject rather than buffer
                  --  the data and resume reassembly afterwards.
                  Send_Encrypted_Alert (S, Unexpected_Message, Result);
               elsif S.State = Closing and then Plain_Len > 0 then
                  Send_Encrypted_Alert (S, Unexpected_Message, Result);
               elsif Plain_Len > 0 and then S.App_Data_Len + Plain_Len <= S.App_Data'Length then
                  S.App_Data (S.App_Data_Len .. S.App_Data_Len + Plain_Len - 1) :=
                    Plaintext (0 .. Plain_Len - 1);
                  S.App_Data_Len := S.App_Data_Len + Plain_Len;
                  S.Empty_Records_Recvd := 0;
                  Result := Plaintext_Ready;
               else
                  --  Empty plaintext record  count + cap (BoGo
                  --  SendEmptyRecords / TOO_MANY_EMPTY_FRAGMENTS).
                  --  Check BEFORE incrementing: the counter then never exceeds the
                  --  cap, so the bound holds BY CONSTRUCTION rather than being
                  --  asserted. Behaviour is identical (the same alert/record
                  --  triggers the error either way) and it is what makes the
                  --  narrowed field subtype and its AoRTE check provable.
                  if S.Empty_Records_Recvd >= Max_Empty_Records then
                     declare
                        Ignored_A : N32;
                     begin
                        Records.Build_Alert_Record (2, AD_Unexpected_Message, S.Server_App, S.Output, Ignored_A);
                     end;
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
                  else
                     S.Empty_Records_Recvd := S.Empty_Records_Recvd + 1;
                     Result := OK;
                  end if;
               end if;

            when 16#16# =>
               --  RFC 8446 4.6 post-handshake handshake message. Until
               --  2026-08-17 this was "Result := OK" -- silently dropped,
               --  which broke any peer that sent KeyUpdate: it rotated its
               --  write key, we never rotated the matching read key, and
               --  every later record failed to decrypt as bad_record_mac.
               --  MUST also run while Closing. BoGo's
               --  Shutdown-Shim-KeyUpdate is explicit about this ("test
               --  that SSL_shutdown still processes KeyUpdate"): the peer
               --  rotates its write key when it sends the KeyUpdate, so a
               --  shim that skips it can no longer decrypt anything that
               --  follows -- including the close_notify it is waiting for.
               if S.State in Connected | Closing then
                  Process_Post_HS_Handshake_Bytes (S, Plaintext, Plain_Len, Result);
               else
                  Result := OK;
               end if;

            when 16#15# =>
               --  Alert. RFC 8446 6 / RFC 5246 7.2: 2-byte payload
               --  `level | description`. Validate level, distinguish
               --  close_notify, tolerate user_canceled (with cap),
               --  reject every other warning with decode_error, and
               --  reject bogus levels with illegal_parameter.
               if Plain_Len < 2 then
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record (2, AD_Decode_Error, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
               elsif Plaintext (0) /= 1 and Plaintext (0) /= 2 then
                  --  Bogus level (BoGo SendBogusAlertType: 0x42).
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record (2, AD_Illegal_Parameter, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Illegal_Parameter;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
               elsif Plaintext (1) = 0 then
                  --  close_notify  reply in kind (warning level 1).
                  --
                  --  RFC 8446 6.1: record the orderly close so the
                  --  application can tell a finished stream from a
                  --  truncated one.
                  S.Peer_Closed_Cleanly := True;
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (Level     => 1,
                        Desc      => 0,
                        Keys      => S.Server_App,
                        Output    => S.Output,
                        Bytes_Out => Ignored_A);
                  end;
                  if S.State = Connected then
                     Set_State (S, Closing);
                  end if;
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Shutdown;
                  end if;
               elsif Plaintext (0) = 1 then
                  --  Warning-level alert (level=1) other than
                  --  close_notify. RFC 8446 6.1 deprecates these
                  --  but keeps user_canceled for back-compat.
                  if Plaintext (1) = 90 then
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                        declare
                           Ignored_A : N32;
                        begin
                           Records.Build_Alert_Record (2, AD_Decode_Error, S.Server_App, S.Output, Ignored_A);
                        end;
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
                     else
                        S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
                        Result := OK;
                     end if;
                  else
                     declare
                        Ignored_A : N32;
                     begin
                        Records.Build_Alert_Record (2, AD_Decode_Error, S.Server_App, S.Output, Ignored_A);
                     end;
                     S.Last_Error := Decode_Error;
                     Set_State (S, Error_State);
                     Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
                  end if;
               else
                  --  Fatal alert from peer (level=2): close without
                  --  reply per RFC 8446 6.2 (no alerts about alerts).
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               end if;

            when others =>
               --  Invalid inner content type (including zero).
               --  RFC 8446 5.4: unexpected_message
               Send_Encrypted_Alert (S, Unexpected_Message, Result);
         end case;
      end;
   end Process_Connected_13;

   procedure Advance_Handshake_13
     (S      : in out Server_Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Result : out Action) is
   begin
      if S.HC.Cfg not in Ready_Config
        or else S.Negotiated_Suite not in TLS13_Suite
      then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      case S.State is
         when Server_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               if S.HC.Cfg.Request_Client_Cert and not S.HC.Using_PSK then
                  Set_State (S, Wait_Client_Certificate);
               else
                  Set_State (S, Wait_Client_Finished);
               end if;
               Result := (if Input_Available (S) > 0 then OK else Need_Input);
            end if;

         when Wait_Client_Hello_Retry =>
            Handle_Client_Hello_Retry (S, D, Result);

         when Wait_Client_Certificate | Wait_Client_Cert_Verify =>
            declare
               C : constant Ready_Config := S.HC.Cfg;
            begin
               Process_Client_Auth (S, D, C, Result);
            end;

         when Wait_Client_Finished =>
            Process_Client_Finished (S, D, Result);

         when others =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake_13;

end SPARKTLS.Server.TLS13;
