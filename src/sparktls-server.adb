with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;               use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HKDF;              use SPARKTLSCrypto.HKDF;

with SPARKTLSCrypto.Ed25519;
with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Key_Schedule;
with SPARKTLS.HC_Alloc;
with X509;
use type X509.Algorithm_ID;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
use SPARKTLSCrypto;
with SPARKTLS.Ticket_Cache;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Server.TLS12;

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

   procedure Build_Hello_Retry_Request
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Group     : in     Unsigned_16;
      HRR_Buf   :    out Byte_Seq;
      HRR_Len   :    out N32;
      Rec_Out   :    out N32);

   procedure Process_Client_Auth
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State in Wait_Client_Certificate | Wait_Client_Cert_Verify;

   procedure Process_Client_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Client_Finished
               and Nonce_Space_Available (S.Server_App);
   procedure Handle_PCF_App_Data
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action);
   procedure Verify_Client_Finished
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Msg_Len   : in     N32;
      Result    :    out Action);



   procedure Process_Connected (S : in out Session; Result : out Action);

   procedure Derive_Handshake_Keys
     (S  : in     Session;
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256;

   procedure Derive_App_Keys
     (S  : in out Session;
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256;

   procedure Set_Traffic_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16)
   with Pre => Suite in Suite_AES_128_GCM_SHA256
                      | Suite_AES_256_GCM_SHA384
                      | Suite_CHACHA20_POLY1305_SHA256;

   --  Alert_Desc / Error_Code mapping is in the parent SPARKTLS
   --  package — child-unit visibility resolves call sites here.

   --  Send a fatal alert and set error state
   procedure Send_Alert_And_Error
     (S      : in out Session;
      Err    : Error_Code;
      Result : out Action)
   with Pre => S.State not in Idle | Closed | Closing | Error_State
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

   --  Map S.Last_Error (set by Parse_Client_Hello) to the right
   --  fatal-alert code and queue it. Centralises the per-error
   --  mapping for the CH-parse failure paths in Process_Server so
   --  adding a new surface-able Error_Code only requires one new
   --  arm in this table, not edits at every parse-dispatch site.
   --  Errors not in the known set fall back to Handshake_Failure
   --  (alert 40) per RFC 8446 §6.
   procedure Dispatch_CH_Parse_Error_Alert
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State not in Idle | Closed | Closing | Error_State;

   procedure Dispatch_CH_Parse_Error_Alert
     (S      : in out Session;
      Result :    out Action)
   is
   begin
      case S.Last_Error is
         when Decode_Error
            | Unexpected_Message
            | Protocol_Version
            | Illegal_Parameter
            | Certificate_Verify_Failed  --  RFC 8446 §4.2.11.2 PSK binder
            | Missing_Extension          --  RFC 8446 §4.2.9 PSK without KE_modes
         =>
            Send_Alert_And_Error (S, S.Last_Error, Result);
         when others =>
            Send_Alert_And_Error (S, Handshake_Failure, Result);
      end case;
   end Dispatch_CH_Parse_Error_Alert;

   --  Send an encrypted fatal alert and set error state.
   --  Used when application/handshake keys are established.
   --  RFC 8446 §6.2 / RFC 5246 §7.2.2: encrypted fatal alert is
   --  sent before the connection terminates so the peer learns the
   --  reason instead of seeing only a TCP RST.
   procedure Send_Encrypted_Alert
     (S      : in out Session;
      Err    : Error_Code;
      Result : out Action)
   with Pre  => S.State not in Idle | Closed | Closing | Error_State
                and Alert_Desc (Err) /= 0
                and Nonce_Space_Available (S.Server_App),
        Post => S.State = Error_State
                and S.Last_Error = Err
                --  Error_Has_Alert (Pending > 0 OR Err = Unexpected_Message)
                --  is NOT in this Post: Records.Build_Alert_Record gives no
                --  postcondition about Output_Pending, so we can't carry
                --  "alert was queued" through proof. Call sites that need
                --  it add a pragma Assert (Output_Pending (S) > 0) before
                --  the bridging Cert/Finished/AEAD-class predicate.
   is
      Dummy : N32;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
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
   --  RFC 5246 §7.4.9 / RFC 8446 §4.4.1: append-only invariant
   --  (transcript drives Finished verify_data).
   procedure Append_Transcript
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq)
   with Pre  => (if Data'First <= Data'Last then
                    Data'Last - Data'First < Transcript_Capacity)
                and HC.Transcript_Len <= Transcript_Capacity,
        Post => HC.Transcript_Len >= HC.Transcript_Len'Old
   is
   begin
      if Data'First <= Data'Last then
         declare
            Len : constant N32 := Data'Last - Data'First + 1;
         begin
            if HC.Transcript_Len <= HC.Transcript'Length - Len then
               HC.Transcript (HC.Transcript_Len ..
                                HC.Transcript_Len + Len - 1) := Data;
               HC.Transcript_Len := HC.Transcript_Len + Len;
            end if;
         end;
      end if;
   end Append_Transcript;

   function Transcript_Hash_256 (HC : Handshake_Context) return Digest
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
   is
      H : Digest;
   begin
      Hash (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (HC : Handshake_Context)
      return SPARKNaCl.Hashing.SHA384.Digest
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKNaCl.Hashing.SHA384.Hash
        (H, HC.Transcript (0 .. HC.Transcript_Len - 1));
      return H;
   end Transcript_Hash_384;

   procedure Configure
     (S                     : out Session;
      Local                 : Identity_Access;
      Random                : Random_Bytes_Fn;
      Trust                 : Trust_Store_Access := null;
      Request_Client_Cert   : Boolean := False;
      Require_Client_Cert   : Boolean := False;
      Tickets               : Ticket_Store_Access := null;
      ALPN                  : String := "";
      Versions              : Version_Policy := Allow_Both;
      TLS12_Ticket_Keys     : TLS12_Ticket_Keys_Access := null;
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;
      Get_Time              : Get_Time_Fn := null;
      Select_Identity       : SNI_Cert_Selector := null;
      Auto_Rotate_TEK            : Boolean := True;
      TEK_Rotation_Interval_Secs : Unsigned_32 := 24 * 3600)
   with SPARK_Mode => Off
   is
      Cfg : Config;
   begin
      Cfg.Random              := Random;
      Cfg.Local               := Local;
      Cfg.Trust               := Trust;
      Cfg.Request_Client_Cert := Request_Client_Cert;
      Cfg.Require_Client_Cert := Require_Client_Cert;
      Cfg.Ticket_Store        := Tickets;
      Cfg.Versions            := Versions;
      Cfg.TLS12_Ticket_Keys   := TLS12_Ticket_Keys;
      Cfg.TLS12_Ticket_Lifetime := TLS12_Ticket_Lifetime;
      Cfg.Get_Time            := Get_Time;
      Cfg.Select_Identity     := Select_Identity;
      Cfg.Auto_Rotate_TEK            := Auto_Rotate_TEK;
      Cfg.TEK_Rotation_Interval_Secs := TEK_Rotation_Interval_Secs;
      if ALPN'Length > 0 and then ALPN'Length <= Max_Hostname_Len then
         Cfg.ALPN.Data (1 .. ALPN'Length) := ALPN;
         Cfg.ALPN.Len := ALPN'Length;
      end if;
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
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         return;
      end if;
      S.HC_Ptr.Cfg := Cfg;
   end Init;

   procedure Rotate_TLS12_Ticket_Key
     (Keys       : in out TLS12_Ticket_Key_Array;
      Active_Idx : in out Natural;
      New_Key_ID : in     Byte_Seq;
      New_TEK    : in     Byte_Seq;
      Now_Secs   : in     Interfaces.Unsigned_64)
   is
      New_Idx : constant Natural :=
         (Active_Idx + 1) mod TLS12_Max_Keys;
   begin
      --  Slot layout after rotation:
      --    Active_Idx   = previously-active key (kept Valid for
      --                   incoming-ticket decrypt during grace).
      --    New_Idx      = newly-installed active key.
      --    Other slots  = whatever they were (Valid or not).
      --
      --  The oldest key in the rotation is whichever slot New_Idx
      --  was previously pointing at — it gets overwritten here. Its
      --  decrypt grace ended at this moment; tickets issued under
      --  it will no longer resume. After TLS12_Max_Keys rotations
      --  the original key is fully purged.
      Keys (New_Idx) :=
        (Key_ID     => New_Key_ID,
         TEK        => New_TEK,
         Valid      => True,
         Created_At => Now_Secs);
      Active_Idx := New_Idx;
   end Rotate_TLS12_Ticket_Key;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with SPARK_Mode => Off
   is
   begin
      case S.State is
         when Connected =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            elsif S.Handshake_Just_Done then
               --  Deliver Handshake_Done after output is drained.
               --  This ensures the caller knows the handshake completed
               --  and has drained all pending output (NSTs) before
               --  we process any queued input records.
               S.Handshake_Just_Done := False;
               Result := Handshake_Done;
            else
               if S.Negotiated_Version = TLS_1_2 then
                  SPARKTLS.Server.TLS12.Process_Connected_12 (S, Result);
               else
                  Process_Connected (S, Result);
               end if;
            end if;

         when Closing =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               --  Zero traffic keys before closing
               S.Server_App.Key := (others => 0);
               S.Server_App.IV := (others => 0);
               S.Client_App.Key := (others => 0);
               S.Client_App.IV := (others => 0);
               Set_State (S, Closed);
               Result := Shutdown;
            end if;

         when Error_State =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.Server_App.Key := (others => 0);
               S.Server_App.IV := (others => 0);
               S.Client_App.Key := (others => 0);
               S.Client_App.IV := (others => 0);
               Set_State (S, Closed);
               Result := Error_Alert;
            end if;

         when Closed | Idle =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;

         when others =>
            if S.HC_Ptr = null then
               S.Last_Error := Internal_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Advance_Handshake (S, S.HC_Ptr.all, Result);

            if S.State in Connected | Error_State | Closed then
               S.Peer_Cert_Valid := S.HC_Ptr.Peer_Cert_Valid;
               --  Zero ALL key material before freeing HC.
               S.HC_Ptr.Shared_Secret := (others => 0);
               S.HC_Ptr.Client_HS_Secret := (others => 0);
               S.HC_Ptr.Server_HS_Secret := (others => 0);
               S.HC_Ptr.Handshake_Secret := (others => 0);
               S.HC_Ptr.Master_Secret := (others => 0);
               S.HC_Ptr.Master_Secret_12 := (others => 0);
               S.HC_Ptr.Local_SK := (others => 0);
               S.HC_Ptr.P256_Local_SK := (others => 0);
               S.HC_Ptr.P384_Local_SK := (others => 0);
               S.HC_Ptr.Transcript
                 (0 .. S.HC_Ptr.Transcript_Len) := (others => 0);
               S.HC_Ptr.Transcript_Len := 0;
               S.HC_Ptr.PSK_Value := (others => 0);
               S.HC_Ptr.PSK_Binder := (others => 0);
               S.HC_Ptr.PSK_Ticket_ID := (others => 0);
               S.HC_Ptr.Client_Random := (others => 0);
               S.HC_Ptr.Server_Random := (others => 0);
               Free_Byte_Seq (S.HC_Ptr.Reasm_Buf);
               HC_Alloc.Free (S.HC_Ptr);
            end if;
      end case;
   end Advance;

   --  RFC 8446 §4.1.2 Wait_Client_Hello state handler. Reads a TLS
   --  record, validates header, runs RFLX-based reassembly for any
   --  multi-record handshake message, decodes the ClientHello body,
   --  populates HC fields (random, cipher suites, key shares, ext
   --  policy, etc.), and transitions to Wait_Client_Hello_Retry or
   --  the ServerHello-build path on success. Pulled out of the giant
   --  Advance_Handshake case dispatch so SPARK can prove each
   --  protocol state's logic in isolation.
   procedure Handle_Wait_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Client_Hello;

   procedure Handle_Wait_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
            if Input_Available (S) = 0 then
               Result := Need_Input;
               return;
            end if;

            --  Parse ClientHello from input. RFC 8446 §5.1 / RFC 5246
            --  §E.1: tolerate any record version on the initial CH —
            --  BoGo LooseInitialRecordVersion sends 0x03ff and expects
            --  the server to accept it. Major byte must still be 0x03
            --  (GarbageInitialRecordVersion sends 0xffff and expects
            --  WRONG_VERSION_NUMBER).
            declare
               Rec : Records.Parse_Result;
            begin
               Records.Parse_Record_Header
                 (Data         => S.Input.Data (S.Input.Read_Pos ..
                                                  S.Input.Write_Pos - 1),
                  Avail        => Available (S.Input),
                  Result       => Rec,
                  Loose_Initial => True);

               if Rec.Overflow then
                  Send_Alert_And_Error (S, Record_Overflow, Result);
                  return;
               end if;

               if Rec.Bad_Version then
                  --  RFC 8446 §5.1: legacy_record_version must lie
                  --  in {3,1}..{3,4}. Out-of-band → protocol_version.
                  Send_Alert_And_Error (S, Protocol_Version, Result);
                  return;
               end if;

               if not Rec.OK then
                  if Rec.Record_Len > 0 then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  else
                     Result := Need_Input;
                  end if;
                  return;
               end if;

               if Rec.Content = Records.Content_Change_Cipher_Spec then
                  --  RFC 8446 §5: CCS for middlebox compatibility is
                  --  permitted only AFTER the first ClientHello has
                  --  been sent or received. CCS arriving before any
                  --  ClientHello (we're still in Wait_Client_Hello)
                  --  is a state-machine violation. TLS-Anvil's
                  --  beginWithChangeCipherSpec test (XSM-1yXVP5Gbsr)
                  --  exercises this.
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
                  return;
               end if;

               if Rec.Content = Records.Content_Alert then
                  --  Plaintext alert before handshake — just close
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

               if Rec.Content /= Records.Content_Handshake then
                  --  Application_data or unknown type before handshake
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
                  return;
               end if;

               declare
                  Frag_Start : constant N32 :=
                     S.Input.Read_Pos + Rec.Fragment_Pos;
                  Frag_Len   : constant N32 := Rec.Fragment_Len;
                  Parse_OK   : Boolean;

                  --  Maximum handshake message we'll reassemble (128 KB).
                  --  Larger messages are rejected.
                  Max_HS_Msg : constant N32 := 131072;

                  procedure Free_Reasm is
                  begin
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0;
                     HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                  end Free_Reasm;
               begin
                  --  Check if we're in the middle of reassembly
                  if HC.Reasm_Need > 0 then
                     --  Append this fragment to the reassembly buffer
                     declare
                        Copy_Len : constant N32 :=
                           N32'Min (Frag_Len,
                                    HC.Reasm_Need - HC.Reasm_Len);
                     begin
                        if HC.Reasm_Buf /= null and then
                           HC.Reasm_Len + Copy_Len <=
                              N32 (HC.Reasm_Buf'Length)
                        then
                           HC.Reasm_Buf
                             (HC.Reasm_Len ..
                              HC.Reasm_Len + Copy_Len - 1) :=
                              S.Input.Data (Frag_Start ..
                                            Frag_Start + Copy_Len - 1);
                           HC.Reasm_Len := HC.Reasm_Len + Copy_Len;
                        end if;
                     end;
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                     --  Header-pending sentinel: once 4 bytes are
                     --  present, decode the actual HS_Total and
                     --  upgrade Reasm_Need.
                     if HC.Reasm_Hdr_Pending
                       and then HC.Reasm_Len >= 4
                       and then HC.Reasm_Buf /= null
                     then
                        declare
                           HS_Total : constant N32 :=
                              N32 (HC.Reasm_Buf (1)) * 65536
                              + N32 (HC.Reasm_Buf (2)) * 256
                              + N32 (HC.Reasm_Buf (3)) + 4;
                        begin
                           HC.Reasm_Hdr_Pending := False;
                           if HS_Total < 4 or HS_Total > Max_HS_Msg then
                              Free_Reasm;
                              Send_Alert_And_Error
                                (S, Decode_Error, Result);
                              return;
                           end if;
                           HC.Reasm_Need := HS_Total;
                        end;
                     end if;

                     if HC.Reasm_Len < HC.Reasm_Need then
                        --  Still need more fragments
                        Result := OK;
                        return;
                     end if;

                     --  Full message reassembled — parse it.
                     --  The reassembly path already enforces
                     --  HS_Total <= Max_HS_Msg (line 465 above), so
                     --  Reasm_Len cannot exceed Max_HS_Msg here. The
                     --  guard is defensive: it lets Parse_Client_Hello's
                     --  Pre be discharged without proving the entire
                     --  reassembly invariant chain in one go.
                     if HC.Reasm_Len = 0
                       or HC.Reasm_Len > N32 (Max_HS_Msg)
                     then
                        Free_Reasm;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        return;
                     end if;
                     declare
                        R_Len : constant N32 := HC.Reasm_Len;
                        Full_Msg : constant Byte_Seq :=
                           HC.Reasm_Buf (0 .. R_Len - 1);
                     begin
                        Handshake.Server_Msgs.Parse_Client_Hello
                          (S, HC, Full_Msg, Parse_OK);
                        if Parse_OK then
                           Append_Transcript (HC, Full_Msg);
                        end if;
                     end;
                     Free_Reasm;

                     if not Parse_OK then
                        Dispatch_CH_Parse_Error_Alert (S, Result);
                        return;
                     end if;

                  else
                     --  Fresh handshake record. Check if the message
                     --  spans multiple records by reading the 3-byte
                     --  handshake length.
                     if Frag_Len < 4 then
                        --  RFC 8446 §5.1: handshake messages MAY span
                        --  records. The first fragment is shorter than
                        --  the 4-byte HS header itself — start
                        --  reassembly with a header-pending sentinel.
                        --  The reassembly path decodes the real
                        --  HS_Total once 4 bytes are accumulated.
                        if Frag_Len = 0 then
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           Send_Alert_And_Error
                             (S, Decode_Error, Result);
                           return;
                        end if;
                        HC.Reasm_Buf := new Byte_Seq'
                           (0 .. Max_HS_Msg - 1 => 0);
                        HC.Reasm_Need := 4;
                        HC.Reasm_Hdr_Pending := True;
                        HC.Reasm_Len := Frag_Len;
                        HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                           S.Input.Data (Frag_Start ..
                                         Frag_Start + Frag_Len - 1);
                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        Result := OK;
                        return;
                     end if;

                     declare
                        HS_Msg_Len : constant N32 :=
                           N32 (S.Input.Data (Frag_Start + 1)) * 65536 +
                           N32 (S.Input.Data (Frag_Start + 2)) * 256 +
                           N32 (S.Input.Data (Frag_Start + 3));
                        HS_Total   : constant N32 := HS_Msg_Len + 4;
                     begin
                        if HS_Total > Max_HS_Msg then
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           Send_Alert_And_Error
                             (S, Decode_Error, Result);
                           return;
                        end if;

                        if HS_Total > Frag_Len then
                           --  Message spans multiple records.
                           --  Start reassembly.
                           HC.Reasm_Buf := new Byte_Seq'
                              (0 .. HS_Total - 1 => 0);
                           HC.Reasm_Need := HS_Total;
                           HC.Reasm_Len := Frag_Len;
                           HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                              S.Input.Data (Frag_Start ..
                                            Frag_Start + Frag_Len - 1);
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           Result := OK;
                           return;
                        end if;
                     end;

                     --  Single-record message — parse directly.
                     --  Copy (not rename) to avoid SPARK aliasing between
                     --  the Frag parameter and the in-out Session global.
                     declare
                        Frag : constant Byte_Seq :=
                           S.Input.Data (Frag_Start ..
                                         Frag_Start + Frag_Len - 1);
                     begin
                        Handshake.Server_Msgs.Parse_Client_Hello
                          (S, HC, Frag, Parse_OK);

                        if not Parse_OK then
                           Dispatch_CH_Parse_Error_Alert (S, Result);
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           return;
                        end if;

                        Append_Transcript (HC, Frag);
                     end;
                     S.Input.Read_Pos :=
                        S.Input.Read_Pos + Rec.Record_Len;
                  end if;

                  --  RFC 6066 §3 + RFC 8446 §4.4.2.4: SNI-based
                  --  certificate selection. When a Select_Identity
                  --  callback is installed and the client sent a
                  --  non-empty server_name, ask the callback to map
                  --  the hostname to an Identity. A non-null result
                  --  replaces HC.Cfg.Local for this session — all
                  --  subsequent cert chain build / signing uses it.
                  --  A null result means "no match"; we fall back to
                  --  HC.Cfg.Local (the default identity), matching
                  --  openssl's permissive behaviour rather than
                  --  raising `unrecognized_name`.
                  if HC.Cfg.Select_Identity /= null
                    and then HC.Peer_SNI.Len > 0
                  then
                     declare
                        Picked : constant Identity_Access :=
                           HC.Cfg.Select_Identity
                             (HC.Peer_SNI.Data
                                (HC.Peer_SNI.Data'First ..
                                 HC.Peer_SNI.Data'First
                                   + HC.Peer_SNI.Len - 1));
                     begin
                        if Picked /= null then
                           HC.Cfg.Local := Picked;
                        end if;
                     end;
                  end if;

                  --  Version negotiation: dispatch based on HC.Version
                  --  (set by Parse_Client_Hello from supported_versions)
                  --  and the configured Version_Policy.
                  declare
                     Policy : constant Version_Policy := HC.Cfg.Versions;
                     Want_13 : constant Boolean :=
                        HC.Version = TLS_1_3
                        and Policy /= TLS_1_2_Only;
                     Want_12 : constant Boolean :=
                        (HC.Version = TLS_1_2
                         or (HC.Version = TLS_1_3
                             and Policy = TLS_1_2_Only))
                        and Policy /= TLS_1_3_Only;
                  begin
                     if Want_13 then
                        --  TLS 1.3 requires a TLS 1.3 cipher suite
                        --  and at least one supported ECDHE group
                        --  (from supported_groups OR key_share)
                        if S.Negotiated_Suite = 0 or else
                           not (HC.Client_Has_X25519 or
                                HC.Client_Has_P256 or
                                HC.Client_Has_P384 or
                                HC.Client_Supports_X25519 or
                                HC.Client_Supports_P256 or
                                HC.Client_Supports_P384)
                        then
                           if Want_12 and S.Negotiated_Suite_12 /= 0 then
                              --  Fall back to TLS 1.2
                              HC.Version := TLS_1_2;
                              SPARKTLS.Server.TLS12.Build_Server_Flight_12
                                (S, HC, Result);
                           else
                              Send_Alert_And_Error
                                (S, Handshake_Failure, Result);
                           end if;
                        else
                           Build_Server_Flight (S, HC, Result);
                        end if;
                     elsif Want_12 and S.Negotiated_Suite_12 /= 0 then
                        HC.Version := TLS_1_2;
                        SPARKTLS.Server.TLS12.Build_Server_Flight_12
                          (S, HC, Result);
                     else
                        --  No matching version/suite. Distinguish a
                        --  pure version-policy violation (the client
                        --  offered a version outside our allowed set)
                        --  from "no shared cipher": when our Cfg.
                        --  Versions excludes the client's negotiated
                        --  version, RFC 5246 §7.2.2 / RFC 8446 §6 say
                        --  emit protocol_version (alert 70), not
                        --  handshake_failure (40). BoGo's MinimumVersion-
                        --  Server2-TLS13-TLS12 expects 70.
                        if (HC.Version = TLS_1_2 and Policy = TLS_1_3_Only)
                          or else
                           (HC.Version = TLS_1_3 and Policy = TLS_1_2_Only)
                        then
                           Send_Alert_And_Error
                             (S, Protocol_Version, Result);
                        else
                           Send_Alert_And_Error
                             (S, Handshake_Failure, Result);
                        end if;
                     end if;
                  end;
               end;
            end;
   end Handle_Wait_Client_Hello;

   --  Dispatch handshake states to the appropriate handler
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      case S.State is
         when Wait_Client_Hello =>
            Handle_Wait_Client_Hello (S, HC, Result);

         when Server_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               if HC.Cfg.Request_Client_Cert and not HC.Using_PSK then
                  Set_State (S, Wait_Client_Certificate);
               else
                  Set_State (S, Wait_Client_Finished);
               end if;
               --  Don't return Need_Input if there's already data buffered
               --  (e.g., CCS records in the same TCP packet as ClientHello)
               if Input_Available (S) > 0 then
                  Result := OK;
               else
                  Result := Need_Input;
               end if;
            end if;

         when Wait_Client_Hello_Retry =>
            --  After HRR, wait for the client's second ClientHello.
            --  Same parsing as Wait_Client_Hello but we expect the
            --  client to include key_share for our requested group.
            if Input_Available (S) = 0 then
               Result := Need_Input;
               return;
            end if;

            declare
               Rec : Records.Parse_Result;
            begin
               Records.Parse_Record_Header
                 (Data   => S.Input.Data (S.Input.Read_Pos ..
                                           S.Input.Write_Pos - 1),
                  Avail  => Available (S.Input),
                  Result => Rec);

               if Rec.Overflow then
                  Send_Alert_And_Error (S, Record_Overflow, Result);
                  return;
               end if;

               if Rec.Bad_Version then
                  --  RFC 8446 §5.1: legacy_record_version must lie
                  --  in {3,1}..{3,4}. Out-of-band → protocol_version.
                  Send_Alert_And_Error (S, Protocol_Version, Result);
                  return;
               end if;

               if not Rec.OK then
                  if Rec.Record_Len > 0 then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  else
                     Result := Need_Input;
                  end if;
                  return;
               end if;

               if Rec.Content = Records.Content_Change_Cipher_Spec then
                  declare
                     CCS_Pos : constant N32 :=
                        S.Input.Read_Pos + Rec.Fragment_Pos;
                     CCS_OK : constant Boolean :=
                        Rec.Fragment_Len = 1
                        and then S.Input.Data (CCS_Pos) = 16#01#;
                  begin
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     if CCS_OK then
                        Result := OK;
                     else
                        --  RFC 5246 §7.1 / RFC 8446 §5: CCS payload MUST
                        --  be the single byte 0x01 (BoGo
                        --  BadChangeCipherSpec-*).
                        Send_Alert_And_Error
                          (S, Unexpected_Message, Result);
                     end if;
                  end;
                  return;
               end if;

               if Rec.Content /= Records.Content_Handshake then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
                  return;
               end if;

               --  Parse second ClientHello
               declare
                  Frag_Start : constant N32 :=
                     S.Input.Read_Pos + Rec.Fragment_Pos;
                  Frag_Len   : constant N32 := Rec.Fragment_Len;
                  Frag : constant Byte_Seq :=
                     S.Input.Data (Frag_Start ..
                                    Frag_Start + Frag_Len - 1);
                  Parse_OK : Boolean;
               begin
                  --  Save CH1 extension fingerprint before re-parsing
                  declare
                     CH1_Hash  : constant Unsigned_32 := HC.CH_Ext_Hash;
                     CH1_Count : constant Natural := HC.CH_Ext_Count;
                  begin
                     --  Reset for CH2 parsing. Seen_Ext_Count + Tags
                     --  ALSO must reset — otherwise the duplicate-ext
                     --  check at Apply_CH_Extension fires on every
                     --  CH2 ext (they all "match" the CH1 entries),
                     --  Parse_Client_Hello returns OK=False, and the
                     --  caller emits illegal_parameter. RFC 8446 §4.2
                     --  duplicate semantics are intra-CH-message, so
                     --  resetting between CH1 and CH2 is correct.
                     HC.Client_Has_X25519 := False;
                     HC.Client_Has_P256 := False;
                     HC.Client_Has_P384 := False;
                     HC.CH_Ext_Hash := 0;
                     HC.CH_Ext_Count := 0;
                     HC.Seen_Ext_Count := 0;
                     HC.Seen_Ext_Tags := (others => 0);

                     Handshake.Server_Msgs.Parse_Client_Hello
                       (S, HC, Frag, Parse_OK);

                     if not Parse_OK then
                        --  After HRR, CH2 parse failures are
                        --  illegal_parameter (RFC 8446 §4.1.4)
                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error
                          (S, Illegal_Parameter, Result);
                        return;
                     end if;

                     --  RFC 8446 §4.1.2: CH2 extensions must be in
                     --  the same order as CH1. Compare fingerprints.
                     --  Cookie is excluded from the hash in both CH1
                     --  and CH2, so adding cookie doesn't affect it.
                     if HC.CH_Ext_Hash /= CH1_Hash then
                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error
                          (S, Illegal_Parameter, Result);
                        return;
                     end if;
                  end;

                  --  Append CH2 to transcript
                  Append_Transcript (HC, Frag);
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                  --  Now proceed to build the real ServerHello flight
                  Build_Server_Flight (S, HC, Result);
               end;
            end;

         when Wait_Client_Certificate
            | Wait_Client_Cert_Verify =>
            Process_Client_Auth (S, HC, Result);

         when Wait_Client_Finished =>
            if HC.Version = TLS_1_3 then
               Process_Client_Finished (S, HC, Result);
            else
               --  TLS 1.2 handshake after ServerHelloDone:
               --    1. ClientKeyExchange (plaintext)
               --    2. ChangeCipherSpec
               --    3. Finished (encrypted)
               if not HC.CKE_Received_12 then
                  SPARKTLS.Server.TLS12.Process_Client_Key_Exchange_12
                    (S, HC, Result);
               elsif not HC.CCS_Received then
                  --  CKE done, waiting for CCS
                  SPARKTLS.Server.TLS12.Process_Client_Key_Exchange_12
                    (S, HC, Result);
                  --  CKE handler also accepts CCS records
               else
                  --  CCS received, next must be encrypted Finished
                  SPARKTLS.Server.TLS12.Process_Client_Finished_12
                    (S, HC, Result);
               end if;
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake;

   --  RFC 8446 §4.1.4: Build and send a HelloRetryRequest.
   --  HRR is structurally identical to ServerHello but with:
   --    - random = SHA-256("HelloRetryRequest") (magic constant)
   --    - key_share extension contains only the selected group (no key data)
   --    - supported_versions extension with TLS 1.3
   --  After sending HRR, the transcript is replaced with:
   --    Hash(message_hash(254) || length(Hash.length) || Hash(CH1))
   procedure Build_Hello_Retry_Request
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Group     : in     Unsigned_16;
      HRR_Buf   :    out Byte_Seq;
      HRR_Len   :    out N32;
      Rec_Out   :    out N32)
   is
      use SPARKTLSCrypto.Hashing.SHA256;

      --  RFC 8446 §4.1.3: SHA-256("HelloRetryRequest")
      HRR_Random : constant Bytes_32 :=
        (16#CF#, 16#21#, 16#AD#, 16#74#, 16#E5#, 16#9A#, 16#61#, 16#11#,
         16#BE#, 16#1D#, 16#8C#, 16#02#, 16#1E#, 16#65#, 16#B8#, 16#91#,
         16#C2#, 16#A2#, 16#11#, 16#16#, 16#7A#, 16#BB#, 16#8C#, 16#5E#,
         16#07#, 16#9E#, 16#09#, 16#E2#, 16#C8#, 16#A8#, 16#33#, 16#9C#);

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

      P : N32;
   begin
      HRR_Buf := (others => 0);
      HRR_Len := 0;
      Rec_Out := 0;

      if HRR_Buf'First > 0
        or else HRR_Buf'Last < Msg_Len - 1
      then
         return;
      end if;
      pragma Assert (HRR_Buf'First = 0);
      pragma Assert (HRR_Buf'Last >= Msg_Len - 1);

      --  Handshake header: type=ServerHello(0x02) + length(3)
      HRR_Buf (0) := 16#02#;
      HRR_Buf (1) := 0;
      HRR_Buf (2) := 0;
      HRR_Buf (3) := Byte (Body_Len);
      P := 4;

      --  legacy_version = 0x0303
      HRR_Buf (P)     := 16#03#;
      HRR_Buf (P + 1) := 16#03#;
      P := P + 2;

      --  random = HRR magic constant
      HRR_Buf (P .. P + 31) := HRR_Random;
      P := P + 32;

      --  legacy_session_id echo (must match CH1)
      HRR_Buf (P) := 32;
      P := P + 1;
      HRR_Buf (P .. P + 31) := HC.Legacy_Session_ID;
      P := P + 32;

      --  cipher_suite (use negotiated suite)
      HRR_Buf (P)     := Byte (S.Negotiated_Suite / 256);
      HRR_Buf (P + 1) := Byte (S.Negotiated_Suite mod 256);
      P := P + 2;

      --  legacy_compression_method = 0
      HRR_Buf (P) := 0;
      P := P + 1;

      --  extensions_length
      HRR_Buf (P)     := Byte (Ext_Len / 256);
      HRR_Buf (P + 1) := Byte (Ext_Len mod 256);
      P := P + 2;

      --  key_share extension: type(2) + length(2) + group(2)
      HRR_Buf (P)     := 16#00#;
      HRR_Buf (P + 1) := 16#33#;  --  key_share
      HRR_Buf (P + 2) := 16#00#;
      HRR_Buf (P + 3) := 16#02#;  --  2 bytes data
      HRR_Buf (P + 4) := Byte (Group / 256);
      HRR_Buf (P + 5) := Byte (Group mod 256);
      P := P + 6;

      --  supported_versions extension: type(2) + length(2) + version(2)
      --  but ServerHello format uses 2-byte version (not list)
      HRR_Buf (P)     := 16#00#;
      HRR_Buf (P + 1) := 16#2B#;  --  supported_versions
      HRR_Buf (P + 2) := 16#00#;
      HRR_Buf (P + 3) := 16#02#;  --  2 bytes data
      HRR_Buf (P + 4) := 16#03#;
      HRR_Buf (P + 5) := 16#04#;  --  TLS 1.3
      P := P + 6;

      pragma Assert (P = Msg_Len);

      --  RFC 8446 §4.4.1: Replace transcript with synthetic message_hash.
      --  transcript = Hash(message_hash(254) || length(hash_len) || Hash(CH1))
      --  For SHA-256: message_hash type=254, length=32, then 32-byte hash.
      declare
         CH1_Hash : Digest;
         Synthetic : Byte_Seq (0 .. 35) := (others => 0);  --  type(1) + len(3) + hash(32) = 36
      begin
         --  Hash the current transcript (which contains CH1)
         Hash (CH1_Hash, HC.Transcript (0 .. HC.Transcript_Len - 1));

         --  Build synthetic message_hash handshake message
         Synthetic (0) := 254;  --  message_hash type
         Synthetic (1) := 0;
         Synthetic (2) := 0;
         Synthetic (3) := 32;   --  hash length
         Synthetic (4 .. 35) := Byte_Seq (CH1_Hash);

         --  Replace transcript
         HC.Transcript (0 .. 35) := Synthetic;
         HC.Transcript_Len := 36;
      end;

      --  Append HRR to transcript
      Append_Transcript (HC, HRR_Buf (0 .. Msg_Len - 1));

      HRR_Len := Msg_Len;

      --  Atomic flight assembly: HRR + CCS into scratch, commit only if
      --  the whole flight fits. If commit fails, signal the caller via
      --  Rec_Out = 0 (caller bails to the alert path).
      declare
         Scratch : IO_Buffer;
         CCS_Out : N32;
      begin
         Records.Build_Handshake_Record
           (Fragment  => HRR_Buf (0 .. Msg_Len - 1),
            Output    => Scratch,
            Bytes_Out => Rec_Out);
         if Rec_Out = 0 then
            HRR_Len := 0;
            return;
         end if;

         --  Send CCS for middlebox compatibility
         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            Rec_Out := 0;
            HRR_Len := 0;
            return;
         end if;

         if Free_Space (S.Output) < Scratch.Write_Pos then
            Rec_Out := 0;
            HRR_Len := 0;
            return;
         end if;
         S.Output.Data (S.Output.Write_Pos ..
                        S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
            Scratch.Data (0 .. Scratch.Write_Pos - 1);
         S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
      end;
   end Build_Hello_Retry_Request;

   --  Build the entire server handshake flight:
   --  ServerHello (plaintext record) + CCS + encrypted(EE + Cert + CV + Finished)
   --  RFC 8446 §4.2.11 server-side PSK binder verification. Looks up
   --  the cached PSK by ticket ID, recomputes the binder over the
   --  truncated ClientHello transcript, and either installs the PSK
   --  (HC.Using_PSK := True + HC.PSK_Value/Len populated) on a hash
   --  match or emits a fatal alert on mismatch (matching BoringSSL's
   --  decrypt_error convention per BoGo Resume-Server-InvalidPSKBinder).
   procedure Verify_PSK_Binder
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rejected :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and HC.Cfg.Ticket_Store /= null
                and HC.Transcript_Len <= Transcript_Capacity
                and HC.PSK_Binder_Len <= Max_HS_Msg;

   procedure Verify_PSK_Binder
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rejected :    out Boolean;
      Result   :    out Action)
   is
      PSK     : Bytes_48;
      PSK_Len : N32;
      Suite   : Unsigned_16;
      Found   : Boolean;
   begin
      Rejected := False;
      Result := OK;
      Ticket_Cache.Lookup
        (Cache      => HC.Cfg.Ticket_Store.all,
         ID         => HC.PSK_Ticket_ID,
         Want_Suite => S.Negotiated_Suite,
         PSK        => PSK,
         PSK_Len    => PSK_Len,
         Suite      => Suite,
         Found      => Found);
      pragma Assert (if Found then Suite = S.Negotiated_Suite);
      if not Found or HC.PSK_Binder_Len = 0 then
         return;
      end if;

      declare
         Binder_OK : Boolean := False;
         Binders_Size : constant N32 := 2 + 1 + HC.PSK_Binder_Len;
         Trunc_Len    : N32;
      begin
         if HC.Transcript_Len > Binders_Size then
            Trunc_Len := HC.Transcript_Len - Binders_Size;
            if PSK_Len = 48 then
               declare
                  use SPARKTLSCrypto.HKDF384;
                  Trunc_Hash   : Key_Schedule.Digest_384;
                  Binder_Key   : OKM384_Seq (0 .. 47);
                  Finished_Key : OKM384_Seq (0 .. 47);
                  Expected     : Bytes_48;
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
                  SPARKTLSCrypto.Hashing.SHA256.Hash
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

         if Binder_OK then
            pragma Assert
              (PSK_Binder_Validated_RFC_8446_4_2_11_2 (Binder_OK));
            HC.Using_PSK := True;
            HC.PSK_Value := PSK;
            HC.PSK_Value_Len := PSK_Len;
         else
            --  BoringSSL convention: emit decrypt_error (alert 51 =
            --  Certificate_Verify_Failed in our codes) on binder fail.
            Send_Alert_And_Error
              (S, Certificate_Verify_Failed, Result);
            Rejected := True;
         end if;
      end;
   end Verify_PSK_Binder;

   --  RFC 8446 §4.2.3 server-side signature-algorithm negotiation.
   --  Walks HC.Peer_Sig_Algos in client-preferred order, picks the
   --  first entry compatible with our local identity's key type, and
   --  stores it in HC.Negotiated_Sig_Algo. Emits handshake_failure
   --  on no overlap.
   procedure Negotiate_Sig_Algo
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Algo_OK  :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and HC.Cfg.Local /= null;

   procedure Negotiate_Sig_Algo
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Algo_OK  :    out Boolean;
      Result   :    out Action)
   is
   begin
      Result := OK;
      Algo_OK := False;
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
         Send_Alert_And_Error (S, Handshake_Failure, Result);
      end if;
   end Negotiate_Sig_Algo;

   procedure Build_Server_Flight
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      SH_Buf  : Byte_Seq (0 .. Handshake.Server_Msgs.Max_Server_Hello - 1);
      SH_Len  : N32;
      Rec_Out : N32;
      CCS_Out : N32;
      --  Atomic flight assembly: every record goes into Scratch first.
      --  We commit to S.Output as one block at the end so the peer never
      --  observes a partial flight. Each Build_Encrypted_Record call
      --  advances HC.Server_HS.Counter; if the commit fails we restore
      --  the counter so the next record's AEAD nonce stays in sync with
      --  what the peer actually sees.
      Scratch    : IO_Buffer;
      Saved_Ctr  : Unsigned_64;
      --  Track whether we've started writing encrypted records (so we
      --  know whether a counter rollback is needed on commit failure).
      Encryption_Started : Boolean := False;
   begin
      --  PSK resumption: verify binder, install if valid, fatal-alert
      --  on mismatch. Sets HC.Using_PSK on success.
      if HC.PSK_Offered and then HC.Cfg.Ticket_Store /= null then
         declare
            Rejected : Boolean;
         begin
            Verify_PSK_Binder (S, HC, Rejected, Result);
            if Rejected then return; end if;
         end;
      end if;

      --  RFC 8446 §4.2.3: pick a sig_algorithm compatible with our
      --  local cert. Skipped on PSK resumption (no signature in flight).
      if not HC.Using_PSK then
         declare
            Got_It : Boolean;
         begin
            Negotiate_Sig_Algo (S, HC, Got_It, Result);
            if not Got_It then return; end if;
         end;
      end if;

      --  Check if HelloRetryRequest is needed.
      --
      --  RFC 8446 §4.1.4: HRR is sent ONLY when we cannot proceed
      --  from the offered ClientHello — i.e. no usable key_share
      --  was provided for any group we and the client both support.
      --  We MUST NOT send HRR purely to express a server preference
      --  for a different group: if the client offered P-256 and we
      --  support X25519/P-256/P-384, we use P-256 and proceed. The
      --  Go TLS test client (BoGo) treats preference-based HRR as
      --  an "invalid HelloRetryRequest" and aborts.
      if not HC.HRR_Sent then
         declare
            Need_HRR    : Boolean := False;
            HRR_Group   : Unsigned_16 := 0;
         begin
            --  Only HRR if no usable key_share AT ALL.
            if not (HC.Client_Has_X25519 or HC.Client_Has_P256
                    or HC.Client_Has_P384)
            then
               --  Pick a group from supported_groups for HRR.
               if HC.Client_Supports_X25519 then
                  Need_HRR := True;
                  HRR_Group := 16#001D#;
               elsif HC.Client_Supports_P256 then
                  Need_HRR := True;
                  HRR_Group := 16#0017#;
               elsif HC.Client_Supports_P384 then
                  Need_HRR := True;
                  HRR_Group := 16#0018#;
               end if;
            end if;

            if Need_HRR then
               Build_Hello_Retry_Request
                 (S, HC, HRR_Group, SH_Buf, SH_Len, Rec_Out);
               if SH_Len = 0 then
                  Send_Alert_And_Error (S, Internal_Error, Result);
                  return;
               end if;
               Set_State (S, Wait_Client_Hello_Retry);
               HC.HRR_Sent := True;
               --  RFC 8446 §4.1.4: at-most-one-HRR invariant. After
               --  this assignment, the outer `if not HC.HRR_Sent`
               --  guard prevents any further HRR from being built
               --  in this connection.
               pragma Assert (HRR_Sent_At_Most_Once_RFC_8446_4_1_4 (HC));
               Result := Has_Output;
               return;
            end if;
         end;
      end if;

      --  Build ServerHello
      Handshake.Server_Msgs.Build_Server_Hello (S, HC, SH_Buf, SH_Len);
      if SH_Len = 0 then
         --  RFC 7748 §6.1: small-subgroup X25519 rejection sets
         --  Ext_Parse_Err := Illegal_Parameter so we don't fold it
         --  into the catch-all handshake_failure.
         if HC.Ext_Parse_Err /= No_Error then
            Send_Alert_And_Error (S, HC.Ext_Parse_Err, Result);
         else
            Send_Alert_And_Error (S, Handshake_Failure, Result);
         end if;
         return;
      end if;

      --  Add ServerHello to transcript
      Append_Transcript (HC, SH_Buf (0 .. SH_Len - 1));

      --  Write ServerHello record (plaintext) into Scratch
      Records.Build_Handshake_Record
        (Fragment  => SH_Buf (0 .. SH_Len - 1),
         Output    => Scratch,
         Bytes_Out => Rec_Out);

      if Rec_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      --  Derive handshake keys
      Derive_Handshake_Keys (S, HC);
      --  Save the AEAD counter snapshot now: every Build_Encrypted_Record
      --  call below advances HC.Server_HS.Counter unconditionally
      --  (Post: Keys.Counter = Keys.Counter'Old + 1). If the final
      --  commit fails we restore this so the next record's nonce stays
      --  in sync with whatever the peer last saw.
      Saved_Ctr := HC.Server_HS.Counter;

      --  Send CCS for middlebox compatibility
      Records.Build_CCS_Record (Scratch, CCS_Out);
      if CCS_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      --  Build EncryptedExtensions (encrypted with server HS keys)
      declare
         EE_Buf : Byte_Seq (0 .. 255);
         EE_Len : N32;
         Enc_Out : N32;
      begin
         Handshake.Server_Msgs.Build_Encrypted_Extensions (HC, S, EE_Buf, EE_Len);
         Append_Transcript (HC, EE_Buf (0 .. EE_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => EE_Buf (0 .. EE_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);
         Encryption_Started := True;

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
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
            Handshake.Server_Msgs.Build_Certificate_Request (CR_Buf, CR_Len);
            if CR_Len > 0 then
               Append_Transcript (HC, CR_Buf (0 .. CR_Len - 1));
               Records.Build_Encrypted_Record
                 (Plaintext  => CR_Buf (0 .. CR_Len - 1),
                  Inner_Type => 16#16#,
                  Keys       => HC.Server_HS,
                  Output     => Scratch,
                  Bytes_Out  => Enc_Out);
               if Enc_Out = 0 then
                  HC.Server_HS.Counter := Saved_Ctr;
                  S.Last_Error := Insufficient_Buffer;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;
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
         Handshake.Certs.Build_Certificate_Chain
           (Id     => HC.Cfg.Local.all,
            Result => Cert_Buf,
            Len    => Cert_Len);

         if Cert_Len = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
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

         --  RFC 8446 §4.4.3 modern-scheme invariant: Negotiated_Sig_Algo
         --  is the wire scheme we'll sign with. We never set it to a
         --  PKCS#1 v1.5 value (no Sign_RSA_PKCS1 in our Sign_Algo
         --  type); pin it here so a future addition would fail proof.
         pragma Assert
           (HC.Negotiated_Sig_Algo = 0
              or else CertificateVerify_Modern_Scheme_RFC_8446_4_4_3
                       (HC.Negotiated_Sig_Algo));
         Handshake.Certs.Build_Certificate_Verify
           (Transcript_Hash => CV_Hash,
            Id              => HC.Cfg.Local.all,
            Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
            Role            => Role_Server,
            Random          => HC.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);

         if CV_Len = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         Append_Transcript (HC, CV_Buf (0 .. CV_Len - 1));

         Records.Build_Encrypted_Record
           (Plaintext  => CV_Buf (0 .. CV_Len - 1),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
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
                  Big_Finished : Byte_Seq (0 .. 51) := (others => 0);  --  4 + 48
               begin
                  Key_Schedule.Derive_Finished_Key_384
                    (Fin_Key, HC.Server_HS_Secret);
                  HMAC384.HMAC_SHA_384
                    (Output => Verify_48,
                     M      => TS_Hash,
                     K      => Byte_Seq (Fin_Key));
                  --  RFC 8446 §4.4.4: TLS 1.3 verify_data length =
                  --  Hash.length. SHA-384 → 48 bytes.
                  pragma Assert
                    (Verify_Data_Length_TLS13_RFC_8446_4_4_4
                       (Byte_Seq (Verify_48)));

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
                     Output     => Scratch,
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
                  --  RFC 8446 §4.4.4: TLS 1.3 verify_data length =
                  --  Hash.length. SHA-256 → 32 bytes.
                  pragma Assert
                    (Verify_Data_Length_TLS13_RFC_8446_4_4_4
                       (Byte_Seq (Verify_32)));

                  Handshake.Build_Finished (Verify_32, Fin_Buf, Fin_Len);
                  Append_Transcript (HC, Fin_Buf (0 .. Fin_Len - 1));

                  Records.Build_Encrypted_Record
                    (Plaintext  => Fin_Buf (0 .. Fin_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => HC.Server_HS,
                     Output     => Scratch,
                     Bytes_Out  => Enc_Out);
               end;
         end case;

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      end;

      --  Atomic commit: full flight assembled in Scratch. If S.Output
      --  has room, copy in one shot; otherwise abort and roll the
      --  AEAD counter back so subsequent records (or the alert we may
      --  send) stay nonce-synchronised with the peer.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         if Encryption_Started then
            HC.Server_HS.Counter := Saved_Ctr;
         end if;
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos ..
                     S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
         Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      --  Derive application keys now (using transcript through server Finished)
      Derive_App_Keys (S, HC);

      Set_State (S, Server_Hello_Sent);
      Result := Has_Output;
   end Build_Server_Flight;

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys
     (S  : in     Session;
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
     (TK     :    out Traffic_Keys;
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
   --  RFC 8446 §4.4.2 server-side mTLS Certificate handler. Parses
   --  the client's certificate chain via the shared RFLX-backed
   --  helper, then transitions to Wait_Client_Cert_Verify (cert
   --  present) or Wait_Client_Finished (optional-mode empty cert).
   --  Returns Result = OK on success; otherwise emits the encrypted
   --  alert and sets Result to an Error_* action.
   procedure Handle_Client_Cert_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => Data'First = 0
                and Data'Last >= 3
                and Data'Last < N32'Last - 4
                and Data'Last < Transcript_Capacity
                and S.State = Wait_Client_Certificate
                and Nonce_Space_Available (S.Server_App);

   procedure Handle_Client_Cert_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
      Parse_OK  : Boolean;
      Parse_Err : Error_Code;
   begin
      Result := OK;
      Append_Transcript (HC, Data);
      Handshake.Certs.Parse_Certificate_Chain_13
        (HC                     => HC,
         HS_Msg                 => Data,
         Reject_Cert_Extensions => False,
         OK                     => Parse_OK,
         Err                    => Parse_Err);
      if not Parse_OK then
         Send_Encrypted_Alert (S, Parse_Err, Result);
         return;
      end if;

      if not HC.Peer_Cert_Valid then
         if HC.Cfg.Require_Client_Cert then
            --  RFC 8446 §6 cert reject after server Finished — keys
            --  are live, MUST be encrypted alert.
            Send_Encrypted_Alert
              (S, Certificate_Required, Result);
            return;
         end if;
         Set_State (S, Wait_Client_Finished);
      else
         Set_State (S, Wait_Client_Cert_Verify);
      end if;
   end Handle_Client_Cert_13;

   --  RFC 8446 §4.4.3 server-side mTLS CertificateVerify handler.
   --  Reconstructs the signed Content (64 spaces || ctx_str || 0x00
   --  || transcript_hash), verifies the client's signature against
   --  its leaf cert, runs trust-store chain validation if a Trust
   --  is configured, and transitions to Wait_Client_Finished on
   --  success.
   procedure Handle_Client_CertVerify_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Data'First = 0
                and Data'Length > 0
                and Data'Last < N32'Last - 4
                and S.State = Wait_Client_Cert_Verify
                and HC.Hash_Len in 32 | 48;

   procedure Handle_Client_CertVerify_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
      H_Len : constant N32 := HC.Hash_Len;
      CV_Hash : Byte_Seq (0 .. H_Len - 1);
   begin
      Result := OK;
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

      Append_Transcript (HC, Data);

      declare
         Ctx_Str : constant String :=
            "TLS 1.3, client CertificateVerify";
         C_Len : constant N32 := 64 + N32 (Ctx_Str'Length) + 1 + H_Len;
         Content : Byte_Seq (0 .. C_Len - 1) := (others => 0);
         Verified : Boolean := False;
      begin
         Content (0 .. 63) := (others => 16#20#);
         for I in Ctx_Str'Range loop
            Content (64 + N32 (I - Ctx_Str'First)) :=
               Byte (Character'Pos (Ctx_Str (I)));
         end loop;
         Content (64 + N32 (Ctx_Str'Length)) := 0;
         Content (64 + N32 (Ctx_Str'Length) + 1 ..
                  64 + N32 (Ctx_Str'Length) + H_Len) := CV_Hash;

         if Msg_Len >= 8 then
            declare
               Sig_Scheme : constant Unsigned_16 :=
                  Unsigned_16 (Data (4)) * 256 +
                  Unsigned_16 (Data (5));
               Sig_Len : constant N32 :=
                  N32 (Data (6)) * 256 + N32 (Data (7));
               Sig_Start : constant N32 := 8;
            begin
               --  RFC 8446 §4.2.3: rsa_pkcs1_* MUST NOT be used in
               --  TLS 1.3 CV.
               if Sig_Scheme = 16#0401#
                  or Sig_Scheme = 16#0501#
                  or Sig_Scheme = 16#0601#
               then
                  Send_Encrypted_Alert (S, Illegal_Parameter, Result);
                  return;
               end if;
               if Sig_Len > 0
                  and then Sig_Start + Sig_Len <= N32 (Data'Length)
               then
                  declare
                     Sig : Byte_Seq (0 .. Sig_Len - 1);
                  begin
                     Sig := Data (Sig_Start ..
                                  Sig_Start + Sig_Len - 1);
                     Verified := Cert_Verify.Verify_Signature
                       (Data       => Content,
                        Sig        => Sig,
                        Cert       => HC.Peer_Cert,
                        Sig_Scheme => Sig_Scheme);
                  end;
               end if;
            end;
         end if;

         if not Verified then
            Send_Encrypted_Alert
              (S, Certificate_Verify_Failed, Result);
            pragma Assert (S.Last_Error /= Unexpected_Message);
            pragma Assert (Output_Pending (S) > 0);
            pragma Assert
              (Cert_Validation_Alerted_RFC_5246_7_4_2
                 (S.State, Output_Pending (S), S.Last_Error));
            return;
         end if;
      end;

      --  Trust-store chain validation, if configured.
      if HC.Cfg.Trust /= null
         and then HC.Cfg.Get_Time /= null
         and then HC.Peer_Cert_Valid
      then
         declare
            Cert_DER_Len_Const : constant N32 := HC.Peer_Cert_DER_Len;
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (Cert_DER_Len_Const) - 1) :=
                 (others => 0);
            VR : Validation_Result;
         begin
            for I in N32 range 0 .. HC.Peer_Cert_DER_Len - 1 loop
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
               Send_Encrypted_Alert (S, Bad_Certificate, Result);
               pragma Assert (S.Last_Error /= Unexpected_Message);
               pragma Assert (Output_Pending (S) > 0);
               pragma Assert
                 (Cert_Validation_Alerted_RFC_5246_7_4_2
                    (S.State, Output_Pending (S), S.Last_Error));
               return;
            end if;
         end;
      end if;

      Set_State (S, Wait_Client_Finished);
   end Handle_Client_CertVerify_13;

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
            if Rec.Fragment_Len = 1 and then not HC.CCS_Received then
               HC.CCS_Received := True;
               Result := OK;
            else
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               declare
                  A : N32;
               begin
                  Records.Build_Alert_Record
                    (2, 10, S.Server_App, S.Output, A);
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
            declare
               Frag_Len   : constant N32 := Rec.Fragment_Len;
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Frag_Len - 1);
               Hdr        : constant Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Frag_Len < Records.Tag_Size + 1 then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, A);
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
                  Keys       => HC.Client_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, A);
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
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, A);
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

               declare
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
                  Plain_Len_Const : constant N32 := Plain_Len;
                  Data     : constant Byte_Seq := Plaintext (0 .. Plain_Len_Const - 1);
               begin
                  Handshake.Parse_Handshake_Header
                    (Data, Msg_Type, Msg_Len, Parse_OK);

                  if not Parse_OK then
                     --  RFC 8446 §6.2: malformed handshake → fatal
                     --  decode_error alert. We're past keys, so use
                     --  the encrypted alert path. Was missing the
                     --  alert entirely (peer saw TCP RST).
                     Send_Encrypted_Alert (S, Decode_Error, Result);
                     return;
                  end if;

                  case S.State is
                     when Wait_Client_Certificate =>
                        if Msg_Type /= Handshake.HT_Certificate then
                           Send_Encrypted_Alert
                             (S, Unexpected_Message, Result);
                           return;
                        end if;
                        Handle_Client_Cert_13 (S, HC, Data, Result);

                     when Wait_Client_Cert_Verify =>
                        if Msg_Type /= Handshake.HT_Certificate_Verify then
                           Send_Encrypted_Alert
                             (S, Unexpected_Message, Result);
                           return;
                        end if;
                        Handle_Client_CertVerify_13
                          (S, HC, Data, Msg_Len, Result);

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

   procedure Verify_Client_Finished
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Msg_Len   : in     N32;
      Result    :    out Action)
   is
   begin
      Result := OK;
                  --  Verify client Finished
                  declare
                     Plain_Len_Const : constant N32 := Plain_Len;
                     Data     : constant Byte_Seq := Plaintext (0 .. Plain_Len_Const - 1);
                     Expected_Len : constant N32 :=
                        (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                         then 48 else 32);
                  begin
                     --  Length must match exactly. RFC 8446 §4.4.4
                     --  Finished is the last handshake message in
                     --  the client's first flight; any plaintext
                     --  bytes after it in the same record is
                     --  excess handshake data — fatal
                     --  unexpected_message (BoGo
                     --  TrailingDataWithFinished, expected error
                     --  ":EXCESS_HANDSHAKE_DATA:" / "remote error:
                     --  unexpected message"). Wrong inner Msg_Len
                     --  (length declared in handshake header is too
                     --  big due to trailing bytes in the message)
                     --  is a Finished-verify failure → decrypt_error
                     --  (BoGo TrailingMessageData-TLS13-ClientFinished
                     --  expects ":DIGEST_CHECK_FAILED:" → alert 51).
                     if Msg_Len /= Expected_Len then
                        declare
                           A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 51, S.Server_App, S.Output, A);
                        end;
                        S.Last_Error := Certificate_Verify_Failed;
                        Set_State (S, Error_State);
                        if Output_Pending (S) > 0 then
                           Result := Has_Output;
                        else
                           Result := Error_Alert;
                        end if;
                        return;
                     end if;
                     if N32 (Data'Length) /= 4 + Expected_Len then
                        declare
                           A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 10, S.Server_App, S.Output, A);
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

                     --  Length is correct — verify HMAC
                     declare
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

                                 if Equal (Expected,
                                           Bytes_48 (Data (4 .. 51))) then
                                    Verified := True;
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

                                 if Equal (Expected,
                                           Bytes_32 (Data (4 .. 35))) then
                                    Verified := True;
                                 end if;
                              end;
                        end case;

                        if not Verified then
                           declare
                              A : N32;
                           begin
                              Records.Build_Alert_Record
                                (2, 51, S.Server_App, S.Output, A);
                           end;
                           S.Last_Error := Handshake_Failure;
                           Set_State (S, Error_State);
                           if Output_Pending (S) > 0 then
                              Result := Has_Output;
                           else
                              Result := Error_Alert;
                           end if;
                           return;
                        end if;
                     end;

                     --  Client Finished verified.
                     --  Append client Finished to transcript for res_master derivation
                     Append_Transcript (HC, Data);

                     --  Derive resumption master secret and send NewSessionTicket
                     declare
                        use SPARKTLS.Ticket_Cache;
                        Nonce    : Byte_Seq (0 .. 1) := (0, 0);
                        TID : Ticket_ID := (others => 0);
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
                                    pragma Warnings
                                      (Off, "value conversion implemented by copy");
                                    Ticket_Cache.Store
                                      (HC.Cfg.Ticket_Store.all,
                                       Bytes_48 (PSK_Out), 48,
                                       S.Negotiated_Suite, 0, TID);
                                    pragma Warnings
                                      (On, "value conversion implemented by copy");
                                 end if;
                                 pragma Warnings
                                   (Off, "value conversion implemented by copy");
                                 S.Res_Master := Bytes_48 (Res_Master);
                                 pragma Warnings
                                   (On, "value conversion implemented by copy");
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

                        --  Build and send NewSessionTicket only if the
                        --  client signalled psk_dhe_ke in psk_key_
                        --  exchange_modes (RFC 8446 §4.6.1 + §4.2.9).
                        --  BoGo TLS13-ExpectNoSessionTicketOnBadKE
                        --  Mode-Server checks that we DON'T issue NST
                        --  when the client only offered psk_ke.
                        if HC.Cfg.Ticket_Store /= null
                          and then HC.Has_PSK_DHE_KE
                        then
                           declare
                              --  NST format: type(1) + len(3) + lifetime(4) +
                              --  age_add(4) + nonce_len(1) + nonce(2) +
                              --  ticket_len(2) + ticket(16) + ext_len(2) = 35.
                              --  We never emit the early_data extension —
                              --  0-RTT is intentionally out of scope (see
                              --  Cfg.Resume_Ticket comment in sparktls.ads).
                              NST : Byte_Seq (0 .. 34) := (others => 0);
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

                              --  NewSessionTicket is a post-handshake
                              --  optimisation (RFC 8446 §4.6.1); it is
                              --  not required for handshake completion.
                              --  If S.Output is too full to hold it,
                              --  skip silently and roll back the AEAD
                              --  counter so the next encrypted record
                              --  on these keys keeps its nonce in sync
                              --  with what the peer last received.
                              declare
                                 Saved : constant Unsigned_64 :=
                                    S.Server_App.Counter;
                              begin
                                 Records.Build_Encrypted_Record
                                   (Plaintext  => NST,
                                    Inner_Type => 16#16#,  --  handshake
                                    Keys       => S.Server_App,
                                    Output     => S.Output,
                                    Bytes_Out  => Enc_Out);
                                 if Enc_Out = 0 then
                                    S.Server_App.Counter := Saved;
                                 end if;
                              end;
                           end;
                        end if;
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
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
      Result := OK;
            declare
               Frag_Len   : constant N32 := Rec.Fragment_Len;
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Frag_Len - 1);
               Hdr        : constant Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
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

               --  RFC 8446 §5.4: TLSInnerPlaintext MUST NOT exceed
               --  2^14 + 1 octets. Check before decrypting.
               if Frag_Len - Records.Tag_Size >
                  Records.Max_Fragment + 1
               then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Encrypted_Alert (S, Record_Overflow, Result);
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
                  --  RFC 8446 §4.2.10 / §4.6.1: 0-RTT is intentionally
                  --  not supported by this stack. If a client tried
                  --  it anyway (Early_Data_Offered set in CH), its
                  --  records are encrypted with a key we never
                  --  derived and won't decrypt with Client_HS. The
                  --  RFC requires the server to silently drop those
                  --  records and keep waiting for the client
                  --  Finished (which uses Client_HS keys we do have).
                  --  Bounded to defend against a buggy/malicious
                  --  peer streaming garbage indefinitely.
                  if HC.Early_Data_Offered
                    and then HC.Skipped_Early_Data_Records < 32
                  then
                     HC.Skipped_Early_Data_Records :=
                        HC.Skipped_Early_Data_Records + 1;
                     Result := OK;
                     return;
                  end if;
                  --  MAC failure or empty inner plaintext.
                  --  Send alert with app keys (client switched to app
                  --  keys after receiving our Finished).
                  --  RFC 8446 §5.2: bad_record_mac (20)
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 20, S.Server_App, S.Output, A);
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
                  S.Last_Error := Error_Code'Val
                    (Natural'Min (Natural (Plaintext (1)),
                                  Error_Code'Pos (Error_Code'Last)));
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               elsif Inner_Type /= 16#16# then
                  --  Unexpected inner type during handshake
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, A);
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
               declare
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
               begin
                  Handshake.Parse_Handshake_Header
                    (Plaintext (0 .. Plain_Len - 1),
                     Msg_Type, Msg_Len, Parse_OK);

                  if not Parse_OK then
                     --  Distinguish unknown-type (BoGo
                     --  WrongMessageType injects type+42) from
                     --  malformed shape. Unknown type →
                     --  unexpected_message; otherwise decode_error.
                     declare
                        Raw_Type : constant Byte :=
                           (if Plain_Len >= 1 then Plaintext (0)
                            else 0);
                        Is_Known : constant Boolean :=
                           Raw_Type in 16#01# | 16#02# | 16#04# |
                                       16#08# | 16#0B# | 16#0C# |
                                       16#0D# | 16#0E# | 16#0F# |
                                       16#10# | 16#14#;
                        A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, (if Is_Known then 50 else 10),
                           S.Server_App, S.Output, A);
                        S.Last_Error :=
                          (if Is_Known then Decode_Error
                           else Unexpected_Message);
                     end;
                     Set_State (S, Error_State);
                     if Output_Pending (S) > 0 then
                        Result := Has_Output;
                     else
                        Result := Error_Alert;
                     end if;
                     return;
                  end if;

                  if Msg_Type /= Handshake.HT_Finished then
                     --  Wrong handshake type: unexpected_message (10)
                     declare
                        A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, 10, S.Server_App, S.Output, A);
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

                  Verify_Client_Finished
                    (S, HC, Plaintext, Plain_Len, Msg_Len, Result);
               end;
            end;
   end Handle_PCF_App_Data;

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
            if Rec.Fragment_Len = 1 and then not HC.CCS_Received then
               HC.CCS_Received := True;
               Result := OK;
            else
               --  Invalid CCS (wrong length or duplicate)
               declare
                  A : N32;
               begin
                  Records.Build_Alert_Record
                    (2, 10, S.Server_App, S.Output, A);
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
            Handle_PCF_App_Data (S, HC, Rec, Result);

         when others =>
            --  Plaintext handshake/alert records are not allowed here.
            --  RFC 8446 §5.1: after ServerHello, all records MUST be
            --  encrypted (content type application_data or CCS).
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if Rec.Content = Records.Content_Alert then
               --  Plaintext alert during post-ServerHello handshake.
               --  Just close — do not respond.
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

      if Rec.Overflow then
         Send_Encrypted_Alert (S, Record_Overflow, Result);
         return;
      end if;

      if not Rec.OK then
         if Rec.Record_Len > 0 then
            --  Parsed successfully but unknown content type.
            --  RFC 8446 §5: unexpected_message
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
            --  RFC 8446 §5.1: unencrypted alert after handshake.
            --  Just close — do not respond with an alert.
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

      declare
         Frag_Len   : constant N32 := Rec.Fragment_Len;
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
            S.Input.Data (Frag_Start ..
                           Frag_Start + Frag_Len - 1);
         Hdr        : constant Byte_Seq (0 .. 4) :=
            S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Frag_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Frag_Len < Records.Tag_Size + 1 then
            --  Too short for AEAD tag + at least 1 byte of ciphertext
            --  (the inner content type byte). RFC 8446 §5.4.
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            declare
               Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,
                  Desc      => 10,  --  unexpected_message
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Alert_Out);
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

         --  RFC 8446 §5.4: TLSInnerPlaintext MUST NOT exceed
         --  2^14 + 1 octets. Check before decrypting.
         if Frag_Len - Records.Tag_Size >
            Records.Max_Fragment + 1
         then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            declare
               Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,
                  Desc      => 22,  --  record_overflow
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Alert_Out);
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
            --  MAC failure or empty inner plaintext (RFC 8446 §5.2/§5.4)
            --  Send encrypted bad_record_mac alert
            declare
               Alert_Out : N32;
            begin
               Records.Build_Alert_Record
                 (Level     => 2,       --  fatal
                  Desc      => 20,      --  bad_record_mac
                  Keys      => S.Server_App,
                  Output    => S.Output,
                  Bytes_Out => Alert_Out);
            end;
            Set_State (S, Error_State);
            S.Last_Error := Bad_Record_MAC;
            --  Return Has_Output to drain the alert before Error_Alert
            if Output_Pending (S) > 0 then
               --  RFC 8446 §5.2: AEAD-failure invariant: alert
               --  queued, Error_State entered, Last_Error pinned
               --  to Bad_Record_MAC. No timing oracle leaked.
               pragma Assert
                 (AEAD_Failure_Alerted_RFC_8446_5_2
                    (S.State, Output_Pending (S), S.Last_Error));
               Result := Has_Output;
            else
               Result := Error_Alert;
            end if;
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
                  S.Empty_Records_Recvd := 0;
                  Result := Plaintext_Ready;
               else
                  --  Empty plaintext record — count + cap (BoGo
                  --  SendEmptyRecords / TOO_MANY_EMPTY_FRAGMENTS).
                  S.Empty_Records_Recvd :=
                     S.Empty_Records_Recvd + 1;
                  if S.Empty_Records_Recvd > 32 then
                     declare
                        A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, 10, S.Server_App, S.Output, A);
                     end;
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := (if Output_Pending (S) > 0
                                then Has_Output else Error_Alert);
                  else
                     Result := OK;
                  end if;
               end if;

            when 16#16# =>
               --  Post-handshake message (NewSessionTicket, etc.)
               Result := OK;

            when 16#15# =>
               --  Alert. RFC 8446 §6 / RFC 5246 §7.2: 2-byte payload
               --  `level | description`. Validate level, distinguish
               --  close_notify, tolerate user_canceled (with cap),
               --  reject every other warning with decode_error, and
               --  reject bogus levels with illegal_parameter.
               if Plain_Len < 2 then
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 50, S.Server_App, S.Output, A);
                  end;
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0
                             then Has_Output else Error_Alert);
               elsif Plaintext (0) /= 1 and Plaintext (0) /= 2 then
                  --  Bogus level (BoGo SendBogusAlertType: 0x42).
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 47, S.Server_App, S.Output, A);
                  end;
                  S.Last_Error := Illegal_Parameter;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0
                             then Has_Output else Error_Alert);
               elsif Plaintext (1) = 0 then
                  --  close_notify — reply in kind (warning level 1).
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (Level     => 1,
                        Desc      => 0,
                        Keys      => S.Server_App,
                        Output    => S.Output,
                        Bytes_Out => A);
                  end;
                  Set_State (S, Closing);
                  if Output_Pending (S) > 0 then
                     pragma Assert
                       (Close_Notify_Reply_State_RFC_5246_7_2_1
                          (S.State, Output_Pending (S)));
                     Result := Has_Output;
                  else
                     Result := Shutdown;
                  end if;
               elsif Plaintext (0) = 1 then
                  --  Warning-level alert (level=1) other than
                  --  close_notify. RFC 8446 §6.1 deprecates these
                  --  but keeps user_canceled for back-compat.
                  if Plaintext (1) = 90 then
                     S.Warning_Alerts_Recvd :=
                        S.Warning_Alerts_Recvd + 1;
                     if S.Warning_Alerts_Recvd >= 5 then
                        declare
                           A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 50, S.Server_App, S.Output, A);
                        end;
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := (if Output_Pending (S) > 0
                                   then Has_Output else Error_Alert);
                     else
                        Result := OK;
                     end if;
                  else
                     declare
                        A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, 50, S.Server_App, S.Output, A);
                     end;
                     S.Last_Error := Decode_Error;
                     Set_State (S, Error_State);
                     Result := (if Output_Pending (S) > 0
                                then Has_Output else Error_Alert);
                  end if;
               else
                  --  Fatal alert from peer (level=2): close without
                  --  reply per RFC 8446 §6.2 (no alerts about alerts).
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               end if;

            when others =>
               --  Invalid inner content type (including zero).
               --  RFC 8446 §5.4: unexpected_message
               Send_Encrypted_Alert (S, Unexpected_Message, Result);
         end case;
      end;
   end Process_Connected;

   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   is
      --  RFC 8446 §5.1 caps a single TLS record at 2^14 bytes of
      --  plaintext (Max_Record_Plaintext = 16384). Anything larger has
      --  to be split across multiple records, each with its own header,
      --  AEAD tag, and (for TLS 1.3) per-record nonce.
      --
      --  The loop:
      --    * Slices Plaintext into ≤ Max_Record_Plaintext chunks.
      --    * Pre-checks Free_Space (S.Output) ≥ chunk + record-overhead
      --      BEFORE encrypting, so we never advance the AEAD counter
      --      for a record that won't fit. (Build_Encrypted_Record's
      --      Post is `Counter = Counter'Old + 1` unconditionally — it
      --      bumps the counter even on Bytes_Out := 0. Same shape as
      --      the silent buffer-overflow Bug #2 fixed earlier; we
      --      avoid it here by gating BEFORE the call.)
      --    * Returns Bytes_Written < Plaintext'Length when S.Output
      --      runs out of room. Caller drains and re-calls on the
      --      remaining suffix.
      Total      : constant N32 := N32 (Plaintext'Length);
      Pos        : N32 := 0;
      Chunk      : N32;
      Enc_Out    : N32;
      --  TLS 1.3 record on the wire: Header(5) + InnerType(1) + Tag(16) = 22.
      --  TLS 1.2 record on the wire: Header(5) + ExplicitNonce(8) + Tag(16) = 29.
      TLS13_Overhead : constant N32 := 22;
      TLS12_Overhead : constant N32 := 29;
      Overhead   : constant N32 :=
         (if S.Negotiated_Version = TLS_1_2
          then TLS12_Overhead else TLS13_Overhead);
   begin
      while Pos < Total loop
         pragma Loop_Invariant
           (Pos in 0 .. Total
            and S.Negotiated_Version = S.Negotiated_Version'Loop_Entry);
         pragma Loop_Variant (Increases => Pos);

         Chunk := N32'Min (Max_Record_Plaintext, Total - Pos);

         --  Bail if S.Output can't hold this record. Caller drains.
         if Free_Space (S.Output) < Chunk + Overhead then
            exit;
         end if;

         --  RFC 8446 §5.3 / RFC 5246 §6.1: stop emitting once nonce
         --  space exhausts on this leg.
         exit when not Nonce_Space_Available (S.Server_App);
         if S.Negotiated_Version = TLS_1_2
            and then S.Server_Seq_12 = Unsigned_64'Last
         then
            exit;
         end if;

         --  Copy slice to 0-based scratch so AEAD builders' Pre is
         --  satisfied (Plaintext'First = 0).
         declare
            Frag_Len : constant N32 := Chunk;
            Frag     : Byte_Seq (0 .. Frag_Len - 1);
         begin
            Frag := Plaintext (Plaintext'First + Pos ..
                               Plaintext'First + Pos + Frag_Len - 1);
            if S.Negotiated_Version = TLS_1_2 then
               Records.TLS12.Build_Encrypted_Record_12
                 (Plaintext    => Frag,
                  Content_Type => 16#17#,  --  application_data
                  Keys         => S.Server_App,
                  Implicit_IV  => S.Server_IV_12,
                  Seq_Num      => S.Server_Seq_12,
                  Output       => S.Output,
                  Bytes_Out    => Enc_Out);
            else
               Records.Build_Encrypted_Record
                 (Plaintext  => Frag,
                  Inner_Type => 16#17#,
                  Keys       => S.Server_App,
                  Output     => S.Output,
                  Bytes_Out  => Enc_Out);
            end if;
         end;

         exit when Enc_Out = 0;
         Pos := Pos + Chunk;
      end loop;
      Bytes_Written := Pos;
   end Write_Plaintext;

   procedure Close_Notify (S : in out Session) is
      Alert_Out : N32;
   begin
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Alert_Record_12
           (Level       => 1,
            Desc        => 0,
            Keys        => S.Server_App,
            Implicit_IV => S.Server_IV_12,
            Seq_Num     => S.Server_Seq_12,
            Output      => S.Output,
            Bytes_Out   => Alert_Out);
      else
         Records.Build_Alert_Record
           (Level     => 1,
            Desc      => 0,
            Keys      => S.Server_App,
            Output    => S.Output,
            Bytes_Out => Alert_Out);
      end if;
      --  RFC 8446 §6.1: at most one close_notify per peer; if we
      --  already transitioned to Closing on a prior invocation, the
      --  state-machine transition is a no-op.
      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Server;
