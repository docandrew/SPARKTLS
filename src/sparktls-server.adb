with Interfaces;          use Interfaces;
with SPARKTLS;
with SPARKTLS_Reassembly; use SPARKTLS_Reassembly;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;    use SPARKTLS.Records;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Server_Msgs;
with X509;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Server.TLS12;
with SPARKTLS.Server.TLS13;
with SPARKTLS.Handshake.TLS12;

with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA384;

package body SPARKTLS.Server
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   --  Server_Config_Can_Start moved to the spec's private part alongside
   --  Ready_Config, whose membership test it anchors.

   function Server_Active (S : Session) return Boolean
   is (S.Role = Role_Server and then S.State not in Idle | Closing | Closed | Error_State)
   with Ghost;

   function Handshake_Record_Fragment_Ready (Rec : Records.Parse_Result) return Boolean
   is (Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Fragment_Len >= 1
       and then Rec.Record_Len >= Rec.Fragment_Pos
       and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Fragment_Len < Transcript_Capacity)
   with Ghost;

   --  Forward declarations
   procedure Advance_Handshake
     (S : in out Server_Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action);

   procedure Send_Alert_And_Error (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre  => S.State not in Idle | Closed | Closing | Error_State,
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
      Abort_Flight (S);
      Records.Build_Plaintext_Alert
        (Level     => 2,  --  fatal
         Desc      => Alert_Desc (Err),
         Output    => S.Output,
         Bytes_Out => Dummy,
         Hdr_Buf   => S.Rec_Hdr);
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
   --  (alert 40) per RFC 8446 6.
   procedure Dispatch_CH_Parse_Error_Alert (S : in out Session; Result : out Action)
   with
     Pre  => S.State not in Idle | Closed | Closing | Error_State,
     Post =>
       S.State = Error_State
       and then Result in Has_Output | Error_Alert
       and then S.Role = S.Role'Old
       and then S.Input.Read_Pos = S.Input.Read_Pos'Old
       and then S.Input.Write_Pos = S.Input.Write_Pos'Old;

   --  Send an encrypted fatal alert and set error state.
   --  Used when application/handshake keys are established.
   --  RFC 8446 6.2 / RFC 5246 7.2.2: encrypted fatal alert is
   --  sent before the connection terminates so the peer learns the
   --  reason instead of seeing only a TCP RST.
   procedure Dispatch_CH_Parse_Error_Alert (S : in out Session; Result : out Action) is
   begin
      case S.Last_Error is
         when Decode_Error
            | Unexpected_Message
            | Protocol_Version
            | Illegal_Parameter
            | Certificate_Verify_Failed  --  RFC 8446 4.2.11.2 PSK binder
            | Missing_Extension          --  RFC 8446 4.2.9 PSK without KE_modes
         =>
            Send_Alert_And_Error (S, S.Last_Error, Result);

         when others                                                             =>
            Send_Alert_And_Error (S, Handshake_Failure, Result);
      end case;
   end Dispatch_CH_Parse_Error_Alert;

   ----------------------------------------------------------------------------
   --  Configure
   ----------------------------------------------------------------------------
   function Configure (Cfg : Config) return Session
   is
   begin
      return S : Server_Session :=
        (Role   => Role_Server,
         State  => Wait_Client_Hello,
         HC     => (Cfg => Cfg, others => <>),
         others => <>)
      do
         --  The only allocation in the library's lifetime: the session's two
         --  I/O buffers, RecordFlux-native and 1-based, never freed.
         S.Input.Data  := new RBT_A.Bytes'(1 .. RBT_A.Index (IO_Buffer_Capacity) => 0);
         S.Output.Data := new RBT_A.Bytes'(1 .. RBT_A.Index (IO_Buffer_Capacity) => 0);
         if not Server_Config_Can_Start (Cfg) then
            Set_State (S, Error_State);
            S.Last_Error := Bad_Configuration;
         else

            SPARKTLS.HS_Pool.Acquire (S.Slot);

            if S.Slot = No_Slot then
               Set_State (S, Error_State);
               S.Last_Error := No_Free_Sessions;
            end if;
         end if;
      end return;
   end Configure;

   procedure Scrub_Handshake_Context (HC : in out Handshake_Context) is
   begin
      HC.KE.Shared := (others => 0);
      HC.Client_HS_Secret := (others => 0);
      HC.Server_HS_Secret := (others => 0);
      HC.Handshake_Secret := (others => 0);
      HC.Master_Secret := (others => 0);
      HC.Master_Secret_12 := (others => 0);
      HC.KE.Local_SK := (others => 0);
      HC.KE.P256_SK := (others => 0);
      HC.KE.P384_SK := (others => 0);
      SPARKTLS_Transcript.Wipe (HC.TS);
      HC.T12.Resumed_Master_Secret := (others => 0);
      HC.EMS_Session_Hash := (others => 0);
      HC.PSK.Value := (others => 0);
      HC.PSK.Binder := (others => 0);
      HC.PSK.Offer_ID := (others => 0);
      HC.Client_Random := (others => 0);
      HC.Server_Random := (others => 0);
   end Scrub_Handshake_Context;

   procedure Advance_Server_Non_Handshake
     (S : in out Session; Result : out Action; Handled : out Boolean)
   with
     Pre =>
       S.Role = Role_Server
       and then S.App_Data_Len <= Max_Record_Plaintext
       and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then Empty_Records_Bounded_RFC_8446_5_2 (S)
   is
   begin
      Handled := True;
      case S.State is
         when Connected   =>
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
               case S.Version is
                  when TLS_1_2          =>
                     SPARKTLS.Server.TLS12.Process_Connected_12 (S, Result);

                  when TLS_1_3          =>
                     SPARKTLS.Server.TLS13.Process_Connected_13 (S, Result);

                  when TLS_Undetermined =>
                     S.Last_Error := Internal_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            end if;

         when Closing     =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            elsif Input_Available (S) > 0 then
               case S.Version is
                  when TLS_1_2          =>
                     SPARKTLS.Server.TLS12.Process_Connected_12 (S, Result);

                  when TLS_1_3          =>
                     SPARKTLS.Server.TLS13.Process_Connected_13 (S, Result);

                  when TLS_Undetermined =>
                     S.Last_Error := Internal_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            elsif S.Peer_Closed_Cleanly then
               --  Both directions are closed: our close_notify is sent
               --  and the peer's has arrived. THIS -- not our own send
               --  buffer draining -- is what completes a TLS close.
               --  Zero the traffic keys here, where the connection is
               --  genuinely finished.
               S.Server_App.Key := (others => 0);
               S.Server_App.IV := (others => 0);
               S.Client_App.Key := (others => 0);
               S.Client_App.IV := (others => 0);
               Set_State (S, Closed);
               Result := Shutdown;
            else
               --  Half-duplex close in progress (RFC 8446 6.1). We have
               --  closed our WRITE direction; the peer has not closed
               --  theirs, so the READ direction is still open and this
               --  connection is NOT finished. Stay in Closing.
               --
               --  Critically, keep the read key: it is what authenticates
               --  a late close_notify. Zeroing it here -- which is what
               --  this branch used to do -- destroyed the only means of
               --  telling an orderly close from a truncation attack, and
               --  left Peer_Closed_Cleanly permanently False.
               --
               --  Report Shutdown, not Need_Input: an application that
               --  stops here behaves exactly as it always has and can
               --  never hang waiting for a close_notify that an attacker
               --  simply will not send. One that keeps reading until the
               --  transport ends reaches Closed via the peer's
               --  close_notify, and can then distinguish the two cases.
               --
               --  This mirrors OpenSSL's SSL_shutdown returning 0 (sent,
               --  not yet received) versus 1 (both).
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

         when Closed      =>
            --  Terminal, and reaching it again is normal: a peer may still
            --  have records in flight after our close_notify (BoGo's
            --  Shutdown-Shim-* tests drain with -check-close-notify), and
            --  applications legitimately call Advance again to confirm the
            --  connection is finished.
            --
            --  Report Shutdown idempotently and discard late input. The
            --  traffic keys were zeroed on the way here, so there is
            --  nothing to decrypt with and nothing a late record could
            --  usefully tell us.
            --
            --  Before 2026-08-17 this shared Idle's branch and reported
            --  Internal_Error, turning an ordinary post-close poll into a
            --  spurious failure.
            S.Input.Read_Pos := 0;
            S.Input.Write_Pos := 0;
            Result := Shutdown;

         when Idle        =>
            --  Genuinely a caller error: Advance before Init/Configure.
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;

         when others      =>
            Handled := False;
            Result := Need_Input;
      end case;
   end Advance_Server_Non_Handshake;

   procedure Advance (S : in out Server_Session; Result : out Action) is
      Handled : Boolean;
      --  Snapshot of the handshake slot. The handshake procedures below
      --  take S in out and never touch S.Slot, but that fact does not
      --  cross their call boundary; indexing Slots through a local
      --  constant keeps the guard's S.Slot /= No_Slot structurally in
      --  scope for every Slots (...) below, with no contract needed.
      Slot    : constant Slot_Count := S.Slot;
   begin
      Advance_Server_Non_Handshake (S, Result, Handled);
      if not Handled then
         if Slot = No_Slot then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         --  ClientHello parsing is version-neutral. Once negotiation
         --  commits S.Version, dispatch only to that version's child.
         if S.State = Wait_Client_Hello then
            Advance_Handshake (S, SPARKTLS.HS_Pool.Slots (Slot), Result);
         else
            case S.Version is
               when TLS_1_2          =>
                  SPARKTLS.Server.TLS12.Advance_Handshake_12
                    (S, SPARKTLS.HS_Pool.Slots (Slot), Result);

               when TLS_1_3          =>
                  SPARKTLS.Server.TLS13.Advance_Handshake_13
                    (S, SPARKTLS.HS_Pool.Slots (Slot), Result);

               when TLS_Undetermined =>
                  S.Last_Error := Internal_Error;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
            end case;
         end if;

         if S.State in Connected | Error_State | Closed then
            S.Peer_Cert_Valid := SPARKTLS.HS_Pool.Slots (Slot).Peer_Leaf.Present;
            S.Use_EMS := S.HC.Use_EMS;
            --  Zero ALL key material, then free the slot (Release wipes
            --  the data-plane).
            Scrub_Handshake_Context (S.HC);
            SPARKTLS.HS_Pool.Release (Slot);
            S.Slot := No_Slot;
         end if;
      end if;
   end Advance;

   procedure Complete_Client_Hello
     (S                 : in out Session;
      D                 : in out SPARKTLS.HS_Pool.HS_Data;
      Candidate_Version : in TLS_Version;
      Candidate_12      : in Supported_Suite;
      Result            : out Action)
   with Pre => S.State = Wait_Client_Hello and then S.Role = Role_Server;

   procedure Complete_Client_Hello
     (S                 : in out Session;
      D                 : in out SPARKTLS.HS_Pool.HS_Data;
      Candidate_Version : in TLS_Version;
      Candidate_12      : in Supported_Suite;
      Result            : out Action) is
   begin
      --  RFC 6066 3 + RFC 8446 4.4.2.4: SNI-based certificate
      --  selection. A null callback result means "no match"; use the
      --  default identity already in S.HC.Cfg.Local.
      if S.HC.Cfg.Select_Identity /= null and then S.HC.Peer_SNI.Len > 0 then
         declare
            Picked : constant Maybe_Identity_Access :=
              S.HC.Cfg.Select_Identity
                (S.HC.Peer_SNI.Data
                   (S.HC.Peer_SNI.Data'First .. S.HC.Peer_SNI.Data'First + S.HC.Peer_SNI.Len - 1));
         begin
            if Picked /= null then
               --  A selector result is application data: validate it here,
               --  exactly as Configure validates the default identity.
               if Picked.Has_Identity and then Identity_Valid (Picked.all) then
                  S.HC.Cfg.Local := Valid_Identity_Access (Picked);
               else
                  Send_Alert_And_Error (S, Handshake_Failure, Result);
                  return;
               end if;
            end if;
            pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
         end;
      else
         pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
      end if;

      if not S.HC.Cfg.Local.Has_Identity
        or else not Identity_Valid (S.HC.Cfg.Local.all)
      then
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;

      declare
         --  The Ready_Config VIEW, taken AFTER SNI identity selection --
         --  a view copied any earlier would serve the pre-selection
         --  identity. The predicate check discharges from the runtime
         --  guard directly above (the callback result is app-controlled
         --  input, validated at runtime per project doctrine); the
         --  identity bounds ride Cfg.Local's own Valid_Identity_Access
         --  predicate, which is what retired the assert battery that
         --  used to sit here.
         Cfg     : constant Ready_Config := S.HC.Cfg;
         Policy  : constant Version_Policy := Cfg.Versions;
         Want_13 : constant Boolean := Candidate_Version = TLS_1_3 and Policy /= TLS_1_2_Only;
         Want_12 : constant Boolean :=
           (Candidate_Version = TLS_1_2 or (Candidate_Version = TLS_1_3 and Policy = TLS_1_2_Only))
           and Policy /= TLS_1_3_Only;
      begin
         if Want_13 then
            if S.Negotiated_Suite
               in Suite_AES_128_GCM_SHA256
                | Suite_AES_256_GCM_SHA384
                | Suite_CHACHA20_POLY1305_SHA256
              and then (not S.HC.Client_Saw_Key_Share or else not S.HC.Client_Saw_Supported_Groups)
            then
               Send_Alert_And_Error (S, Missing_Extension, Result);
               return;
            end if;

            if S.Negotiated_Suite
               not in Suite_AES_128_GCM_SHA256
                    | Suite_AES_256_GCM_SHA384
                    | Suite_CHACHA20_POLY1305_SHA256
              or else
                not (S.HC.Client_Has_X25519
                     or S.HC.Client_Has_P256
                     or S.HC.Client_Has_P384
                     or S.HC.Client_Supports_X25519
                     or S.HC.Client_Supports_P256
                     or S.HC.Client_Supports_P384)
            then
               if Want_12 and Candidate_12 /= Suite_None then
                  S.Version := TLS_1_2;
                  S.Negotiated_Suite := Candidate_12;
                  SPARKTLS.Server.TLS12.Build_Server_Flight_12 (S, Cfg, Result);
               else
                  Send_Alert_And_Error (S, Handshake_Failure, Result);
               end if;
            else
               S.Version := TLS_1_3;
               SPARKTLS.Server.TLS13.Build_Server_Flight_13 (S, D, Cfg, Result);
            end if;
            return;
         elsif Want_12 and Candidate_12 /= Suite_None then
            S.Version := TLS_1_2;
            S.Negotiated_Suite := Candidate_12;
            --  Old dead guard (= Unsigned_64'Last, unreachable by
            --  type) deleted with the sealed-channel port.
            SPARKTLS.Server.TLS12.Build_Server_Flight_12 (S, Cfg, Result);
            return;
         else
            if (Candidate_Version = TLS_1_2 and Policy = TLS_1_3_Only)
              or else (Candidate_Version = TLS_1_3 and Policy = TLS_1_2_Only)
            then
               Send_Alert_And_Error (S, Protocol_Version, Result);
            else
               Send_Alert_And_Error (S, Handshake_Failure, Result);
            end if;
            pragma
              Assert
                (if S.State
                    in Wait_Client_Hello
                     | Wait_Client_Hello_Retry
                     | Server_Hello_Sent
                     | Wait_Client_Finished
                 then True);
            return;
         end if;
      end;
   end Complete_Client_Hello;

   --  RFC 8446 4.1.2 Wait_Client_Hello state handler. Reads a TLS
   --  record, validates header, runs RFLX-based reassembly for any
   --  multi-record handshake message, decodes the ClientHello body,
   --  populates HC fields (random, cipher suites, key shares, ext
   --  policy, etc.), and transitions to Wait_Client_Hello_Retry or
   --  the ServerHello-build path on success. Pulled out of the giant
   --  Advance_Handshake case dispatch so SPARK can prove each
   --  protocol state's logic in isolation.
   procedure Handle_Wait_Client_Hello
     (S : in out Server_Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
     --  The state is not decoration: without it the prover knows
     --  nothing about S.State on entry, so every
     --  Send_Alert_And_Error (S, ...) in the body -- whose own Pre is
     --  just "S.State not in Idle | Closed | Closing | Error_State" --
     --  is unprovable. That accounted for 13 of the 18
     --  "precondition might fail" findings in this unit (round 30).
     --  Discharged trivially: the sole caller is the
     --  "when Wait_Client_Hello =>" arm of Advance_Handshake's case.
   with Pre => S.State = Wait_Client_Hello;

   procedure Handle_Wait_Client_Hello
     (S : in out Server_Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (S.State = Wait_Client_Hello);
         pragma Assert_And_Cut (True);
         return;
      end if;

      --  Parse ClientHello from input. RFC 8446 5.1 / RFC 5246
      --  E.1: tolerate any record version on the initial CH
      --  BoGo LooseInitialRecordVersion sends 0x03ff and expects
      --  the server to accept it. Major byte must still be 0x03
      --  (GarbageInitialRecordVersion sends 0xffff and expects
      --  WRONG_VERSION_NUMBER).
      declare
         Rec : Records.Parse_Result;
      begin
         Records.Parse_Record_Header
           (Data          => Byte_Seq (S.Input.Data.all (Ix (S.Input.Read_Pos) .. Ix (S.Input.Write_Pos - 1))),
            Avail         => Available (S.Input),
            Result        => Rec,
            Hdr           => S.Rec_Hdr,
            Loose_Initial => True);

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
               pragma Assert (S.State = Wait_Client_Hello);
            end if;
            return;
         end if;

         if Rec.Content = Records.Content_Change_Cipher_Spec then
            --  RFC 8446 5: CCS for middlebox compatibility is
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
            --  Plaintext alert before handshake  just close
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
            procedure Process_Handshake_Record
            with
              Pre =>
                S.State = Wait_Client_Hello
                and then S.Role = Role_Server
                and then Handshake_Record_Fragment_Ready (Rec)
                and then Rec.Record_Len <= Available (S.Input);

            procedure Process_Handshake_Record is
               Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               Frag_Len   : constant N32 := Rec.Fragment_Len;

               --  Maximum handshake message we'll reassemble (128 KB).
               --  Larger messages are rejected.

               procedure Free_Reasm
               with
                 Pre  => Server_Active (S),
                 Post =>
                   Server_Active (S)
                   and then S.Role = S.Role'Old
                   and then S.State = S.State'Old
                   and then S.Negotiated_Suite = S.Negotiated_Suite'Old
               is
               begin
                  Reset (D.Reasm);
               end Free_Reasm;

               procedure Continue_Reassembly
               with
                 Pre =>
                   S.State = Wait_Client_Hello
                   and then S.Role = Role_Server
                   and then Handshake_Record_Fragment_Ready (Rec)
                   and then Rec.Record_Len <= Available (S.Input)
                   and then Frag_Start <= S.Input.Write_Pos - 1
                   and then Frag_Len <= S.Input.Write_Pos - Frag_Start;

               procedure Continue_Reassembly is
                  More_Input_Needed : Boolean;

                  procedure Decode_Pending_Reassembly_Header
                  with
                    Pre  =>
                      S.State = Wait_Client_Hello
                      and then S.Role = Role_Server
                      and then Header_Ready (D.Reasm),
                    Post =>
                      S.State in Wait_Client_Hello | Error_State
                      and then (if S.State = Wait_Client_Hello then S.Role = Role_Server)
                      and then
                        (if S.State = Wait_Client_Hello
                         then S.HC.Legacy_Session_ID_Len in 0 .. 32);

                  procedure Decode_Pending_Reassembly_Header is
                  begin
                     --  The declared size is derived from the
                     --  buffer's own header bytes, so there is no
                     --  HS_Total to compute and store. Only the
                     --  peer bound check remains.
                     if Message_Too_Large (D.Reasm) then
                        Free_Reasm;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        pragma Assert (S.State = Error_State);
                        pragma Assert (S.Role = Role_Server);
                        pragma
                          Assert_And_Cut
                            (S.State = Error_State
                             and then S.State in Wait_Client_Hello | Error_State
                             and then
                               (if S.State /= Wait_Client_Hello then S.State = Error_State));
                        return;
                     end if;
                     pragma Assert (S.State = Wait_Client_Hello);
                     pragma
                       Assert_And_Cut
                         (S.Role = Role_Server
                          and then S.State = Wait_Client_Hello
                          and then S.State in Wait_Client_Hello | Error_State);
                     pragma
                       Assert_And_Cut
                         (S.Role = Role_Server
                          and then
                            (if S.State = Wait_Client_Hello
                             then S.HC.Legacy_Session_ID_Len in 0 .. 32)
                          and then S.State in Wait_Client_Hello | Error_State);
                     pragma Assert (S.Role = Role_Server);
                  end Decode_Pending_Reassembly_Header;

                  procedure Append_Reassembly_Fragment
                  with
                    Pre  =>
                      S.State = Wait_Client_Hello
                      and then S.Role = Role_Server
                      and then Handshake_Record_Fragment_Ready (Rec)
                      and then Rec.Record_Len <= Available (S.Input)
                      and then Frag_Start <= S.Input.Write_Pos - 1
                      and then Frag_Len <= S.Input.Write_Pos - Frag_Start,
                    Post =>
                      (if S.State = Wait_Client_Hello and then not More_Input_Needed
                       then S.Role = Role_Server)
                      and then
                        (if S.State = Wait_Client_Hello
                         then
                           (if More_Input_Needed
                            then not Has_Message (D.Reasm)
                            else Has_Message (D.Reasm)));

                  procedure Append_Reassembly_Fragment is
                  begin
                     Result := OK;
                     More_Input_Needed := False;
                     --  Append this fragment to the reassembly buffer
                     declare
                        Copy_Len : constant HS_Msg_Len :=
                          N32'Min (N32'Min (Wanted (D.Reasm), Frag_Len), Free_Space (D.Reasm));
                     begin
                        if Copy_Len > 0 then
                           Append
                             (D.Reasm, Byte_Seq (S.Input.Data.all (Ix (Frag_Start) .. Ix (Frag_Start + Copy_Len - 1))));
                        end if;
                     end;
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                     --  Once four bytes are present the peer's declared size
                     --  is readable, so this is where the bound check runs.
                     --  There is no "sentinel" to upgrade any more.
                     if Header_Ready (D.Reasm) then
                        pragma Assert (S.State = Wait_Client_Hello);
                        pragma Assert (S.Role = Role_Server);
                        Decode_Pending_Reassembly_Header;
                        if S.State /= Wait_Client_Hello then
                           return;
                        end if;
                     end if;
                     pragma Assert (S.State = Wait_Client_Hello);
                     if not Has_Message (D.Reasm) then
                        --  Still need more fragments
                        Result := OK;
                        More_Input_Needed := True;
                        pragma Assert (S.State = Wait_Client_Hello);
                        pragma Assert (S.Role = Role_Server);
                        pragma Assert (S.State = Wait_Client_Hello);
                        return;
                     end if;
                     pragma Assert (S.Role = Role_Server);
                  end Append_Reassembly_Fragment;

                  procedure Parse_Completed_Reassembly
                    --  Has_Message is what the body needs to call Message_Length /
                    --  Message on D.Reasm, and the caller already has it:
                    --  Append_Reassembly_Fragment's Post gives
                    --  not More_Input_Needed -> Has_Message, and the call site
                    --  asserts not More_Input_Needed immediately before. Omitting
                    --  it here is the same Defect A as the two handlers in #95 --
                    --  a Pre that leaves out a fact the body needs and the caller
                    --  holds.
                  with
                    Pre =>
                      Has_Message (D.Reasm)
                      and then S.State = Wait_Client_Hello
                      and then S.Role = Role_Server;

                  procedure Parse_Completed_Reassembly is
                     Parse_OK          : Boolean;
                     Candidate_Version : TLS_Version;
                     Candidate_12      : Supported_Suite := Suite_None;
                  begin
                     --  Full message reassembled  parse it.
                     --  This message will be appended to the transcript;
                     --  reject anything larger than the transcript
                     --  buffer before slicing and parsing it.
                     if Message_Length (D.Reasm) > Transcript_Capacity then
                        Free_Reasm;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        pragma Assert (S.Role = Role_Server);
                        return;
                     end if;
                     declare
                        --  Message yields exactly the declared message.
                        --  The old code sliced 0 .. Len - 1, i.e. everything
                        --  BUFFERED, which would have included trailing bytes
                        --  had a peer packed anything after the ClientHello.
                        --  The "Len = 0" arm is gone with it: Has_Message
                        --  guarantees at least a 4-byte header.
                        Full_Msg : constant Message_Bytes := Message (D.Reasm);
                     begin
                        Handshake.Server_Msgs.Parse_Client_Hello
                          (S.Negotiated_Suite,
                           Candidate_12,
                           S.Last_Error,
                           S.HC,
                           Byte_Seq (Full_Msg),
                           Candidate_Version,
                           Parse_OK);
                        if Parse_OK then
                           pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
                           --  Capture the binder transcript hash BEFORE the CH
                           --  enters the stream (RFC 8446 4.2.11.2): binders cover
                           --  everything up to the binders list.
                           declare
                              L : SPARKTLS_Transcript.Transcript_State;
                           begin
                              SPARKTLS_Transcript.Start (L);
                              if S.HC.PSK.Offered
                                and then S.HC.PSK.Binder_Len > 0
                                and then N32 (Full_Msg'Length) > 3 + S.HC.PSK.Binder_Len
                              then
                                 declare
                                    T : constant N32 :=
                                      N32 (Full_Msg'Length) - (3 + S.HC.PSK.Binder_Len);
                                 begin
                                    SPARKTLS_Transcript.Suffix_256
                                      (L,
                                       Byte_Seq (Full_Msg) (0 .. T - 1),
                                       SPARKTLSCrypto.Hashing.SHA256.Digest
                                         (S.HC.PSK.Binder_Hash_256));
                                    SPARKTLS_Transcript.Suffix_384
                                      (L,
                                       Byte_Seq (Full_Msg) (0 .. T - 1),
                                       SPARKTLSCrypto.Hashing.SHA384.Digest
                                         (S.HC.PSK.Binder_Hash_384));
                                    S.HC.PSK.Binder_Hash_Taken := True;
                                 end;
                              end if;
                              SPARKTLS_Transcript.Append (L, Byte_Seq (Full_Msg));
                              --  ENGAGE (phase carve): single constructor site,
                              --  full-message path. L has absorbed the ClientHello.
                              S.HC :=
                                (TS                          => L,
                                 Cfg                         => S.HC.Cfg,
                                 Peer_SNI                    => S.HC.Peer_SNI,
                                 Client_Random               => S.HC.Client_Random,
                                 Server_Random               => S.HC.Server_Random,
                                 Client_Has_X25519           => S.HC.Client_Has_X25519,
                                 Client_Has_P256             => S.HC.Client_Has_P256,
                                 Client_Has_P384             => S.HC.Client_Has_P384,
                                 Client_Saw_Key_Share        => S.HC.Client_Saw_Key_Share,
                                 Client_Saw_Supported_Groups => S.HC.Client_Saw_Supported_Groups,
                                 Client_Supports_X25519      => S.HC.Client_Supports_X25519,
                                 Client_Supports_P256        => S.HC.Client_Supports_P256,
                                 Client_Supports_P384        => S.HC.Client_Supports_P384,
                                 KE                          => S.HC.KE,
                                 HRR_Sent                    => S.HC.HRR_Sent,
                                 Got_HRR                     => S.HC.Got_HRR,
                                 HRR_Cipher_Suite            => S.HC.HRR_Cipher_Suite,
                                 HRR_Selected_Group          => S.HC.HRR_Selected_Group,
                                 HRR_Cookie_Len              => S.HC.HRR_Cookie_Len,
                                 HRR_Cookie                  => S.HC.HRR_Cookie,
                                 Sent_HRR_CCS                => S.HC.Sent_HRR_CCS,
                                 CH_Ext_Hash                 => S.HC.CH_Ext_Hash,
                                 CH_Ext_Count                => S.HC.CH_Ext_Count,
                                 Seen_Ext_Tags               => S.HC.Seen_Ext_Tags,
                                 Seen_Ext_Count              => S.HC.Seen_Ext_Count,
                                 Client_HS                   => S.HC.Client_HS,
                                 Server_HS                   => S.HC.Server_HS,
                                 Client_HS_Secret            => S.HC.Client_HS_Secret,
                                 Server_HS_Secret            => S.HC.Server_HS_Secret,
                                 Handshake_Secret            => S.HC.Handshake_Secret,
                                 Master_Secret               => S.HC.Master_Secret,
                                 Neg                         => S.HC.Neg,
                                 Legacy_Session_ID           => S.HC.Legacy_Session_ID,
                                 Legacy_Session_ID_Len       => S.HC.Legacy_Session_ID_Len,
                                 Peer_Sig_Algos              => S.HC.Peer_Sig_Algos,
                                 Peer_Sig_Algo_Count         => S.HC.Peer_Sig_Algo_Count,
                                 Negotiated_Sig_Algo         => S.HC.Negotiated_Sig_Algo,
                                 CCS_Received                => S.HC.CCS_Received,
                                 T12                         => S.HC.T12,
                                 PSK                         => S.HC.PSK,
                                 Cert_Request_Received       => S.HC.Cert_Request_Received,
                                 Has_TLS_1_3                 => S.HC.Has_TLS_1_3,
                                 Saw_Supported_Versions      => S.HC.Saw_Supported_Versions,
                                 SV_Has_Acceptable           => S.HC.SV_Has_Acceptable,
                                 CKE_Received_12             => S.HC.CKE_Received_12,
                                 Use_EMS                     => S.HC.Use_EMS,
                                 EMS_Session_Hash            => S.HC.EMS_Session_Hash,
                                 EMS_Hash_Taken              => S.HC.EMS_Hash_Taken,
                                 Saw_Reneg_Info              => S.HC.Saw_Reneg_Info,
                                 Ext_Parse_Err               => S.HC.Ext_Parse_Err,
                                 Client_ALPN                 => S.HC.Client_ALPN,
                                 Client_ALPN_List            => S.HC.Client_ALPN_List,
                                 Client_ALPN_Count           => S.HC.Client_ALPN_Count,
                                 Master_Secret_12            => S.HC.Master_Secret_12,
                                 Client_Write_IV_12          => S.HC.Client_Write_IV_12,
                                 Server_Write_IV_12          => S.HC.Server_Write_IV_12,
                                 MS_Derivation               => S.HC.MS_Derivation,
                                 Using_PSK                   => S.HC.Using_PSK,
                                 Early_Data_Offered          => S.HC.Early_Data_Offered,
                                 Skipped_Early_Data_Records  => S.HC.Skipped_Early_Data_Records);
                           end;
                        end if;
                     end;
                     Free_Reasm;

                     if not Parse_OK then
                        Dispatch_CH_Parse_Error_Alert (S, Result);
                        return;
                     end if;
                     pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
                     Complete_Client_Hello (S, D, Candidate_Version, Candidate_12, Result);
                  end Parse_Completed_Reassembly;
               begin
                  Append_Reassembly_Fragment;
                  if S.State /= Wait_Client_Hello or else More_Input_Needed then
                     return;
                  end if;

                  pragma Assert (S.State = Wait_Client_Hello);
                  pragma Assert (S.Role = Role_Server);
                  pragma Assert (not More_Input_Needed);
                  Parse_Completed_Reassembly;
               end Continue_Reassembly;

               procedure Process_Fresh_Handshake_Record
               with
                 Pre =>
                   S.State = Wait_Client_Hello
                   and then S.Role = Role_Server
                   and then Handshake_Record_Fragment_Ready (Rec)
                   and then Rec.Record_Len <= Available (S.Input)
                   and then S.Input.Read_Pos <= IO_Buffer_Capacity - Rec.Record_Len
                   and then Frag_Start <= S.Input.Write_Pos - 1
                   and then Frag_Len <= S.Input.Write_Pos - Frag_Start
                   and then Frag_Len < Transcript_Capacity;

               procedure Parse_Single_Record_Client_Hello
               with
                 Pre =>
                   S.State = Wait_Client_Hello
                   and then S.Role = Role_Server
                   and then Handshake_Record_Fragment_Ready (Rec)
                   and then Rec.Record_Len <= Available (S.Input)
                   and then S.Input.Read_Pos <= IO_Buffer_Capacity - Rec.Record_Len
                   and then Frag_Len >= 4
                   and then Frag_Start <= S.Input.Write_Pos - 1
                   and then Frag_Len <= S.Input.Write_Pos - Frag_Start
                   and then Frag_Len < Transcript_Capacity;

               procedure Parse_Single_Record_Client_Hello is
                  Parse_OK          : Boolean;
                  Candidate_Version : TLS_Version;
                  Candidate_12      : Supported_Suite := Suite_None;
               begin
                  --  Single-record message: parse directly. Copy
                  --  instead of renaming to avoid aliasing between
                  --  the fragment parameter and the in-out Session.
                  declare
                     Frag : constant Byte_Seq (0 .. Frag_Len - 1) :=
                       Byte_Seq (S.Input.Data.all (Ix (Frag_Start) .. Ix (Frag_Start + Frag_Len - 1)));
                  begin
                     Handshake.Server_Msgs.Parse_Client_Hello
                       (S.Negotiated_Suite,
                        Candidate_12,
                        S.Last_Error,
                        S.HC,
                        Frag,
                        Candidate_Version,
                        Parse_OK);

                     if not Parse_OK then
                        pragma Assert (S.State = Wait_Client_Hello);
                        Dispatch_CH_Parse_Error_Alert (S, Result);
                        pragma Assert (S.State = Error_State);
                        S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                        pragma Assert (S.State = Error_State);
                        return;
                     end if;
                     pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);

                     pragma Assert (Frag_Len < Transcript_Capacity);
                     pragma Assert (Frag'Last - Frag'First = Frag_Len - 1);
                     declare
                        L : SPARKTLS_Transcript.Transcript_State;
                     begin
                        SPARKTLS_Transcript.Start (L);
                        --  Capture the binder transcript hash BEFORE the CH
                        --  enters the stream (RFC 8446 4.2.11.2), exactly as
                        --  the reassembled-message path does. Missing here
                        --  since the streaming-transcript carve: every
                        --  resumption through the single-record path failed
                        --  binder verification (alert 51) against RFC
                        --  clients -- masked by self-play resume tests and a
                        --  silently refreshed BoGo baseline.
                        if S.HC.PSK.Offered
                          and then S.HC.PSK.Binder_Len > 0
                          and then Frag_Len > 3 + S.HC.PSK.Binder_Len
                        then
                           declare
                              T : constant N32 := Frag_Len - (3 + S.HC.PSK.Binder_Len);
                           begin
                              SPARKTLS_Transcript.Suffix_256
                                (L,
                                 Frag (Frag'First .. Frag'First + T - 1),
                                 SPARKTLSCrypto.Hashing.SHA256.Digest (S.HC.PSK.Binder_Hash_256));
                              SPARKTLS_Transcript.Suffix_384
                                (L,
                                 Frag (Frag'First .. Frag'First + T - 1),
                                 SPARKTLSCrypto.Hashing.SHA384.Digest (S.HC.PSK.Binder_Hash_384));
                              S.HC.PSK.Binder_Hash_Taken := True;
                           end;
                        end if;
                        SPARKTLS_Transcript.Append (L, Frag);
                        --  ENGAGE (phase carve): single-record path.
                        S.HC :=
                          (TS                          => L,
                           Cfg                         => S.HC.Cfg,
                           Peer_SNI                    => S.HC.Peer_SNI,
                           Client_Random               => S.HC.Client_Random,
                           Server_Random               => S.HC.Server_Random,
                           Client_Has_X25519           => S.HC.Client_Has_X25519,
                           Client_Has_P256             => S.HC.Client_Has_P256,
                           Client_Has_P384             => S.HC.Client_Has_P384,
                           Client_Saw_Key_Share        => S.HC.Client_Saw_Key_Share,
                           Client_Saw_Supported_Groups => S.HC.Client_Saw_Supported_Groups,
                           Client_Supports_X25519      => S.HC.Client_Supports_X25519,
                           Client_Supports_P256        => S.HC.Client_Supports_P256,
                           Client_Supports_P384        => S.HC.Client_Supports_P384,
                           KE                          => S.HC.KE,
                           HRR_Sent                    => S.HC.HRR_Sent,
                           Got_HRR                     => S.HC.Got_HRR,
                           HRR_Cipher_Suite            => S.HC.HRR_Cipher_Suite,
                           HRR_Selected_Group          => S.HC.HRR_Selected_Group,
                           HRR_Cookie_Len              => S.HC.HRR_Cookie_Len,
                           HRR_Cookie                  => S.HC.HRR_Cookie,
                           Sent_HRR_CCS                => S.HC.Sent_HRR_CCS,
                           CH_Ext_Hash                 => S.HC.CH_Ext_Hash,
                           CH_Ext_Count                => S.HC.CH_Ext_Count,
                           Seen_Ext_Tags               => S.HC.Seen_Ext_Tags,
                           Seen_Ext_Count              => S.HC.Seen_Ext_Count,
                           Client_HS                   => S.HC.Client_HS,
                           Server_HS                   => S.HC.Server_HS,
                           Client_HS_Secret            => S.HC.Client_HS_Secret,
                           Server_HS_Secret            => S.HC.Server_HS_Secret,
                           Handshake_Secret            => S.HC.Handshake_Secret,
                           Master_Secret               => S.HC.Master_Secret,
                           Neg                         => S.HC.Neg,
                           Legacy_Session_ID           => S.HC.Legacy_Session_ID,
                           Legacy_Session_ID_Len       => S.HC.Legacy_Session_ID_Len,
                           Peer_Sig_Algos              => S.HC.Peer_Sig_Algos,
                           Peer_Sig_Algo_Count         => S.HC.Peer_Sig_Algo_Count,
                           Negotiated_Sig_Algo         => S.HC.Negotiated_Sig_Algo,
                           CCS_Received                => S.HC.CCS_Received,
                           T12                         => S.HC.T12,
                           PSK                         => S.HC.PSK,
                           Cert_Request_Received       => S.HC.Cert_Request_Received,
                           Has_TLS_1_3                 => S.HC.Has_TLS_1_3,
                           Saw_Supported_Versions      => S.HC.Saw_Supported_Versions,
                           SV_Has_Acceptable           => S.HC.SV_Has_Acceptable,
                           CKE_Received_12             => S.HC.CKE_Received_12,
                           Use_EMS                     => S.HC.Use_EMS,
                           EMS_Session_Hash            => S.HC.EMS_Session_Hash,
                           EMS_Hash_Taken              => S.HC.EMS_Hash_Taken,
                           Saw_Reneg_Info              => S.HC.Saw_Reneg_Info,
                           Ext_Parse_Err               => S.HC.Ext_Parse_Err,
                           Client_ALPN                 => S.HC.Client_ALPN,
                           Client_ALPN_List            => S.HC.Client_ALPN_List,
                           Client_ALPN_Count           => S.HC.Client_ALPN_Count,
                           Master_Secret_12            => S.HC.Master_Secret_12,
                           Client_Write_IV_12          => S.HC.Client_Write_IV_12,
                           Server_Write_IV_12          => S.HC.Server_Write_IV_12,
                           MS_Derivation               => S.HC.MS_Derivation,
                           Using_PSK                   => S.HC.Using_PSK,
                           Early_Data_Offered          => S.HC.Early_Data_Offered,
                           Skipped_Early_Data_Records  => S.HC.Skipped_Early_Data_Records);
                     end;
                  end;
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                  Reset (D.Reasm);
                  pragma Assert (S.HC.Legacy_Session_ID_Len in 0 .. 32);
                  Complete_Client_Hello (S, D, Candidate_Version, Candidate_12, Result);
               end Parse_Single_Record_Client_Hello;

               procedure Start_Header_Pending_Reassembly
               with
                 Pre =>
                   S.State = Wait_Client_Hello
                   and then Frag_Len in 1 .. 3
                   and then Rec.Record_Len <= Available (S.Input)
                   and then S.Input.Read_Pos <= IO_Buffer_Capacity - Rec.Record_Len
                   and then Frag_Start <= S.Input.Write_Pos - 1
                   and then Frag_Len <= S.Input.Write_Pos - Frag_Start;

               procedure Start_Header_Pending_Reassembly is
               begin
                  --  Fewer than four bytes: there is no
                  --  "header-pending phase" to enter, just
                  --  a buffer that does not yet have a
                  --  readable header.
                  Reset (D.Reasm);
                  Append (D.Reasm, Byte_Seq (S.Input.Data.all (Ix (Frag_Start) .. Ix (Frag_Start + Frag_Len - 1))));
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK;
                  pragma Assert (S.State = Wait_Client_Hello);
               end Start_Header_Pending_Reassembly;

               procedure Start_Known_Length_Reassembly (HS_Total : N32)
               with
                 Pre =>
                   S.State = Wait_Client_Hello
                   and then Frag_Len >= 4
                   and then HS_Total in 4 .. Max_HS_Msg
                   and then HS_Total > Frag_Len
                   and then Rec.Record_Len <= Available (S.Input)
                   and then S.Input.Read_Pos <= IO_Buffer_Capacity - Rec.Record_Len
                   and then Frag_Start <= S.Input.Write_Pos - 1
                   and then Frag_Len <= S.Input.Write_Pos - Frag_Start;

               procedure Start_Known_Length_Reassembly (HS_Total : N32) is
               begin
                  --  HS_Total is not stored: the
                  --  declared size comes from the
                  --  bytes we are about to append,
                  --  so there is nothing that can
                  --  disagree with them.
                  Reset (D.Reasm);
                  Append (D.Reasm, Byte_Seq (S.Input.Data.all (Ix (Frag_Start) .. Ix (Frag_Start + Frag_Len - 1))));
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK;
                  pragma Assert (S.State = Wait_Client_Hello);
               end Start_Known_Length_Reassembly;

               procedure Process_Fresh_Handshake_Record is
               begin
                  --  Fresh handshake record. Check if the message
                  --  spans multiple records by reading the 3-byte
                  --  handshake length.
                  if Frag_Len < 4 then
                     --  RFC 8446 Section 5.1: handshake messages MAY
                     --  span records. The first fragment is shorter
                     --  than the 4-byte HS header itself, so start
                     --  reassembly with a header-pending sentinel.
                     if Frag_Len = 0 then
                        S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        pragma Assert (S.State = Error_State);
                        return;
                     end if;

                     pragma Assert (Frag_Len in 1 .. 3);
                     Start_Header_Pending_Reassembly;
                     return;
                  end if;

                  declare
                     HS_Msg_Len : constant N32 :=
                       N32 (S.Input.Data.all (Ix (Frag_Start + 1))) * 65536
                       + N32 (S.Input.Data.all (Ix (Frag_Start + 2))) * 256
                       + N32 (S.Input.Data.all (Ix (Frag_Start + 3)));
                     HS_Total   : constant N32 := HS_Msg_Len + 4;
                  begin
                     if HS_Total > Max_HS_Msg then
                        S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        pragma Assert (S.State = Error_State);
                        return;
                     end if;

                     if HS_Total > Frag_Len then
                        pragma Assert (HS_Total in 4 .. Max_HS_Msg);
                        Start_Known_Length_Reassembly (HS_Total);
                        return;
                     end if;
                  end;

                  pragma Assert (Frag_Len >= 4);
                  Parse_Single_Record_Client_Hello;
               end Process_Fresh_Handshake_Record;
            begin
               Result := Error_Alert;
               --  Mid-reassembly? The inner
               --  "Need > 0 and Phase = Idle"
               --  rejection is gone: that was a
               --  contradiction the old two-field
               --  encoding allowed to be written
               --  but never reached. One field
               --  cannot contradict itself.
               if Used (D.Reasm) > 0 then
                  Continue_Reassembly;
                  return;

               end if;

               pragma Assert (Used (D.Reasm) = 0);
               pragma Assert (Frag_Len < Transcript_Capacity);
               Process_Fresh_Handshake_Record;
            end Process_Handshake_Record;
         begin
            Result := Error_Alert;
            Process_Handshake_Record;
         end;
      end;
      return;
   end Handle_Wait_Client_Hello;

   --  Advance only the version-neutral ClientHello state.
   procedure Advance_Handshake
     (S : in out Server_Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      if S.HC.Cfg not in Ready_Config then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
      elsif S.State = Wait_Client_Hello then
         Handle_Wait_Client_Hello (S, D, Result);
      else
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
      end if;
   end Advance_Handshake;

   procedure Close_Notify (S : in out Session) is
      Ignored_Alert_Out : N32;
   begin
      --  The session may already be fully closed: Advance zeroes the
      --  traffic keys and sets Closed once BOTH directions have closed
      --  (RFC 8446 6.1). It reports that with the same Shutdown result it
      --  uses for a half-duplex close, so an application cannot tell the
      --  two apart and will reasonably call us in either case. Encrypting
      --  here would build an alert under the all-zero scrubbed key and
      --  burn a sequence number on a dead session. Nothing to send.
      if S.State not in Connected | Closing then
         return;
      end if;
      case S.Version is
         when TLS_1_2          =>
            Abort_Flight (S);
            Records.TLS12.Build_Alert_Record_12
              (Level       => 1,
               Desc        => 0,
               Keys        => S.Server_App,
               Implicit_IV => S.Server_IV_12,
               Output      => S.Output,
               Bytes_Out   => Ignored_Alert_Out,
               Hdr_Buf     => S.Rec_Hdr);

         when TLS_1_3          =>
            Abort_Flight (S);
            Records.Build_Alert_Record
              (Level     => 1,
               Desc      => 0,
               Keys      => S.Server_App,
               Output    => S.Output,
               Bytes_Out => Ignored_Alert_Out,
               Hdr_Buf   => S.Rec_Hdr);

         when TLS_Undetermined =>
            return;
      end case;
      --  RFC 8446 6.1: at most one close_notify per peer; if we
      --  already transitioned to Closing on a prior invocation, the
      --  state-machine transition is a no-op.
      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Server;
