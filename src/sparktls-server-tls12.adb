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
with SPARKTLS.Tickets_12;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;

package body SPARKTLS.Server.TLS12 with
   SPARK_Mode => On
is
   use Handshake.TLS12;

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Alert_Desc (Err) /= 0
                and Alert_Desc (Err) /= 90,
        Post => S.State = Error_State
                --  RFC 8446 §6.2 / RFC 5246 §7.2.2: a fatal alert
                --  MUST be sent to the peer before the connection
                --  closes. We satisfy this by queueing the alert
                --  record in the output buffer (Result = Has_Output)
                --  before transitioning to Error_State. The
                --  Error_Has_Alert ghost predicate captures the
                --  invariant: in Error_State, output is non-empty
                --  unless the error is one we couldn't write
                --  (Unexpected_Message after early plaintext).
                and Error_Has_Alert (S.State, Output_Pending (S),
                                     S.Last_Error);

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

   --  ----- RFC 5246 §7.2.1 post-CCS encrypted alert helper ---------
   --  After the client has sent ChangeCipherSpec, RFC 5246 §7.2.1
   --  requires further alerts to be sent encrypted under the
   --  established traffic keys. Sending a plaintext alert at this
   --  point is a protocol violation; strict TLS 1.2 clients reject
   --  it as unexpected_message.
   --
   --  Mirrors Send_Encrypted_Alert in server.adb (TLS 1.3 path)
   --  using Build_Alert_Record_12 with TLS 1.2 implicit IV +
   --  explicit sequence number.
   procedure Send_Encrypted_Alert_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Err    : Error_Code;
      Result : out Action)
   with Pre  => S.State not in Idle | Closed | Closing | Error_State
                and Alert_Desc (Err) /= 0
                and Alert_Desc (Err) /= 90
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Server_Seq_12),
        Post => S.State = Error_State
                and S.Last_Error = Err;
                --  Error_Has_Alert is NOT in this Post — see
                --  matching note on Send_Encrypted_Alert in
                --  sparktls-server.adb. Call sites bridge to
                --  Pending > 0 via local pragma Assert.

   procedure Send_Encrypted_Alert_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Err    : Error_Code;
      Result : out Action)
   is
      Dummy : N32;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Alert_Desc (Err),
         Keys        => S.Server_App,
         Implicit_IV => HC.Server_Write_IV_12,
         Seq_Num     => HC.Server_Seq_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Alert_12;

   --  Post-handshake encrypted fatal alert. Mirrors
   --  Send_Encrypted_Alert_12 but reads IV/seq from S-level state
   --  (HC has been freed once we entered Connected). For use in
   --  Process_Connected_12. Same "alerts after CCS MUST be
   --  encrypted" RFC 5246 §7.2.1 / §7.2.2 constraint that the §2.8
   --  TLS 1.3 mTLS bypass exposed: a plaintext alert here lands as
   --  a bad record type on the peer and is silently dropped.
   procedure Send_Encrypted_Alert_Connected_12
     (S      : in out Session;
      Err    : Error_Code;
      Result : out Action)
   is
      Dummy : N32;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Alert_Desc (Err),
         Keys        => S.Server_App,
         Implicit_IV => S.Server_IV_12,
         Seq_Num     => S.Server_Seq_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Alert_Connected_12;

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
                --  RFC 5246 §7.4.9 transcript-monotonicity invariant:
                --  the handshake transcript is the basis for Finished
                --  verify_data. Once a byte enters the transcript it
                --  cannot be removed or rewritten, otherwise the peer's
                --  Finished computation will diverge from ours and
                --  authentic handshakes will fail. Length never shrinks.
                and then HC.Transcript_Len >= HC.Transcript_Len'Old
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
   --  Forward decl: full handshake state machine entry that the resume
   --  attempt may fall through to.
   procedure Build_Server_Flight_12_Full
     (S : in out Session; HC : in out Handshake_Context; Result : out Action);

   --  Resumed-handshake server flight (RFC 5077 §3.3 abbreviated).
   --  Caller has set HC.TLS12_Resuming + HC.Master_Secret_12 +
   --  S.Negotiated_Suite from the decrypted ticket. Emits
   --  SH → NST → CCS → encrypted Finished as one atomic flight,
   --  then transitions to Wait_Client_Finished to receive the
   --  client's CCS + Finished.
   procedure Build_Abbreviated_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action);

   procedure Build_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
   begin
      --  RFC 5077 §3.4: if the client offered a non-empty session_ticket
      --  extension AND we have configured ticket-encryption keys, try
      --  to decrypt + resume. On success we run the abbreviated flight;
      --  on any failure (unknown Key_ID, tag mismatch, expiry, suite
      --  mismatch, etc.) we silently fall through to the full handshake
      --  — RFC 5077 §3.4 requires this: "If the server refuses to use
      --  the ticket, it SHOULD proceed with a full handshake."
      if HC.TLS12_Ticket_Offered
        and then HC.TLS12_Peer_Ticket_Len > 0
        and then HC.Cfg.TLS12_Ticket_Keys /= null
      then
         declare
            Plain : SPARKTLS.Tickets_12.Ticket_Plain;
            OK    : Boolean;
         begin
            SPARKTLS.Tickets_12.Decrypt_Ticket
              (Ticket  => HC.TLS12_Peer_Ticket
                            (0 .. HC.TLS12_Peer_Ticket_Len - 1),
               Keys    => HC.Cfg.TLS12_Ticket_Keys.all,
               Now     => 0,    --  TODO: wire Cfg.Get_Time → Unix
               Max_Age => 0,    --  0 = no expiry check (paired with Now=0)
               Plain   => Plain,
               Status  => OK);
            if OK
              and then S.Negotiated_Suite_12 /= 0
              and then Plain.Suite = S.Negotiated_Suite_12
            then
               --  Resume: install ticket's master_secret + force suite.
               HC.Master_Secret_12 := Plain.Master_Secret;
               S.Negotiated_Suite := Plain.Suite;
               HC.TLS12_Resuming := True;
               Build_Abbreviated_Server_Flight_12 (S, HC, Result);
               return;
            end if;
         end;
      end if;

      Build_Server_Flight_12_Full (S, HC, Result);
   end Build_Server_Flight_12;

   procedure Build_Server_Flight_12_Full
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
         if HC.Peer_Sig_Algo_Count = 0 then
            --  RFC 5246 §7.4.1.4.1: when client omits the
            --  signature_algorithms extension, the server uses a
            --  default. RFC 5246 specifies SHA-1, but SHA-1 is
            --  deprecated and we don't support it. Modern practice
            --  (OpenSSL, Go) is to default to SHA-256 with the
            --  cert's algorithm. TLS-Anvil's
            --  ecdsaNoSignatureAlgorithmsExtension test (5246-MjFVuYUzfF)
            --  exercises this path.
            case HC.Cfg.Local.Sign_Algo is
               when Sign_RSA_PSS    => Negotiated := 16#0804#;  -- PSS-SHA256
               when Sign_ECDSA_P256 => Negotiated := 16#0403#;
               when Sign_ECDSA_P384 => Negotiated := 16#0503#;
               when Sign_Ed25519    => Negotiated := 16#0807#;
               when Sign_None       => null;
            end case;
            --  RFC 5246 §7.4.1.4.1 strong-hash invariant: every value
            --  the case selects above is a SHA-256-or-stronger scheme.
            --  This pragma Assert pins the property; a future edit
            --  that introduces a SHA-1 default (e.g. 0x0201, 0x0202)
            --  would fail SPARK proof here.
            pragma Assert
              (Negotiated = 0
                 or else Sig_Scheme_Has_Strong_Hash_RFC_5246_7_4_1_4_1
                          (Negotiated));
         else
            for I in Natural range 0 .. HC.Peer_Sig_Algo_Count - 1 loop
               pragma Loop_Invariant
                 (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                    (Negotiated, HC.Peer_Sig_Algos,
                     HC.Peer_Sig_Algo_Count));
               declare
                  Scheme : constant Unsigned_16 := HC.Peer_Sig_Algos (I);
               begin
                  case HC.Cfg.Local.Sign_Algo is
                     when Sign_RSA_PSS =>
                        --  An RSA key can sign with either PSS or
                        --  PKCS#1 v1.5 padding. RFC 5246 §7.4.1.4.1 +
                        --  RFC 8446 §4.2.3 — accept any RSA scheme the
                        --  client offered. PSS preferred where both
                        --  are offered (the picking loop selects the
                        --  first match, so client ordering wins).
                        --  PKCS#1-SHA1 (0x0201) intentionally not
                        --  accepted — SHA-1 is deprecated.
                        if Scheme = 16#0804# or Scheme = 16#0805#
                           or Scheme = 16#0806#
                           or Scheme = 16#0401# or Scheme = 16#0501#
                           or Scheme = 16#0601#
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
            --  RFC 5246 §7.4.1.4.1 / RFC 8446 §4.2.3: post-loop the
            --  Negotiated scheme (if non-zero) is one the client
            --  offered. The loop invariant builds this incrementally:
            --  every iteration either exits with Negotiated set to
            --  HC.Peer_Sig_Algos(I), or leaves Negotiated unchanged.
            pragma Assert
              (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                 (Negotiated, HC.Peer_Sig_Algos,
                  HC.Peer_Sig_Algo_Count));
         end if;
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
   end Build_Server_Flight_12_Full;

   ------------------------------------------------------------------
   --  Derive AEAD keys / IVs from an already-set HC.Master_Secret_12.
   --  Used by the abbreviated (resumed) TLS 1.2 handshake: master_secret
   --  comes from the RFC 5077 ticket plaintext, not from ECDHE. Mirrors
   --  the back half of Derive_Keys_12 (the Expand_Keys + S.Server_App
   --  assignments) without the master-secret PRF step.
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

   ------------------------------------------------------------------
   --  Build the abbreviated (resumed) server flight: SH → NST →
   --  CCS → encrypted Finished. Caller has already restored
   --  HC.Master_Secret_12 + forced S.Negotiated_Suite from the ticket.
   ------------------------------------------------------------------
   procedure Build_Abbreviated_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      use Key_Schedule_12;
      use type SPARKTLS.Tickets_12.Bytes_4;
      Gen_Random : constant Random_Bytes_Fn := HC.Cfg.Random;
      Rec_Out    : N32;
      Scratch    : IO_Buffer;
      Saved_Seq  : Unsigned_64;
      Use_384    : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      --  Mirror the full-flight setup that Build_Server_Flight_12_Full
      --  did before we diverted. We don't pick a group (no ECDHE), we
      --  don't pick a signature scheme (no SKE), but we DO need the
      --  Negotiated_Sig_Algo to be cleared so Build_Server_Hello_12
      --  doesn't try to echo a stale value.
      HC.Negotiated_Sig_Algo := 0;

      --  Fresh server random (32 bytes).
      Gen_Random (Byte_Seq (HC.Server_Random));

      --  1. ServerHello (with empty session_ticket ext, since
      --     TLS12_Ticket_Offered + TLS12_Ticket_Keys are set).
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1);
         Hello_Len : N32;
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

      --  2. Derive AEAD keys (no master-secret PRF — restored from
      --     ticket; just expand to traffic keys + IVs).
      Derive_Keys_Resumed_12 (S, HC);

      --  3. NewSessionTicket (re-issued under our active TEK with a
      --     fresh nonce). RFC 5077 §3.3: the server MUST send NST in
      --     the resumed flight if it advertised session_ticket in SH.
      declare
         Active_Key : TLS12_Ticket_Key
            renames HC.Cfg.TLS12_Ticket_Keys
                      (HC.Cfg.TLS12_Active_TEK_Idx);
         Nonce_Buf  : Byte_Seq (0 .. 11) := (others => 0);
         Plain      : SPARKTLS.Tickets_12.Ticket_Plain;
         Ticket_Buf : Byte_Seq (0 .. 255) := (others => 0);
         Ticket_Len : N32;
         NST_Buf    : Byte_Seq (0 .. 271) := (others => 0);
         NST_Total  : N32;
         NST_Rec_Out : N32;
         NST_Hdr_Len : constant N32 := 4 + 4 + 2;
      begin
         Gen_Random (Nonce_Buf);
         Plain.Master_Secret := HC.Master_Secret_12;
         Plain.Suite         := S.Negotiated_Suite;
         Plain.Created_At    := 0;
         Plain.SID_Len       := 0;
         Plain.SID           := (others => 0);
         SPARKTLS.Tickets_12.Encrypt_Ticket
           (Plain      => Plain,
            Key_ID     =>
              SPARKTLS.Tickets_12.Bytes_4 (Active_Key.Key_ID),
            TEK        =>
              SPARKTLS.Tickets_12.Bytes_32 (Active_Key.TEK),
            Nonce      => SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
            Ticket     => Ticket_Buf,
            Ticket_Len => Ticket_Len);

         NST_Total := NST_Hdr_Len + Ticket_Len;
         NST_Buf (0) := 16#04#;
         declare
            Body_Len : constant N32 := 4 + 2 + Ticket_Len;
         begin
            NST_Buf (1) := Byte (Body_Len / 65536);
            NST_Buf (2) := Byte ((Body_Len / 256) mod 256);
            NST_Buf (3) := Byte (Body_Len mod 256);
         end;
         NST_Buf (4) :=
            Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 24)
                  and 16#FF#);
         NST_Buf (5) :=
            Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 16)
                  and 16#FF#);
         NST_Buf (6) :=
            Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 8)
                  and 16#FF#);
         NST_Buf (7) :=
            Byte (HC.Cfg.TLS12_Ticket_Lifetime and 16#FF#);
         NST_Buf (8) := Byte (Ticket_Len / 256);
         NST_Buf (9) := Byte (Ticket_Len mod 256);
         NST_Buf (10 .. 10 + Ticket_Len - 1) :=
            Ticket_Buf (0 .. Ticket_Len - 1);

         Append_Transcript (HC, NST_Buf (0 .. NST_Total - 1));

         Records.Build_Handshake_Record
           (NST_Buf (0 .. NST_Total - 1), Scratch, NST_Rec_Out);
         if NST_Rec_Out = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  4. ChangeCipherSpec (plaintext, content type 20).
      declare
         CCS_Out : N32;
      begin
         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  5. Server Finished (encrypted with the just-derived app keys).
      Saved_Seq := HC.Server_Seq_12;
      declare
         FB : Byte_Seq (0 .. Finished_12_Total_Len - 1); FL : N32;
         TH : Digest; TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         EO : N32;
      begin
         if Use_384 then
            SPARKNaCl.Hashing.SHA384.Hash
              (TH_384, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12, Label_Server_Finished,
                               Byte_Seq (TH_384), True, FB, FL);
         else
            Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12, Label_Server_Finished,
                               Byte_Seq (TH), False, FB, FL);
         end if;

         --  Append server Finished plaintext to transcript so the
         --  client's expected Finished hash (which covers up to
         --  server Finished) matches.
         Append_Transcript (HC, FB (0 .. FL - 1));

         Records.TLS12.Build_Encrypted_Record_12
           (FB (0 .. FL - 1), 16#16#, S.Server_App,
            HC.Server_Write_IV_12, HC.Server_Seq_12, Scratch, EO);
         if EO = 0 then
            HC.Server_Seq_12 := Saved_Seq;
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  Atomic commit.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         HC.Server_Seq_12 := Saved_Seq;
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos ..
                     S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
         Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      --  Mirror state into Session record.
      S.Negotiated_Version := TLS_1_2;
      S.Client_IV_12  := HC.Client_Write_IV_12;
      S.Server_IV_12  := HC.Server_Write_IV_12;
      S.Client_Seq_12 := HC.Client_Seq_12;
      S.Server_Seq_12 := HC.Server_Seq_12;

      --  Mark CKE-received so the existing Process_Client_CCS_12 /
      --  Process_Client_Finished_12 state-check predicates don't
      --  trip on the missing ClientKeyExchange (abbreviated flow).
      HC.CKE_Received_12 := True;

      --  Server flight is on the wire; await client CCS + Finished.
      Set_State (S, Wait_Client_Finished);
      Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
   end Build_Abbreviated_Server_Flight_12;

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
      --  RFC 7627 §4: master_secret derivation. If the client
      --  offered the extended_master_secret extension we use the
      --  EMS PRF (label "extended master secret", seed = transcript
      --  hash). Otherwise we MUST use the original RFC 5246 §8.1
      --  PRF (label "master secret", seed = client_random ||
      --  server_random). Mismatch here breaks Finished verification
      --  for any client that didn't request EMS — caught by
      --  TLS-Anvil's HappyFlow battery (12/12 fail without this).
      pragma Assert (EMS_Label_Consistent (HC.Use_EMS,
        (if HC.Use_EMS then "extended master secret" else "master secret")));

      if HC.Use_EMS then
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
         --  RFC 7627 §4: ghost-record the PRF branch taken so
         --  EMS_PRF_Binding_RFC_7627_4 can prove on exit.
         HC.MS_Derivation := Extended;
      else
         declare
            --  Initialize so flow can see Seed is fully defined before
            --  the PRF call; the two slice writes below cover the full
            --  range, but flow analysis can't see a slice-pair as a
            --  whole-array write.
            Seed : Byte_Seq (0 .. 63) := (others => 0);
         begin
            Seed (0 .. 31)  := Byte_Seq (HC.Client_Random);
            Seed (32 .. 63) := Byte_Seq (HC.Server_Random);
            if Use_384 then
               PRF_SHA384 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "master secret", Seed);
            else
               PRF_SHA256 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "master secret", Seed);
            end if;
         end;
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
         if Rec.Bad_Version then
            Send_Alert_And_Error (S, Protocol_Version, Result);
         elsif Rec.Overflow then
            Send_Alert_And_Error (S, Record_Overflow, Result);
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         declare
            CCS_Pos    : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_OK     : constant Boolean :=
               Rec.Fragment_Len = 1
               and then S.Input.Data (CCS_Pos) = 16#01#
               and then not HC.CCS_Received;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if CCS_OK then
               HC.CCS_Received := True; Result := OK;
               --  RFC 5246 §7.1 single-CCS invariant: after this
               --  assignment the server's view records that the client
               --  has signaled switch-to-encrypted exactly once. Future
               --  CCS records on this connection MUST be rejected via
               --  the `not HC.CCS_Received` guard above.
               pragma Assert (Single_CCS_RFC_5246_7_1 (HC));
            else
               --  RFC 5246 §7.1: CCS payload MUST be the single byte
               --  0x01 (BoGo BadChangeCipherSpec-*).
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
         end;
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
                  --  RFC 5246 §7.2.1: invariant after queued reply.
                  pragma Assert
                    (Close_Notify_Reply_State_RFC_5246_7_2_1
                       (S.State, Output_Pending (S)));
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

      --  RFC 5246 §7.4.7: only one ClientKeyExchange permitted. A
      --  second handshake-content record after we've already seen
      --  CKE is a state-machine violation — fatal alert.
      --  TLS-Anvil's secondClientKeyExchange test (XSM-zmpmr7nVki).
      if HC.CKE_Received_12 then
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
         SS_OK  : Boolean    := False;
         --  RFC 5246 §7.2.2 / RFC 8446 §6.2: invalid peer share is
         --  illegal_parameter; an unselectable group is the generic
         --  handshake_failure.
         SS_Err : Error_Code := Handshake_Failure;
      begin
         case HC.Selected_Group is
            when Group_X25519 =>
               HC.Shared_Secret (0 .. 31) :=
                  SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
               --  RFC 7748 §6.1 / RFC 8422 §5.10: reject all-zeros
               --  shared secret (small-subgroup defence). The
               --  helper's Post is formally proven by SPARK.
               SS_OK := Shared_Secret_Is_Acceptable_X25519
                          (HC.Shared_Secret (0 .. 31));
               if not SS_OK then
                  SS_Err := Illegal_Parameter;
               end if;
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
                  else
                     SS_Err := Illegal_Parameter;
                  end if;
               end;
            when Group_Secp384r1 =>
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
            Send_Alert_And_Error (S, SS_Err, Result); return;
         end if;
      end;

      Derive_Keys_12 (S, HC);
      HC.CKE_Received_12 := True;
      Result := (if Input_Available (S) > 0 then OK else Need_Input);
      --  RFC 5246 §7.4.7: at this exit point, the single-CKE
      --  invariant MUST hold. A future edit that drops the
      --  HC.CKE_Received_12 := True assignment above would fail
      --  this pragma — that's the point.
      pragma Assert (Single_CKE_RFC_5246_7_4_7 (HC));
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
         --  RFC 5246 §7.2.1: alerts are under the current write
         --  state. We're past the client's CCS (READ side encrypted)
         --  but before our own CCS (WRITE side still plaintext), so
         --  the alert MUST be plaintext.
         if Rec.Bad_Version then
            Send_Alert_And_Error (S, Protocol_Version, Result);
         elsif Rec.Overflow then
            Send_Alert_And_Error (S, Record_Overflow, Result);
         else
            Result := Need_Input;
         end if;
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

         declare
            Min_Frag : constant N32 :=
              (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256
               then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;
         end;

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
            if Msg_Len /= Finished_Verify_Len then
               --  Finished length mismatch — RFC 8446 §6.2:
               --  decrypt_error (alert 51). BoGo
               --  TrailingMessageData-ClientFinished expects this
               --  rather than decode_error.
               Send_Alert_And_Error
                 (S, Certificate_Verify_Failed, Result);
               return;
            end if;
            --  RFC 5246 §7.4.9: Finished is the last handshake
            --  message in the client's flight. Any plaintext bytes
            --  in the same record beyond `4 + Finished_Verify_Len`
            --  is excess data → fatal unexpected_message
            --  (BoGo TrailingDataWithFinished). Server's WRITE state
            --  is still plaintext at this point (CCS not yet sent),
            --  so the alert MUST be plaintext — sending it encrypted
            --  leaves Go's TLS stack seeing garbage on the wire.
            if PL /= 4 + Finished_Verify_Len then
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
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
                     --  RFC 5246 §7.4.9 / §7.2.1: Finished verify
                     --  mismatch → fatal alert. Server WRITE state
                     --  is still plaintext (no CCS sent yet) so the
                     --  alert MUST be plaintext, not encrypted.
                     Send_Alert_And_Error
                       (S, Handshake_Failure, Result);
                     pragma Assert
                       (S.Last_Error /= Unexpected_Message);
                     pragma Assert (Output_Pending (S) > 0);
                     pragma Assert
                       (Finished_Mismatch_Alerted_RFC_8446_4_4_4
                          (S.State, Output_Pending (S), S.Last_Error));
                     return;
                  end if;
               end;
            end;

            Append_Transcript (HC, Plaintext (0 .. PL - 1));
         end;
      end;

      --  Atomic flight assembly: build [NST?] + CCS + encrypted Finished
      --  into a scratch buffer; commit only if the whole flight fits in
      --  S.Output. The Finished encryption advances HC.Server_Seq_12, so
      --  we save it and roll back on commit failure to keep AEAD nonces
      --  in sync with what the peer actually sees.
      --
      --  NST goes BEFORE CCS (RFC 5077 §3.3): server's WRITE state is
      --  still plaintext until CCS, so NST is a plaintext handshake
      --  record (content type 22). NST is appended to the transcript
      --  before the server's Finished hash is computed (RFC 5077 §3.5).
      --
      --  SKIPPED in the resumed (abbreviated) handshake: the server
      --  already sent SH+NST+CCS+Finished before the client's
      --  Finished. RFC 5077 §3.3 — the abbreviated flight inverts
      --  the order so this code path must NOT re-emit.
      if not HC.TLS12_Resuming then
      declare
         Scratch       : IO_Buffer;
         CCS_Out       : N32;
         EO            : N32;
         Saved_Seq     : constant Unsigned_64 := HC.Server_Seq_12;
         FB : Byte_Seq (0 .. Finished_12_Total_Len - 1); FL : N32;
         TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
      begin
         --  RFC 5077 §3.3 NewSessionTicket (full handshake): issued iff
         --  the client offered the session_ticket extension AND we have
         --  configured ticket-encryption keys. Resumed-flight NSTs (the
         --  abbreviated case) are emitted from a different code path.
         if HC.TLS12_Ticket_Offered
           and then HC.Cfg.TLS12_Ticket_Keys /= null
           and then HC.Cfg.Random /= null
           and then HC.Cfg.TLS12_Active_TEK_Idx < TLS12_Max_Keys
           and then HC.Cfg.TLS12_Ticket_Keys
                      (HC.Cfg.TLS12_Active_TEK_Idx).Valid
         then
            declare
               use type SPARKTLS.Tickets_12.Bytes_4;
               Active_Key : TLS12_Ticket_Key
                  renames HC.Cfg.TLS12_Ticket_Keys
                            (HC.Cfg.TLS12_Active_TEK_Idx);
               Nonce_Buf  : Byte_Seq (0 .. 11) := (others => 0);
               Plain      : SPARKTLS.Tickets_12.Ticket_Plain;
               Ticket_Buf : Byte_Seq (0 .. 255) := (others => 0);
               Ticket_Len : N32;
               NST_Hdr_Len : constant N32 := 4 + 4 + 2;  --  hs+life+tlen
               NST_Buf    : Byte_Seq (0 .. 271) := (others => 0);
               NST_Total  : N32;
               NST_Rec_Out : N32;
            begin
               HC.Cfg.Random.all (Nonce_Buf);

               --  Ticket plaintext = master_secret + suite + 0 (no
               --  time source) + sid_len=0 (we don't encode the SID
               --  in the encrypted state; clients echo their own SID
               --  on resumption attempts).
               Plain.Master_Secret := HC.Master_Secret_12;
               Plain.Suite         := S.Negotiated_Suite_12;
               Plain.Created_At    := 0;
               Plain.SID_Len       := 0;
               Plain.SID           := (others => 0);

               SPARKTLS.Tickets_12.Encrypt_Ticket
                 (Plain      => Plain,
                  Key_ID     =>
                    SPARKTLS.Tickets_12.Bytes_4
                      (Active_Key.Key_ID),
                  TEK        =>
                    SPARKTLS.Tickets_12.Bytes_32
                      (Active_Key.TEK),
                  Nonce      =>
                    SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
                  Ticket     => Ticket_Buf,
                  Ticket_Len => Ticket_Len);

               --  Build NewSessionTicket handshake message:
               --    type(1)=4 + len(3) + lifetime_hint(4) +
               --    ticket_len(2) + ticket(N)
               NST_Total := NST_Hdr_Len + Ticket_Len;
               NST_Buf (0) := 16#04#;
               --  body length = lifetime(4) + ticket_len(2) + ticket(N)
               declare
                  Body_Len : constant N32 := 4 + 2 + Ticket_Len;
               begin
                  NST_Buf (1) := Byte (Body_Len / 65536);
                  NST_Buf (2) := Byte ((Body_Len / 256) mod 256);
                  NST_Buf (3) := Byte (Body_Len mod 256);
               end;
               --  lifetime_hint (4 bytes, big-endian seconds)
               NST_Buf (4) :=
                  Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 24)
                        and 16#FF#);
               NST_Buf (5) :=
                  Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 16)
                        and 16#FF#);
               NST_Buf (6) :=
                  Byte (Shift_Right (HC.Cfg.TLS12_Ticket_Lifetime, 8)
                        and 16#FF#);
               NST_Buf (7) :=
                  Byte (HC.Cfg.TLS12_Ticket_Lifetime and 16#FF#);
               --  ticket_len (2 bytes)
               NST_Buf (8) := Byte (Ticket_Len / 256);
               NST_Buf (9) := Byte (Ticket_Len mod 256);
               --  ticket bytes
               NST_Buf (10 .. 10 + Ticket_Len - 1) :=
                  Ticket_Buf (0 .. Ticket_Len - 1);

               --  Append to transcript BEFORE server Finished hash.
               Append_Transcript (HC, NST_Buf (0 .. NST_Total - 1));

               --  Emit as plaintext handshake record (server WRITE
               --  state still pre-CCS).
               Records.Build_Handshake_Record
                 (NST_Buf (0 .. NST_Total - 1),
                  Scratch, NST_Rec_Out);
               if NST_Rec_Out = 0 then
                  S.Last_Error := Insufficient_Buffer;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;
            end;
         end if;

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
      end if;  --  end "if not HC.TLS12_Resuming"

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

      --  RFC 5246 §7.2.1 / §7.2.2: post-Finished alerts MUST be
      --  encrypted under the app keys; a plaintext alert lands as a
      --  bad record type on the peer (same root cause as the §2.8
      --  TLS 1.3 mTLS bypass).
      if Rec.Overflow then
         Send_Encrypted_Alert_Connected_12 (S, Record_Overflow, Result); return;
      end if;
      if Rec.Bad_Version then
         Send_Encrypted_Alert_Connected_12 (S, Protocol_Version, Result); return;
      end if;
      if not Rec.OK then
         if Rec.Record_Len > 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
         else Result := Need_Input; end if;
         return;
      end if;

      --  TLS 1.2: CCS in Connected is ignored
      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      --  RFC 5246 §7.4.1.2 / RFC 5746: a TLS 1.2 server MAY refuse
      --  client-initiated renegotiation. A Handshake record in the
      --  Connected state is a renegotiation attempt — reply with a
      --  no_renegotiation warning alert (level 1, desc 100) and
      --  continue. BoGo Renegotiate-Server-Forbidden expects
      --  "remote error: no renegotiation" specifically.
      if Rec.Content = Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         declare
            A : N32;
         begin
            Records.TLS12.Build_Alert_Record_12
              (Level       => 1,
               Desc        => 100,
               Keys        => S.Server_App,
               Implicit_IV => S.Server_IV_12,
               Seq_Num     => S.Server_Seq_12,
               Output      => S.Output,
               Bytes_Out   => A);
         end;
         Result := (if Output_Pending (S) > 0
                    then Has_Output else OK);
         return;
      end if;

      --  Only app_data and alert are valid encrypted record types
      if Rec.Content not in Records.Content_Application_Data
                          | Records.Content_Alert
      then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
         return;
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

         declare
            --  ChaCha20-Poly1305 (RFC 7905) omits the on-wire
            --  explicit_nonce; AES-GCM (RFC 5288) includes it.
            Min_Frag : constant N32 :=
              (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256
               then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
               return;
            end if;
         end;

         Decrypt_Record_12 (Encrypted, Hdr, S.Client_App,
                            S.Client_IV_12, S.Client_Seq_12,
                            Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Encrypted_Alert_Connected_12 (S, Bad_Record_MAC, Result);
            return;
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
