with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Tickets_12;
with SPARKTLS.Cert_Verify;       use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;
with X509;
use type X509.Certificate;

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
                and then Result in Has_Output | Error_Alert
                and then S.Role = S.Role'Old
                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                and then S.Negotiated_Suite_12 = S.Negotiated_Suite_12'Old
                --  RFC 8446 §6.2 / RFC 5246 §7.2.2: a fatal alert
                --  MUST be sent to the peer before the connection
                --  closes. We satisfy this by queueing the alert
                --  record in the output buffer (Result = Has_Output)
                --  before transitioning to Error_State. The
                --  Error_Has_Alert ghost predicate captures the
                --  invariant: in Error_State, output is non-empty
                --  unless the error is one we couldn't write
                --  (Unexpected_Message after early plaintext).
                and then Error_Has_Alert (S.State, Output_Pending (S),
                                          S.Last_Error)
                and then
                  (if Output_Pending (S) > 0 then S.Last_Error = Err)
                and then
                  (if S.Output.Write_Pos'Old <= IO_Buffer_Capacity - 7 then
                     Output_Pending (S) > 0 and then S.Last_Error = Err);

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Records.Build_Plaintext_Alert (2, Alert_Desc (Err), S.Output, Dummy);
      --  When the output buffer is full, no alert byte hit the wire;
      --  collapse the recorded error to Unexpected_Message so the
      --  Error_Has_Alert ghost remains satisfied (RFC 8446 §6 lets
      --  Unexpected_Message close silently).
      if Output_Pending (S) = 0 then
         S.Last_Error := Unexpected_Message;
      end if;
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
                and then Alert_Desc (Err) /= 0
                and then Alert_Desc (Err) /= 90
                and then HC.Cfg.Local /= null
                and then HC.Cfg.Local.Has_Identity
                and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                      (HC.Cfg.Local)
                and then HC.Cfg.Random /= null
                and then Reasm_Building (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then Records.TLS12.Nonce_Space_Available_12
                      (HC.Server_Seq_12),
        Post => S.State = Error_State
                and S.Role = S.Role'Old
                and S.Last_Error = Err
                and HC.Cfg.Local /= null
                and HC.Cfg.Local.Has_Identity
                and SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                      (HC.Cfg.Local)
                and HC.Cfg.Random /= null
                and Reasm_Building (HC)
                and Reasm_Buffer_Shaped (HC);
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
   with Pre => Records.TLS12.Nonce_Space_Available_12 (S.Server_Seq_12)
               and S.State not in Idle | Closed | Error_State
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
	                and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                           (HC.Cfg.Local)
				                   and then HC.Cfg.Random /= null
					                   and then Reasm_Building (HC)
					                   and then Reasm_Buffer_Shaped (HC),
		           Post => HC.Cfg.Local /= null
	                   and then HC.Cfg.Local.Has_Identity
	                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                              (HC.Cfg.Local)
	                   and then HC.Cfg.Random /= null
                   and then Reasm_Building (HC)
                   and then HC.Version = HC.Version'Old
                   and then HC.Selected_Group = HC.Selected_Group'Old
                   and then HC.Client_Seq_12 = HC.Client_Seq_12'Old
                   and then HC.Server_Seq_12 = HC.Server_Seq_12'Old
                   and then HC.Peer_Cert = HC.Peer_Cert'Old
                   and then HC.Peer_Cert_Valid = HC.Peer_Cert_Valid'Old
	                   and then HC.Peer_Cert_DER_Len = HC.Peer_Cert_DER_Len'Old
	                   and then
	                     HC.Reasm_Len = HC.Reasm_Len'Old
	                   and then HC.Reasm_Need = HC.Reasm_Need'Old
	                   and then HC.Reasm_Hdr_Pending =
	                     HC.Reasm_Hdr_Pending'Old
				                   and then
				                     Reasm_Buffer_Shaped (HC)
			                   and then
			                     (if HC.Peer_Cert_Valid'Old
                         and then HC.Peer_Cert_DER_Len'Old
                           in 1 .. Max_Cert_DER_Len
                         and then X509.Spans_Valid
                           (HC.Peer_Cert'Old,
                            X509.N32 (HC.Peer_Cert_DER_Len'Old) - 1)
                      then HC.Peer_Cert_Valid
                           and then HC.Peer_Cert_DER_Len
                             in 1 .. Max_Cert_DER_Len
                           and then X509.Spans_Valid
                             (HC.Peer_Cert,
                              X509.N32 (HC.Peer_Cert_DER_Len) - 1))
                   --  RFC 5246 §7.4.9 transcript-monotonicity invariant:
                --  the handshake transcript is the basis for Finished
                --  verify_data. Once a byte enters the transcript it
                --  cannot be removed or rewritten, otherwise the peer's
                --  Finished computation will diverge from ours and
                --  authentic handshakes will fail. Length never shrinks.
                and then HC.Transcript_Len >= HC.Transcript_Len'Old
                and then
                  (if HC.Transcript_Len'Old <= HC.Transcript'Length -
                                                N32 (Data'Length)
                   then HC.Transcript_Len =
                          HC.Transcript_Len'Old + N32 (Data'Length))
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len <= HC.Transcript'Length - Len then
         HC.Transcript (HC.Transcript_Len ..
                          HC.Transcript_Len + Len - 1) := Data;
         HC.Transcript_Len := HC.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   procedure Set_Server_Random_12
     (HC     : in out Handshake_Context;
	      Random : in     Bytes_32)
			   with Pre  => Reasm_Building (HC)
			                and then Reasm_Buffer_Shaped (HC),
	        Post => HC.Version = HC.Version'Old
	                and then (if HC.Cfg.Local'Old /= null
	                          then HC.Cfg.Local /= null)
		                and then (if HC.Cfg.Local'Old /= null
		                              and then HC.Cfg.Local'Old.Has_Identity
	                   then HC.Cfg.Local /= null
		                               and then HC.Cfg.Local.Has_Identity)
		                and then
		                  (if SPARKTLS.Handshake.Server_Msgs
		                        .Local_Config_Valid (HC.Cfg.Local'Old)
		                   then SPARKTLS.Handshake.Server_Msgs
		                          .Local_Config_Valid (HC.Cfg.Local))
				                and then (if HC.Cfg.Random'Old /= null
				                          then HC.Cfg.Random /= null)
				                and then Reasm_Building (HC)
				                and then Reasm_Buffer_Shaped (HC);

   procedure Set_Server_Random_12
     (HC     : in out Handshake_Context;
      Random : in     Bytes_32)
   is
   begin
      HC.Server_Random := Random;
   end Set_Server_Random_12;

   ------------------------------------------------------------------
   --  Forward decl: full handshake state machine entry that the resume
   --  attempt may fall through to.
   procedure Build_Server_Flight_12_Full
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre  => HC.Version = TLS_1_2
	                and then HC.Cfg.Local /= null
	                and then HC.Cfg.Local.Has_Identity
	                and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                           (HC.Cfg.Local)
	                and then HC.Cfg.Random /= null
			                and then S.State = Wait_Client_Hello
			                and then S.Role = Role_Server
			                and then Reasm_Building (HC)
			                and then Reasm_Buffer_Shaped (HC)
			                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
	        Post => S.State in Server_Hello_Sent | Error_State
	                and then S.Role = Role_Server
	                and then HC.Version = TLS_1_2
	                and then HC.Cfg.Local /= null
			                and then HC.Cfg.Local.Has_Identity
			                and then
				                  SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
				                    (HC.Cfg.Local)
				                and then HC.Cfg.Random /= null
					                and then
						                  (if S.State = Server_Hello_Sent
						                   then Reasm_Building (HC)
						                        and then Reasm_Buffer_Shaped (HC));

   --  Resumed-handshake server flight (RFC 5077 §3.3 abbreviated).
   --  Caller has set HC.TLS12_Resuming + HC.Master_Secret_12 +
   --  S.Negotiated_Suite from the decrypted ticket. Emits
   --  SH → NST → CCS → encrypted Finished as one atomic flight,
   --  then transitions to Wait_Client_Finished to receive the
   --  client's CCS + Finished.
   procedure Build_Abbreviated_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre  => HC.Version = TLS_1_2
	                and then HC.Cfg.Local /= null
	                and then HC.Cfg.Local.Has_Identity
	                and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                           (HC.Cfg.Local)
	                and then HC.Cfg.Random /= null
                and then HC.Cfg.TLS12_Ticket_Keys /= null
	                and then HC.Cfg.TLS12_Active_TEK_Idx < TLS12_Max_Keys
	                and then S.State = Wait_Client_Hello
	                and then S.Role = Role_Server
		                and then S.Negotiated_Suite in
	                  Suite_ECDHE_RSA_AES128_GCM_SHA256
	                  | Suite_ECDHE_RSA_AES256_GCM_SHA384
	                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
	                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
		                  | Suite_ECDHE_RSA_CHACHA20_SHA256
		                  | Suite_ECDHE_ECDSA_CHACHA20_SHA256
                and then Reasm_Building (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                  (HC.Server_Seq_12),
	        Post => S.State in Wait_Client_Finished | Error_State
	                and then S.Role = Role_Server
	                and then HC.Version = TLS_1_2
	                and then HC.Cfg.Local /= null
			                and then HC.Cfg.Local.Has_Identity
			                and then
				                  SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
				                    (HC.Cfg.Local)
					                and then HC.Cfg.Random /= null
					                and then Reasm_Building (HC)
					                and then Reasm_Buffer_Shaped (HC);

   procedure Build_Server_Flight_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
   begin
      --  RFC 5077 §5.6 TEK auto-rotation. Cheap check (one
      --  Get_Time call + one comparison) at the start of every
      --  TLS 1.2 server handshake. Required preconditions: keys
      --  exist, auto-rotate is on, Get_Time + Random are wired.
      --  Without Get_Time we can't tell if the interval elapsed;
      --  without Random we can't generate the new key.
      if HC.Cfg.Auto_Rotate_TEK
        and then HC.Cfg.TLS12_Ticket_Keys /= null
        and then HC.Cfg.Get_Time /= null
        and then HC.Cfg.Random /= null
        and then HC.Cfg.TLS12_Active_TEK_Idx < TLS12_Max_Keys
      then
         declare
            Now       : constant Unsigned_64 :=
              SPARKTLS.Tickets_12.To_Unix_Seconds
                (HC.Cfg.Get_Time.all);
            Active    : constant Natural :=
              HC.Cfg.TLS12_Active_TEK_Idx;
            Last      : constant Unsigned_64 :=
              HC.Cfg.TLS12_Ticket_Keys.all (Active).Created_At;
            Interval  : constant Unsigned_64 :=
              Unsigned_64 (HC.Cfg.TEK_Rotation_Interval_Secs);
         begin
            if Now >= Last + Interval then
               declare
                  New_Key_ID : Byte_Seq (0 .. 3);
                  New_TEK    : Byte_Seq (0 .. 31);
                  New_Active : Natural := Active;
               begin
                  HC.Cfg.Random.all (New_Key_ID);
                  HC.Cfg.Random.all (New_TEK);
                  SPARKTLS.Server.Rotate_TLS12_Ticket_Key
                    (Keys       => HC.Cfg.TLS12_Ticket_Keys.all,
                     Active_Idx => New_Active,
                     New_Key_ID => New_Key_ID,
                     New_TEK    => New_TEK,
                     Now_Secs   => Now);
                  HC.Cfg.TLS12_Active_TEK_Idx := New_Active;
               end;
            end if;
         end;
      end if;

      --  RFC 5077 §3.4: if the client offered a non-empty session_ticket
      --  extension AND we have configured ticket-encryption keys, try
      --  to decrypt + resume. On success we run the abbreviated flight;
      --  on any failure (unknown Key_ID, tag mismatch, expiry, suite
      --  mismatch, etc.) we silently fall through to the full handshake
      --  — RFC 5077 §3.4 requires this: "If the server refuses to use
      --  the ticket, it SHOULD proceed with a full handshake."
      if HC.TLS12_Ticket_Offered
        and then HC.TLS12_Peer_Ticket_Len > 0
        and then HC.TLS12_Peer_Ticket_Len <= Max_TLS12_Ticket_Len
        and then HC.Cfg.TLS12_Ticket_Keys /= null
        and then HC.Cfg.TLS12_Active_TEK_Idx < TLS12_Max_Keys
      then
         declare
            Plain : SPARKTLS.Tickets_12.Ticket_Plain;
            OK    : Boolean;
            --  RFC 5077 §5.6 expiry: with a clock callback we enforce
            --  Cfg.TLS12_Ticket_Lifetime as the hard maximum age. No
            --  clock → degrade to "no expiry check" (still safe
            --  because the encrypted ticket integrity is unaffected,
            --  but operators MUST supply Cfg.Get_Time in production).
            Now : constant Unsigned_64 :=
              (if HC.Cfg.Get_Time /= null
               then SPARKTLS.Tickets_12.To_Unix_Seconds
                      (HC.Cfg.Get_Time.all)
               else 0);
            Max_Age : constant Unsigned_32 :=
              (if HC.Cfg.Get_Time /= null
               then HC.Cfg.TLS12_Ticket_Lifetime
               else 0);
         begin
            SPARKTLS.Tickets_12.Decrypt_Ticket
              (Ticket  => HC.TLS12_Peer_Ticket
                            (0 .. HC.TLS12_Peer_Ticket_Len - 1),
               Keys    => HC.Cfg.TLS12_Ticket_Keys.all,
               Now     => Now,
               Max_Age => Max_Age,
               Plain   => Plain,
               Status  => OK);
            if OK
              and then S.Negotiated_Suite_12 /= 0
              and then S.Negotiated_Suite_12 in
                Suite_ECDHE_RSA_AES128_GCM_SHA256
                | Suite_ECDHE_RSA_AES256_GCM_SHA384
                | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                | Suite_ECDHE_RSA_CHACHA20_SHA256
                | Suite_ECDHE_ECDSA_CHACHA20_SHA256
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
      pragma Assert (Valid_ECDHE_Group (HC.Selected_Group));

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
         Client_Sent_Recognized_Group : constant Boolean :=
           HC.Client_Supports_X25519
           or else HC.Client_Supports_P256
           or else HC.Client_Supports_P384;

         function Compatible_Local_Sig (Scheme : Unsigned_16) return Boolean is
         begin
            case HC.Cfg.Local.Sign_Algo is
               when Sign_RSA_PSS =>
                  return Scheme in 16#0804# | 16#0805# | 16#0806#
                                 | 16#0401# | 16#0501# | 16#0601#;
               when Sign_ECDSA_P256 =>
                  return Scheme = 16#0403#
                    and then
                      (not Client_Sent_Recognized_Group
                       or else HC.Client_Supports_P256);
               when Sign_ECDSA_P384 =>
                  return Scheme = 16#0503#
                    and then
                      (not Client_Sent_Recognized_Group
                       or else HC.Client_Supports_P384);
               when Sign_Ed25519 =>
                  return Scheme = 16#0807#;
               when Sign_None =>
                  return False;
            end case;
         end Compatible_Local_Sig;
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
               when Sign_ECDSA_P256 =>
                  if not Client_Sent_Recognized_Group
                    or else HC.Client_Supports_P256
                  then
                     Negotiated := 16#0403#;
                  end if;
               when Sign_ECDSA_P384 =>
                  if not Client_Sent_Recognized_Group
                    or else HC.Client_Supports_P384
                  then
                     Negotiated := 16#0503#;
                  end if;
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
         elsif HC.Cfg.Sign_Sig_Algo_Count > 0 then
            for J in Sig_Algo_Index loop
               pragma Loop_Invariant
                 (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                    (Negotiated, HC.Peer_Sig_Algos,
                     HC.Peer_Sig_Algo_Count));
               exit when J >= HC.Cfg.Sign_Sig_Algo_Count;
               if Compatible_Local_Sig (HC.Cfg.Sign_Sig_Algos (J))
                 and then Sig_Scheme_In_List
                            (HC.Cfg.Sign_Sig_Algos (J),
                             HC.Peer_Sig_Algos,
                             HC.Peer_Sig_Algo_Count)
               then
                  Negotiated := HC.Cfg.Sign_Sig_Algos (J);
                  exit;
               end if;
            end loop;
            pragma Assert
              (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                 (Negotiated, HC.Peer_Sig_Algos,
                  HC.Peer_Sig_Algo_Count));
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
                        if Scheme = 16#0403#
                          and then
                            (not Client_Sent_Recognized_Group
                             or else HC.Client_Supports_P256)
                        then
                           Negotiated := Scheme;
                           exit;
                        end if;
                     when Sign_ECDSA_P384 =>
                        if Scheme = 16#0503#
                          and then
                            (not Client_Sent_Recognized_Group
                             or else HC.Client_Supports_P384)
                        then
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

      if HC.Cfg.Require_ALPN
        and then not Has_ALPN_Match_12 (HC)
      then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
      end if;

      --  1. ServerHello
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1); Hello_Len : N32;
      begin
			         Build_Server_Hello_12 (S, HC, Hello_Buf, Hello_Len);
		         pragma Assert (Reasm_Buffer_Shaped (HC));
		         pragma Assert (S.Role = Role_Server);
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
         Cert_Buf : Byte_Seq (0 .. Max_Record_Plaintext - 1);
         Cert_Len : N32;
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
         pragma Assert (Valid_ECDHE_Group (HC.Selected_Group));
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

      --  4. CertificateRequest (optional client auth)
      if HC.Cfg.Request_Client_Cert then
         declare
            Cert_Type_RSA_Sign   : constant Byte := 16#01#;
            Cert_Type_ECDSA_Sign : constant Byte := 16#40#;
            Certificate_Types    : constant Byte_Seq (0 .. 1) :=
              (Cert_Type_RSA_Sign, Cert_Type_ECDSA_Sign);

            Sig_RSA_PKCS1_SHA256 : constant Unsigned_16 := 16#0401#;
            Sig_RSA_PKCS1_SHA384 : constant Unsigned_16 := 16#0501#;
            Sig_RSA_PKCS1_SHA512 : constant Unsigned_16 := 16#0601#;
            Sig_ECDSA_P256_SHA256 : constant Unsigned_16 := 16#0403#;
            Sig_ECDSA_P384_SHA384 : constant Unsigned_16 := 16#0503#;
            Sig_RSA_PSS_SHA256   : constant Unsigned_16 := 16#0804#;
            Sig_RSA_PSS_SHA384   : constant Unsigned_16 := 16#0805#;
            Sig_RSA_PSS_SHA512   : constant Unsigned_16 := 16#0806#;
            Sig_Ed25519          : constant Unsigned_16 := 16#0807#;

            function U16_Bytes (V : Unsigned_16) return Byte_Seq is
              ((0 => Byte (V / 256),
                1 => Byte (V mod 256)));

            Signature_Algorithms : constant Byte_Seq :=
              U16_Bytes (Sig_RSA_PKCS1_SHA256)
              & U16_Bytes (Sig_RSA_PKCS1_SHA384)
              & U16_Bytes (Sig_RSA_PKCS1_SHA512)
              & U16_Bytes (Sig_ECDSA_P256_SHA256)
              & U16_Bytes (Sig_ECDSA_P384_SHA384)
              & U16_Bytes (Sig_RSA_PSS_SHA256)
              & U16_Bytes (Sig_RSA_PSS_SHA384)
              & U16_Bytes (Sig_RSA_PSS_SHA512)
              & U16_Bytes (Sig_Ed25519);

            Certificate_Authorities : constant Byte_Seq (0 .. 1) :=
              (16#00#, 16#00#);
            CR_Body_Len : constant N32 :=
              1 + N32 (Certificate_Types'Length)
              + 2 + N32 (Signature_Algorithms'Length)
              + N32 (Certificate_Authorities'Length);
            CR_Buf : Byte_Seq (0 .. 4 + CR_Body_Len - 1) :=
              (others => 0);
         begin
            pragma Assert (CR_Body_Len = 25);
            CR_Buf (0) := Handshake.HT_Certificate_Request;
            CR_Buf (1) := Byte (CR_Body_Len / 65536);
            CR_Buf (2) := Byte ((CR_Body_Len / 256) mod 256);
            CR_Buf (3) := Byte (CR_Body_Len mod 256);

            --  certificate_types<1..2^8-1>
            CR_Buf (4) := Byte (Certificate_Types'Length);
            CR_Buf (5 .. 6) := Certificate_Types;

            --  supported_signature_algorithms<2..2^16-2>
            CR_Buf (7) := Byte (Signature_Algorithms'Length / 256);
            CR_Buf (8) := Byte (Signature_Algorithms'Length mod 256);
            CR_Buf (9 .. 26) := Signature_Algorithms;

            --  certificate_authorities<0..2^16-1>, empty.
            CR_Buf (27 .. 28) := Certificate_Authorities;

            Append_Transcript (HC, CR_Buf);
            Records.Build_Handshake_Record (CR_Buf, Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end;
      end if;

      --  5. ServerHelloDone
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

      pragma Assert (S.Role = Role_Server);
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
	   with Pre  => HC.Version = TLS_1_2
	                   and then HC.Cfg.Local /= null
		                   and then HC.Cfg.Local.Has_Identity
		                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
		                              (HC.Cfg.Local)
	                   and then HC.Cfg.Random /= null
                   and then Reasm_Building (HC)
                   and then Reasm_Buffer_Shaped (HC)
                   and then S.Negotiated_Suite in
	                  Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                  | Suite_ECDHE_RSA_CHACHA20_SHA256
                  | Suite_ECDHE_ECDSA_CHACHA20_SHA256,
	        Post => HC.Version = TLS_1_2
		                   and then HC.Cfg.Local /= null
		                   and then HC.Cfg.Local.Has_Identity
		                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
		                              (HC.Cfg.Local)
                   and then HC.Cfg.Random /= null
                   and then Reasm_Building (HC)
                   and then Reasm_Buffer_Shaped (HC)
                   and then S.State = S.State'Old
                and then S.Role = S.Role'Old
                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                and then HC.Server_Seq_12 = 0
                and then Records.TLS12.Nonce_Space_Available_12
                  (HC.Server_Seq_12)
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
      S.Exporter_Secret := HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := HC.Client_Random;
      S.Exporter_Server_Random := HC.Server_Random;
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
         Active_TEK_Idx : constant Natural :=
            HC.Cfg.TLS12_Active_TEK_Idx;
         Active_Key_ID : constant Byte_Seq :=
            HC.Cfg.TLS12_Ticket_Keys (Active_TEK_Idx).Key_ID;
         Active_TEK : constant Byte_Seq :=
            HC.Cfg.TLS12_Ticket_Keys (Active_TEK_Idx).TEK;
      begin
      --  Mirror the full-flight setup that Build_Server_Flight_12_Full
      --  did before we diverted. We don't pick a group (no ECDHE), we
      --  don't pick a signature scheme (no SKE), but we DO need the
      --  Negotiated_Sig_Algo to be cleared so Build_Server_Hello_12
      --  doesn't try to echo a stale value.
      HC.Negotiated_Sig_Algo := 0;
      pragma Assert (Reasm_Building (HC));

	      --  Fresh server random (32 bytes).
	      declare
	         Server_Random : Bytes_32;
	      begin
	         Gen_Random (Byte_Seq (Server_Random));
	         Set_Server_Random_12 (HC, Server_Random);
	      end;

      if HC.Cfg.Require_ALPN
        and then not Has_ALPN_Match_12 (HC)
      then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
      end if;

      --  1. ServerHello (with empty session_ticket ext, since
      --     TLS12_Ticket_Offered + TLS12_Ticket_Keys are set).
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1);
         Hello_Len : N32;
      begin
			         Build_Server_Hello_12 (S, HC, Hello_Buf, Hello_Len);
		         pragma Assert (Reasm_Buffer_Shaped (HC));
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
            Nonce_Buf  : Byte_Seq (0 .. 11) := (others => 0);
         Plain      : SPARKTLS.Tickets_12.Ticket_Plain;
         Ticket_Buf : Byte_Seq (0 .. 255) := (others => 0);
         Ticket_Len : N32;
         NST_Buf    : Byte_Seq (0 .. 271) := (others => 0);
         NST_Total  : N32;
         NST_Rec_Out : N32;
      begin
         Gen_Random (Nonce_Buf);
         Plain.Master_Secret := HC.Master_Secret_12;
         Plain.Suite         := S.Negotiated_Suite;
         Plain.Created_At    :=
           (if HC.Cfg.Get_Time /= null
            then SPARKTLS.Tickets_12.To_Unix_Seconds
                   (HC.Cfg.Get_Time.all)
            else 0);
         Plain.SID_Len       := 0;
         Plain.SID           := (others => 0);
         SPARKTLS.Tickets_12.Encrypt_Ticket
           (Plain      => Plain,
            Key_ID     =>
              SPARKTLS.Tickets_12.Bytes_4 (Active_Key_ID),
            TEK        =>
              SPARKTLS.Tickets_12.Bytes_32 (Active_TEK),
            Nonce      => SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
            Ticket     => Ticket_Buf,
            Ticket_Len => Ticket_Len);

         SPARKTLS.Handshake.TLS12.Build_New_Session_Ticket_12
           (Lifetime_Hint => HC.Cfg.TLS12_Ticket_Lifetime,
            Ticket        => Ticket_Buf (0 .. Ticket_Len - 1),
            Result        => NST_Buf,
            Len           => NST_Total);
         if NST_Total = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;

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
            EMS_Len : constant N32 :=
              (if HC.TLS12_EMS_Transcript_Len > 0
               then HC.TLS12_EMS_Transcript_Len
               else HC.Transcript_Len);
            TH     : Digest;
            TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         begin
            pragma Assert (EMS_Len > 0);
            pragma Assert (EMS_Len <= Transcript_Capacity);
            if Use_384 then
               SPARKNaCl.Hashing.SHA384.Hash
                 (TH_384, HC.Transcript (0 .. EMS_Len - 1));
               PRF_SHA384 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "extended master secret", Byte_Seq (TH_384));
            else
               Hash (TH, HC.Transcript (0 .. EMS_Len - 1));
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
      S.Exporter_Secret := HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := HC.Client_Random;
      S.Exporter_Server_Random := HC.Server_Random;
   end Derive_Keys_12;

   ------------------------------------------------------------------
   procedure Process_Client_Key_Exchange_12
	     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
	   is
	      Rec : Records.Parse_Result;
		      CKE_Transcript_Nonempty : Boolean := False
		        with Ghost;

	      procedure Compute_Shared_Secret_12
	        (OK  :    out Boolean;
	         Err :    out Error_Code)
	      with Pre  => HC.Version = TLS_1_2
	                   and then HC.Cfg.Local /= null
	                   and then HC.Cfg.Local.Has_Identity
	                   and then SPARKTLS.Handshake.Server_Msgs
	                              .Local_Config_Valid (HC.Cfg.Local)
		                   and then HC.Cfg.Random /= null
		                   and then Reasm_Building (HC)
		                   and then Reasm_Buffer_Shaped (HC)
		                   and then Valid_ECDHE_Group (HC.Selected_Group)
	                   and then SPARKTLSCrypto.P384.Field.Initialized,
	           Post => HC.Version = HC.Version'Old
	                   and then HC.Cfg.Local /= null
	                   and then HC.Cfg.Local.Has_Identity
	                   and then SPARKTLS.Handshake.Server_Msgs
	                              .Local_Config_Valid (HC.Cfg.Local)
		                   and then HC.Cfg.Random /= null
		                   and then HC.Selected_Group = HC.Selected_Group'Old
		                   and then Valid_ECDHE_Group (HC.Selected_Group)
			                   and then HC.Transcript_Len =
			                     HC.Transcript_Len'Old
			                   and then Reasm_Building (HC)
	                   and then Reasm_Buffer_Shaped (HC)
	      is
	      begin
	         OK := False;
	         --  RFC 5246 §7.2.2 / RFC 8446 §6.2: invalid peer share is
	         --  illegal_parameter; an unselectable group is the generic
	         --  handshake_failure.

	         case HC.Selected_Group is
	            when Group_X25519 =>
	               HC.Shared_Secret (0 .. 31) :=
	                  SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
	               --  RFC 7748 §6.1 / RFC 8422 §5.10: reject all-zeros
	               --  shared secret (small-subgroup defence). The
	               --  helper's Post is formally proven by SPARK.
	               OK := Shared_Secret_Is_Acceptable_X25519
	                       (HC.Shared_Secret (0 .. 31));
	               if OK then
	                  Err := No_Error;
	               else
	                  Err := Illegal_Parameter;
	               end if;
	               pragma Assert (Reasm_Building (HC));

	            when Group_Secp256r1 =>
	               declare
	                  use SPARKTLSCrypto.P256.Point;
	                  subtype P256_SK_Seq is Byte_Seq (0 .. 31);
	                  subtype P256_PK_Seq is Byte_Seq (0 .. 64);
	                  Pt       : P256_Jacobian;
	                  V        : SPARKNaCl.U32;
	                  Local_SK : constant P256_SK_Seq := HC.P256_Local_SK;
	                  Peer_PK  : constant P256_PK_Seq := HC.P256_Peer_PK;
	               begin
	                  pragma Assert (Local_SK'First = 0);
	                  pragma Assert (Local_SK'Length = 32);
	                  pragma Assert (Peer_PK'First = 0);
	                  pragma Assert (Peer_PK'Length = 65);
	                  P256_Decode (Pt, Peer_PK, V);
	                  if V /= 0 then
	                     P256_Mul (Pt, Local_SK, 32);
	                     P256_To_Affine (Pt);
	                     declare
	                        E : Byte_Seq (0 .. 64);
	                     begin
	                        P256_Encode (E, Pt);
	                        HC.Shared_Secret := (others => 0);
	                        HC.Shared_Secret (0 .. 31) := E (1 .. 32);
	                     end;
	                     OK := True;
	                     Err := No_Error;
	                  else
	                     Err := Illegal_Parameter;
	                  end if;
	                  pragma Assert (Reasm_Building (HC));
	               end;

	            when Group_Secp384r1 =>
	               declare
	                  subtype P384_SK_Seq is Byte_Seq (0 .. 47);
	                  subtype P384_PK_Seq is Byte_Seq (0 .. 96);
	                  SS       : Bytes_48;
	                  OK384    : Boolean;
	                  Local_SK : constant P384_SK_Seq := HC.P384_Local_SK;
	                  Peer_PK  : constant P384_PK_Seq := HC.P384_Peer_PK;
	               begin
	                  pragma Assert (Local_SK'First = 0);
	                  pragma Assert (Local_SK'Length = 48);
	                  pragma Assert (Peer_PK'First = 0);
	                  pragma Assert (Peer_PK'Length = 97);
	                  SPARKTLSCrypto.P384.Point.P384_ECDHE
	                    (SS, OK384, Local_SK, Peer_PK);
	                  if OK384 then
	                     HC.Shared_Secret := SS;
	                     OK := True;
	                     Err := No_Error;
	                  else
	                     Err := Illegal_Parameter;
	                  end if;
	                  pragma Assert (Reasm_Building (HC));
	               end;

	            when others =>
	               pragma Assert (False);
	         end case;
	      end Compute_Shared_Secret_12;
	   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Building (HC));
         pragma Assert (Reasm_Buffer_Shaped (HC));
         return;
      end if;

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
         pragma Assert (Reasm_Building (HC));
         pragma Assert
           (if S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
            then Reasm_Buffer_Shaped (HC));
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
         pragma Assert (Reasm_Building (HC));
         pragma Assert
           (if S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
            then Reasm_Buffer_Shaped (HC));
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
                  pragma Assert (A in 0 | 7);
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
            pragma Assert (Reasm_Building (HC));
            pragma Assert
              (if S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
               then Reasm_Buffer_Shaped (HC));
            return;
         end;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         pragma Assert (Reasm_Building (HC));
         pragma Assert
           (if S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
            then Reasm_Buffer_Shaped (HC));
         return;
      end if;

      --  RFC 5246 §7.4.7: only one ClientKeyExchange permitted. A
      --  second handshake-content record after we've already seen
      --  CKE is a state-machine violation — fatal alert.
      --  TLS-Anvil's secondClientKeyExchange test (XSM-zmpmr7nVki).
      if HC.CKE_Received_12 then
         if Rec.Content = Records.Content_Handshake
           and then Rec.Fragment_Len >= 4
         then
            declare
               FS       : constant N32 :=
                 S.Input.Read_Pos + Rec.Fragment_Pos;
               Frag_Len : constant N32 := Rec.Fragment_Len;
            begin
               pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
               declare
                  Frag     : constant Byte_Seq :=
                    S.Input.Data (FS .. FS + Frag_Len - 1);
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
               begin
                  Handshake.Parse_Handshake_Header
                    (Frag, Msg_Type, Msg_Len, Parse_OK);
	            if not Parse_OK then
	               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	               Send_Alert_And_Error
	                 (S,
	                  (if Frag (Frag'First) in
	                     16#01# | 16#02# | 16#04# | 16#08# |
	                     16#0B# | 16#0C# | 16#0D# | 16#0E# |
	                     16#0F# | 16#10# | 16#14#
	                   then Decode_Error else Unexpected_Message),
	                  Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

                  if Msg_Type = Handshake.HT_Certificate_Verify then
                     if Msg_Len < 4
                       or else Msg_Len + 4 /= Frag_Len
                     then
                        S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        pragma Assert (Reasm_Building (HC));
                        return;
                     end if;

	                     declare
	                        F : constant N32 := Frag'First;
	                     begin
	                        pragma Assert (Frag_Len >= 8);
	                        pragma Assert (F + 7 <= Frag'Last);
	                        declare
	                           Sig_Len : constant N32 :=
	                             N32 (Frag (F + 6)) * 256
	                             + N32 (Frag (F + 7));
	                        begin
	                           if Sig_Len /= Msg_Len - 4 then
	                              S.Input.Read_Pos :=
	                                S.Input.Read_Pos + Rec.Record_Len;
	                              Send_Alert_And_Error
	                                (S, Decode_Error, Result);
	                              pragma Assert (Reasm_Building (HC));
	                              return;
	                           end if;
	                        end;
	                     end;
                  end if;
               end;
            end;
         end if;
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;

	         procedure Parse_Complete_CKE
	           (Msg      : in     Byte_Seq;
	            CKE_Good :    out Boolean)
	         with Pre => Msg'Length > 0
	                     and then Msg'Length <= HC.Transcript'Length
		                     and then Msg'Last < N32 (Natural'Last)
			                     and then Reasm_Building (HC)
			                     and then Reasm_Buffer_Shaped (HC)
			                     and then HC.Cfg.Local /= null
	                     and then HC.Cfg.Local.Has_Identity
	                     and then SPARKTLS.Handshake.Server_Msgs
                       .Local_Config_Valid (HC.Cfg.Local)
                     and then HC.Cfg.Random /= null
                     and then Valid_ECDHE_Group (HC.Selected_Group),
		              Post => HC.Version = HC.Version'Old
		                      and then Reasm_Building (HC)
		                      and then Reasm_Buffer_Shaped (HC)
		                      and then HC.Cfg.Local /= null
	                      and then HC.Cfg.Local.Has_Identity
	                      and then SPARKTLS.Handshake.Server_Msgs
	                        .Local_Config_Valid (HC.Cfg.Local)
	                      and then HC.Cfg.Random /= null
			                      and then HC.Selected_Group = HC.Selected_Group'Old
			                      and then Valid_ECDHE_Group (HC.Selected_Group)
	         is
            Msg_Type : Byte;
            Msg_Len  : N32;
            POK      : Boolean;
         begin
            CKE_Good := False;
            Handshake.Parse_Handshake_Header (Msg, Msg_Type, Msg_Len, POK);
            if not POK
              or else Msg_Type /= HT_Client_Key_Exchange
              or else 4 + Msg_Len /= N32 (Msg'Length)
            then
               return;
            end if;
            if Msg_Len > Max_Client_Key_Exchange then
               return;
            end if;
            if Msg_Len < 4 then
               HC.Ext_Parse_Err := Illegal_Parameter;
               return;
            end if;

	            declare
	               Msg_Len_Const : constant N32 := Msg_Len;
	               Body_Data     : Byte_Seq (0 .. Msg_Len_Const - 1);
	            begin
	               pragma Assert (Msg'First + 4 <= Msg'Last);
	               pragma Assert
	                 (Msg'First + 4 + Msg_Len - 1 = Msg'Last);
	               Body_Data :=
	                 Msg (Msg'First + 4 .. Msg'First + 4 + Msg_Len - 1);
	               Parse_Client_Key_Exchange (HC, Body_Data, CKE_Good);
            end;
         end Parse_Complete_CKE;

	         procedure Fail_Decode
         with Pre  => Reasm_Building (HC)
                      and then S.State not in
                        Idle | Closing | Closed | Error_State
                      and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                      and then S.Input.Read_Pos + Rec.Record_Len
                        <= S.Input.Write_Pos
                      and then S.Input.Read_Pos + Rec.Record_Len
                        <= IO_Buffer_Capacity,
              Post => Reasm_Building (HC)
                      and then S.State = Error_State
                      and then Result /= OK
                      and then S.Negotiated_Suite =
                        S.Negotiated_Suite'Old
         is
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Reasm_Building (HC));
	         end Fail_Decode;

	         procedure Fail_Unexpected
	         with Pre  => Reasm_Building (HC)
	                      and then S.State not in
	                        Idle | Closing | Closed | Error_State
	                      and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
	                      and then S.Input.Read_Pos + Rec.Record_Len
	                        <= S.Input.Write_Pos
	                      and then S.Input.Read_Pos + Rec.Record_Len
	                        <= IO_Buffer_Capacity,
	              Post => Reasm_Building (HC)
	                      and then S.State = Error_State
	                      and then Result /= OK
	                      and then S.Negotiated_Suite =
	                        S.Negotiated_Suite'Old
	         is
	         begin
	            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	            Send_Alert_And_Error (S, Unexpected_Message, Result);
	            pragma Assert (Reasm_Building (HC));
	         end Fail_Unexpected;

	         procedure Finish_CKE
		           (Msg : in Byte_Seq)
			         with Pre  => Reasm_Building (HC)
			                      and then Reasm_Buffer_Shaped (HC)
			                      and then Msg'Length > 0
		                      and then Msg'Length <= HC.Transcript'Length
	                      and then Msg'Last < N32 (Natural'Last)
	                      and then S.State not in
                        Idle | Closing | Closed | Error_State
                      and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                      and then S.Input.Read_Pos + Rec.Record_Len
                        <= S.Input.Write_Pos
                      and then S.Input.Read_Pos + Rec.Record_Len
                        <= IO_Buffer_Capacity
                      and then HC.Cfg.Local /= null
                      and then HC.Cfg.Local.Has_Identity
                      and then SPARKTLS.Handshake.Server_Msgs
                        .Local_Config_Valid (HC.Cfg.Local)
                      and then HC.Cfg.Random /= null
                      and then Valid_ECDHE_Group (HC.Selected_Group),
		              Post => Reasm_Building (HC)
		                      and then Reasm_Buffer_Shaped (HC)
		                      and then HC.Version = HC.Version'Old
	                      and then HC.Cfg.Local /= null
	                      and then HC.Cfg.Local.Has_Identity
	                      and then SPARKTLS.Handshake.Server_Msgs
	                        .Local_Config_Valid (HC.Cfg.Local)
			                      and then HC.Cfg.Random /= null
			                      and then S.Negotiated_Suite =
			                        S.Negotiated_Suite'Old
				                      and then HC.Selected_Group = HC.Selected_Group'Old
				                      and then
			                        (if Result = OK
		                         then S.State = S.State'Old
	                              and then HC.Transcript_Len > 0
	                              and then HC.Transcript_Len <= Transcript_Capacity
		                              and then
		                                HC.TLS12_EMS_Transcript_Len <=
		                                  Transcript_Capacity
		                         else S.State = Error_State)
	         is
	            CKE_OK : Boolean;
	            Saved_Negotiated_Suite : constant Unsigned_16 :=
	              S.Negotiated_Suite
	              with Ghost;
		         begin
		            Parse_Complete_CKE (Msg, CKE_OK);
	            if not CKE_OK then
	               if HC.Ext_Parse_Err /= No_Error then
	                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	                  Send_Alert_And_Error (S, HC.Ext_Parse_Err, Result);
	                  pragma Assert (Reasm_Building (HC));
	                  pragma Assert
	                    (S.Negotiated_Suite = Saved_Negotiated_Suite);
	               else
	                  Fail_Decode;
	                  pragma Assert
	                    (S.Negotiated_Suite = Saved_Negotiated_Suite);
	               end if;
	               return;
	            end if;

	            Append_Transcript (HC, Msg);
	            HC.TLS12_EMS_Transcript_Len := HC.Transcript_Len;
	            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
		            Result := OK;
	            pragma Assert
	              (S.Negotiated_Suite = Saved_Negotiated_Suite);
		         end Finish_CKE;

	         procedure Start_CKE_Reassembly
	           (Source         : in     Byte_Seq;
	            New_Need       : in     N32;
	            Buffer_Length  : in     N32;
	            Header_Pending : in     Boolean)
			         with Pre  => Source'Length > 0
		                      and then Source'Last < N32'Last
	                      and then New_Need > 0
	                      and then New_Need <= Buffer_Length
	                      and then Buffer_Length <= Max_HS_Msg
                              and then
                                (if Header_Pending then
                                   New_Need = 4
                                   and then Buffer_Length = Max_HS_Msg)
                              and then N32 (Source'Length) <= New_Need
                              and then HC.Reasm_Need = 0,
	              Post => HC.Reasm_Buf /= null
	                      and then HC.Reasm_Buf'First = 0
	                      and then HC.Reasm_Buf'Length = Buffer_Length
	                      and then HC.Reasm_Len = N32 (Source'Length)
	                      and then HC.Reasm_Need = New_Need
	                      and then HC.Reasm_Hdr_Pending = Header_Pending
	                      and then Reasm_Building (HC)
	                      and then Reasm_Buffer_Shaped (HC)
         is
            Source_Len : constant N32 := N32 (Source'Length);
         begin
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Buf :=
              new Byte_Seq'(0 .. Buffer_Length - 1 => 0);
	            HC.Reasm_Need := New_Need;
	            HC.Reasm_Hdr_Pending := Header_Pending;
	            HC.Reasm_Len := Source_Len;

	            for I in N32 range 0 .. Source_Len - 1 loop
	               pragma Loop_Invariant (HC.Reasm_Buf /= null);
	               pragma Loop_Invariant (HC.Reasm_Buf'First = 0);
		               pragma Loop_Invariant
		                 (HC.Reasm_Buf'Length = Buffer_Length);
		               pragma Loop_Invariant (Buffer_Length <= Max_HS_Msg);
		               pragma Loop_Invariant (Buffer_Length <= N32'Last);
		               pragma Loop_Invariant (HC.Reasm_Need = New_Need);
		               pragma Loop_Invariant
		                 (HC.Reasm_Hdr_Pending = Header_Pending);
		               pragma Loop_Invariant (HC.Reasm_Len = Source_Len);
		               pragma Loop_Invariant (Source_Len <= New_Need);
		               pragma Loop_Invariant (New_Need <= Buffer_Length);
		               pragma Loop_Invariant
		                 (if Header_Pending then
		                    New_Need = 4
		                    and then Source_Len <= 4
		                    and then Buffer_Length = Max_HS_Msg);
		               pragma Loop_Invariant (I <= Source_Len - 1);
	               pragma Loop_Invariant
	                 (Source'First + I in Source'Range);
	               pragma Loop_Invariant (I in HC.Reasm_Buf'Range);
	               HC.Reasm_Buf (I) := Source (Source'First + I);
	            end loop;
	         end Start_CKE_Reassembly;
	      begin
         --  Slice bound: Parse_Record_Header Post gives Record_Len <= Avail,
         --  i.e., Read_Pos + Record_Len <= Write_Pos <= IO_Buffer_Capacity.
         --  So FS + Frag_Len = Read_Pos + Fragment_Pos + Fragment_Len
         --                  = Read_Pos + Record_Len <= Write_Pos.
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         if HC.Reasm_Need > 0 then
            if HC.Reasm_Buf = null
              or else HC.Reasm_Len > N32 (HC.Reasm_Buf'Length)
            then
               Fail_Decode;
               return;
            end if;

            declare
               Remaining : constant N32 :=
                 (if HC.Reasm_Len <= HC.Reasm_Need
                  then HC.Reasm_Need - HC.Reasm_Len
                  else 0);
               Take : constant N32 := N32'Min (Remaining, Frag_Len);
            begin
               if Take > 0 then
                  if HC.Reasm_Len + Take > N32 (HC.Reasm_Buf'Length) then
                     Fail_Decode;
                     return;
                  end if;
                  HC.Reasm_Buf
                    (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                    S.Input.Data (FS .. FS + Take - 1);
                  HC.Reasm_Len := HC.Reasm_Len + Take;
               end if;

               if Take /= Frag_Len then
                  --  A CKE handshake message may span records, but this
                  --  state expects exactly that one message before CCS.
                  HC.Reasm_Hdr_Pending := False;
                  pragma Assert (Reasm_Building (HC));
                  Fail_Decode;
                  return;
               end if;
            end;

            if HC.Reasm_Hdr_Pending
              and then HC.Reasm_Len >= 4
              and then HC.Reasm_Buf /= null
            then
               declare
                  HS_Msg_Len : constant N32 :=
                     N32 (HC.Reasm_Buf (1)) * 65536 +
                     N32 (HC.Reasm_Buf (2)) * 256 +
                     N32 (HC.Reasm_Buf (3));
                  HS_Total : constant N32 := HS_Msg_Len + 4;
               begin
	                  if HC.Reasm_Buf (0) /= HT_Client_Key_Exchange then
	                     HC.Reasm_Hdr_Pending := False;
	                     pragma Assert (Reasm_Building (HC));
	                     Fail_Unexpected;
	                     return;
	                  end if;
	                  if HS_Msg_Len > Max_Client_Key_Exchange then
	                     HC.Reasm_Hdr_Pending := False;
	                     pragma Assert (Reasm_Building (HC));
	                     Fail_Decode;
	                     return;
	                  end if;
                  pragma Assert (HS_Total <= Max_HS_Msg);

                  HC.Reasm_Need := HS_Total;
                  HC.Reasm_Hdr_Pending := False;
               end;
            end if;

            if HC.Reasm_Len < HC.Reasm_Need then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Result := OK;
               pragma Assert (HC.Reasm_Buf /= null);
               pragma Assert (HC.Reasm_Buf'First = 0);
               pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
               pragma Assert (HC.Reasm_Need > 0);
               pragma Assert
                 (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
               pragma Assert (Reasm_Building (HC));
               pragma Assert (Reasm_Buffer_Shaped (HC));
               return;
            end if;

	            declare
	               Need : constant N32 := HC.Reasm_Need;
	            begin
	               if Need > HC.Transcript'Length then
	                  Fail_Decode;
	                  return;
	               end if;

	               declare
	                  Full : constant Byte_Seq :=
	                    HC.Reasm_Buf (0 .. Need - 1);
	               begin
	                  Free_Byte_Seq (HC.Reasm_Buf);
	                  HC.Reasm_Len := 0;
	                  HC.Reasm_Need := 0;
	                  HC.Reasm_Hdr_Pending := False;
	                  Result := OK;
		                  Finish_CKE (Full);
			                  if Result /= OK then
			                     return;
			                  end if;
			                  pragma Assert (HC.Transcript_Len > 0);
			                  CKE_Transcript_Nonempty :=
                            (HC.Transcript_Len > 0);
			               end;
		            end;
         elsif Frag_Len < 4 then
	            if Frag_Len = 0 then
	               Fail_Decode;
	               return;
	            end if;

                  pragma Assert (HC.Reasm_Need = 0);
	            Start_CKE_Reassembly
	              (Source         => S.Input.Data (FS .. FS + Frag_Len - 1),
	               New_Need       => 4,
	               Buffer_Length  => Max_HS_Msg,
	               Header_Pending => True);
	            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	            Result := OK;
	            pragma Assert (Reasm_Building (HC));
	            pragma Assert (Reasm_Buffer_Shaped (HC));
            return;
         else
            declare
               HS_Msg_Len : constant N32 :=
                  N32 (S.Input.Data (FS + 1)) * 65536 +
                  N32 (S.Input.Data (FS + 2)) * 256 +
                  N32 (S.Input.Data (FS + 3));
               HS_Total : constant N32 := HS_Msg_Len + 4;
            begin
	               if S.Input.Data (FS) /= HT_Client_Key_Exchange then
	                  Fail_Unexpected;
	                  return;
	               end if;
	               if HS_Msg_Len > Max_Client_Key_Exchange then
	                  Fail_Decode;
	                  return;
	               end if;

	               if HS_Total > Frag_Len then
	                  pragma Assert (HS_Total <= Max_HS_Msg);
                  pragma Assert (HC.Reasm_Need = 0);
	                  Start_CKE_Reassembly
	                    (Source         =>
	                       S.Input.Data (FS .. FS + Frag_Len - 1),
	                     New_Need       => HS_Total,
	                     Buffer_Length  => HS_Total,
	                     Header_Pending => False);
	                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	                  Result := OK;
                  pragma Assert (Reasm_Building (HC));
                  pragma Assert (Reasm_Buffer_Shaped (HC));
                  return;
               end if;
            end;

            declare
               Frag : constant Byte_Seq :=
                 S.Input.Data (FS .. FS + Frag_Len - 1);
            begin
               Result := OK;
	               Finish_CKE (Frag);
		               if Result /= OK then
		                  return;
		               end if;
		               pragma Assert (HC.Transcript_Len > 0);
		               CKE_Transcript_Nonempty := (HC.Transcript_Len > 0);
		            end;
		         end if;
      end;

	      --  Compute ECDHE shared secret
	      pragma Assert (Reasm_Building (HC));
	      pragma Assert
	        (SPARKTLS.Handshake.TLS12.Valid_ECDHE_Group (HC.Selected_Group));
	      declare
	         SS_OK  : Boolean    := False;
	         SS_Err : Error_Code := Handshake_Failure;
	      begin
	         Compute_Shared_Secret_12 (SS_OK, SS_Err);
	            pragma Assert (Reasm_Coherent (HC));
	            pragma Assert
	              (HC.Reasm_Buf = null or else HC.Reasm_Len <= HC.Reasm_Need);
            if not SS_OK then
               Send_Alert_And_Error (S, SS_Err, Result);
               pragma Assert (Reasm_Building (HC));
               return;
            end if;
      end;

      pragma Assert (S.State in Wait_Client_Cert_Verify | Wait_Client_Finished);
	      pragma Assert
	        (S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
	                            | Suite_ECDHE_RSA_AES256_GCM_SHA384
	                            | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
	                            | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
	                            | Suite_ECDHE_RSA_CHACHA20_SHA256
	                            | Suite_ECDHE_ECDSA_CHACHA20_SHA256);
		      pragma Assert (Reasm_Building (HC));
	      pragma Assert (CKE_Transcript_Nonempty);
		      pragma Assert (HC.Transcript_Len > 0);
	      Derive_Keys_12 (S, HC);
      HC.CKE_Received_12 := True;
      Result := (if Input_Available (S) > 0 then OK else Need_Input);
      --  RFC 5246 §7.4.7: at this exit point, the single-CKE
      --  invariant MUST hold. A future edit that drops the
      --  HC.CKE_Received_12 := True assignment above would fail
         --  this pragma — that's the point.
         pragma Assert (Single_CKE_RFC_5246_7_4_7 (HC));
         pragma Assert (Reasm_Building (HC));
         pragma Assert (Reasm_Buffer_Shaped (HC));
      end Process_Client_Key_Exchange_12;

   ------------------------------------------------------------------
   procedure Process_Client_Certificate_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

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
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         if Frag_Len < 7 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Reasm_Building (HC));
            return;
         end if;

         declare
            Frag     : constant Byte_Seq :=
              S.Input.Data (FS .. FS + Frag_Len - 1);
            Msg_Type : Byte;
            Msg_Len  : N32;
            Parse_OK : Boolean;
         begin
            Handshake.Parse_Handshake_Header
              (Frag, Msg_Type, Msg_Len, Parse_OK);

            if not Parse_OK then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error
                 (S,
                  (if Frag (Frag'First) in
                     16#01# | 16#02# | 16#04# | 16#08# |
                     16#0B# | 16#0C# | 16#0D# | 16#0E# |
                     16#0F# | 16#10# | 16#14#
                   then Decode_Error else Unexpected_Message),
                  Result);
               pragma Assert (Reasm_Building (HC));
               return;
            end if;

            if Msg_Type /= Handshake.HT_Certificate then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               pragma Assert (Reasm_Building (HC));
               return;
            end if;

            if Msg_Len < 3
              or else Msg_Len + 4 /= Frag_Len
            then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               pragma Assert (Reasm_Building (HC));
               return;
            end if;

	            declare
	               F : constant N32 := Frag'First;
	            begin
	               pragma Assert (Frag_Len >= 7);
	               pragma Assert (F + 6 <= Frag'Last);
	               declare
	                  List_Len : constant N32 :=
	                    N32 (Frag (F + 4)) * 65536
	                    + N32 (Frag (F + 5)) * 256
	                    + N32 (Frag (F + 6));
	               begin
	                  if List_Len /= Msg_Len - 3 then
	                     S.Input.Read_Pos :=
	                       S.Input.Read_Pos + Rec.Record_Len;
	                     Send_Alert_And_Error (S, Decode_Error, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;
                     if List_Len = 0 and then HC.Cfg.Require_Client_Cert then
                        S.Input.Read_Pos :=
                          S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error (S, Handshake_Failure, Result);
                        pragma Assert (Reasm_Building (HC));
                        return;
                     end if;
	               end;
            end;

            declare
               HS_Msg    : Byte_Seq (0 .. Frag_Len - 1);
               Chain_OK  : Boolean;
               Chain_Err : Error_Code;
            begin
	               for I in N32 range 0 .. Frag_Len - 1 loop
	                  HS_Msg (I) := Frag (Frag'First + I);
	               end loop;

	               pragma Assert (Reasm_Buffer_Shaped (HC));
	               SPARKTLS.Handshake.Certs.Parse_Certificate_Chain_12
	                 (HC     => HC,
	                  HS_Msg => HS_Msg,
                  OK     => Chain_OK,
                  Err    => Chain_Err);
               pragma Assert (Reasm_Building (HC));

               if not Chain_OK then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Chain_Err, Result);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;
                  pragma Assert
	                  (if HC.Peer_Cert_Valid
	                     then HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
	                          and then X509.Spans_Valid
	                            (HC.Peer_Cert,
	                             X509.N32 (HC.Peer_Cert_DER_Len) - 1));
	                  pragma Assert (Reasm_Buffer_Shaped (HC));
	            end;

            Append_Transcript (HC, Frag);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if HC.Peer_Cert_Valid then
               pragma Assert
                 (HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
                  and then X509.Spans_Valid
                    (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1));
               Set_State (S, Wait_Client_Cert_Verify);
            elsif HC.Peer_Cert_DER_Len > 0 then
               Send_Alert_And_Error (S, Decode_Error, Result);
               pragma Assert (Reasm_Building (HC));
               return;
            elsif HC.Cfg.Require_Client_Cert then
               Send_Alert_And_Error (S, Handshake_Failure, Result);
               pragma Assert (Reasm_Building (HC));
               return;
            else
               Set_State (S, Wait_Client_Finished);
            end if;
            Result := (if Input_Available (S) > 0 then OK else Need_Input);
            pragma Assert (Reasm_Building (HC));
         end;
      end;
   end Process_Client_Certificate_12;

   ------------------------------------------------------------------
   procedure Process_Client_CertVerify_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

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
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         if Frag_Len < 8 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Reasm_Building (HC));
            return;
         end if;

         declare
            Frag     : constant Byte_Seq :=
              S.Input.Data (FS .. FS + Frag_Len - 1);
            Msg_Type : Byte;
            Msg_Len  : N32;
            Parse_OK : Boolean;
         begin
            Handshake.Parse_Handshake_Header
              (Frag, Msg_Type, Msg_Len, Parse_OK);

	            if not Parse_OK then
	               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	               Send_Alert_And_Error
	                 (S,
	                  (if Frag (Frag'First) in
	                     16#01# | 16#02# | 16#04# | 16#08# |
	                     16#0B# | 16#0C# | 16#0D# | 16#0E# |
	                     16#0F# | 16#10# | 16#14#
	                   then Decode_Error else Unexpected_Message),
	                  Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

	            if Msg_Type /= Handshake.HT_Certificate_Verify then
	               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	               Send_Alert_And_Error (S, Unexpected_Message, Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

	            if Msg_Len < 4
	              or else Msg_Len + 4 /= Frag_Len
	            then
	               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	               Send_Alert_And_Error (S, Decode_Error, Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

            declare
               F          : constant N32 := Frag'First;
               Sig_Scheme : constant Unsigned_16 :=
                 Unsigned_16 (Frag (F + 4)) * 256
                 + Unsigned_16 (Frag (F + 5));
               Sig_Len    : constant N32 :=
                 N32 (Frag (F + 6)) * 256 + N32 (Frag (F + 7));
               Verified   : Boolean;
            begin
               if Sig_Len = 0
                 or else Sig_Len /= Msg_Len - 4
                 or else F + 8 + Sig_Len - 1 > Frag'Last
               then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;

               if HC.Cfg.Verify_Sig_Algo_Count > 0
                 and then not Sig_Scheme_In_List
                                (Sig_Scheme,
                                 HC.Cfg.Verify_Sig_Algos,
                                 HC.Cfg.Verify_Sig_Algo_Count)
               then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Illegal_Parameter, Result);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;

               declare
                  Sig : Byte_Seq (0 .. Sig_Len - 1);
               begin
                  for I in N32 range 0 .. Sig_Len - 1 loop
                     Sig (I) := Frag (F + 8 + I);
                  end loop;

                  Verified := Cert_Verify.Verify_Signature_TLS12
                    (Data       => HC.Transcript (0 .. HC.Transcript_Len - 1),
                     Sig        => Sig,
                     Cert       => HC.Peer_Cert,
                     Sig_Scheme => Sig_Scheme);
               end;

               if not Verified then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error
                    (S, Certificate_Verify_Failed, Result);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;
            end;

            declare
               Cert_DER_Len_Const : constant N32 := HC.Peer_Cert_DER_Len;
               Leaf_Last : constant X509.N32 :=
                 X509.N32 (Cert_DER_Len_Const) - 1;
               Cert_X : X509.Byte_Seq (0 .. Leaf_Last) := (others => 0);
               VR : Validation_Result;
            begin
               for I in N32 range 0 .. HC.Peer_Cert_DER_Len - 1 loop
                  pragma Loop_Invariant
                    (Cert_DER_Len_Const = HC.Peer_Cert_DER_Len);
                  pragma Loop_Invariant
                    (HC.Peer_Cert = HC.Peer_Cert'Loop_Entry);
                  pragma Loop_Invariant
                    (HC.Peer_Cert_DER_Len =
                       HC.Peer_Cert_DER_Len'Loop_Entry);
                  pragma Loop_Invariant
                    (Leaf_Last = X509.N32 (HC.Peer_Cert_DER_Len) - 1);
                  pragma Loop_Invariant (Leaf_Last < X509.N32'Last);
                  pragma Loop_Invariant
                    (X509.Spans_Valid
                       (HC.Peer_Cert'Loop_Entry,
                        X509.N32 (HC.Peer_Cert_DER_Len'Loop_Entry) - 1));
                  Cert_X (X509.N32 (I)) :=
                    X509.Byte (HC.Peer_Cert_DER (I));
               end loop;

               VR := Validate_Leaf_Policy
                 (Leaf     => HC.Peer_Cert,
                  Leaf_DER => Cert_X
                    (0 .. X509.N32 (HC.Peer_Cert_DER_Len) - 1),
                  Hostname => "",
                  Purpose  => Purpose_Client,
                  Mode     => HC.Cfg.Verify_Mode);
               if VR /= Valid then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Bad_Certificate, Result);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;

               if not HC.Cfg.Skip_Verify then
                  if HC.Cfg.Trust = null or else HC.Cfg.Get_Time = null then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Bad_Certificate, Result);
                     pragma Assert (Reasm_Building (HC));
                     return;
                  end if;

                  VR := Validate_Chain
                    (Leaf_DER   =>
                       Cert_X
                         (0 .. X509.N32 (HC.Peer_Cert_DER_Len) - 1),
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
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Bad_Certificate, Result);
                     pragma Assert (Reasm_Building (HC));
                     return;
                  end if;
               end if;
            end;

            Append_Transcript (HC, Frag);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Set_State (S, Wait_Client_Finished);
            Result := (if Input_Available (S) > 0 then OK else Need_Input);
            pragma Assert (Reasm_Building (HC));
         end;
      end;
   end Process_Client_CertVerify_12;

   ------------------------------------------------------------------
   procedure Process_Client_CCS_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      pragma Unreferenced (S, HC);
   begin
      --  The normal TLS 1.2 server dispatcher consumes CCS inline before
      --  Process_Client_Finished_12. Keep this stale hook reject-only so
      --  an unexpected dispatch path fails closed.
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
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Building (HC));
         return;
      end if;

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
	         pragma Assert (Reasm_Building (HC));
	         return;
	      end if;

	      if Rec.Content /= Records.Content_Handshake then
	         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	         Send_Alert_And_Error (S, Unexpected_Message, Result);
	         pragma Assert (Reasm_Building (HC));
	         return;
	      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
	         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
	            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	            Send_Alert_And_Error (S, Record_Overflow, Result);
	            pragma Assert (Reasm_Building (HC));
	            return;
	         end if;

         declare
            Min_Frag : constant N32 :=
              (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256
               then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
	            if Frag_Len < Min_Frag then
	               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	               Send_Alert_And_Error (S, Decode_Error, Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;
         end;

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

	            Decrypt_Record_12 (Encrypted, Hdr, S.Client_App,
	                               HC.Client_Write_IV_12, HC.Client_Seq_12,
	                               Plaintext, PL, DV);
	            pragma Assert (Reasm_Building (HC));
	            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

	            if not DV then
	               Send_Alert_And_Error (S, Bad_Record_MAC, Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

            if HC.Reasm_Need > 0 or else PL < 4 then
	               if HC.Reasm_Need = 0 then
	                  if PL = 0 then
	                     Send_Alert_And_Error (S, Decode_Error, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;

                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
                  HC.Reasm_Need := 4;
                  HC.Reasm_Hdr_Pending := True;
                  HC.Reasm_Len := PL;
                  HC.Reasm_Buf (0 .. PL - 1) := Plaintext (0 .. PL - 1);
               else
	                  if HC.Reasm_Buf = null
	                    or else HC.Reasm_Len > N32 (HC.Reasm_Buf'Length)
	                  then
	                     Send_Alert_And_Error (S, Decode_Error, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;

                  declare
                     Remaining : constant N32 :=
                       (if HC.Reasm_Len <= HC.Reasm_Need
                        then HC.Reasm_Need - HC.Reasm_Len
                        else 0);
                     Take : constant N32 := N32'Min (Remaining, PL);
                  begin
                     if Take > 0 then
                        if HC.Reasm_Len + Take >
                           N32 (HC.Reasm_Buf'Length)
	                        then
	                           Send_Alert_And_Error (S, Decode_Error, Result);
	                           pragma Assert (Reasm_Building (HC));
	                           return;
	                        end if;
                        HC.Reasm_Buf
                          (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                          Plaintext (0 .. Take - 1);
                        HC.Reasm_Len := HC.Reasm_Len + Take;
                     end if;

	                     if Take /= PL then
	                        HC.Reasm_Hdr_Pending := False;
	                        Send_Alert_And_Error (S, Unexpected_Message, Result);
	                        pragma Assert (Reasm_Building (HC));
	                        return;
	                     end if;
                  end;
               end if;

               if HC.Reasm_Hdr_Pending
                 and then HC.Reasm_Len >= 4
                 and then HC.Reasm_Buf /= null
               then
	                  if HC.Reasm_Buf (0) /= HT_Finished then
	                     HC.Reasm_Hdr_Pending := False;
	                     Send_Alert_And_Error
	                       (S, Unexpected_Message, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;
                  if HC.Reasm_Buf (1) /= 0
                    or else HC.Reasm_Buf (2) /= 0
                    or else HC.Reasm_Buf (3) /= Byte (Finished_Verify_Len)
                  then
	                     HC.Reasm_Hdr_Pending := False;
	                     Send_Alert_And_Error
	                       (S, Certificate_Verify_Failed, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;
                  HC.Reasm_Need := Finished_12_Total_Len;
                  HC.Reasm_Hdr_Pending := False;
               end if;

               if HC.Reasm_Len < HC.Reasm_Need then
                  Result := (if Input_Available (S) > 0 then OK else Need_Input);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;

               declare
                  Need : constant N32 := HC.Reasm_Need;
	               begin
	                  if Need > N32 (Plaintext'Length) then
	                     Send_Alert_And_Error (S, Decode_Error, Result);
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;

                  Plaintext (0 .. Need - 1) :=
                    HC.Reasm_Buf (0 .. Need - 1);
                  PL := Need;
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0;
                  HC.Reasm_Need := 0;
                  HC.Reasm_Hdr_Pending := False;
               end;
            elsif PL >= 4 then
               if Plaintext (0) = HT_Finished
                 and then Plaintext (1) = 0
                 and then Plaintext (2) = 0
                 and then Plaintext (3) = Byte (Finished_Verify_Len)
                 and then Finished_12_Total_Len > PL
               then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Buf :=
                    new Byte_Seq'(0 .. Finished_12_Total_Len - 1 => 0);
                  HC.Reasm_Need := Finished_12_Total_Len;
                  HC.Reasm_Hdr_Pending := False;
                  HC.Reasm_Len := PL;
                  HC.Reasm_Buf (0 .. PL - 1) := Plaintext (0 .. PL - 1);
                  Result := (if Input_Available (S) > 0 then OK else Need_Input);
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;
            end if;

	            if PL < 4 then
	               Send_Alert_And_Error (S, Decode_Error, Result);
	               pragma Assert (Reasm_Building (HC));
	               return;
	            end if;

            declare
               Msg_Type : constant Byte := Plaintext (0);
            begin
	               if Msg_Type /= HT_Finished then
	                  Send_Alert_And_Error (S, Unexpected_Message, Result);
	                  pragma Assert (Reasm_Building (HC));
	                  return;
	               end if;
               if Plaintext (1) /= 0
                 or else Plaintext (2) /= 0
                 or else Plaintext (3) /= Byte (Finished_Verify_Len)
               then
                  --  Finished length mismatch — RFC 8446 §6.2:
                  --  decrypt_error (alert 51). BoGo
                  --  TrailingMessageData-ClientFinished expects this
                  --  rather than decode_error.
	                  Send_Alert_And_Error
	                    (S, Certificate_Verify_Failed, Result);
	                  pragma Assert (Reasm_Building (HC));
	                  return;
	               end if;
               --  RFC 5246 §7.4.9: Finished is the last handshake
               --  message in the client's flight. Any bytes in the same
               --  record beyond `4 + Finished_Verify_Len` are excess
               --  data and therefore fatal unexpected_message. In the
               --  abbreviated resume flow, the server has already sent
               --  CCS+Finished, so the alert must use the encrypted
               --  write epoch. In the full flow, the server has not sent
               --  CCS yet, so the alert remains plaintext.
               if PL /= 4 + Finished_Verify_Len then
                  if HC.TLS12_Resuming then
                     Send_Encrypted_Alert_12 (S, HC, Unexpected_Message, Result);
                  else
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  end if;
                  pragma Assert (Reasm_Building (HC));
                  return;
               end if;

               declare
                  Exp : Verify_Data_12;
                  TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
	               begin
	                  if Use_384 then
	                     SPARKNaCl.Hashing.SHA384.Hash
	                       (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
	                     Prove_Client_Finished_Label;
	                     pragma Assert (Valid_Finished_Label
	                                      (Label_Client_Finished));
	                     pragma Assert (TH4'Length = 48);
	                     declare
	                        TH_Bytes : constant Byte_Seq (0 .. 47) :=
	                          Byte_Seq (TH4);
	                     begin
	                        pragma Assert (TH_Bytes'First = 0);
	                        pragma Assert (TH_Bytes'Last = 47);
	                        pragma Assert (TH_Bytes'Length = 48);
	                        pragma Assert
	                          (TH_Bytes'Length = 32
	                           or else TH_Bytes'Length = 48);
	                        Compute_Finished_12 (Exp, HC.Master_Secret_12,
	                                             Label_Client_Finished,
	                                             TH_Bytes, True);
	                     end;
	                  else
	                     Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
	                     Prove_Client_Finished_Label;
	                     pragma Assert (Valid_Finished_Label
	                                      (Label_Client_Finished));
	                     pragma Assert (TH'Length = 32);
	                     declare
	                        TH_Bytes : constant Byte_Seq (0 .. 31) :=
	                          Byte_Seq (TH);
	                     begin
	                        pragma Assert (TH_Bytes'First = 0);
	                        pragma Assert (TH_Bytes'Last = 31);
	                        pragma Assert (TH_Bytes'Length = 32);
	                        pragma Assert
	                          (TH_Bytes'Length = 32
	                           or else TH_Bytes'Length = 48);
	                        Compute_Finished_12 (Exp, HC.Master_Secret_12,
	                                             Label_Client_Finished,
	                                             TH_Bytes, False);
	                     end;
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
	                        pragma Assert (Reasm_Building (HC));
	                        pragma Assert (Output_Pending (S) > 0);
                        pragma Assert
                          (S.Last_Error /= Unexpected_Message);
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
               --  Renaming a deref-and-index of HC.Cfg.* trips SPARK
               --  E0007; copy fields into local constants instead.
               Active_Key_ID : constant SPARKTLS.Tickets_12.Bytes_4 :=
                  HC.Cfg.TLS12_Ticket_Keys
                    (HC.Cfg.TLS12_Active_TEK_Idx).Key_ID;
               Active_TEK    : constant SPARKTLS.Tickets_12.Bytes_32 :=
                  HC.Cfg.TLS12_Ticket_Keys
                    (HC.Cfg.TLS12_Active_TEK_Idx).TEK;
               Nonce_Buf  : Byte_Seq (0 .. 11);
               Plain      : SPARKTLS.Tickets_12.Ticket_Plain;
               Ticket_Buf : Byte_Seq (0 .. 255);
               Ticket_Len : N32;
               NST_Buf    : Byte_Seq (0 .. 271);
               NST_Total  : N32;
               NST_Rec_Out : N32;
            begin
               HC.Cfg.Random.all (Nonce_Buf);

               --  Ticket plaintext = master_secret + suite + creation
               --  time + sid_len=0 (we don't encode the SID in the
               --  encrypted state; clients echo their own SID on
               --  resumption attempts). Created_At drives the
               --  expiry check on the decrypt side; without
               --  Cfg.Get_Time we encode 0 and Decrypt_Ticket skips
               --  the age window check (acceptable for dev / test).
               Plain.Master_Secret := HC.Master_Secret_12;
               Plain.Suite         := S.Negotiated_Suite_12;
               Plain.Created_At    :=
                 (if HC.Cfg.Get_Time /= null
                  then SPARKTLS.Tickets_12.To_Unix_Seconds
                         (HC.Cfg.Get_Time.all)
                  else 0);
               Plain.SID_Len       := 0;
               Plain.SID           := (others => 0);

               SPARKTLS.Tickets_12.Encrypt_Ticket
                 (Plain      => Plain,
                  Key_ID     => Active_Key_ID,
                  TEK        => Active_TEK,
                  Nonce      =>
                    SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
                  Ticket     => Ticket_Buf,
                  Ticket_Len => Ticket_Len);

               --  Build NewSessionTicket handshake message via RFLX.
               SPARKTLS.Handshake.TLS12.Build_New_Session_Ticket_12
                 (Lifetime_Hint => HC.Cfg.TLS12_Ticket_Lifetime,
                  Ticket        => Ticket_Buf (0 .. Ticket_Len - 1),
                  Result        => NST_Buf,
                  Len           => NST_Total);
               if NST_Total = 0 then
	                  S.Last_Error := Insufficient_Buffer;
	                  Set_State (S, Error_State);
	                  Result := Error_Alert;
	                  pragma Assert (Reasm_Building (HC));
	                  return;
	               end if;
               pragma Assert (NST_Total > 0);
               pragma Assert (NST_Total - 1 <= NST_Buf'Last);

               declare
                  NST_Last : constant N32 := NST_Total - 1;
                  NST_Data : Byte_Seq renames
                    NST_Buf (0 .. NST_Last);
               begin
                  pragma Assert (NST_Data'Length > 0);

                  --  Append to transcript BEFORE server Finished hash.
                  Append_Transcript (HC, NST_Data);

                  --  Emit as plaintext handshake record (server WRITE
                  --  state still pre-CCS).
                  Records.Build_Handshake_Record
                    (NST_Data, Scratch, NST_Rec_Out);
                  if NST_Rec_Out = 0 then
	                     S.Last_Error := Insufficient_Buffer;
	                     Set_State (S, Error_State);
	                     Result := Error_Alert;
	                     pragma Assert (Reasm_Building (HC));
	                     return;
	                  end if;
               end;
            end;
         end if;

         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
	            S.Last_Error := Insufficient_Buffer;
	            Set_State (S, Error_State);
	            Result := Error_Alert;
	            pragma Assert (Reasm_Building (HC));
	            return;
	         end if;

	         if Use_384 then
		            SPARKNaCl.Hashing.SHA384.Hash
		              (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
		            Prove_Server_Finished_Label;
		            pragma Assert (Valid_Finished_Label (Label_Server_Finished));
		            pragma Assert (TH4'Length = 48);
		            declare
		               TH_Bytes : constant Byte_Seq (0 .. 47) :=
		                 Byte_Seq (TH4);
		            begin
		               pragma Assert (TH_Bytes'First = 0);
		               pragma Assert (TH_Bytes'Last = 47);
		               pragma Assert (TH_Bytes'Length = 48);
		               pragma Assert
		                 (TH_Bytes'Length = 32
		                  or else TH_Bytes'Length = 48);
		               Build_Finished_12
		                 (HC.Master_Secret_12, Label_Server_Finished,
		                  TH_Bytes, True, FB, FL);
		            end;
		         else
		            Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
		            Prove_Server_Finished_Label;
		            pragma Assert (Valid_Finished_Label (Label_Server_Finished));
		            pragma Assert (TH'Length = 32);
		            declare
		               TH_Bytes : constant Byte_Seq (0 .. 31) :=
		                 Byte_Seq (TH);
		            begin
		               pragma Assert (TH_Bytes'First = 0);
		               pragma Assert (TH_Bytes'Last = 31);
		               pragma Assert (TH_Bytes'Length = 32);
		               pragma Assert
		                 (TH_Bytes'Length = 32
		                  or else TH_Bytes'Length = 48);
		               Build_Finished_12
		                 (HC.Master_Secret_12, Label_Server_Finished,
		                  TH_Bytes, False, FB, FL);
		            end;
		         end if;

	         pragma Assert (FL = Finished_12_Total_Len);
	         pragma Assert (FB'First = 0);
	         pragma Assert (FB'Last = Finished_12_Total_Len - 1);
	         pragma Assert (HC.Server_Write_IV_12'First = 0);
	         pragma Assert (HC.Server_Write_IV_12'Last = 11);
	         pragma Assert
	           (HC.Server_Write_IV_12'Length =
	            Records.TLS12.Implicit_IV_Len);
	         Build_Encrypted_Record_12
	           (FB (0 .. FL - 1), 16#16#, S.Server_App,
	            HC.Server_Write_IV_12, HC.Server_Seq_12, Scratch, EO);
	         if EO = 0 then
	            HC.Server_Seq_12 := Saved_Seq;  --  Build_Encrypted_Record_12
	                                            --  always advances; rollback.
	            S.Last_Error := Insufficient_Buffer;
	            Set_State (S, Error_State);
	            Result := Error_Alert;
	            pragma Assert (Reasm_Building (HC));
	            return;
	         end if;

         --  Atomic commit
	         if Free_Space (S.Output) < Scratch.Write_Pos then
	            HC.Server_Seq_12 := Saved_Seq;
	            S.Last_Error := Insufficient_Buffer;
	            Set_State (S, Error_State);
	            Result := Error_Alert;
	            pragma Assert (Reasm_Building (HC));
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
	      pragma Assert (Reasm_Building (HC));
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

      pragma Assert
        (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);

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
            pragma Assert (A <= N32 (S.Output.Data'Length));
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
      begin
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert_Connected_12 (S, Record_Overflow, Result);
            return;
         end if;

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

            declare
               --  ChaCha20-Poly1305 (RFC 7905) omits the on-wire
               --  explicit_nonce; AES-GCM (RFC 5288) includes it.
               Min_Frag : constant N32 :=
                 (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256
                  then GCM_Tag_Len
                  else Explicit_Nonce_Len + GCM_Tag_Len);
            begin
               if Frag_Len < Min_Frag then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Encrypted_Alert_Connected_12
                    (S, Unexpected_Message, Result);
                  return;
               end if;
            end;

            if S.Client_Seq_12 = Unsigned_64'Last then
               Send_Encrypted_Alert_Connected_12 (S, Internal_Error, Result);
               return;
            end if;

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
                  if S.State = Closing and then PL > 0 then
                     Send_Encrypted_Alert_Connected_12
                       (S, Unexpected_Message, Result);
                  elsif PL > 0
                     and then S.App_Data_Len <= S.App_Data'Length
                     and then PL <= S.App_Data'Length - S.App_Data_Len
                  then
                     S.App_Data
                       (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                        Plaintext (0 .. PL - 1);
                     S.App_Data_Len := S.App_Data_Len + PL;
                     S.Empty_Records_Recvd := 0;
                     Result := Plaintext_Ready;
                  else
                     S.Empty_Records_Recvd :=
                        S.Empty_Records_Recvd + 1;
                     if S.Empty_Records_Recvd > Max_Empty_Records then
                        S.Last_Error := Unexpected_Message;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        Result := OK;
                     end if;
                     pragma Assert
                       (Empty_Records_Bounded_RFC_8446_5_2 (S));
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
                        pragma Assert (A <= N32 (S.Output.Data'Length));
	                     end;
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
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
      end;
   end Process_Connected_12;

end SPARKTLS.Server.TLS12;
