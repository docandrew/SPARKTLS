with SPARKTLS.HS_Pool;
with Interfaces;                    use Interfaces;
with SPARKNaCl;                     use SPARKNaCl;
with SPARKTLS_Reassembly;           use SPARKTLS_Reassembly;
with SPARKTLS_Reassembly_G;
with SPARKTLSCrypto.Hashing.SHA256; use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA512;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;              use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Tickets_12;
with SPARKTLS.Cert_Verify;          use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;
with X509;
with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
use type X509.Certificate;

package body SPARKTLS.Server.TLS12
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   use Handshake.TLS12;

   procedure Send_Alert_And_Error (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre => Alert_Desc (Err) /= 0 and Alert_Desc (Err) /= 90,
     Post =>
       S.State = Error_State
       and then Result in Has_Output | Error_Alert
       and then S.Role = S.Role'Old
       and then S.Negotiated_Suite = S.Negotiated_Suite'Old
       and then Error_Has_Alert (S.State, Output_Pending (S), S.Last_Error)
       and then (if Output_Pending (S) > 0 then S.Last_Error = Err)
       and then (if S.Output.Write_Pos'Old <= IO_Buffer_Capacity - 7
                 then Output_Pending (S) > 0 and then S.Last_Error = Err);

   procedure Send_Alert_And_Error (S : in out Session; Err : Error_Code; Result : out Action) is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Records.Build_Plaintext_Alert (2, Alert_Desc (Err), S.Output, Dummy);
      --  When the output buffer is full, no alert byte hit the wire;
      --  collapse the recorded error to Unexpected_Message so the
      --  Error_Has_Alert ghost remains satisfied (RFC 8446 6 lets
      --  Unexpected_Message close silently).
      if Output_Pending (S) = 0 then
         S.Last_Error := Unexpected_Message;
      end if;
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Alert_And_Error;

   --  ----- RFC 5246 7.2.1 post-CCS encrypted alert helper ---------
   --  After the client has sent ChangeCipherSpec, RFC 5246 7.2.1
   --  requires further alerts to be sent encrypted under the
   --  established traffic keys. Sending a plaintext alert at this
   --  point is a protocol violation; strict TLS 1.2 clients reject
   --  it as unexpected_message.
   --
   --  Mirrors Send_Encrypted_Alert in server.adb (TLS 1.3 path)
   --  using Build_Alert_Record_12 with TLS 1.2 implicit IV +
   --  explicit sequence number.
   procedure Send_Encrypted_Alert_12 (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre => Alert_Desc (Err) /= 0 and then Alert_Desc (Err) /= 90,
     Post => S.State = Error_State and S.Role = S.Role'Old and S.Last_Error = Err;
   --  Error_Has_Alert is NOT in this Post  see
   --  matching note on Send_Encrypted_Alert in
   --  sparktls-server.adb. Call sites bridge to
   --  Pending > 0 via local pragma Assert.

   procedure Send_Encrypted_Alert_12 (S : in out Session; Err : Error_Code; Result : out Action) is
      Dummy : N32;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Alert_Desc (Err),
         Keys        => S.Server_App,
         Implicit_IV => S.HC.Server_Write_IV_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Alert_12;

   --  Post-handshake encrypted fatal alert. Mirrors
   --  Send_Encrypted_Alert_12 but reads IV/seq from S-level state
   --  (HC has been freed once we entered Connected). For use in
   --  Process_Connected_12. Same "alerts after CCS MUST be
   --  encrypted" RFC 5246 7.2.1 / 7.2.2 constraint that the 2.8
   --  TLS 1.3 mTLS bypass exposed: a plaintext alert here lands as
   --  a bad record type on the peer and is silently dropped.
   procedure Send_Encrypted_Alert_Connected_12
     (S : in out Session; Err : Error_Code; Result : out Action)
   with Pre => S.State not in Idle | Closed | Error_State
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
         Output      => S.Output,
         Bytes_Out   => Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Alert_Connected_12;

   procedure Append_Transcript (HC : in out Engaged_Context; Data : Byte_Seq)
   with
     Pre =>
       Data'Length
       > 0
         --  transcript-append bound
       and then Data'Last < N32'Last - 256,
     Post => HC.KE = HC.KE'Old
   is
   begin
      SPARKTLS_Transcript.Append (HC.TS, Data);
   end Append_Transcript;

   procedure Set_Server_Random_12 (HC : in out Handshake_Context; Random : in Bytes_32);

   procedure Set_Server_Random_12 (HC : in out Handshake_Context; Random : in Bytes_32) is
   begin
      HC.Server_Random := Random;
   end Set_Server_Random_12;

   ------------------------------------------------------------------
   --  Forward decl: full handshake state machine entry that the resume
   --  attempt may fall through to.
   procedure Build_Server_Flight_12_Full
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action)
   with
     Pre =>
       S.Version = TLS_1_2 and then S.State = Wait_Client_Hello and then S.Role = Role_Server;
     --  No Role conjunct: S is Server_Session, so
     --  S.Role = Role_Server is the discriminant -- stating it
     --  would be a tautology carried in every VC of this body.

   --  Resumed-handshake server flight (RFC 5077 3.3 abbreviated).
   --  Caller has set HC.T12.Resuming + HC.Master_Secret_12 +
   --  S.Negotiated_Suite from the decrypted ticket. Emits
   --  SH â NST â CCS â encrypted Finished as one atomic flight,
   --  then transitions to Wait_Client_Finished to receive the
   --  client's CCS + Finished.
   procedure Build_Abbreviated_Server_Flight_12
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action)
   with
     Pre =>
       S.Version = TLS_1_2
       and then S.HC.Cfg.Get_Active_TEK /= null
       and then S.HC.Cfg.Get_TEK_By_Id /= null
       and then S.State = Wait_Client_Hello
       and then S.Role = Role_Server
       and then S.Negotiated_Suite in
                  Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                  | Suite_ECDHE_RSA_CHACHA20_SHA256
                  | Suite_ECDHE_ECDSA_CHACHA20_SHA256;

   procedure Build_Server_Flight_12
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action) is
   begin
      --  TEK rotation is NOT performed here. The library no longer holds
      --  ticket-encryption keys -- Config.Get_Active_TEK / Get_TEK_By_Id
      --  fetch them -- so key lifetime and rotation policy belong to the
      --  callback implementation, which is also the only party that knows
      --  whether keys are shared across threads, processes or nodes.

      --  RFC 5077 3.4: if the client offered a non-empty session_ticket
      --  extension AND we have configured ticket-encryption keys, try
      --  to decrypt + resume. On success we run the abbreviated flight;
      --  on any failure (unknown Key_ID, tag mismatch, expiry, suite
      --  mismatch, etc.) we silently fall through to the full handshake
      --   RFC 5077 3.4 requires this: "If the server refuses to use
      --  the ticket, it SHOULD proceed with a full handshake."
      if S
           .HC
           .T12
           .Ticket_Offered
           --  >= Key_ID width, not merely > 0: Ticket_Key_ID reads a 4-byte
           --  prefix, and the peer chooses this length. A 1..3 byte ticket is
           --  malformed -- fall through to a full handshake per RFC 5077 3.4.
        and then S.HC.T12.Peer_Ticket_Len >= SPARKTLS.Tickets_12.Ticket_Key_ID_Size
        and then S.HC.T12.Peer_Ticket_Len <= Max_TLS12_Ticket_Len
        and then S.HC.Cfg.Get_Active_TEK /= null
        and then S.HC.Cfg.Get_TEK_By_Id
                 /= null
                    --  No clock => we cannot enforce the RFC 5077 5.6 age window, so
                    --  we refuse to resume rather than honour a ticket of unknown
                    --  age. Falls through to a full handshake, which 3.4 permits.
        and then S.HC.Cfg.Get_Time /= null
      then
         declare
            Plain     : SPARKTLS.Tickets_12.Ticket_Plain;
            OK        : Boolean;
            --  RFC 5077 5.6 expiry: with a clock callback we enforce
            --  Cfg.TLS12_Ticket_Lifetime as the hard maximum age. No
            --  clock â degrade to "no expiry check" (still safe
            --  because the encrypted ticket integrity is unaffected,
            --  but operators MUST supply Cfg.Get_Time in production).
            Now       : constant Unsigned_64 :=
              (if S.HC.Cfg.Get_Time /= null
               then SPARKTLS.Tickets_12.To_Unix_Seconds (S.HC.Cfg.Get_Time.all)
               else 0);
            Max_Age   : constant Unsigned_32 :=
              (if S.HC.Cfg.Get_Time /= null then S.HC.Cfg.TLS12_Ticket_Lifetime else 0);
            --  Fetch exactly the key the ticket names (O(1)), rather than
            --  trying every configured key in turn. A miss is not an error:
            --  RFC 5077 3.4 says fall through to a full handshake.
            Wanted_ID : constant Byte_Seq :=
              SPARKTLS.Tickets_12.Ticket_Key_ID
                (S.HC.T12.Peer_Ticket (0 .. S.HC.T12.Peer_Ticket_Len - 1));
            TEK       : Byte_Seq (0 .. 31) := (others => 0);
            TEK_Found : Boolean := False;
         begin
            S.HC.Cfg.Get_TEK_By_Id.all (Wanted_ID, TEK, TEK_Found);
            if not TEK_Found then
               OK := False;
            else
               SPARKTLS.Tickets_12.Decrypt_Ticket
                 (Ticket  => S.HC.T12.Peer_Ticket (0 .. S.HC.T12.Peer_Ticket_Len - 1),
                  TEK     => TEK,
                  Now     => Now,
                  Max_Age => Max_Age,
                  Plain   => Plain,
                  Status  => OK);
            end if;
            if OK
              and then S.Negotiated_Suite in
                         Suite_ECDHE_RSA_AES128_GCM_SHA256
                         | Suite_ECDHE_RSA_AES256_GCM_SHA384
                         | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                         | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                         | Suite_ECDHE_RSA_CHACHA20_SHA256
                         | Suite_ECDHE_ECDSA_CHACHA20_SHA256
              and then Plain.Suite = Wire_Of (S.Negotiated_Suite)
            then
               --  Resume: install ticket's master_secret + force suite.
               S.HC.Master_Secret_12 := Plain.Master_Secret;
               S.Negotiated_Suite := To_Suite (Plain.Suite);
               S.HC.T12.Resuming := True;
               Build_Abbreviated_Server_Flight_12 (S, Cfg, Result);
               return;
            end if;
         end;
      end if;

      Build_Server_Flight_12_Full (S, Cfg, Result);
   end Build_Server_Flight_12;

   procedure Build_Server_Flight_12_Full
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action)
   is
      Gen_Random : constant Random_Bytes_Fn := Cfg.Random;
      Rec_Out    : N32;
      --  Atomic flight assembly: build every record into a scratch buffer
      --  first. We commit to S.Output only when the entire flight has
      --  been built and we know it fits, so the peer never observes a
      --  partial flight. (All four records here are plaintext, so the
      --  AEAD counter doesn't need rolling back on failure.)
      Scratch    : IO_Buffer;
   begin
      --  TLS 1.2 uses supported_groups (no key_share extension)
      if S.HC.Client_Has_X25519 or S.HC.Client_Supports_X25519 then
         S.HC.KE.Curve := Group_X25519;
         S.HC.KE.Negotiated := True;
      elsif S.HC.Client_Has_P256 or S.HC.Client_Supports_P256 then
         S.HC.KE.Curve := Group_Secp256r1;
         S.HC.KE.Negotiated := True;
      elsif S.HC.Client_Has_P384 or S.HC.Client_Supports_P384 then
         S.HC.KE.Curve := Group_Secp384r1;
         S.HC.KE.Negotiated := True;
      else
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;
      pragma Assert (S.HC.KE.Negotiated);

      --  The unversioned dispatcher commits the selected TLS 1.2 suite
      --  before entering this package.
      if S.Negotiated_Suite not in
           Suite_ECDHE_RSA_AES128_GCM_SHA256
           | Suite_ECDHE_RSA_AES256_GCM_SHA384
           | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
           | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
           | Suite_ECDHE_RSA_CHACHA20_SHA256
           | Suite_ECDHE_ECDSA_CHACHA20_SHA256
      then
         --  No matching TLS 1.2 ECDHE+AEAD suite
         Send_Alert_And_Error (S, Handshake_Failure, Result);
         return;
      end if;

      --  Negotiate signature scheme: pick the first client-offered
      --  scheme that is compatible with our local key's signing
      --  algorithm. RSA-PKCS#1 v1.5 schemes (0x0401/0x0501/0x0601)
      --  would be valid in TLS 1.2 but we don't yet implement
      --  v1.5 *signing* in SPARKTLSCrypto.RSA  only verify  so
      --  we offer PSS only for RSA keys. Verify is supported, so
      --  client cert sigs in v1.5 are still accepted via the
      --  cert_verify path.
      declare
         Negotiated                   : Unsigned_16 := 0;
         Client_Sent_Recognized_Group : constant Boolean :=
           S.HC.Client_Supports_X25519
           or else S.HC.Client_Supports_P256
           or else S.HC.Client_Supports_P384;

         function Compatible_Local_Sig (Scheme : Unsigned_16) return Boolean is
         begin
            case Cfg.Local.Sign_Algo is
               when Sign_RSA_PSS =>
                  return Scheme in 16#0804# | 16#0805# | 16#0806# | 16#0401# | 16#0501# | 16#0601#;

               when Sign_ECDSA_P256 =>
                  return
                    Scheme = 16#0403#
                    and then (not Client_Sent_Recognized_Group or else S.HC.Client_Supports_P256);

               when Sign_ECDSA_P384 =>
                  return
                    Scheme = 16#0503#
                    and then (not Client_Sent_Recognized_Group or else S.HC.Client_Supports_P384);

               when Sign_Ed25519 =>
                  return Scheme = 16#0807#;

               when Sign_None =>
                  return False;
            end case;
         end Compatible_Local_Sig;
      begin
         if S.HC.Peer_Sig_Algo_Count = 0 then
            --  RFC 5246 7.4.1.4.1: when client omits the
            --  signature_algorithms extension, the server uses a
            --  default. RFC 5246 specifies SHA-1, but SHA-1 is
            --  deprecated and we don't support it. Modern practice
            --  (OpenSSL, Go) is to default to SHA-256 with the
            --  cert's algorithm. TLS-Anvil's
            --  ecdsaNoSignatureAlgorithmsExtension test (5246-MjFVuYUzfF)
            --  exercises this path.
            case Cfg.Local.Sign_Algo is
               when Sign_RSA_PSS =>
                  Negotiated := 16#0804#;  -- PSS-SHA256

               when Sign_ECDSA_P256 =>
                  if not Client_Sent_Recognized_Group or else S.HC.Client_Supports_P256 then
                     Negotiated := 16#0403#;
                  end if;

               when Sign_ECDSA_P384 =>
                  if not Client_Sent_Recognized_Group or else S.HC.Client_Supports_P384 then
                     Negotiated := 16#0503#;
                  end if;

               when Sign_Ed25519 =>
                  Negotiated := 16#0807#;

               when Sign_None =>
                  null;
            end case;
            --  RFC 5246 7.4.1.4.1 strong-hash invariant: every value
            --  the case selects above is a SHA-256-or-stronger scheme.
            --  This pragma Assert pins the property; a future edit
            --  that introduces a SHA-1 default (e.g. 0x0201, 0x0202)
            --  would fail SPARK proof here.
            pragma
              Assert
                (Negotiated = 0 or else Sig_Scheme_Has_Strong_Hash_RFC_5246_7_4_1_4_1 (Negotiated));
         elsif Cfg.Sign_Sig_Algo_Count > 0 then
            for J in Sig_Algo_Index loop
               pragma
                 Loop_Invariant
                   (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                      (Negotiated, S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count));
               exit when J >= Cfg.Sign_Sig_Algo_Count;
               if Compatible_Local_Sig (Cfg.Sign_Sig_Algos (J))
                 and then Sig_Scheme_In_List
                            (Cfg.Sign_Sig_Algos (J), S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count)
               then
                  Negotiated := Cfg.Sign_Sig_Algos (J);
                  exit;
               end if;
            end loop;
            pragma
              Assert
                (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                   (Negotiated, S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count));
         else
            for I in Natural range 0 .. S.HC.Peer_Sig_Algo_Count - 1 loop
               pragma
                 Loop_Invariant
                   (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                      (Negotiated, S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count));
               declare
                  Scheme : constant Unsigned_16 := S.HC.Peer_Sig_Algos (I);
               begin
                  case Cfg.Local.Sign_Algo is
                     when Sign_RSA_PSS =>
                        --  An RSA key can sign with either PSS or
                        --  PKCS#1 v1.5 padding. RFC 5246 7.4.1.4.1 +
                        --  RFC 8446 4.2.3  accept any RSA scheme the
                        --  client offered. PSS preferred where both
                        --  are offered (the picking loop selects the
                        --  first match, so client ordering wins).
                        --  PKCS#1-SHA1 (0x0201) intentionally not
                        --  accepted  SHA-1 is deprecated.
                        if Scheme = 16#0804#
                          or Scheme = 16#0805#
                          or Scheme = 16#0806#
                          or Scheme = 16#0401#
                          or Scheme = 16#0501#
                          or Scheme = 16#0601#
                        then
                           Negotiated := Scheme;
                           exit;
                        end if;

                     when Sign_ECDSA_P256 =>
                        if Scheme = 16#0403#
                          and then (not Client_Sent_Recognized_Group
                                    or else S.HC.Client_Supports_P256)
                        then
                           Negotiated := Scheme;
                           exit;
                        end if;

                     when Sign_ECDSA_P384 =>
                        if Scheme = 16#0503#
                          and then (not Client_Sent_Recognized_Group
                                    or else S.HC.Client_Supports_P384)
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
            --  RFC 5246 7.4.1.4.1 / RFC 8446 4.2.3: post-loop the
            --  Negotiated scheme (if non-zero) is one the client
            --  offered. The loop invariant builds this incrementally:
            --  every iteration either exits with Negotiated set to
            --  S.HC.Peer_Sig_Algos(I), or leaves Negotiated unchanged.
            pragma
              Assert
                (Negotiated_Sig_Algo_From_Offered_RFC_5246_7_4_1_4_1
                   (Negotiated, S.HC.Peer_Sig_Algos, S.HC.Peer_Sig_Algo_Count));
         end if;
         if Negotiated = 0 then
            Send_Alert_And_Error (S, Handshake_Failure, Result);
            return;
         end if;
         S.HC.Negotiated_Sig_Algo := Negotiated;
      end;

      case S.HC.KE.Curve is
         when Group_X25519 =>
            Gen_Random (Byte_Seq (S.HC.KE.Local_SK));

         when Group_Secp256r1 =>
            Gen_Random (Byte_Seq (S.HC.KE.P256_SK));

         when Group_Secp384r1 =>
            Gen_Random (Byte_Seq (S.HC.KE.P384_SK));

         when others =>
            null;
      end case;

      if Cfg.Require_ALPN and then not SPARKTLS.Handshake.Server_Msgs.Has_ALPN_Match (S.HC) then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
      end if;

      --  1. ServerHello
      --  Re-establish S.HC.Cfg facts locally: Build_Server_Hello_12's Pre
      --  names S.HC.Cfg (Handshake.TLS12 cannot see Server's Ready_Config),
      --  and the prover cannot link the Cfg copy back to S.HC.Cfg. Three
      --  null checks, semantically unreachable, fail closed.
      if S.HC.Cfg not in Ready_Config then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1);
         Hello_Len : N32;
      begin
         Build_Server_Hello_12 (S.Negotiated_Suite, S.Negotiated_ALPN, S.HC, Hello_Buf, Hello_Len);
         pragma Assert (S.Role = Role_Server);
         if Hello_Len = 0 then
            Send_Alert_And_Error (S, Internal_Error, Result);
            return;
         end if;
         Append_Transcript (S.HC, Hello_Buf (0 .. Hello_Len - 1));
         Records.Build_Handshake_Record (Hello_Buf (0 .. Hello_Len - 1), Scratch, Rec_Out);
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
         Build_Certificate_Chain_12 (Cfg.Local.all, Cert_Buf, Cert_Len);
         if Cert_Len > 0 then
            Append_Transcript (S.HC, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Handshake_Record (Cert_Buf (0 .. Cert_Len - 1), Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end if;
      end;

      --  3. ServerKeyExchange
      declare
         SKE_Buf : Byte_Seq (0 .. Max_Server_Key_Exchange - 1);
         SKE_Len : N32;
      begin
         pragma Assert (S.HC.KE.Negotiated);
         Build_Server_Key_Exchange (S.HC, Cfg.Local.all, Gen_Random, SKE_Buf, SKE_Len);
         if SKE_Len > 0 then
            Append_Transcript (S.HC, SKE_Buf (0 .. SKE_Len - 1));
            Records.Build_Handshake_Record (SKE_Buf (0 .. SKE_Len - 1), Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end if;
      end;

      --  4. CertificateRequest (optional client auth)
      if Cfg.Request_Client_Cert then
         declare
            Cert_Type_RSA_Sign   : constant Byte := 16#01#;
            Cert_Type_ECDSA_Sign : constant Byte := 16#40#;
            Certificate_Types    : constant Byte_Seq (0 .. 1) :=
              (Cert_Type_RSA_Sign, Cert_Type_ECDSA_Sign);

            Sig_RSA_PKCS1_SHA256  : constant Unsigned_16 := 16#0401#;
            Sig_RSA_PKCS1_SHA384  : constant Unsigned_16 := 16#0501#;
            Sig_RSA_PKCS1_SHA512  : constant Unsigned_16 := 16#0601#;
            Sig_ECDSA_P256_SHA256 : constant Unsigned_16 := 16#0403#;
            Sig_ECDSA_P384_SHA384 : constant Unsigned_16 := 16#0503#;
            Sig_RSA_PSS_SHA256    : constant Unsigned_16 := 16#0804#;
            Sig_RSA_PSS_SHA384    : constant Unsigned_16 := 16#0805#;
            Sig_RSA_PSS_SHA512    : constant Unsigned_16 := 16#0806#;
            Sig_Ed25519           : constant Unsigned_16 := 16#0807#;

            function U16_Bytes (V : Unsigned_16) return Byte_Seq
            is ((0 => Byte (V / 256), 1 => Byte (V mod 256)));

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

            Certificate_Authorities : constant Byte_Seq (0 .. 1) := (16#00#, 16#00#);
            CR_Body_Len             : constant N32 :=
              1 + N32 (Certificate_Types'Length) + 2 + N32 (Signature_Algorithms'Length)
              + N32 (Certificate_Authorities'Length);
            CR_Buf                  : Byte_Seq (0 .. 4 + CR_Body_Len - 1) := (others => 0);
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

            Append_Transcript (S.HC, CR_Buf);
            Records.Build_Handshake_Record (CR_Buf, Scratch, Rec_Out);
            if Rec_Out = 0 then
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end;
      end if;

      --  5. ServerHelloDone
      declare
         Done_Buf : Byte_Seq (0 .. 3);
         Done_Len : N32;
      begin
         Build_Server_Hello_Done (Done_Buf, Done_Len);
         Append_Transcript (S.HC, Done_Buf (0 .. Done_Len - 1));
         Records.Build_Handshake_Record (Done_Buf (0 .. Done_Len - 1), Scratch, Rec_Out);
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
      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
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
   procedure Derive_Keys_Resumed_12 (S : in out Session; Cfg : in Ready_Config)
   with
     Pre =>
       S.Version = TLS_1_2
       and then S.Negotiated_Suite in
                  Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                  | Suite_ECDHE_RSA_CHACHA20_SHA256
                  | Suite_ECDHE_ECDSA_CHACHA20_SHA256,
     Post =>
       S.State = S.State'Old
       and then S.Role = S.Role'Old
       and then S.Negotiated_Suite = S.Negotiated_Suite'Old
       and then S.Server_App.Counter = 0
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite in
          Suite_ECDHE_RSA_AES256_GCM_SHA384
          | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
        (if S.Negotiated_Suite in
              Suite_ECDHE_RSA_AES128_GCM_SHA256
              | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
         then 16
         else 32);
      IV_Len  : constant N32 :=
        (if S.Negotiated_Suite in
              Suite_ECDHE_RSA_CHACHA20_SHA256
              | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then 12
         else 4);
      CK      : Byte_Seq (0 .. Key_Len - 1);
      SK      : Byte_Seq (0 .. Key_Len - 1);
      CI      : Byte_Seq (0 .. 11) := (others => 0);
      SI      : Byte_Seq (0 .. 11) := (others => 0);
   begin
      Expand_Keys_12
        (CK,
         SK,
         CI,
         SI,
         S.HC.Master_Secret_12,
         S.HC.Server_Random,
         S.HC.Client_Random,
         Key_Len,
         IV_Len,
         Use_384);
      declare
         Int_Suite : constant Supported_Suite :=
           (case S.Negotiated_Suite is
              when Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                Suite_AES_128_GCM_SHA256,
              when Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                Suite_AES_256_GCM_SHA384,
              when others => Suite_CHACHA20_POLY1305_SHA256);
      begin
         S.Client_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;
      S.HC.Client_Write_IV_12 := CI;
      S.HC.Server_Write_IV_12 := SI;
      S.Exporter_Secret := S.HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;
   end Derive_Keys_Resumed_12;

   ------------------------------------------------------------------
   --  Build the abbreviated (resumed) server flight: SH â NST â
   --  CCS â encrypted Finished. Caller has already restored
   --  HC.Master_Secret_12 + forced S.Negotiated_Suite from the ticket.
   ------------------------------------------------------------------
   procedure Build_Abbreviated_Server_Flight_12
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action)
   is
      use Key_Schedule_12;
      use type SPARKTLS.Tickets_12.Bytes_4;
      Gen_Random    : constant Random_Bytes_Fn := Cfg.Random;
      Rec_Out       : N32;
      Scratch       : IO_Buffer;
      Saved_Seq     : Record_Counter;
      Use_384       : constant Boolean :=
        S.Negotiated_Suite in
          Suite_ECDHE_RSA_AES256_GCM_SHA384
          | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      --  Sealing key comes from the caller's store, not from Config.
      --  Filled by Get_Active_TEK below; if the callback reports no key
      --  we simply do not issue a ticket.
      Active_Key_ID : Byte_Seq (0 .. 3) := (others => 0);
      Active_TEK    : Byte_Seq (0 .. 31) := (others => 0);
      Have_TEK      : Boolean := False;
   begin
      --  Get_Time /= null for the same reason as the full flight: an
      --  unexpirable ticket is worse than no ticket. Have_TEK stays
      --  False, which the NST path already reads as "issue nothing".
      if Cfg.Get_Active_TEK /= null and then Cfg.Get_Time /= null then
         Cfg.Get_Active_TEK.all (Active_Key_ID, Active_TEK, Have_TEK);
      end if;
      --  Mirror the full-flight setup that Build_Server_Flight_12_Full
      --  did before we diverted. We don't pick a group (no ECDHE), we
      --  don't pick a signature scheme (no SKE), but we DO need the
      --  Negotiated_Sig_Algo to be cleared so Build_Server_Hello_12
      --  doesn't try to echo a stale value.
      S.HC.Negotiated_Sig_Algo := 0;

      --  Fresh server random (32 bytes).
      declare
         Server_Random : Bytes_32;
      begin
         Gen_Random (Byte_Seq (Server_Random));
         Set_Server_Random_12 (S.HC, Server_Random);
      end;

      if Cfg.Require_ALPN and then not SPARKTLS.Handshake.Server_Msgs.Has_ALPN_Match (S.HC) then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
      end if;

      --  1. ServerHello (with empty session_ticket ext, since
      --     TLS12_Ticket_Offered + TLS12_Ticket_Keys are set).
      declare
         Hello_Buf : Byte_Seq (0 .. Max_Server_Hello_12 - 1);
         Hello_Len : N32;
      begin
         if S.HC.Cfg not in Ready_Config then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         Build_Server_Hello_12 (S.Negotiated_Suite, S.Negotiated_ALPN, S.HC, Hello_Buf, Hello_Len);
         if Hello_Len = 0 then
            Send_Alert_And_Error (S, Internal_Error, Result);
            return;
         end if;
         Append_Transcript (S.HC, Hello_Buf (0 .. Hello_Len - 1));
         Records.Build_Handshake_Record (Hello_Buf (0 .. Hello_Len - 1), Scratch, Rec_Out);
         if Rec_Out = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  2. Derive AEAD keys (no master-secret PRF  restored from
      --     ticket; just expand to traffic keys + IVs).
      Derive_Keys_Resumed_12 (S, Cfg);

      --  3. NewSessionTicket (re-issued under our active TEK with a
      --     fresh nonce). RFC 5077 3.3: the server MUST send NST in
      --     the resumed flight if it advertised session_ticket in SH.
      declare
         Nonce_Buf   : Byte_Seq (0 .. 11) := (others => 0);
         Plain       : SPARKTLS.Tickets_12.Ticket_Plain;
         Ticket_Buf  : Byte_Seq (0 .. 255) := (others => 0);
         Ticket_Len  : N32;
         NST_Buf     : Byte_Seq (0 .. 271) := (others => 0);
         NST_Total   : N32;
         NST_Rec_Out : N32;
      begin
         Gen_Random (Nonce_Buf);
         Plain.Master_Secret := S.HC.Master_Secret_12;
         Plain.Suite := Wire_Of (S.Negotiated_Suite);
         Plain.Created_At :=
           (if Cfg.Get_Time /= null then SPARKTLS.Tickets_12.To_Unix_Seconds (Cfg.Get_Time.all)
            else 0);
         Plain.SID_Len := 0;
         Plain.SID := (others => 0);
         SPARKTLS.Tickets_12.Encrypt_Ticket
           (Plain      => Plain,
            Key_ID     => SPARKTLS.Tickets_12.Bytes_4 (Active_Key_ID),
            TEK        => SPARKTLS.Tickets_12.Bytes_32 (Active_TEK),
            Nonce      => SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
            Ticket     => Ticket_Buf,
            Ticket_Len => Ticket_Len);

         SPARKTLS.Handshake.TLS12.Build_New_Session_Ticket_12
           (Lifetime_Hint => Cfg.TLS12_Ticket_Lifetime,
            Ticket        => Ticket_Buf (0 .. Ticket_Len - 1),
            Result        => NST_Buf,
            Len           => NST_Total);
         if NST_Total = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;

         Append_Transcript (S.HC, NST_Buf (0 .. NST_Total - 1));

         Records.Build_Handshake_Record (NST_Buf (0 .. NST_Total - 1), Scratch, NST_Rec_Out);
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
      declare
         FB     : Byte_Seq (0 .. Finished_12_Total_Len - 1);
         FL     : N32;
         TH     : Digest;
         TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         EO     : N32;
      begin
         if Use_384 then
            SPARKTLS_Transcript.Current_384 (S.HC.TS, TH_384);
            Build_Finished_12
              (S.HC.Master_Secret_12, Label_Server_Finished, Byte_Seq (TH_384), True, FB, FL);
         else
            SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
            Build_Finished_12
              (S.HC.Master_Secret_12, Label_Server_Finished, Byte_Seq (TH), False, FB, FL);
         end if;

         --  Append server Finished plaintext to transcript so the
         --  client's expected Finished hash (which covers up to
         --  server Finished) matches.
         Append_Transcript (S.HC, FB (0 .. FL - 1));

         Records.TLS12.Build_Encrypted_Record_12
           (FB (0 .. FL - 1), 16#16#, S.Server_App, S.HC.Server_Write_IV_12, Scratch, EO);
         --  No counter rewind on the failure paths below: both are fatal
         --  (Error_State), so the advanced counter is never used again --
         --  and a burned nonce STAYS burned, rather than relying on the
         --  discarded Scratch ciphertext never leaking.
         if EO = 0 then
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
      end;

      --  Atomic commit.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
        Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      --  Mirror state into Session record. The sequence counters no
      --  longer need mirroring: they live INSIDE S.Server_App /
      --  S.Client_App, which are already Session state -- the
      --  handshake-to-connected counter handoff is gone by construction.
      S.Client_IV_12 := S.HC.Client_Write_IV_12;
      S.Server_IV_12 := S.HC.Server_Write_IV_12;

      --  Mark CKE-received so the existing Process_Client_CCS_12 /
      --  Process_Client_Finished_12 state-check predicates don't
      --  trip on the missing ClientKeyExchange (abbreviated flow).
      S.HC.CKE_Received_12 := True;

      --  Server flight is on the wire; await client CCS + Finished.
      Set_State (S, Wait_Client_Finished);
      Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
   end Build_Abbreviated_Server_Flight_12;

   procedure Derive_Keys_12 (S : in out Session; Cfg : in Ready_Config) is
      use Key_Schedule_12;
      Use_384    : constant Boolean :=
        S.Negotiated_Suite in
          Suite_ECDHE_RSA_AES256_GCM_SHA384
          | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len    : constant N32 :=
        (if S.Negotiated_Suite in
              Suite_ECDHE_RSA_AES128_GCM_SHA256
              | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
         then 16
         else 32);
      --  RFC 5288 3: AES-GCM IV salt is 4 bytes.
      --  RFC 7905 2: ChaCha20-Poly1305 IV is 12 bytes.
      IV_Len     : constant N32 :=
        (if S.Negotiated_Suite in
              Suite_ECDHE_RSA_CHACHA20_SHA256
              | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then 12
         else 4);
      CK         : Byte_Seq (0 .. Key_Len - 1);
      SK         : Byte_Seq (0 .. Key_Len - 1);
      CI         : Byte_Seq (0 .. 11) := (others => 0);
      SI         : Byte_Seq (0 .. 11) := (others => 0);
      Shared_Len : constant N32 := (if S.HC.KE.Curve = Group_Secp384r1 then 48 else 32);
   begin
      --  RFC 7627 4: master_secret derivation. If the client
      --  offered the extended_master_secret extension we use the
      --  EMS PRF (label "extended master secret", seed = transcript
      --  hash). Otherwise we MUST use the original RFC 5246 8.1
      --  PRF (label "master secret", seed = client_random ||
      --  server_random). Mismatch here breaks Finished verification
      --  for any client that didn't request EMS  caught by
      --  TLS-Anvil's HappyFlow battery (12/12 fail without this).
      pragma
        Assert
          (EMS_Label_Consistent
             (S.HC.Use_EMS, (if S.HC.Use_EMS then "extended master secret" else "master secret")));

      if S.HC.Use_EMS then
         declare
            TH     : Digest;
            TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         begin
            if Use_384 then
               if S.HC.EMS_Hash_Taken then
                  TH_384 := SPARKNaCl.Hashing.SHA384.Digest (S.HC.EMS_Session_Hash);
               else
                  SPARKTLS_Transcript.Current_384 (S.HC.TS, TH_384);
               end if;
               PRF_SHA384
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "extended master secret",
                  Byte_Seq (TH_384));
            else
               if S.HC.EMS_Hash_Taken then
                  TH := Digest (S.HC.EMS_Session_Hash (0 .. 31));
               else
                  SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
               end if;
               PRF_SHA256
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "extended master secret",
                  Byte_Seq (TH));
            end if;
         end;
         --  RFC 7627 4: ghost-record the PRF branch taken so
         --  EMS_PRF_Binding_RFC_7627_4 can prove on exit.
         S.HC.MS_Derivation := Extended;
      else
         declare
            --  Initialize so flow can see Seed is fully defined before
            --  the PRF call; the two slice writes below cover the full
            --  range, but flow analysis can't see a slice-pair as a
            --  whole-array write.
            Seed : Byte_Seq (0 .. 63) := (others => 0);
         begin
            Seed (0 .. 31) := Byte_Seq (S.HC.Client_Random);
            Seed (32 .. 63) := Byte_Seq (S.HC.Server_Random);
            if Use_384 then
               PRF_SHA384
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "master secret",
                  Seed);
            else
               PRF_SHA256
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "master secret",
                  Seed);
            end if;
         end;
         S.HC.MS_Derivation := Legacy;
      end if;

      Expand_Keys_12
        (CK,
         SK,
         CI,
         SI,
         S.HC.Master_Secret_12,
         S.HC.Server_Random,
         S.HC.Client_Random,
         Key_Len,
         IV_Len,
         Use_384);

      declare
         Int_Suite : constant Supported_Suite :=
           (case S.Negotiated_Suite is
              when Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                Suite_AES_128_GCM_SHA256,
              when Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                Suite_AES_256_GCM_SHA384,
              when others => Suite_CHACHA20_POLY1305_SHA256);
      begin
         --  Verify the mapping matches the ghost function

         S.Client_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;

      S.HC.Client_Write_IV_12 := CI;
      S.HC.Server_Write_IV_12 := SI;
      S.Exporter_Secret := S.HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;
   end Derive_Keys_12;

   ------------------------------------------------------------------
   procedure Process_Client_Key_Exchange_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Rec                     : Records.Parse_Result;
      CKE_Transcript_Nonempty : Boolean := False
      with Ghost;

      procedure Compute_Shared_Secret_12 (OK : out Boolean; Err : out Error_Code)
      with
        Pre =>
          S.Version = TLS_1_2
          and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local),
        Post =>
          SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)
          and then S.HC.TS = S.HC.TS'Old
      is
      begin
         OK := False;
         --  RFC 5246 7.2.2 / RFC 8446 6.2: invalid peer share is
         --  illegal_parameter; an unselectable group is the generic
         --  handshake_failure.

         case S.HC.KE.Curve is
            when Group_X25519 =>
               S.HC.KE.Shared (0 .. 31) :=
                 SPARKNaCl.Scalar.Mult (S.HC.KE.Local_SK, S.HC.KE.Peer_PK);
               --  RFC 7748 6.1 / RFC 8422 5.10: reject all-zeros
               --  shared secret (small-subgroup defence). The
               --  helper's Post is formally proven by SPARK.
               OK := Shared_Secret_Is_Acceptable_X25519 (S.HC.KE.Shared (0 .. 31));
               if OK then
                  Err := No_Error;
               else
                  Err := Illegal_Parameter;
               end if;

            when Group_Secp256r1 =>
               declare
                  use SPARKTLSCrypto.P256.Point;
                  subtype P256_SK_Seq is Byte_Seq (0 .. 31);
                  subtype P256_PK_Seq is Byte_Seq (0 .. 64);
                  Pt       : P256_Jacobian;
                  V        : SPARKNaCl.U32;
                  Local_SK : constant P256_SK_Seq := S.HC.KE.P256_SK;
                  Peer_PK  : constant P256_PK_Seq := S.HC.KE.P256_PK;
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
                        S.HC.KE.Shared := (others => 0);
                        S.HC.KE.Shared (0 .. 31) := E (1 .. 32);
                     end;
                     OK := True;
                     Err := No_Error;
                  else
                     Err := Illegal_Parameter;
                  end if;
               end;

            when Group_Secp384r1 =>
               declare
                  subtype P384_SK_Seq is Byte_Seq (0 .. 47);
                  subtype P384_PK_Seq is Byte_Seq (0 .. 96);
                  SS       : Bytes_48;
                  OK384    : Boolean;
                  Local_SK : constant P384_SK_Seq := S.HC.KE.P384_SK;
                  Peer_PK  : constant P384_PK_Seq := S.HC.KE.P384_PK;
               begin
                  pragma Assert (Local_SK'First = 0);
                  pragma Assert (Local_SK'Length = 48);
                  pragma Assert (Peer_PK'First = 0);
                  pragma Assert (Peer_PK'Length = 97);
                  SPARKTLSCrypto.P384.Point.P384_ECDHE (SS, OK384, Local_SK, Peer_PK);
                  if OK384 then
                     S.HC.KE.Shared := SS;
                     OK := True;
                     Err := No_Error;
                  else
                     Err := Illegal_Parameter;
                  end if;
               end;

            when others =>
               pragma Assert (False);
         end case;
      end Compute_Shared_Secret_12;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

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
            CCS_Pos : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_OK  : constant Boolean :=
              Rec.Fragment_Len = 1
              and then S.Input.Data (CCS_Pos) = 16#01#
              and then not S.HC.CCS_Received;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if CCS_OK then
               S.HC.CCS_Received := True;
               Result := OK;
               --  RFC 5246 7.1 single-CCS invariant: after this
               --  assignment the server's view records that the client
               --  has signaled switch-to-encrypted exactly once. Future
               --  CCS records on this connection MUST be rejected via
               --  the `not S.HC.CCS_Received` guard above.
               pragma Assert (Single_CCS_RFC_5246_7_1 (S.HC));
            else
               --  RFC 5246 7.1: CCS payload MUST be the single byte
               --  0x01 (BoGo BadChangeCipherSpec-*).
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
         end;
         return;
      end if;

      if Rec.Content = Records.Content_Alert then
         --  RFC 5246 7.2.1: close_notify can arrive at any time
         --  (including mid-handshake before keys are established).
         --  We must reply with close_notify (warning level) and
         --  close. Other plaintext alerts during handshake are
         --  protocol violations  fatal.
         declare
            FS          : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            Alert_Level : Byte := 0;
            Alert_Desc  : Byte := 0;
         begin
            if Rec.Fragment_Len >= 2 then
               Alert_Level := S.Input.Data (FS);
               Alert_Desc := S.Input.Data (FS + 1);
            end if;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Alert_Desc = 0 then
               --  close_notify  reply in kind (plaintext warning).
               declare
                  A : N32;
               begin
                  Records.Build_Plaintext_Alert
                    (Level => 1, Desc => 0, Output => S.Output, Bytes_Out => A);
                  pragma Assert (A in 0 | 7);
               end;
               Set_State (S, Closing);
               if Output_Pending (S) > 0 then
                  --  RFC 5246 7.2.1: invariant after queued reply.
                  pragma
                    Assert (Close_Notify_Reply_State_RFC_5246_7_2_1 (S.State, Output_Pending (S)));
                  Result := Has_Output;
               else
                  Result := Shutdown;
               end if;
            else
               --  Other alert mid-handshake  peer is closing on us
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

      --  RFC 5246 7.4.7: only one ClientKeyExchange permitted. A
      --  second handshake-content record after we've already seen
      --  CKE is a state-machine violation  fatal alert.
      --  TLS-Anvil's secondClientKeyExchange test (XSM-zmpmr7nVki).
      if S.HC.CKE_Received_12 then
         if Rec.Content = Records.Content_Handshake and then Rec.Fragment_Len >= 4 then
            declare
               FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               Frag_Len : constant N32 := Rec.Fragment_Len;
            begin
               pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
               declare
                  Frag     : constant Byte_Seq := S.Input.Data (FS .. FS + Frag_Len - 1);
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
               begin
                  Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);
                  if not Parse_OK then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error
                       (S,
                        (if Frag (Frag'First) in
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
                              | 16#14#
                         then Decode_Error
                         else Unexpected_Message),
                        Result);
                     return;
                  end if;

                  if Msg_Type = Handshake.HT_Certificate_Verify then
                     if Msg_Len < 4 or else Msg_Len + 4 /= Frag_Len then
                        S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        return;
                     end if;

                     declare
                        F : constant N32 := Frag'First;
                     begin
                        pragma Assert (Frag_Len >= 8);
                        pragma Assert (F + 7 <= Frag'Last);
                        declare
                           Sig_Len : constant N32 := N32 (Frag (F + 6)) * 256 + N32 (Frag (F + 7));
                        begin
                           if Sig_Len /= Msg_Len - 4 then
                              S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                              Send_Alert_And_Error (S, Decode_Error, Result);
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
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;

         procedure Parse_Complete_CKE (Msg : in Byte_Seq; CKE_Good : out Boolean)
         with
           Pre =>
             Msg'Length > 0
             and then Msg'Last < N32 (Natural'Last)
             and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local),
           Post =>
             SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)
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
               S.HC.Ext_Parse_Err := Illegal_Parameter;
               return;
            end if;

            declare
               Msg_Len_Const : constant N32 := Msg_Len;
               Body_Data     : Byte_Seq (0 .. Msg_Len_Const - 1);
            begin
               pragma Assert (Msg'First + 4 <= Msg'Last);
               pragma Assert (Msg'First + 4 + Msg_Len - 1 = Msg'Last);
               Body_Data := Msg (Msg'First + 4 .. Msg'First + 4 + Msg_Len - 1);
               Parse_Client_Key_Exchange (S.HC, Body_Data, CKE_Good);
            end;
         end Parse_Complete_CKE;

         procedure Fail_Decode
         with
           Pre =>
             S.Input.Read_Pos <= N32'Last - Rec.Record_Len
             and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
             and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity,
           Post =>
             S.State = Error_State
             and then Result /= OK
             and then S.Negotiated_Suite = S.Negotiated_Suite'Old
         is
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
         end Fail_Decode;

         procedure Fail_Unexpected
         with
           Pre =>
             S.Input.Read_Pos <= N32'Last - Rec.Record_Len
             and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
             and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity,
           Post =>
             S.State = Error_State
             and then Result /= OK
             and then S.Negotiated_Suite = S.Negotiated_Suite'Old
         is
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Unexpected_Message, Result);
         end Fail_Unexpected;

         procedure Finish_CKE (Msg : in Byte_Seq)
         with
           Pre =>
             Msg'Length > 0
             and then Msg'Last < N32 (Natural'Last)
             and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
             and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
             and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity
             and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local),
           Post =>
             SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)
             and then S.Negotiated_Suite = S.Negotiated_Suite'Old
             and then (if Result = OK then S.State = S.State'Old else S.State = Error_State)
         is
            CKE_OK                 : Boolean;
            Saved_Negotiated_Suite : constant Supported_Suite := S.Negotiated_Suite
            with Ghost;
         begin
            Parse_Complete_CKE (Msg, CKE_OK);
            if not CKE_OK then
               if S.HC.Ext_Parse_Err /= No_Error then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, S.HC.Ext_Parse_Err, Result);
                  pragma Assert (S.Negotiated_Suite = Saved_Negotiated_Suite);
               else
                  Fail_Decode;
                  pragma Assert (S.Negotiated_Suite = Saved_Negotiated_Suite);
               end if;
               return;
            end if;

            Append_Transcript (S.HC, Msg);
            if S.Negotiated_Suite in
                 Suite_ECDHE_RSA_AES256_GCM_SHA384
                 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
            then
               declare
                  D : SPARKNaCl.Hashing.SHA384.Digest;
               begin
                  SPARKTLS_Transcript.Current_384 (S.HC.TS, D);
                  S.HC.EMS_Session_Hash := Bytes_48 (D);
               end;
            else
               declare
                  D : Digest;
               begin
                  SPARKTLS_Transcript.Current_256 (S.HC.TS, D);
                  S.HC.EMS_Session_Hash := (others => 0);
                  S.HC.EMS_Session_Hash (0 .. 31) := Byte_Seq (D);
               end;
            end if;
            S.HC.EMS_Hash_Taken := True;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            pragma Assert (S.Negotiated_Suite = Saved_Negotiated_Suite);
         end Finish_CKE;

      begin
         --  Slice bound: Parse_Record_Header Post gives Record_Len <= Avail,
         --  i.e., Read_Pos + Record_Len <= Write_Pos <= IO_Buffer_Capacity.
         --  So FS + Frag_Len = Read_Pos + Fragment_Pos + Fragment_Len
         --                  = Read_Pos + Record_Len <= Write_Pos.
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         if Used (D.Reasm) > 0 then

            declare
               --  Was "(if Len <= Need then Need - Len else 0)" -- a guard
               --  that substituted a ZERO-LENGTH COPY for a state it could
               --  not handle, hiding the underflow rather than preventing it
               --  (task #89). Wanted computes the shortfall inside the module
               --  where the subtraction is safe, and the Min against
               --  Free_Space discharges Append's precondition, so the
               --  buffer-overflow branch is gone too.
               Take : constant HS_Msg_Len :=
                 N32'Min (N32'Min (Wanted (D.Reasm), Frag_Len), Free_Space (D.Reasm));
            begin
               if Take > 0 then
                  Append (D.Reasm, S.Input.Data (FS .. FS + Take - 1));
               end if;

               if Take /= Frag_Len then
                  --  A CKE handshake message may span records, but this
                  --  state expects exactly that one message before CCS.
                  Fail_Decode;
                  return;
               end if;
            end;

            if Header_Ready (D.Reasm) then
               if Declared_Type (D.Reasm) /= HT_Client_Key_Exchange then
                  Fail_Unexpected;
                  return;
               end if;
               if Declared_Size (D.Reasm) - 4 > Max_Client_Key_Exchange then
                  Fail_Decode;
                  return;
               end if;
            end if;

            if not Has_Message (D.Reasm) then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Result := OK;
               return;
            end if;

            declare
               Full : constant Message_Bytes := Message (D.Reasm);
            begin
               begin
                  Reset (D.Reasm);
                  Result := OK;
                  Finish_CKE (Byte_Seq (Full));
                  if Result /= OK then
                     return;
                  end if;
                  pragma Assert (SPARKTLS_Transcript.Started (S.HC.TS));
                  CKE_Transcript_Nonempty := (SPARKTLS_Transcript.Started (S.HC.TS));
               end;
            end;
         elsif Frag_Len < 4 then
            if Frag_Len = 0 then
               Fail_Decode;
               return;
            end if;

            Reset (D.Reasm);
            Append (D.Reasm, S.Input.Data (FS .. FS + Frag_Len - 1));
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            return;
         else
            declare
               HS_Msg_Len : constant N32 :=
                 N32 (S.Input.Data (FS + 1)) * 65536 + N32 (S.Input.Data (FS + 2)) * 256
                 + N32 (S.Input.Data (FS + 3));
               HS_Total   : constant N32 := HS_Msg_Len + 4;
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
                  Reset (D.Reasm);
                  Append (D.Reasm, S.Input.Data (FS .. FS + Frag_Len - 1));
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK;
                  return;
               end if;
            end;

            declare
               Frag : constant Byte_Seq := S.Input.Data (FS .. FS + Frag_Len - 1);
            begin
               Result := OK;
               Finish_CKE (Frag);
               if Result /= OK then
                  return;
               end if;
               pragma Assert (SPARKTLS_Transcript.Started (S.HC.TS));
               CKE_Transcript_Nonempty := (SPARKTLS_Transcript.Started (S.HC.TS));
            end;
         end if;
      end;

      --  Compute ECDHE shared secret
      declare
         SS_OK  : Boolean := False;
         SS_Err : Error_Code := Handshake_Failure;
      begin
         Compute_Shared_Secret_12 (SS_OK, SS_Err);
         if not SS_OK then
            Send_Alert_And_Error (S, SS_Err, Result);
            return;
         end if;
      end;
      pragma Assert (CKE_Transcript_Nonempty);
      pragma Assert (SPARKTLS_Transcript.Started (S.HC.TS));
      if S.HC.Cfg not in Ready_Config then
         --  Fail closed (Init's gate makes this unreachable).
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      declare
         Cfg : constant Ready_Config := S.HC.Cfg;
      begin
         Derive_Keys_12 (S, Cfg);
      end;
      S.HC.CKE_Received_12 := True;
      Result := (if Input_Available (S) > 0 then OK else Need_Input);
      --  RFC 5246 7.4.7: at this exit point, the single-CKE
      --  invariant MUST hold. A future edit that drops the
      --  S.HC.CKE_Received_12 := True assignment above would fail
      --  this pragma  that's the point.
      pragma Assert (Single_CKE_RFC_5246_7_4_7 (S.HC));
   end Process_Client_Key_Exchange_12;

   procedure Process_Client_Certificate_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

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

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
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
            return;
         end if;

         declare
            Frag     : constant Byte_Seq := S.Input.Data (FS .. FS + Frag_Len - 1);
            Msg_Type : Byte;
            Msg_Len  : N32;
            Parse_OK : Boolean;
         begin
            Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);

            if not Parse_OK then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error
                 (S,
                  (if Frag (Frag'First) in
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
                        | 16#14#
                   then Decode_Error
                   else Unexpected_Message),
                  Result);
               return;
            end if;

            if Msg_Type /= Handshake.HT_Certificate then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;

            if Msg_Len < 3 or else Msg_Len + 4 /= Frag_Len then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;

            declare
               F : constant N32 := Frag'First;
            begin
               pragma Assert (Frag_Len >= 7);
               pragma Assert (F + 6 <= Frag'Last);
               declare
                  List_Len : constant N32 :=
                    N32 (Frag (F + 4)) * 65536 + N32 (Frag (F + 5)) * 256 + N32 (Frag (F + 6));
               begin
                  if List_Len /= Msg_Len - 3 then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  if List_Len = 0 and then S.HC.Cfg.Require_Client_Cert then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
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
               SPARKTLS.Handshake.Certs.Parse_Certificate_Chain_12
                 (HC => S.HC, D => D, HS_Msg => HS_Msg, OK => Chain_OK, Err => Chain_Err);

               if not Chain_OK then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Chain_Err, Result);
                  return;
               end if;
            end;

            Append_Transcript (S.HC, Frag);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if D.Peer_Leaf.Present then
               --  Bounds + Spans_Valid ride Pool_Entry's predicate.
               pragma Assert (D.Peer_Leaf.Present);
               Set_State (S, Wait_Client_Cert_Verify);
            elsif D.Peer_Leaf.DER_Len > 0 then
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            elsif S.HC.Cfg.Require_Client_Cert then
               Send_Alert_And_Error (S, Handshake_Failure, Result);
               return;
            else
               Set_State (S, Wait_Client_Finished);
            end if;
            Result := (if Input_Available (S) > 0 then OK else Need_Input);
         end;
      end;
   end Process_Client_Certificate_12;

   ------------------------------------------------------------------
   procedure Process_Client_CertVerify_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

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

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
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
            return;
         end if;

         declare
            Frag     : constant Byte_Seq := S.Input.Data (FS .. FS + Frag_Len - 1);
            Msg_Type : Byte;
            Msg_Len  : N32;
            Parse_OK : Boolean;
         begin
            Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);

            if not Parse_OK then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error
                 (S,
                  (if Frag (Frag'First) in
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
                        | 16#14#
                   then Decode_Error
                   else Unexpected_Message),
                  Result);
               return;
            end if;

            if Msg_Type /= Handshake.HT_Certificate_Verify then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;

            if Msg_Len < 4 or else Msg_Len + 4 /= Frag_Len then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;

            declare
               F          : constant N32 := Frag'First;
               Sig_Scheme : constant Unsigned_16 :=
                 Unsigned_16 (Frag (F + 4)) * 256 + Unsigned_16 (Frag (F + 5));
               Sig_Len    : constant N32 := N32 (Frag (F + 6)) * 256 + N32 (Frag (F + 7));
               Verified   : Boolean;
            begin
               if Sig_Len = 0 or else Sig_Len /= Msg_Len - 4 or else F + 8 + Sig_Len - 1 > Frag'Last
               then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;

               if S.HC.Cfg.Verify_Sig_Algo_Count > 0
                 and then not Sig_Scheme_In_List
                                (Sig_Scheme,
                                 S.HC.Cfg.Verify_Sig_Algos,
                                 S.HC.Cfg.Verify_Sig_Algo_Count)
               then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Illegal_Parameter, Result);
                  return;
               end if;

               declare
                  Sig : Byte_Seq (0 .. Sig_Len - 1);
               begin
                  for I in N32 range 0 .. Sig_Len - 1 loop
                     Sig (I) := Frag (F + 8 + I);
                  end loop;

                  declare
                     TH2 : SPARKTLSCrypto.Hashing.SHA256.Digest;
                     TH3 : SPARKTLSCrypto.Hashing.SHA384.Digest;
                     TH5 : SPARKTLSCrypto.Hashing.SHA512.Digest;
                  begin
                     SPARKTLS_Transcript.Current_256 (S.HC.TS, TH2);
                     SPARKTLS_Transcript.Current_384 (S.HC.TS, TH3);
                     SPARKTLS_Transcript.Current_512 (S.HC.TS, TH5);
                     Verified :=
                       Cert_Verify.Verify_Signature_TLS12_Hashed
                         (H256_In    => Bytes_32 (TH2),
                          H384_In    => Bytes_48 (TH3),
                          H512_In    => Bytes_64 (TH5),
                          Sig        => Sig,
                          Cert       => D.Peer_Leaf.Cert,
                          Sig_Scheme => Sig_Scheme);
                  end;
               end;

               if not Verified then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Certificate_Verify_Failed, Result);
                  return;
               end if;
            end;

            declare
               Leaf_Last : constant X509.N32 := D.Peer_Leaf.DER_Len - 1;
               --  DER is X509.Byte_Seq now (#101): validators take it
               --  directly -- the conversion copy loop is gone, and with
               --  it the Leaf_DER bound obligations it generated.
               Cert_X    : X509.Byte_Seq renames D.Peer_Leaf.DER (0 .. Leaf_Last);
               VR        : Validation_Result;
            begin

               VR :=
                 Validate_Leaf_Policy
                   (Leaf     => D.Peer_Leaf.Cert,
                    Leaf_DER => Cert_X,
                    Hostname => "",
                    Purpose  => Purpose_Client,
                    Mode     => S.HC.Cfg.Verify_Mode);
               if VR /= Valid then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Bad_Certificate, Result);
                  return;
               end if;

               if not S.HC.Cfg.Skip_Verify then
                  if S.HC.Cfg.Trust = null or else S.HC.Cfg.Get_Time = null then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Bad_Certificate, Result);
                     return;
                  end if;

                  VR :=
                    Validate_Chain
                      (Leaf_DER   => Cert_X,
                       Leaf       => D.Peer_Leaf.Cert,
                       Ints       => D.Peer_Ints,
                       Int_Count  => D.Peer_Int_Count,
                       Roots      => S.HC.Cfg.Trust.Roots,
                       Root_Count => S.HC.Cfg.Trust.Root_Count,
                       Now        => S.HC.Cfg.Get_Time.all,
                       Hostname   => "",
                       Purpose    => Purpose_Client,
                       Mode       => S.HC.Cfg.Verify_Mode);
                  if VR /= Valid then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Bad_Certificate, Result);
                     return;
                  end if;
               end if;
            end;

            Append_Transcript (S.HC, Frag);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Set_State (S, Wait_Client_Finished);
            Result := (if Input_Available (S) > 0 then OK else Need_Input);
         end;
      end;
   end Process_Client_CertVerify_12;

   ------------------------------------------------------------------
   ------------------------------------------------------------------
   procedure Process_Client_Finished_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      use SPARKTLS.Records.TLS12;
      use Key_Schedule_12;
      Rec     : Records.Parse_Result;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite in
          Suite_ECDHE_RSA_AES256_GCM_SHA384
          | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);
      if not Rec.OK then
         --  RFC 5246 7.2.1: alerts are under the current write
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
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Record_Overflow, Result);
            return;
         end if;

         declare
            Min_Frag : constant N32 :=
              (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256 then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
         end;

         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         declare
            Encrypted : Byte_Seq (0 .. Frag_Len - 1);
            Hdr       : Byte_Seq (0 .. 4);
            Plaintext : Byte_Seq (0 .. Frag_Len - 1);
            PL        : N32;
            DV        : Boolean;
         begin
            for I in N32 range 0 .. Frag_Len - 1 loop
               Encrypted (I) := S.Input.Data (FS + I);
            end loop;
            for I in N32 range 0 .. 4 loop
               Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
            end loop;

            Decrypt_Record_12
              (Encrypted, Hdr, S.Client_App, S.HC.Client_Write_IV_12, Plaintext, PL, DV);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if not DV then
               Send_Alert_And_Error (S, Bad_Record_MAC, Result);
               return;
            end if;

            if Used (D.Reasm) > 0 or else PL < 4 then
               if Used (D.Reasm) = 0 and then PL = 0 then
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;

               declare
                  Take : constant HS_Msg_Len :=
                    N32'Min (N32'Min (Wanted (D.Reasm), PL), Free_Space (D.Reasm));
               begin
                  if Take > 0 then
                     Append (D.Reasm, Plaintext (0 .. Take - 1));
                  end if;

                  --  Finished is the last message of the client's flight;
                  --  anything after it in the same record is unexpected.
                  if Take /= PL then
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                     return;
                  end if;
               end;

               if Header_Ready (D.Reasm) then
                  if Declared_Type (D.Reasm) /= HT_Finished then
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                     return;
                  end if;
                  if Declared_Size (D.Reasm) /= Finished_12_Total_Len then
                     Send_Alert_And_Error (S, Certificate_Verify_Failed, Result);
                     return;
                  end if;
               end if;

               if not Has_Message (D.Reasm) then
                  Result := (if Input_Available (S) > 0 then OK else Need_Input);
                  return;
               end if;

               declare
                  Full : constant Message_Bytes := Message (D.Reasm);
               begin
                  if Full'Length > N32 (Plaintext'Length) then
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;

                  Plaintext (0 .. Full'Length - 1) := Byte_Seq (Full);
                  PL := Full'Length;
                  Reset (D.Reasm);
               end;
            elsif PL >= 4 then
               if Plaintext (0) = HT_Finished
                 and then Plaintext (1) = 0
                 and then Plaintext (2) = 0
                 and then Plaintext (3) = Byte (Finished_Verify_Len)
                 and then Finished_12_Total_Len > PL
               then
                  Reset (D.Reasm);
                  Append (D.Reasm, Plaintext (0 .. PL - 1));
                  Result := (if Input_Available (S) > 0 then OK else Need_Input);
                  return;
               end if;
            end if;

            if PL < 4 then
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;

            declare
               Msg_Type : constant Byte := Plaintext (0);
            begin
               if Msg_Type /= HT_Finished then
                  Send_Alert_And_Error (S, Unexpected_Message, Result);
                  return;
               end if;
               if Plaintext (1) /= 0
                 or else Plaintext (2) /= 0
                 or else Plaintext (3) /= Byte (Finished_Verify_Len)
               then
                  --  Finished length mismatch RFC 8446 6.2:
                  --  decrypt_error (alert 51). BoGo
                  --  TrailingMessageData-ClientFinished expects this
                  --  rather than decode_error.
                  Send_Alert_And_Error (S, Certificate_Verify_Failed, Result);
                  return;
               end if;
               --  RFC 5246 7.4.9: Finished is the last handshake
               --  message in the client's flight. Any bytes in the same
               --  record beyond `4 + Finished_Verify_Len` are excess
               --  data and therefore fatal unexpected_message. In the
               --  abbreviated resume flow, the server has already sent
               --  CCS+Finished, so the alert must use the encrypted
               --  write epoch. In the full flow, the server has not sent
               --  CCS yet, so the alert remains plaintext.
               if PL /= 4 + Finished_Verify_Len then
                  if S.HC.T12.Resuming then
                     Send_Encrypted_Alert_12 (S, Unexpected_Message, Result);
                  else
                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  end if;
                  return;
               end if;

               declare
                  Exp : Verify_Data_12;
                  TH  : Digest;
                  TH4 : SPARKNaCl.Hashing.SHA384.Digest;
               begin
                  if Use_384 then
                     SPARKTLS_Transcript.Current_384 (S.HC.TS, TH4);
                     Prove_Client_Finished_Label;
                     pragma Assert (Valid_Finished_Label (Label_Client_Finished));
                     pragma Assert (TH4'Length = 48);
                     declare
                        TH_Bytes : constant Byte_Seq (0 .. 47) := Byte_Seq (TH4);
                     begin
                        pragma Assert (TH_Bytes'First = 0);
                        pragma Assert (TH_Bytes'Last = 47);
                        pragma Assert (TH_Bytes'Length = 48);
                        pragma Assert (TH_Bytes'Length = 32 or else TH_Bytes'Length = 48);
                        Compute_Finished_12
                          (Exp, S.HC.Master_Secret_12, Label_Client_Finished, TH_Bytes, True);
                     end;
                  else
                     SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
                     Prove_Client_Finished_Label;
                     pragma Assert (Valid_Finished_Label (Label_Client_Finished));
                     pragma Assert (TH'Length = 32);
                     declare
                        TH_Bytes : constant Byte_Seq (0 .. 31) := Byte_Seq (TH);
                     begin
                        pragma Assert (TH_Bytes'First = 0);
                        pragma Assert (TH_Bytes'Last = 31);
                        pragma Assert (TH_Bytes'Length = 32);
                        pragma Assert (TH_Bytes'Length = 32 or else TH_Bytes'Length = 48);
                        Compute_Finished_12
                          (Exp, S.HC.Master_Secret_12, Label_Client_Finished, TH_Bytes, False);
                     end;
                  end if;

                  --  Constant-time comparison (prevents timing attacks
                  --  on the verify_data). SPARKNaCl.Equal uses XOR
                  --  accumulation  no early exit on mismatch.
                  declare
                     Received : constant Key_Schedule_12.Verify_Data_12 :=
                       Key_Schedule_12.Verify_Data_12
                         (Plaintext (4 .. 4 + Finished_Verify_Len - 1));
                  begin
                     if not Equal (Byte_Seq (Received), Byte_Seq (Exp)) then
                        --  RFC 5246 7.4.9 / 7.2.1: Finished verify
                        --  mismatch â fatal alert. Server WRITE state
                        --  is still plaintext (no CCS sent yet) so the
                        --  alert MUST be plaintext, not encrypted.
                        Send_Alert_And_Error (S, Handshake_Failure, Result);
                        return;
                     end if;
                  end;
               end;

               Append_Transcript (S.HC, Plaintext (0 .. PL - 1));
            end;
         end;
      end;

      --  Atomic flight assembly: build [NST?] + CCS + encrypted Finished
      --  into a scratch buffer; commit only if the whole flight fits in
      --  S.Output. The Finished encryption advances S.Server_App.Counter, so
      --  we save it and roll back on commit failure to keep AEAD nonces
      --  in sync with what the peer actually sees.
      --
      --  NST goes BEFORE CCS (RFC 5077 3.3): server's WRITE state is
      --  still plaintext until CCS, so NST is a plaintext handshake
      --  record (content type 22). NST is appended to the transcript
      --  before the server's Finished hash is computed (RFC 5077 3.5).
      --
      --  SKIPPED in the resumed (abbreviated) handshake: the server
      --  already sent SH+NST+CCS+Finished before the client's
      --  Finished. RFC 5077 3.3  the abbreviated flight inverts
      --  the order so this code path must NOT re-emit.
      if not S.HC.T12.Resuming then
         declare
            Scratch : IO_Buffer;
            CCS_Out : N32;
            EO      : N32;
            FB      : Byte_Seq (0 .. Finished_12_Total_Len - 1);
            FL      : N32;
            TH      : Digest;
            TH4     : SPARKNaCl.Hashing.SHA384.Digest;

            subtype Commit_Length is Buffer_Size range 1 .. IO_Buffer_Capacity;
            Len : constant Commit_Length := Scratch.Write_Pos;
         begin
            --  RFC 5077 3.3 NewSessionTicket (full handshake): issued iff
            --  the client offered the session_ticket extension AND we have
            --  configured ticket-encryption keys. Resumed-flight NSTs (the
            --  abbreviated case) are emitted from a different code path.
            if S.HC.T12.Ticket_Offered
              and then S.HC.Cfg.Get_Active_TEK
                       /= null
                          --  Fail closed without a clock: Created_At would be 0 and the
                          --  decrypt-side age check would pass forever, so the ticket
                          --  would never expire. Issue none instead.
              and then S.HC.Cfg.Get_Time /= null
            then
               declare
                  use type SPARKTLS.Tickets_12.Bytes_4;
                  --  Sealing key supplied by the caller's store.
                  Key_ID_Buf  : Byte_Seq (0 .. 3) := (others => 0);
                  TEK_Buf     : Byte_Seq (0 .. 31) := (others => 0);
                  Have_TEK    : Boolean := False;
                  Nonce_Buf   : Byte_Seq (0 .. 11);
                  Plain       : SPARKTLS.Tickets_12.Ticket_Plain;
                  Ticket_Buf  : Byte_Seq (0 .. 255);
                  Ticket_Len  : N32;
                  NST_Buf     : Byte_Seq (0 .. 271);
                  NST_Total   : N32;
                  NST_Rec_Out : N32;
               begin
                  S.HC.Cfg.Get_Active_TEK.all (Key_ID_Buf, TEK_Buf, Have_TEK);
                  S.HC.Cfg.Random.all (Nonce_Buf);

                  --  Ticket plaintext = master_secret + suite + creation
                  --  time + sid_len=0 (we don't encode the SID in the
                  --  encrypted state; clients echo their own SID on
                  --  resumption attempts). Created_At drives the
                  --  expiry check on the decrypt side; without
                  --  Cfg.Get_Time we encode 0 and Decrypt_Ticket skips
                  --  the age window check (acceptable for dev / test).
                  Plain.Master_Secret := S.HC.Master_Secret_12;
                  Plain.Suite := Wire_Of (S.Negotiated_Suite);
                  Plain.Created_At :=
                    (if S.HC.Cfg.Get_Time /= null
                     then SPARKTLS.Tickets_12.To_Unix_Seconds (S.HC.Cfg.Get_Time.all)
                     else 0);
                  Plain.SID_Len := 0;
                  Plain.SID := (others => 0);

                  SPARKTLS.Tickets_12.Encrypt_Ticket
                    (Plain      => Plain,
                     Key_ID     => SPARKTLS.Tickets_12.Bytes_4 (Key_ID_Buf),
                     TEK        => SPARKTLS.Tickets_12.Bytes_32 (TEK_Buf),
                     Nonce      => SPARKTLS.Tickets_12.Bytes_12 (Nonce_Buf),
                     Ticket     => Ticket_Buf,
                     Ticket_Len => Ticket_Len);

                  --  Build NewSessionTicket handshake message via RFLX.
                  SPARKTLS.Handshake.TLS12.Build_New_Session_Ticket_12
                    (Lifetime_Hint => S.HC.Cfg.TLS12_Ticket_Lifetime,
                     Ticket        => Ticket_Buf (0 .. Ticket_Len - 1),
                     Result        => NST_Buf,
                     Len           => NST_Total);
                  if NST_Total = 0 then
                     S.Last_Error := Insufficient_Buffer;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                     return;
                  end if;
                  pragma Assert (NST_Total > 0);
                  pragma Assert (NST_Total - 1 <= NST_Buf'Last);

                  declare
                     NST_Last : constant N32 := NST_Total - 1;
                     NST_Data : Byte_Seq renames NST_Buf (0 .. NST_Last);
                  begin
                     pragma Assert (NST_Data'Length > 0);

                     --  Append to transcript BEFORE server Finished hash.
                     Append_Transcript (S.HC, NST_Data);

                     --  Emit as plaintext handshake record (server WRITE
                     --  state still pre-CCS).
                     Records.Build_Handshake_Record (NST_Data, Scratch, NST_Rec_Out);
                     if NST_Rec_Out = 0 then
                        S.Last_Error := Insufficient_Buffer;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
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
               return;
            end if;

            if Use_384 then
               SPARKTLS_Transcript.Current_384 (S.HC.TS, TH4);
               Prove_Server_Finished_Label;
               pragma Assert (Valid_Finished_Label (Label_Server_Finished));
               pragma Assert (TH4'Length = 48);
               declare
                  TH_Bytes : constant Byte_Seq (0 .. 47) := Byte_Seq (TH4);
               begin
                  pragma Assert (TH_Bytes'First = 0);
                  pragma Assert (TH_Bytes'Last = 47);
                  pragma Assert (TH_Bytes'Length = 48);
                  pragma Assert (TH_Bytes'Length = 32 or else TH_Bytes'Length = 48);
                  Build_Finished_12
                    (S.HC.Master_Secret_12, Label_Server_Finished, TH_Bytes, True, FB, FL);
               end;
            else
               SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
               Prove_Server_Finished_Label;
               pragma Assert (Valid_Finished_Label (Label_Server_Finished));
               pragma Assert (TH'Length = 32);
               declare
                  TH_Bytes : constant Byte_Seq (0 .. 31) := Byte_Seq (TH);
               begin
                  pragma Assert (TH_Bytes'First = 0);
                  pragma Assert (TH_Bytes'Last = 31);
                  pragma Assert (TH_Bytes'Length = 32);
                  pragma Assert (TH_Bytes'Length = 32 or else TH_Bytes'Length = 48);
                  Build_Finished_12
                    (S.HC.Master_Secret_12, Label_Server_Finished, TH_Bytes, False, FB, FL);
               end;
            end if;

            pragma Assert (FL = Finished_12_Total_Len);
            pragma Assert (FB'First = 0);
            pragma Assert (FB'Last = Finished_12_Total_Len - 1);
            pragma Assert (S.HC.Server_Write_IV_12'First = 0);
            pragma Assert (S.HC.Server_Write_IV_12'Last = 11);
            pragma Assert (S.HC.Server_Write_IV_12'Length = Records.TLS12.Implicit_IV_Len);

            Build_Encrypted_Record_12
              (FB (0 .. FL - 1), 16#16#, S.Server_App, S.HC.Server_Write_IV_12, Scratch, EO);

            if EO = 0 then
               --  Fatal path: no rewind, the burned nonce stays
               --  burned and the connection dies here.
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            --  Atomic commit
            if Free_Space (S.Output) < Scratch.Write_Pos then
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            declare
               New_Write_Pos : constant Buffer_Size := S.Output.Write_Pos + Len;
            begin
               S.Output.Data (S.Output.Write_Pos .. New_Write_Pos - 1) :=
                  Scratch.Data (0 .. Len - 1);
               S.Output.Write_Pos := New_Write_Pos;
            end;
         end;
      end if;  --  end "if not S.HC.T12.Resuming"

      --  Copy TLS 1.2 state to Session
      S.Client_IV_12 := S.HC.Client_Write_IV_12;
      S.Server_IV_12 := S.HC.Server_Write_IV_12;
      --  Counters live inside S.Client_App / S.Server_App: no mirror.

      Set_State (S, Connected);
      S.Handshake_Just_Done := True;
      Result := (if Output_Pending (S) > 0 then Has_Output else Handshake_Done);
      if Result = Handshake_Done then
         S.Handshake_Just_Done := False;
      end if;
   end Process_Client_Finished_12;

   ------------------------------------------------------------------
   procedure Advance_Handshake_12
     (S      : in out Server_Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Result : out Action) is
   begin
      case S.State is
         when Server_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               if S.HC.Cfg.Request_Client_Cert then
                  Set_State (S, Wait_Client_Certificate);
               else
                  --  Process_Client_Finished_12 first consumes the
                  --  ClientKeyExchange and CCS before the Finished.
                  Set_State (S, Wait_Client_Finished);
               end if;
               Result := (if Input_Available (S) > 0 then OK else Need_Input);
            end if;

         when Wait_Client_Certificate | Wait_Client_Cert_Verify =>
            if S.State = Wait_Client_Certificate then
               Process_Client_Certificate_12 (S, D, Result);
            elsif not S.HC.CKE_Received_12 then
               Process_Client_Key_Exchange_12 (S, D, Result);
            else
               Process_Client_CertVerify_12 (S, D, Result);
            end if;

         when Wait_Client_Finished =>
            if not S.HC.CKE_Received_12 then
               Process_Client_Key_Exchange_12 (S, D, Result);
            elsif not S.HC.CCS_Received then
               --  The CKE handler also accepts the following CCS record.
               Process_Client_Key_Exchange_12 (S, D, Result);
            else
               Process_Client_Finished_12 (S, D, Result);
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake_12;

   procedure Process_Connected_12 (S : in out Session; Result : out Action) is
      use SPARKTLS.Records.TLS12;
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

      --  RFC 5246 7.2.1 / 7.2.2: post-Finished alerts MUST be
      --  encrypted under the app keys; a plaintext alert lands as a
      --  bad record type on the peer (same root cause as the 2.8
      --  TLS 1.3 mTLS bypass).
      if Rec.Overflow then
         Send_Encrypted_Alert_Connected_12 (S, Record_Overflow, Result);
         return;
      end if;
      if Rec.Bad_Version then
         Send_Encrypted_Alert_Connected_12 (S, Protocol_Version, Result);
         return;
      end if;
      if not Rec.OK then
         if Rec.Record_Len > 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      pragma Assert (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);

      --  TLS 1.2: CCS in Connected is ignored
      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      --  RFC 5246 7.4.1.2 / RFC 5746: a TLS 1.2 server MAY refuse
      --  client-initiated renegotiation. A Handshake record in the
      --  Connected state is a renegotiation attempt  reply with a
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
               Output      => S.Output,
               Bytes_Out   => A);
            pragma Assert (A <= N32 (S.Output.Data'Length));
         end;
         Result := (if Output_Pending (S) > 0 then Has_Output else OK);
         return;
      end if;

      --  Only app_data and alert are valid encrypted record types
      if Rec.Content not in Records.Content_Application_Data | Records.Content_Alert then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert_Connected_12 (S, Record_Overflow, Result);
            return;
         end if;

         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);

         declare
            Encrypted : Byte_Seq (0 .. Frag_Len - 1);
            Hdr       : Byte_Seq (0 .. 4);
            Plaintext : Byte_Seq (0 .. Frag_Len - 1);
            PL        : N32;
            DV        : Boolean;
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
                 (if S.Client_App.Suite = Suite_CHACHA20_POLY1305_SHA256 then GCM_Tag_Len
                  else Explicit_Nonce_Len + GCM_Tag_Len);
            begin
               if Frag_Len < Min_Frag then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
                  return;
               end if;
            end;

            --  The old `= Unsigned_64'Last` pre-guard is gone: it was dead
            --  by type (Record_Counter tops out one below), the #46
            --  off-by-one. Counter exhaustion now fails closed INSIDE
            --  Decrypt_Record_12, once, as Valid = False.
            Decrypt_Record_12 (Encrypted, Hdr, S.Client_App, S.Client_IV_12, Plaintext, PL, DV);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if not DV then
               Send_Encrypted_Alert_Connected_12 (S, Bad_Record_MAC, Result);
               return;
            end if;

            case Rec.Content is
               when Records.Content_Application_Data =>
                  if S.State = Closing and then PL > 0 then
                     Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
                  elsif PL > 0
                    and then S.App_Data_Len <= S.App_Data'Length
                    and then PL <= S.App_Data'Length - S.App_Data_Len
                  then
                     S.App_Data (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                       Plaintext (0 .. PL - 1);
                     S.App_Data_Len := S.App_Data_Len + PL;
                     S.Empty_Records_Recvd := 0;
                     Result := Plaintext_Ready;
                  else
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Empty_Records_Recvd >= Max_Empty_Records then
                        S.Last_Error := Unexpected_Message;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        S.Empty_Records_Recvd := S.Empty_Records_Recvd + 1;
                        Result := OK;
                     end if;
                  end if;

               when Records.Content_Alert =>
                  if PL >= 2 and then Plaintext (1) = 0 then
                     --  RFC 8446 6.1: record the orderly close, so the
                     --  application can distinguish a finished stream
                     --  from a truncated one, and so the Closing branch
                     --  knows both directions are shut.
                     S.Peer_Closed_Cleanly := True;
                     --  close_notify received  RFC 5246 7.2.1 (and
                     --  RFC 8446 6.1) require a close_notify reply at
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
                  --  RFC 5246 6 / RFC 8446 5.1: an unrecognised record
                  --  content type is unexpected_message, not something to
                  --  skip. Silently returning OK let a peer feed us
                  --  records we neither processed nor rejected.
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
            end case;
         end;
      end;
   end Process_Connected_12;

end SPARKTLS.Server.TLS12;
