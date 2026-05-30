with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;               use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HKDF;              use SPARKTLSCrypto.HKDF;

with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Client_Msgs;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
use SPARKTLSCrypto;
with SPARKTLS.HC_Alloc;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Client.TLS12;

with X509;

package body SPARKTLS.Client with
   SPARK_Mode => On
is
   --  Send a fatal alert encrypted under the client_handshake_
   --  traffic_secret, then transition to Error_State. Prepends the
   --  legacy CCS record (RFC 8446 §D.4 / "middlebox-compat") because
   --  BoGo's runner parses any plaintext-looking record from the
   --  client as a CCS and rejects subsequent traffic if it wasn't.
   --  Used by every TLS 1.3 client reject path that fires AFTER
   --  HC.Client_HS is derived (i.e. anything after we receive the
   --  ServerHello). The legacy CCS we emit here is the ONLY one
   --  the client sends in a TLS 1.3 connection, so duplicate-CCS
   --  rules in the peer are not violated.
   procedure Send_HS_Encrypted_Alert
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Err    : Error_Code;
      Result :    out Action)
   with Pre  => Nonce_Space_Available (HC.Client_HS)
                and S.State not in Idle | Closing | Closed | Error_State,
        Post => S.State = Error_State
                --  Frame: post-handshake app key is not touched (only
                --  the handshake-secret key is used to encrypt the
                --  alert). Pin so callers can preserve
                --  Nonce_Space_Available (S.Client_App).
                and S.Client_App = S.Client_App'Old
   is
      A1, A2 : N32;
   begin
      Records.Build_CCS_Record (S.Output, A1);
      Records.Build_Alert_Record
        (Level     => 2,
         Desc      => Alert_Desc (Err),
         Keys      => HC.Client_HS,
         Output    => S.Output,
         Bytes_Out => A2);
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Result := (if Output_Pending (S) > 0
                 then Has_Output else Error_Alert);
   end Send_HS_Encrypted_Alert;

   --  Send a fatal alert encrypted under the client_application_
   --  traffic_secret. Used on every TLS 1.3 client reject path that
   --  fires AFTER the handshake completes (post-handshake messages,
   --  AEAD-failure on app records, bogus peer alerts). No CCS prefix
   --  — the legacy middlebox-compat CCS was already emitted as part
   --  of the client flight, and a duplicate would be a protocol
   --  violation per RFC 8446 §D.4.
   procedure Send_App_Encrypted_Alert
     (S      : in out Session;
      Err    : Error_Code;
      Result :    out Action)
   with Pre  => Nonce_Space_Available (S.Client_App)
                and S.State not in Idle | Closing | Closed | Error_State,
        Post => S.State = Error_State
   is
      A : N32;
   begin
      Records.Build_Alert_Record
        (Level     => 2,
         Desc      => Alert_Desc (Err),
         Keys      => S.Client_App,
         Output    => S.Output,
         Bytes_Out => A);
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Result := (if Output_Pending (S) > 0
                 then Has_Output else Error_Alert);
   end Send_App_Encrypted_Alert;

   --  Forward declarations for internal procedures
   procedure Derive_Handshake_Keys
     (S  : in     Session;
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256;

   --  RFC 8446 §4.3.1 / RFC 7301: scan a TLS 1.3 EncryptedExtensions
   --  message for an application_layer_protocol_negotiation entry.
   --  On a well-formed entry, copy the protocol name into
   --  S.Negotiated_ALPN. On a malformed entry (empty protocol_name,
   --  list-length mismatch, truncated bytes), set OK=False so the
   --  caller can send an illegal_parameter alert. Absent ALPN ext
   --  is fine (OK=True, S.Negotiated_ALPN unchanged).
   --
   --  EE wire shape: HS_hdr(4) + ext_total_len(2) + extensions
   --  Each extension: tag(2) + len(2) + body(len)
   --  ALPN body: list_len(2) + (proto_len(1) + name)*
   procedure Extract_ALPN_From_EE
     (Data : in     Byte_Seq;
      HC   : in     Handshake_Context;
      S    : in out Session;
      OK   :    out Boolean;
      Err  :    out Error_Code)
   with Pre  => Data'Length >= 4
                and Data'Last < N32'Last
                and Data'First >= 0,
        Post => S.State = S.State'Old;
   --  OK = False signals a fatal protocol error. `Err` discriminates
   --  the alert kind so the caller picks the right alert code:
   --    Unsupported_Extension : server sent an EE extension we did
   --                            not offer in CH.
   --    Illegal_Parameter     : ALPN body malformed / doesn't match
   --                            offered protocol (RFC 7301 §3.2).
   procedure Send_Client_Certificate
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Scratch : in out IO_Buffer;
      Result  :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and Nonce_Space_Available (HC.Client_HS)
               and HC.Transcript_Len > 0;
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and Nonce_Space_Available (HC.Client_HS)
               and HC.Transcript_Len > 0
               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256;
   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Data'First = 0
                and Data'Length >= 4
                and Data'Last < N32'Last - 4
                and Data'Length <= Transcript_Capacity
                and Nonce_Space_Available (HC.Client_HS),
        --  State-sane exit ⇒ handshake-secret key is unchanged (no
        --  alert was sent, which is the only path that touches it)
        --  AND app key still has nonce headroom (it's either untouched
        --  or freshly installed by Derive_App_Keys_And_Send_Finished
        --  with Counter = 0).
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and Nonce_Space_Available (S.Client_App));
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App);
   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App);
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App)
               and then Plaintext'First = 0
               and then Plain_Len >= 0
               and then Plaintext'Last < N32'Last / 2
               and then Plain_Len <= N32 (Plaintext'Length)
               and then (HC.Reasm_Buf = null
                         or else (HC.Reasm_Buf'First = 0
                                  and then HC.Reasm_Buf'Last in 0 .. 131071
                                  and then HC.Reasm_Len
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then HC.Reasm_Need
                                     <= N32 (HC.Reasm_Buf'Length)));


   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App);
   procedure Handle_Connected_App_Record
     (S      : in out Session;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App);
   procedure Set_Traffic_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16)
   with Pre => Suite in Suite_AES_128_GCM_SHA256
                      | Suite_AES_256_GCM_SHA384
                      | Suite_CHACHA20_POLY1305_SHA256;

   --  Advance the handshake state machine (operates on dereferenced HC).
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);
   procedure Handle_WSH_Frame_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello;
   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello
               and then Reasm_Coherent (HC);
   procedure Parse_SH_From_Reasm_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello
               and then HC.Reasm_Buf /= null
               and then HC.Reasm_Need > 0
               and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length);
   procedure Finalize_SH_Processing
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello;
   procedure Reassemble_For_SH
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello
               and then Reasm_Coherent (HC);
   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Rec        : in     Records.Parse_Result;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Max_HS_Msg : in     N32;
      Result     :    out Action)
   with Pre => S.State = Wait_Server_Hello
               and then Reasm_Coherent (HC)
               and then Frag_Len >= 0
               and then Frag_Start >= 0
               and then Max_HS_Msg = 131072;







   --  Append handshake message bytes to the transcript.
   --  RFC 5246 §7.4.9 / RFC 8446 §4.4.1: the transcript drives
   --  Finished verify_data, so it is append-only — losing bytes
   --  desyncs from the peer.
   procedure Append_Transcript
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq)
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

   --================================================================
   --  Extract_ALPN_From_EE — see forward decl above for contract.
   --
   --  All offsets are computed against P, kept invariant by the
   --  outer guard `P + 4 <= Ext_End and P + 4 + E_Len <= Ext_End`
   --  before the inner read. Ext_End is the absolute index just
   --  past the last extension byte; computed once from the 2-byte
   --  ext_total_len read at fixed offset Body+0..1.
   --================================================================
   procedure Extract_ALPN_From_EE
     (Data : in     Byte_Seq;
      HC   : in     Handshake_Context;
      S    : in out Session;
      OK   :    out Boolean;
      Err  :    out Error_Code)
   is
      ALPN_Tag : constant N32 := 16#0010#;
      Body_Start : constant N32 := Data'First + 4;
   begin
      OK  := True;
      Err := Illegal_Parameter;  --  default for ALPN-shape failures

      --  Need at least HS hdr + 2-byte ext_total_len = 6 bytes.
      if N32 (Data'Length) < 6 then
         return;
      end if;

      declare
         Ext_Total : constant N32 :=
            N32 (Data (Body_Start)) * 256
            + N32 (Data (Body_Start + 1));
         Ext_End : constant N32 := Body_Start + 2 + Ext_Total;
         P : N32 := Body_Start + 2;
      begin
         --  Bound: extensions fit within the EE message.
         if Ext_End > Data'Last + 1 then
            return;
         end if;

         --  RFC 8446 §4.2 priority: structural checks (duplicates)
         --  take precedence over semantic checks (matrix policy).
         --  BoGo DuplicateExtensionClient-* expects decode_error
         --  even when the duplicated tag is also not in
         --  Allowed_EE. We must therefore detect ALL duplicates
         --  before running ANY policy validation — single-pass
         --  merging would short-circuit on the first instance with
         --  unsupported_extension before its duplicate is reached.
         declare
            subtype Seen_Range is N32 range 1 .. 32;
            Seen_Tags  : array (Seen_Range) of N32 := (others => 0);
            Seen_Count : N32 := 0;
            Q          : N32 := P;
         begin
            while Q + 4 <= Ext_End loop
               pragma Loop_Invariant
                 (Q >= Body_Start + 2
                  and Q + 4 <= Ext_End
                  and Ext_End <= Data'Last + 1
                  and Seen_Count <= 32);
               declare
                  T : constant N32 :=
                     N32 (Data (Q)) * 256 + N32 (Data (Q + 1));
                  L : constant N32 :=
                     N32 (Data (Q + 2)) * 256 + N32 (Data (Q + 3));
               begin
                  exit when Q + 4 + L > Ext_End;
                  for I in N32 range 1 .. Seen_Count loop
                     pragma Loop_Invariant (Seen_Count <= 32);
                     if Seen_Tags (I) = T then
                        OK  := False;
                        Err := Decode_Error;
                        return;
                     end if;
                  end loop;
                  if Seen_Count < 32 then
                     Seen_Count := Seen_Count + 1;
                     Seen_Tags (Seen_Count) := T;
                  end if;
                  Q := Q + 4 + L;
               end;
            end loop;
         end;

         while P + 4 <= Ext_End loop
            pragma Loop_Invariant
              (P >= Body_Start + 2
               and P + 4 <= Ext_End
               and Ext_End <= Data'Last + 1);
            declare
               Tag : constant N32 :=
                  N32 (Data (P)) * 256 + N32 (Data (P + 1));
               E_Len : constant N32 :=
                  N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
            begin
               --  Skip if extension overflows what's left.
               exit when P + 4 + E_Len > Ext_End;

               --  RFC 8446 §4.2 matrix policy: rejects extensions
               --  not allowed in EE, ones we didn't offer in CH, and
               --  ones with non-empty body where RFC mandates empty
               --  (RFC 6066 §3 server_name ack). BoGo
               --  UnknownExtension-Client-TLS13,
               --  UnofferedExtension-Client-TLS13,
               --  EncryptedExtensionsWithKeyShare-TLS13,
               --  UnsolicitedServerNameAck-TLS13,
               --  ExtensionTrailingData-ServerName-Client-TLS13.
               declare
                  V_OK  : Boolean;
                  V_Err : Error_Code;
               begin
                  Validate_Server_Ext
                    (Where    => E_EE,
                     Tag      => Unsigned_16 (Tag),
                     Body_Len => E_Len,
                     HC       => HC,
                     OK       => V_OK,
                     Err      => V_Err);
                  if not V_OK then
                     OK  := False;
                     Err := V_Err;
                     return;
                  end if;
               end;

               if Tag = ALPN_Tag then
                  declare
                     A_OK  : Boolean;
                     A_Err : Error_Code;
                  begin
                     Validate_ALPN_Echo_Body
                       (Data       => Data,
                        Body_Start => P + 4,
                        E_Len      => E_Len,
                        HC         => HC,
                        S          => S,
                        OK         => A_OK,
                        Err        => A_Err);
                     if not A_OK then
                        OK  := False;
                        Err := A_Err;
                        return;
                     end if;
                  end;
               end if;

               P := P + 4 + E_Len;
            end;
         end loop;
      end;
   end Extract_ALPN_From_EE;

   procedure Configure
     (S                    : out Session;
      Hostname             : String;
      Trust                : Trust_Store_Access;
      Random               : Random_Bytes_Fn;
      Clock                : Get_Time_Fn;
      Local                : Identity_Access := null;
      Mode                 : Validation_Mode := Mode_WebPKI;
      ALPN                 : String := "";
      Versions             : Version_Policy := Allow_Both;
      Resume               : Session_Ticket := (others => <>);
      Skip_Verify          : Boolean := False;
      Skip_Hostname_Verify : Boolean := False)
   is
      Cfg : Config;
   begin
      Cfg.Random      := Random;
      Cfg.Trust       := Trust;
      Cfg.Local       := Local;
      --  Skip_Verify defaults to True when no trust store is given
      --  (otherwise the handshake would fail with a confusing
      --  "missing trust store" rather than the intended "validation
      --  off"). An explicit Skip_Verify=True overrides both cases.
      Cfg.Skip_Verify := Trust = null or Skip_Verify;
      Cfg.Skip_Hostname_Verify := Skip_Hostname_Verify;
      Cfg.Get_Time    := Clock;
      Cfg.Verify_Mode := Mode;
      Cfg.Versions    := Versions;
      Cfg.Resume_Ticket := Resume;
      if Hostname'Length > 0
         and then Hostname'Length <= Max_Hostname_Len
      then
         Cfg.Server_Name.Data (1 .. Hostname'Length) := Hostname;
         Cfg.Server_Name.Len := Hostname'Length;
      end if;
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

      --  RFC 8446 §4.6.1: if the caller passed a previously-saved
      --  resumption ticket via Cfg, copy it into S.Ticket before
      --  Build_Client_Hello so the CH carries the pre_shared_key
      --  extension and the binder is computed from the ticket's PSK.
      if Cfg.Resume_Ticket.Valid
        and then Cfg.Resume_Ticket.PSK_Len > 0
        and then Cfg.Resume_Ticket.Ticket_Len > 0
      then
         S.Ticket := Cfg.Resume_Ticket;
      end if;

      Handshake.Client_Msgs.Build_Client_Hello (S, S.HC_Ptr.all, CH_Buf, CH_Len);

      if CH_Len = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         HC_Alloc.Free (S.HC_Ptr);
         return;
      end if;

      Append_Transcript (S.HC_Ptr.all, CH_Buf (0 .. CH_Len - 1));

      --  RFC 8446 §5.1: initial ClientHello uses record version 0x0301
      --  (TLS 1.0) for middlebox compatibility, even though the actual
      --  protocol is negotiated via supported_versions.
      Records.Build_Initial_ClientHello_Record
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
   --  RFC 8446 §4.3.1 client-side EncryptedExtensions handler.
   --  Body shape check (≥ 2-byte ext-len prefix), ALPN extraction
   --  per RFC 7301, transition to Wait_Server_Finished (PSK path)
   --  or Wait_Certificate (full handshake).
   procedure Handle_EE_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                and then Data'Length <= Transcript_Capacity
                and then Nonce_Space_Available (HC.Client_HS),
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and S.Client_App = S.Client_App'Old);

   procedure Handle_EE_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
   begin
      Result := OK;
      --  Defense-in-depth: EE only legal in Wait_Encrypted_Extensions.
      if S.State /= Wait_Encrypted_Extensions then
         Send_HS_Encrypted_Alert (S, HC, Unexpected_Message, Result);
         return;
      end if;
      if N32 (Data'Length) < 6 then
         Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
         return;
      end if;
      declare
         Ext_Tot_Decl : constant N32 :=
            N32 (Data (Data'First + 4)) * 256
            + N32 (Data (Data'First + 5));
         Expected_Body : constant N32 := 2 + Ext_Tot_Decl;
      begin
         if N32 (Data'Length) - 4 /= Expected_Body then
            Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
            return;
         end if;
      end;
      Append_Transcript (HC, Data);

      declare
         ALPN_OK  : Boolean;
         ALPN_Err : Error_Code;
      begin
         Extract_ALPN_From_EE (Data, HC, S, ALPN_OK, ALPN_Err);
         if not ALPN_OK then
            Send_HS_Encrypted_Alert (S, HC, ALPN_Err, Result);
            return;
         end if;
      end;

      if HC.Using_PSK then
         Set_State (S, Wait_Server_Finished);
      else
         Set_State (S, Wait_Certificate);
      end if;
   end Handle_EE_13;

   --  RFC 8446 §4.3.2 client-side CertificateRequest handler. Body
   --  length-validation (ctx_len(1) + ctx + ext_len(2) + extensions),
   --  per-RFC-§4.2 extension-policy gating, signature_algorithms
   --  required, picks a compatible HC.Negotiated_Sig_Algo.
   procedure Handle_CertReq_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                and then Data'Length <= Transcript_Capacity
                and then Nonce_Space_Available (HC.Client_HS),
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and S.Client_App = S.Client_App'Old);

   procedure Handle_CertReq_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
   begin
      Result := OK;
      if HC.Using_PSK then
         Send_HS_Encrypted_Alert (S, HC, Unexpected_Message, Result);
         return;
      end if;
      if Data'Length >= 7 then
         declare
            Ctx_Len_Decl : constant N32 := N32 (Data (Data'First + 4));
            Ext_Off_Decl : constant N32 :=
               Data'First + 5 + Ctx_Len_Decl;
            Body_OK : Boolean := False;
         begin
            if Ctx_Len_Decl /= 0 then
               Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
               return;
            end if;
            if Ext_Off_Decl + 1 <= Data'Last then
               declare
                  Ext_Tot : constant N32 :=
                     N32 (Data (Ext_Off_Decl)) * 256
                     + N32 (Data (Ext_Off_Decl + 1));
                  Expected : constant N32 :=
                     1 + Ctx_Len_Decl + 2 + Ext_Tot;
               begin
                  Body_OK := N32 (Data'Length) - 4 = Expected;
               end;
            end if;
            if not Body_OK then
               Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      Append_Transcript (HC, Data);
      HC.Cert_Request_Received := True;
      declare
         Picked     : Unsigned_16 := 0;
         Sig_Found  : Boolean := False;
      begin
         if Data'Length >= 7 then
            declare
               Ctx_Len  : constant N32 := N32 (Data (Data'First + 4));
               Ext_Off  : constant N32 := Data'First + 5 + Ctx_Len;
            begin
               if Ext_Off + 1 <= Data'Last then
                  declare
                     Ext_Tot : constant N32 :=
                        N32 (Data (Ext_Off)) * 256
                        + N32 (Data (Ext_Off + 1));
                     Ext_End : constant N32 := Ext_Off + 2 + Ext_Tot;
                     P : N32 := Ext_Off + 2;
                  begin
                     if Ext_End <= Data'Last + 1 then
                        while P + 4 <= Ext_End loop
                           pragma Loop_Invariant
                             (P >= Ext_Off + 2
                              and P + 4 <= Ext_End
                              and Ext_End <= Data'Last + 1);
                           declare
                              Tag : constant N32 :=
                                 N32 (Data (P)) * 256
                                 + N32 (Data (P + 1));
                              E_Len : constant N32 :=
                                 N32 (Data (P + 2)) * 256
                                 + N32 (Data (P + 3));
                              V_OK  : Boolean;
                              V_Err : Error_Code;
                           begin
                              exit when P + 4 + E_Len > Ext_End;
                              Validate_Server_Ext
                                (Where    => E_CR,
                                 Tag      => Unsigned_16 (Tag),
                                 Body_Len => E_Len,
                                 HC       => HC,
                                 OK       => V_OK,
                                 Err      => V_Err);
                              if not V_OK then
                                 Send_HS_Encrypted_Alert
                                   (S, HC, V_Err, Result);
                                 return;
                              end if;
                              if Tag = 16#000D# and E_Len >= 4 then
                                 declare
                                    List_Len : constant N32 :=
                                       N32 (Data (P + 4)) * 256
                                       + N32 (Data (P + 5));
                                 begin
                                    if List_Len + 2 = E_Len
                                      and List_Len >= 2
                                    then
                                       Sig_Found := True;
                                       if HC.Cfg.Local /= null then
                                          Picked :=
                                            Handshake.Pick_Sig_Algo
                                              (Data (P + 6 ..
                                                     P + 5 + List_Len),
                                               HC.Cfg.Local.Sign_Algo);
                                       end if;
                                    end if;
                                 end;
                              elsif Tag = 16#002F# and E_Len >= 2 then
                                 declare
                                    Outer_Len : constant N32 :=
                                       N32 (Data (P + 4)) * 256
                                       + N32 (Data (P + 5));
                                    DN_P : N32 := P + 6;
                                    DN_End : constant N32 :=
                                       P + 6 + Outer_Len;
                                    Bad : Boolean := False;
                                 begin
                                    if 2 + Outer_Len /= E_Len
                                      or DN_End > Ext_End
                                      or Outer_Len = 0
                                    then
                                       Bad := True;
                                    else
                                       while not Bad
                                         and then DN_P < DN_End
                                       loop
                                          pragma Loop_Invariant
                                            (DN_P <= DN_End);
                                          pragma Loop_Variant
                                            (Increases => DN_P);
                                          if DN_P + 2 > DN_End then
                                             Bad := True;
                                          else
                                             declare
                                                DN_Len : constant N32 :=
                                                   N32 (Data (DN_P)) * 256
                                                   + N32 (Data (DN_P + 1));
                                             begin
                                                if DN_P + 2 + DN_Len
                                                    > DN_End
                                                  or DN_Len = 0
                                                then
                                                   Bad := True;
                                                else
                                                   DN_P := DN_P + 2 + DN_Len;
                                                end if;
                                             end;
                                          end if;
                                       end loop;
                                    end if;
                                    if Bad then
                                       Send_HS_Encrypted_Alert
                                         (S, HC, Decode_Error, Result);
                                       return;
                                    end if;
                                 end;
                              end if;
                              P := P + 4 + E_Len;
                           end;
                        end loop;
                     end if;
                  end;
               end if;
            end;
         end if;

         if not Sig_Found then
            Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
            return;
         end if;

         if HC.Cfg.Local /= null then
            HC.Negotiated_Sig_Algo := Picked;
         end if;
      end;
   end Handle_CertReq_13;

   --  RFC 8446 §4.4.2 client-side Certificate handler. Parses chain
   --  via Parse_Certificate_Chain_13, runs hostname binding (RFC 6125
   --  §6.4) and trust-chain validation, transitions to
   --  Wait_Certificate_Verify.
   procedure Handle_Cert_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                and then Data'Length <= Transcript_Capacity
                and then Nonce_Space_Available (HC.Client_HS),
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and S.Client_App = S.Client_App'Old);

   procedure Handle_Cert_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
   begin
      Result := OK;
      if HC.Using_PSK then
         Send_HS_Encrypted_Alert (S, HC, Unexpected_Message, Result);
         return;
      end if;
      if Data'Length >= 8 then
         declare
            Ctx_Len_D : constant N32 := N32 (Data (Data'First + 4));
            List_Off  : constant N32 := Data'First + 5 + Ctx_Len_D;
            Body_OK   : Boolean := False;
         begin
            if List_Off + 2 <= Data'Last then
               declare
                  List_Len_D : constant N32 :=
                     N32 (Data (List_Off)) * 65536
                     + N32 (Data (List_Off + 1)) * 256
                     + N32 (Data (List_Off + 2));
                  Expected : constant N32 :=
                     1 + Ctx_Len_D + 3 + List_Len_D;
               begin
                  Body_OK := N32 (Data'Length) - 4 = Expected;
               end;
            end if;
            if not Body_OK then
               Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      Append_Transcript (HC, Data);

      declare
         Parse_OK  : Boolean;
         Parse_Err : Error_Code;
      begin
         Handshake.Certs.Parse_Certificate_Chain_13
           (HC                     => HC,
            HS_Msg                 => Data,
            Reject_Cert_Extensions => True,
            OK                     => Parse_OK,
            Err                    => Parse_Err);
         if not Parse_OK then
            Send_HS_Encrypted_Alert (S, HC, Parse_Err, Result);
            return;
         end if;
      end;

      if HC.Cfg.Server_Name.Len > 0
        and then not HC.Cfg.Skip_Hostname_Verify
        and then HC.Peer_Cert_Valid
      then
         declare
            Cert_DER_Len_C : constant N32 := HC.Peer_Cert_DER_Len;
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (Cert_DER_Len_C) - 1) := (others => 0);
         begin
            for I in N32 range 0 .. Cert_DER_Len_C - 1 loop
               Cert_X (X509.N32 (I)) :=
                  X509.Byte (HC.Peer_Cert_DER (I));
            end loop;
            if not X509.Matches_Hostname
                    (HC.Peer_Cert, Cert_X,
                     HC.Cfg.Server_Name.Data
                       (1 .. HC.Cfg.Server_Name.Len))
            then
               Send_HS_Encrypted_Alert (S, HC, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;

      if not HC.Cfg.Skip_Verify
         and then HC.Cfg.Trust /= null
         and then HC.Cfg.Get_Time /= null
         and then HC.Peer_Cert_Valid
      then
         declare
            Cert_DER_Len_Const : constant N32 := HC.Peer_Cert_DER_Len;
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (Cert_DER_Len_Const) - 1) := (others => 0);
            VR : Validation_Result;
         begin
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
   end Handle_Cert_13;

   --  RFC 8446 §4.4.3 client-side CertificateVerify handler.
   --  Re-hashes the transcript (suite-dependent), verifies the
   --  signature over the canonical CV content, transitions to
   --  Wait_Server_Finished. Also enforces RFC 8446 §4.2.3 (no
   --  rsa_pkcs1_* in TLS 1.3) and RFC 8446 §4.4.2.2 (leaf
   --  keyUsage=digitalSignature).
   procedure Handle_CV_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                and then Data'Length <= Transcript_Capacity
                and then Nonce_Space_Available (HC.Client_HS),
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and S.Client_App = S.Client_App'Old);

   procedure Handle_CV_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
   begin
      Result := OK;
      if Data'Length >= 8 then
         declare
            Sig_Len : constant N32 :=
               N32 (Data (Data'First + 6)) * 256
               + N32 (Data (Data'First + 7));
         begin
            if N32 (Data'Length) - 4 /= 4 + Sig_Len then
               Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      declare
         H_Len   : constant N32 := HC.Hash_Len;
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

         if not HC.Peer_Cert_Valid then
            Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
            return;
         end if;

         if X509.Has_Key_Usage (HC.Peer_Cert)
           and then not X509.KU_Digital_Signature (HC.Peer_Cert)
         then
            Send_HS_Encrypted_Alert (S, HC, Bad_Certificate, Result);
            return;
         end if;

         if HC.Cfg.Skip_Verify then
            Set_State (S, Wait_Server_Finished);
            return;
         end if;

         declare
            Context_Str : constant String :=
               "TLS 1.3, server CertificateVerify";
            Content_Len : constant N32 :=
               64 + N32 (Context_Str'Length) + 1 + H_Len;
            Content     : Byte_Seq (0 .. Content_Len - 1) := (others => 0);
         begin
            Content (0 .. 63) := (others => 16#20#);
            for I in Context_Str'Range loop
               Content (64 + N32 (I - Context_Str'First)) :=
                  Byte (Character'Pos (Context_Str (I)));
            end loop;
            Content (64 + N32 (Context_Str'Length)) := 16#00#;
            Content (64 + N32 (Context_Str'Length) + 1 ..
                     64 + N32 (Context_Str'Length) + H_Len) := CV_Hash;

            if Msg_Len >= 8 then
               declare
                  Sig_Scheme : constant Unsigned_16 :=
                     Unsigned_16 (Data (4)) * 256 +
                     Unsigned_16 (Data (5));
                  Sig_Len : constant N32 :=
                     N32 (Data (6)) * 256 + N32 (Data (7));
                  Sig_Start : constant N32 := 8;
               begin
                  if Sig_Scheme = 16#0401#
                     or Sig_Scheme = 16#0501#
                     or Sig_Scheme = 16#0601#
                  then
                     S.Last_Error := Illegal_Parameter;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                     return;
                  end if;

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
   end Handle_CV_13;

   --  RFC 8446 §4.4.4 client-side Finished handler. Verifies server
   --  Finished verify_data with the suite-appropriate HMAC, then
   --  triggers app-key derivation + client Finished emission.
   procedure Handle_Finished_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                and then Data'Length <= Transcript_Capacity
                and then Nonce_Space_Available (HC.Client_HS),
        --  Handle_Finished installs the app traffic secret via
        --  Derive_App_Keys_And_Send_Finished, so S.Client_App is
        --  replaced (not pinned to 'Old). Nonce headroom is guaranteed
        --  because the new key starts with Counter = 0.
        Post => (if S.State /= Error_State
                 then HC.Client_HS = HC.Client_HS'Old
                      and Nonce_Space_Available (S.Client_App));

   procedure Handle_Finished_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
   begin
      Result := OK;
      if S.State = Wait_Certificate
        or else S.State = Wait_Certificate_Verify
      then
         Send_HS_Encrypted_Alert (S, HC, Unexpected_Message, Result);
         return;
      end if;
      if Msg_Len /= HC.Hash_Len then
         Send_HS_Encrypted_Alert
           (S, HC, Certificate_Verify_Failed, Result);
         return;
      end if;
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

      Derive_App_Keys_And_Send_Finished (S, HC, Result);
   end Handle_Finished_13;

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
         --  Distinguish "unknown message type" (BoGo WrongMessageType
         --  injects type+42) from "malformed length / shape" so we
         --  emit the right alert. Pre-condition: handshake records
         --  are decrypted under HC.Client_HS — we're post-SH.
         declare
            Raw_Type : constant Byte :=
               (if Data'Length >= 1 then Data (Data'First) else 0);
            Is_Known : constant Boolean :=
               Raw_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                           16#0B# | 16#0C# | 16#0D# | 16#0E# |
                           16#0F# | 16#10# | 16#14#;
         begin
            Send_HS_Encrypted_Alert
              (S, HC,
               (if Is_Known then Decode_Error else Unexpected_Message),
               Result);
         end;
         return;
      end if;

      case Msg_Type is
         when Handshake.HT_Encrypted_Extensions =>
            Handle_EE_13 (S, HC, Data, Result);
            if Result /= OK then return; end if;

         when Handshake.HT_Certificate_Request =>
            Handle_CertReq_13 (S, HC, Data, Result);
            if Result /= OK then return; end if;
         when Handshake.HT_Certificate =>
            Handle_Cert_13 (S, HC, Data, Result);
            if Result /= OK then
               return;
            end if;

         when Handshake.HT_Certificate_Verify =>
            Handle_CV_13 (S, HC, Data, Msg_Len, Result);
            if Result /= OK then
               return;
            end if;

         when Handshake.HT_Finished =>
            Handle_Finished_13 (S, HC, Data, Msg_Len, Result);
            if Result /= OK then
               return;
            end if;

         when others =>
            --  RFC 8446 §4: unknown handshake type → unexpected_message.
            --  BoGo's WrongMessageType-TLS13-* injects `type + 42` here.
            Send_HS_Encrypted_Alert
              (S, HC, Unexpected_Message, Result);
      end case;
   end Process_Handshake_Message;

   --  mTLS: send client Certificate + CertificateVerify if requested.
   --  Called before sending Client Finished.
   procedure Send_Client_Certificate
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Scratch : in out IO_Buffer;
      Result  :    out Action)
   is
      Enc_Out : N32;
   begin
      Result := OK;

      if not HC.Cert_Request_Received then
         return;
      end if;

      --  RFC 8446 §4.4.2: when we have NO identity, send an empty
      --  Certificate. When we DO have an identity but it can't sign
      --  with any algorithm in the server's offered list, send a
      --  fatal handshake_failure alert — BoringSSL emits
      --  `:NO_COMMON_SIGNATURE_ALGORITHMS:` here, which BoGo's
      --  Client-SignDefault tests use as the expected outcome.
      if HC.Cfg.Local /= null
        and then HC.Cfg.Local.Has_Identity
        and then HC.Negotiated_Sig_Algo = 0
      then
         Send_HS_Encrypted_Alert (S, HC, Handshake_Failure, Result);
         return;
      end if;

      if HC.Cfg.Local = null or else not HC.Cfg.Local.Has_Identity then
         --  Server requested cert but we have none.
         --  Send empty Certificate message (allowed by RFC 8446 S.4.4.2).
         declare
            Empty_Cert : Byte_Seq (0 .. 7) := (others => 0);
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
               Output     => Scratch,
               Bytes_Out  => Enc_Out);
            if Enc_Out = 0 then
               Result := Error_Alert;
            end if;
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
               Output     => Scratch,
               Bytes_Out  => Enc_Out);
            if Enc_Out = 0 then
               Result := Error_Alert;
               return;
            end if;
         end if;
      end;

      --  Send CertificateVerify (RFC 8446 §4.4.3). Required after
      --  any non-empty client Certificate to prove possession of
      --  the private key. Was Ed25519-only — RSA-PSS / ECDSA certs
      --  skipped the CV entirely, so the runner saw [Cert, Finished]
      --  and rejected with "unexpected handshake message of type
      --  finishedMsg when waiting for certificateVerifyMsg".
      if HC.Cfg.Local.Sign_Algo in
           Sign_Ed25519 | Sign_RSA_PSS
           | Sign_ECDSA_P256 | Sign_ECDSA_P384
      then
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
                     Output     => Scratch,
                     Bytes_Out  => Enc_Out);
                  if Enc_Out = 0 then
                     Result := Error_Alert;
                     return;
                  end if;
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
      Cert_Result  : Action;
      --  Atomic flight assembly: client mTLS flight is
      --  [Cert + CertVerify] (optional) + CCS + Finished. We build into
      --  Scratch and only commit once everything fits, so the peer
      --  never sees a half-flight. Each Build_Encrypted_Record call
      --  advances HC.Client_HS.Counter; we save it and restore on any
      --  failure to keep AEAD nonces in sync with what the peer saw.
      Scratch   : IO_Buffer;
      Saved_Ctr : constant Unsigned_64 := HC.Client_HS.Counter;
      Pre_CCS_Out : N32;
      --  RFC 8446 §7.1: client_application_traffic_secret_0 uses
      --  the transcript hash through SERVER's Finished — NOT
      --  including any subsequent client Cert/CV. Snapshot the
      --  hash BEFORE Send_Client_Certificate appends our Cert,
      --  so App keys match what the peer derives. Was: re-hashed
      --  AFTER Send_Client_Certificate had appended the empty Cert,
      --  producing keys that diverged from the peer's, leading to
      --  "bad record MAC" on the first post-handshake record.
      App_TS_Hash_256 : constant Digest := Transcript_Hash_256 (HC);
      App_TS_Hash_384 : constant Key_Schedule.Digest_384 :=
                          Transcript_Hash_384 (HC);
   begin
      --  RFC 8446 §D.4: middlebox-compatibility CCS goes FIRST
      --  in the client's post-server-Finished flight, BEFORE any
      --  encrypted record. Otherwise the runner-side Go TLS stack
      --  rejects with "invalid TLS 1.3 ChangeCipherSpec" because
      --  it expects a CCS where it sees an app_data record.
      --
      --  If we already emitted the dummy CCS between HRR and CH2
      --  (HC.Sent_HRR_CCS), skip — the server's
      --  expectChangeCipherSpec was cleared by that one and a
      --  second CCS would be rejected as unexpected.
      if not HC.Sent_HRR_CCS then
         Records.Build_CCS_Record (Scratch, Pre_CCS_Out);
         if Pre_CCS_Out = 0 then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      else
         Pre_CCS_Out := 0;
      end if;

      --  mTLS: send client certificate before Finished if requested
      Send_Client_Certificate (S, HC, Scratch, Cert_Result);
      if Cert_Result = Error_Alert then
         HC.Client_HS.Counter := Saved_Ctr;
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
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

            --  Finished for SHA-384: header(4) + 48-byte verify_data.
            --  (Build_Finished assumes Bytes_32, so build manually.)
            declare
               Big_Finished : Byte_Seq (0 .. 51) := (others => 0);  -- 4 + 48
            begin
               Big_Finished (0) := Handshake.HT_Finished;
               Big_Finished (1) := 16#00#;
               Big_Finished (2) := 16#00#;
               Big_Finished (3) := 16#30#;  --  48
               Big_Finished (4 .. 51) := Verify_48;

               --  RFC 8446 §7.1: Res_Master uses
               --  Hash(CH..client_Finished). Append before the
               --  Client_Finished_Sent state hashes for Res_Master.
               Append_Transcript (HC, Big_Finished);

               --  CCS already emitted at top of flight (RFC 8446 §D.4).
               CCS_Out := 1;

               Records.Build_Encrypted_Record
                 (Plaintext  => Big_Finished,
                  Inner_Type => 16#16#,
                  Keys       => HC.Client_HS,
                  Output     => Scratch,
                  Bytes_Out  => Enc_Out);
            end;

            if Enc_Out = 0 then
               HC.Client_HS.Counter := Saved_Ctr;
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret_384
              (Master, Key_Schedule.Digest_384 (HC.Handshake_Secret));

            --  RFC 8446 §7.1: app traffic secrets use the
            --  Server-Finished snapshot (App_TS_Hash_384), NOT
            --  the current TS_Hash which would include any
            --  client Cert/CV appended by Send_Client_Certificate.
            Key_Schedule.Derive_App_Traffic_Secrets_384
              (Client_App_Sec, Server_App_Sec, Master,
               App_TS_Hash_384);

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

            --  RFC 8446 §7.1: resumption_master_secret derivation
            --  uses Hash(CH..client_Finished). The Res_Master
            --  derivation runs later in the Client_Finished_Sent
            --  state (Advance_Handshake), which calls
            --  Transcript_Hash_256/384(HC) — so the client's
            --  Finished MUST be in the transcript by then or PSK
            --  resumption derives a wrong key and the next
            --  connection's binder fails server-side.
            Append_Transcript (HC, Finished_Buf (0 .. Finished_Len - 1));

            --  CCS already emitted at top of flight (RFC 8446 §D.4).
            CCS_Out := 1;

            Records.Build_Encrypted_Record
              (Plaintext  => Finished_Buf (0 .. Finished_Len - 1),
               Inner_Type => 16#16#,
               Keys       => HC.Client_HS,
               Output     => Scratch,
               Bytes_Out  => Enc_Out);

            if Enc_Out = 0 then
               HC.Client_HS.Counter := Saved_Ctr;
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret
              (Master, Digest (HC.Handshake_Secret (0 .. 31)));

            --  RFC 8446 §7.1: app traffic secrets use the
            --  Server-Finished snapshot (App_TS_Hash_256), NOT
            --  the current TS_Hash which would include any
            --  client Cert/CV appended by Send_Client_Certificate.
            Key_Schedule.Derive_App_Traffic_Secrets
              (Client_App_Sec, Server_App_Sec,
               Master, App_TS_Hash_256);

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

      --  Atomic commit: full client flight assembled in Scratch.
      if Free_Space (S.Output) < Scratch.Write_Pos then
         HC.Client_HS.Counter := Saved_Ctr;
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos ..
                     S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
         Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      Set_State (S, Client_Finished_Sent);
      Result := Has_Output;
   end Derive_App_Keys_And_Send_Finished;

   --  Advance handshake states (called with dereferenced HC_Ptr)
   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Rec        : in     Records.Parse_Result;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Max_HS_Msg : in     N32;
      Result     :    out Action)
   is
   begin
      Result := OK;
                           --  Fresh record. Frag_Len < 4 → start
                           --  reassembly with Hdr_Pending sentinel.
                           if Frag_Len < 4 then
                              if Frag_Len = 0 then
                                 S.Input.Read_Pos :=
                                    S.Input.Read_Pos + Rec.Record_Len;
                                 S.Last_Error := Decode_Error;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Buf := new Byte_Seq'
                                 (0 .. Max_HS_Msg - 1 => 0);
                              HC.Reasm_Need := 4;
                              HC.Reasm_Hdr_Pending := True;
                              HC.Reasm_Len := Frag_Len;
                              HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                                 S.Input.Data
                                   (Frag_Start ..
                                    Frag_Start + Frag_Len - 1);
                              S.Input.Read_Pos :=
                                 S.Input.Read_Pos + Rec.Record_Len;
                              Result := OK;
                              return;
                           end if;

                           --  Header is in this fragment. Decode
                           --  HS_Total; if msg spans, start reassembly.
                           declare
                              HS_Len : constant N32 :=
                                 N32 (S.Input.Data (Frag_Start + 1))
                                   * 65536 +
                                 N32 (S.Input.Data (Frag_Start + 2))
                                   * 256 +
                                 N32 (S.Input.Data (Frag_Start + 3));
                              HS_Total : constant N32 := HS_Len + 4;
                           begin
                              if HS_Total > Max_HS_Msg then
                                 S.Input.Read_Pos :=
                                    S.Input.Read_Pos + Rec.Record_Len;
                                 S.Last_Error := Decode_Error;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                              if HS_Total > Frag_Len then
                                 Free_Byte_Seq (HC.Reasm_Buf);
                                 HC.Reasm_Buf := new Byte_Seq'
                                    (0 .. HS_Total - 1 => 0);
                                 HC.Reasm_Need := HS_Total;
                                 HC.Reasm_Len := Frag_Len;
                                 HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                                    S.Input.Data
                                      (Frag_Start ..
                                       Frag_Start + Frag_Len - 1);
                                 S.Input.Read_Pos :=
                                    S.Input.Read_Pos + Rec.Record_Len;
                                 Result := OK;
                                 return;
                              end if;
                              --  Single-record happy path: copy the
                              --  WHOLE record fragment (could include
                              --  trailing packed messages per BoGo's
                              --  PackHandshakeFlight) into Reasm_Buf.
                              --  Set Reasm_Need to just the SH size so
                              --  dispatch sees one message; the
                              --  TLS 1.2 Process_Server_Flight will
                              --  drain trailing leftover bytes.
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Buf := new Byte_Seq'
                                 (0 .. Frag_Len - 1 => 0);
                              HC.Reasm_Need := HS_Total;
                              HC.Reasm_Len := Frag_Len;
                              HC.Reasm_Buf.all :=
                                 S.Input.Data
                                   (Frag_Start ..
                                    Frag_Start + Frag_Len - 1);
                              S.Input.Read_Pos :=
                                 S.Input.Read_Pos + Rec.Record_Len;
                           end;
   end Reasm_Fresh_Fragment;

   procedure Reassemble_For_SH
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
      Frag_Len : constant N32 := Rec.Fragment_Len;
      Frag_Start : constant N32 :=
         S.Input.Read_Pos + Rec.Fragment_Pos;
      Max_HS_Msg : constant N32 := 131072;
   begin
      Result := OK;
                        if HC.Reasm_Need > 0
                          and then HC.Reasm_Buf /= null
                        then
                           declare
                              Need : constant N32 :=
                                 HC.Reasm_Need - HC.Reasm_Len;
                              Take : constant N32 :=
                                 N32'Min (Frag_Len, Need);
                           begin
                              if HC.Reasm_Len + Take <=
                                    N32 (HC.Reasm_Buf'Length)
                              then
                                 HC.Reasm_Buf
                                   (HC.Reasm_Len ..
                                    HC.Reasm_Len + Take - 1) :=
                                    S.Input.Data
                                      (Frag_Start ..
                                       Frag_Start + Take - 1);
                                 HC.Reasm_Len := HC.Reasm_Len + Take;
                              end if;
                           end;
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;

                           --  Header just arrived: decode HS_Total.
                           if HC.Reasm_Hdr_Pending
                             and then HC.Reasm_Len >= 4
                           then
                              declare
                                 HS_Total : constant N32 :=
                                    N32 (HC.Reasm_Buf (1)) * 65536
                                    + N32 (HC.Reasm_Buf (2)) * 256
                                    + N32 (HC.Reasm_Buf (3)) + 4;
                              begin
                                 HC.Reasm_Hdr_Pending := False;
                                 if HS_Total < 4
                                   or HS_Total > Max_HS_Msg
                                 then
                                    Free_Byte_Seq (HC.Reasm_Buf);
                                    HC.Reasm_Len := 0;
                                    HC.Reasm_Need := 0;
                                    S.Last_Error := Decode_Error;
                                    Set_State (S, Error_State);
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 HC.Reasm_Need := HS_Total;
                              end;
                           end if;

                           if HC.Reasm_Len < HC.Reasm_Need then
                              Result := OK;
                              return;  --  need more fragments
                           end if;
                        else
                           Reasm_Fresh_Fragment
                             (S, HC, Rec, Frag_Len, Frag_Start,
                              Max_HS_Msg, Result);
                        end if;
   end Reassemble_For_SH;

   procedure Finalize_SH_Processing
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
                        --  PackHandshake (TLS 1.2 PackHandshakeFlight):
                        --  the record may pack SH + Cert + SKE + ... +
                        --  SHD. Preserve trailing bytes so the next
                        --  Process_Server_Flight call drains them via
                        --  its in-progress reassembly path; otherwise
                        --  free the buffer.
                        if HC.Version /= TLS_1_3
                          and then HC.Reasm_Buf /= null
                          and then HC.Reasm_Len > HC.Reasm_Need
                        then
                           declare
                              Old_Need : constant N32 := HC.Reasm_Need;
                              Leftover : constant N32 :=
                                 HC.Reasm_Len - Old_Need;
                           begin
                              HC.Reasm_Buf (0 .. Leftover - 1) :=
                                 HC.Reasm_Buf
                                   (Old_Need .. HC.Reasm_Len - 1);
                              HC.Reasm_Len := Leftover;
                              if Leftover < 4 then
                                 HC.Reasm_Need := 4;
                                 HC.Reasm_Hdr_Pending := True;
                              else
                                 declare
                                    Next_Len : constant N32 :=
                                       N32 (HC.Reasm_Buf (1)) * 65536
                                       + N32 (HC.Reasm_Buf (2)) * 256
                                       + N32 (HC.Reasm_Buf (3));
                                 begin
                                    HC.Reasm_Need := Next_Len + 4;
                                    HC.Reasm_Hdr_Pending := False;
                                 end;
                              end if;
                           end;
                        else
                           Free_Byte_Seq (HC.Reasm_Buf);
                           HC.Reasm_Len := 0;
                           HC.Reasm_Need := 0;
                           HC.Reasm_Hdr_Pending := False;
                        end if;

                        if HC.Version = TLS_1_3 then
                           Derive_Handshake_Keys (S, HC);
                           Set_State (S, Wait_Encrypted_Extensions);
                        else
                           --  RFC 5077 §3.4 client-side resume detection.
                           --  If we sent a session_ticket ext AND the
                           --  server echoed it AND we have a cached
                           --  ticket AND the suites match — we're in
                           --  the abbreviated handshake. Install the
                           --  cached master_secret + flag for the
                           --  TLS 1.2 flight machinery to skip Cert/
                           --  SKE/Done waiting and route NST → server
                           --  CCS+Finished → our CCS+Finished.
                           if HC.TLS12_Sent_Ticket_Ext
                             and then HC.TLS12_Server_Will_Issue
                             and then HC.Cfg.TLS12_Resume_Ticket.Valid
                             and then HC.Cfg.TLS12_Resume_Ticket.Suite
                                        = S.Negotiated_Suite_12
                           then
                              HC.TLS12_Resuming := True;
                              HC.Master_Secret_12 :=
                                 HC.Cfg.TLS12_Resume_Ticket.Master_Secret;
                           end if;
                           Set_State (S, Wait_Server_Finished);
                        end if;
                        Result := OK;
   end Finalize_SH_Processing;

   procedure Parse_SH_From_Reasm_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
                        --  Full ServerHello reassembled in HC.Reasm_Buf.
                        declare
                           Frag : constant Byte_Seq :=
                              HC.Reasm_Buf (0 .. HC.Reasm_Need - 1);
                           Parse_OK : Boolean;
                        begin
                           --  RFC 8446 §4 / RFC 5246 §7.4: the first
                           --  message in this state MUST be ServerHello
                           --  (type 2). Any other handshake type is an
                           --  unexpected_message — BoGo
                           --  WrongMessageType-ServerHello tests this.
                           if Frag (Frag'First)
                              /= Handshake.HT_Server_Hello
                           then
                              S.Last_Error := Unexpected_Message;
                           end if;
                           Handshake.Client_Msgs.Parse_Server_Hello
                             (S, HC, Frag, Parse_OK);

                           if not Parse_OK
                             and then S.Last_Error = No_Error
                           then
                              Handshake.TLS12.Parse_Server_Hello_12
                                (S, HC, Frag, Parse_OK);
                           end if;

                           if not Parse_OK then
                              if S.Last_Error = No_Error then
                                 S.Last_Error := Handshake_Failure;
                              end if;
                              --  Queue a plaintext alert on the wire so
                              --  the peer sees a real :DECODE_ERROR: /
                              --  :ILLEGAL_PARAMETER: rather than TCP RST.
                              --  Pre-key state — alert is unencrypted.
                              declare
                                 A : N32;
                              begin
                                 Records.Build_Plaintext_Alert
                                   (Level     => 2,
                                    Desc      =>
                                       Alert_Desc (S.Last_Error),
                                    Output    => S.Output,
                                    Bytes_Out => A);
                              end;
                              Set_State (S, Error_State);
                              Result := (if Output_Pending (S) > 0
                                         then Has_Output else Error_Alert);
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Len := 0;
                              HC.Reasm_Need := 0;
                              HC.Reasm_Hdr_Pending := False;
                              return;
                           end if;

                           --  RFC 8446 §4.1.4 HelloRetryRequest: if
                           --  the SH was actually an HRR (sentinel
                           --  random recognised by Parse_Server_Hello),
                           --  replace the CH1 transcript with a
                           --  synthetic `message_hash` (§4.4.1):
                           --
                           --    Transcript-Hash(CH1) → 32 bytes
                           --    Transcript becomes 0xFE 00 00 20 || hash
                           --
                           --  Then append the HRR bytes and build &
                           --  send CH2. Stay in Wait_Server_Hello to
                           --  receive the real SH.
                           if HC.Got_HRR and then not HC.Sent_HRR_CCS then
                              declare
                                 H : SPARKTLSCrypto.Hashing.SHA256.Digest;
                              begin
                                 SPARKTLSCrypto.Hashing.SHA256.Hash
                                   (H,
                                    HC.Transcript
                                      (0 .. HC.Transcript_Len - 1));
                                 HC.Transcript_Len := 0;
                                 HC.Transcript (0) := 16#FE#;
                                 HC.Transcript (1) := 16#00#;
                                 HC.Transcript (2) := 16#00#;
                                 HC.Transcript (3) := 16#20#;
                                 for I in N32 range 0 .. 31 loop
                                    HC.Transcript (4 + I) :=
                                       Byte (H (I));
                                 end loop;
                                 HC.Transcript_Len := 36;
                              end;
                              Append_Transcript (HC, Frag);
                              --  Build and send CH2.
                              declare
                                 CH2_Buf : Byte_Seq
                                   (0 .. Handshake.Client_Msgs
                                            .Max_Client_Hello - 1);
                                 CH2_Len : N32;
                                 Rec_Out : N32;
                              begin
                                 Handshake.Client_Msgs.Build_Client_Hello
                                   (S, HC, CH2_Buf, CH2_Len,
                                    Retry_Mode => True);
                                 if CH2_Len = 0 then
                                    S.Last_Error := Internal_Error;
                                    Set_State (S, Error_State);
                                    Result := Error_Alert;
                                    Free_Byte_Seq (HC.Reasm_Buf);
                                    HC.Reasm_Len := 0;
                                    HC.Reasm_Need := 0;
                                    HC.Reasm_Hdr_Pending := False;
                                    return;
                                 end if;
                                 Append_Transcript
                                   (HC, CH2_Buf (0 .. CH2_Len - 1));
                                 --  RFC 8446 §D.4 middlebox-compat:
                                 --  emit dummy CCS between HRR and
                                 --  CH2 so the server's
                                 --  expectChangeCipherSpec is
                                 --  satisfied. This is the only CCS
                                 --  the client sends in the HRR
                                 --  flow; the post-SH flight skips
                                 --  the CCS emission it would
                                 --  normally do (handled below).
                                 declare
                                    CCS_Bytes : N32;
                                 begin
                                    Records.Build_CCS_Record
                                      (S.Output, CCS_Bytes);
                                 end;
                                 HC.Sent_HRR_CCS := True;
                                 Records.Build_Handshake_Record
                                   (CH2_Buf (0 .. CH2_Len - 1),
                                    S.Output, Rec_Out);
                              end;
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Len := 0;
                              HC.Reasm_Need := 0;
                              HC.Reasm_Hdr_Pending := False;
                              --  Reset Has_TLS_1_3 so the next SH
                              --  parse re-derives it; without this,
                              --  the second SH's matrix lookup uses
                              --  a stale Where.
                              HC.Has_TLS_1_3 := False;
                              Result := (if Output_Pending (S) > 0
                                         then Has_Output else OK);
                              return;
                           end if;

                           Append_Transcript (HC, Frag);
                        end;
   end Parse_SH_From_Reasm_13;

   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
      --  Reassemble across records (BoGo SplitHandshakeRecords with
      --  MaxHandshakeRecordLength=1 fragments ServerHello into ~80
      --  single-byte records). Reassemble_For_SH does the heavy
      --  reassembly bookkeeping; Parse_SH_From_Reasm_13 decodes the
      --  completed SH (and handles HRR); Finalize_SH_Processing
      --  installs handshake keys and transitions state.
      Reassemble_For_SH (S, HC, Rec, Result);
      if Result /= OK then return; end if;
      if HC.Reasm_Len < HC.Reasm_Need then return; end if;

      Parse_SH_From_Reasm_13 (S, HC, Result);

      Finalize_SH_Processing (S, HC, Result);
   end Handle_WSH_HS_Frame;

   procedure Handle_WSH_Frame_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
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

               if Rec.Bad_Version then
                  S.Last_Error := Protocol_Version;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

               --  RFC 8446 §5.1 / §5.2: a record whose declared
               --  fragment length exceeds the per-type cap must be
               --  rejected with `record_overflow`. Without this
               --  check the parser would loop on Need_Input
               --  forever. BoGo LargePlaintext sends maxPlaintext+1.
               if Rec.Overflow then
                  S.Last_Error := Record_Overflow;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

               if not Rec.OK then
                  Result := Need_Input;
                  return;
               end if;

               case Rec.Content is
                  when Records.Content_Handshake =>
                     Handle_WSH_HS_Frame (S, HC, Rec, Result);

                  when Records.Content_Change_Cipher_Spec =>
                     --  RFC 8446 §5: a TLS 1.3 client may receive at
                     --  most ONE CCS for middlebox-compat between
                     --  ServerHello and the encrypted handshake.
                     --  Subsequent CCS records are unexpected. BoGo
                     --  TooManyChangeCipherSpec-Client-TLS13 forces 33
                     --  CCS records and expects rejection
                     --  (:TOO_MANY_EMPTY_FRAGMENTS:). Payload MUST be
                     --  the single byte 0x01 (BoGo BadChangeCipherSpec).
                     declare
                        CCS_Pos : constant N32 :=
                           S.Input.Read_Pos + Rec.Fragment_Pos;
                        CCS_OK  : constant Boolean :=
                           Rec.Fragment_Len = 1
                           and then S.Input.Data (CCS_Pos) = 16#01#;
                     begin
                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        if CCS_OK and then not HC.CCS_Received then
                           HC.CCS_Received := True;
                           Result := OK;
                        else
                           --  Pre-key state: plaintext alert.
                           declare
                              A : N32;
                           begin
                              Records.Build_Plaintext_Alert
                                (Level     => 2,
                                 Desc      => Alert_Desc (Unexpected_Message),
                                 Output    => S.Output,
                                 Bytes_Out => A);
                           end;
                           S.Last_Error := Unexpected_Message;
                           Set_State (S, Error_State);
                           Result := (if Output_Pending (S) > 0
                                      then Has_Output else Error_Alert);
                        end if;
                     end;

                  when Records.Content_Alert =>
                     --  Plaintext alert before keys are established
                     --  (e.g. server's close_notify or fatal alert).
                     --  Process by closing — keep parity with the
                     --  later alert-handling sites.
                     S.Input.Read_Pos :=
                        S.Input.Read_Pos + Rec.Record_Len;
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := Error_Alert;

                  when others =>
                     --  RFC 8446 §6.2: any other record type — most
                     --  commonly Content_Application_Data — before
                     --  ServerHello is a record-layer state-machine
                     --  violation. Reject with unexpected_message
                     --  (BoGo AppDataBeforeHandshake, expected
                     --  ":UNEXPECTED_RECORD:").
                     S.Input.Read_Pos :=
                        S.Input.Read_Pos + Rec.Record_Len;
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            end;
   end Handle_WSH_Frame_13;

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
            Handle_WSH_Frame_13 (S, HC, Result);

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
                        use SPARKTLSCrypto.HKDF384;
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
            if Output_Pending (S) > 0 then
               --  Drain queued output (e.g. abbreviated TLS 1.2
               --  resumption's CCS+Finished) before handing control
               --  back to the caller.
               Result := Has_Output;
            elsif S.Handshake_Just_Done then
               --  Deliver Handshake_Done exactly once after the
               --  handshake finished AND all queued output is on the
               --  wire. The caller relies on this signal to mark the
               --  connection ready for app data.
               S.Handshake_Just_Done := False;
               Result := Handshake_Done;
            elsif S.Negotiated_Version = TLS_1_2 then
               SPARKTLS.Client.TLS12.Process_Connected_12 (S, Result);
            else
               Process_Connected (S, Result);
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
               --  Persist resumption flags out of HC before free.
               S.Resumed_From_PSK := S.HC_Ptr.Using_PSK;
               --  Zero traffic keys on error (Connected path keeps them)
               if S.State = Error_State then
                  S.Server_App.Key := (others => 0);
                  S.Server_App.IV := (others => 0);
                  S.Client_App.Key := (others => 0);
                  S.Client_App.IV := (others => 0);
               end if;
               --  Zero ALL key material before freeing HC.
               --  This includes ephemeral keys (forward secrecy),
               --  transcript (contains plaintext handshake), and
               --  PSK material (resumption secrets).
               S.HC_Ptr.Shared_Secret := (others => 0);
               S.HC_Ptr.Client_HS_Secret := (others => 0);
               S.HC_Ptr.Server_HS_Secret := (others => 0);
               S.HC_Ptr.Handshake_Secret := (others => 0);
               S.HC_Ptr.Master_Secret := (others => 0);
               S.HC_Ptr.Master_Secret_12 := (others => 0);
               --  Ephemeral private keys
               S.HC_Ptr.Local_SK := (others => 0);
               S.HC_Ptr.P256_Local_SK := (others => 0);
               S.HC_Ptr.P384_Local_SK := (others => 0);
               --  Transcript (32 KB of plaintext handshake messages)
               S.HC_Ptr.Transcript
                 (0 .. S.HC_Ptr.Transcript_Len) := (others => 0);
               S.HC_Ptr.Transcript_Len := 0;
               --  PSK material
               S.HC_Ptr.PSK_Value := (others => 0);
               S.HC_Ptr.PSK_Binder := (others => 0);
               S.HC_Ptr.PSK_Ticket_ID := (others => 0);
               --  Client/server random
               S.HC_Ptr.Client_Random := (others => 0);
               S.HC_Ptr.Server_Random := (others => 0);
               Free_Byte_Seq (S.HC_Ptr.Reasm_Buf);
               HC_Alloc.Free (S.HC_Ptr);
            end if;
      end case;
   end Advance;

   --  Helper: derive key/IV and set Traffic_Keys based on suite.
   --  Suite must be one of the three RFC 8446 TLS-1.3 / RFC 5288/7905
   --  TLS-1.2 negotiable AEAD suites — matches the Traffic_Keys
   --  Predicate at sparktls.ads:770.
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
            --  RFC 8446 §7.1: Early_Secret = HKDF-Extract(0, PSK).
            --  PSK = ticket-derived secret iff the server actually
            --  selected our PSK (HC.Using_PSK) AND the ticket was
            --  bound to the same suite (PSK_Len matches the hash
            --  output size). Otherwise PSK = all-zeros, which is
            --  the §7.1 "fresh full handshake" sentinel.
            PSK_Bytes  : Bytes_48 :=
              (if HC.Using_PSK and then S.Ticket.PSK_Len = 48
               then S.Ticket.PSK
               else (others => 0));
            Client_Sec : OKM384_Seq (0 .. 47);
            Server_Sec : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Early_Secret_384 (Early, PSK_Bytes);
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
            --  See SHA-384 branch above for PSK rationale.
            PSK_Bytes  : Bytes_32 :=
              (if HC.Using_PSK and then S.Ticket.PSK_Len = 32
               then Bytes_32 (S.Ticket.PSK (0 .. 31))
               else (others => 0));
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret (Early, PSK_Bytes);
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
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   is
   begin
      Result := OK;
                  declare
                     Pos : N32 := 0;
                     Max_HS_Msg : constant N32 := 131072;
                  begin
                     --  If we have a partial message from a previous
                     --  record, continue filling the reassembly buffer.
                     if HC.Reasm_Need > 0 and HC.Reasm_Buf /= null then
                        declare
                           --  PackHandshake leftover can leave
                           --  Reasm_Len > Reasm_Need temporarily;
                           --  guard the subtraction.
                           Remaining : constant N32 :=
                              (if HC.Reasm_Len <= HC.Reasm_Need
                               then HC.Reasm_Need - HC.Reasm_Len
                               else 0);
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

                        --  Header-pending sentinel: once 4 bytes are
                        --  in, decode the real HS_Total. BoGo's
                        --  SplitHandshakeRecords (1-byte fragments)
                        --  exercises this.
                        if HC.Reasm_Hdr_Pending
                          and then HC.Reasm_Len >= 4
                        then
                           declare
                              HS_Total : constant N32 :=
                                 N32 (HC.Reasm_Buf (1)) * 65536
                                 + N32 (HC.Reasm_Buf (2)) * 256
                                 + N32 (HC.Reasm_Buf (3)) + 4;
                           begin
                              HC.Reasm_Hdr_Pending := False;
                              if HS_Total > Max_HS_Msg then
                                 Free_Byte_Seq (HC.Reasm_Buf);
                                 HC.Reasm_Len := 0;
                                 HC.Reasm_Need := 0;
                                 S.Last_Error := Decode_Error;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                              HC.Reasm_Need := HS_Total;
                           end;
                           --  Now that Reasm_Need is real, drain more
                           --  body bytes from this same record if any.
                           if HC.Reasm_Len < HC.Reasm_Need
                             and Pos < Plain_Len
                           then
                              declare
                                 Need2 : constant N32 :=
                                    HC.Reasm_Need - HC.Reasm_Len;
                                 Take2 : constant N32 :=
                                    N32'Min (Need2, Plain_Len - Pos);
                              begin
                                 if HC.Reasm_Len + Take2 <=
                                       N32 (HC.Reasm_Buf'Length)
                                 then
                                    HC.Reasm_Buf
                                      (HC.Reasm_Len ..
                                       HC.Reasm_Len + Take2 - 1) :=
                                       Plaintext (Pos .. Pos + Take2 - 1);
                                    HC.Reasm_Len := HC.Reasm_Len + Take2;
                                 end if;
                                 Pos := Pos + Take2;
                              end;
                           end if;
                        end if;

                        if HC.Reasm_Len >= HC.Reasm_Need then
                           --  Full message reassembled. Belt-and-braces
                           --  bound check: Reasm_Need is always set to
                           --  4 (header sentinel) or HS_Total >= 4, so
                           --  this is unreachable in practice but the
                           --  prover doesn't know without an explicit
                           --  guard before slicing for PHM.
                           if HC.Reasm_Need < 4
                             or else HC.Reasm_Need > Transcript_Capacity
                           then
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Len := 0;
                              HC.Reasm_Need := 0;
                              S.Last_Error := Decode_Error;
                              Set_State (S, Error_State);
                              Result := Error_Alert;
                              return;
                           end if;
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

                     --  Process complete messages in this record.
                     --  Loop condition includes state sanity so the loop
                     --  exits cleanly after PHM moves us to Error_State.
                     while Pos + 4 <= Plain_Len
                       and then S.State not in Idle | Closing
                                              | Closed | Error_State
                     loop
                        pragma Loop_Invariant
                          (Pos >= 0 and then Pos + 4 <= Plain_Len
                           and then Plain_Len <= N32 (Plaintext'Length)
                           and then Plaintext'First = 0
                           and then Plaintext'Last < N32'Last / 2
                           and then S.State not in Idle | Closing
                                                 | Closed | Error_State
                           and then Nonce_Space_Available (HC.Client_HS)
                           and then Nonce_Space_Available (S.Client_App));
                        declare
                           HS_Len : constant N32 :=
                              N32 (Plaintext (Pos + 1)) * 65536 +
                              N32 (Plaintext (Pos + 2)) * 256 +
                              N32 (Plaintext (Pos + 3));
                           Msg_Total : constant N32 := 4 + HS_Len;
                           Msg_End   : constant N32 := Pos + Msg_Total;
                        begin
                           --  PHM.Pre requires Data'Length
                           --  <= Transcript_Capacity (the transcript
                           --  buffer cap). Reject oversize HS messages
                           --  early so the loop body satisfies the
                           --  contract and so we don't allocate beyond
                           --  what we can transcript.
                           if Msg_Total > Transcript_Capacity then
                              S.Last_Error := Decode_Error;
                              Set_State (S, Error_State);
                              Result := Error_Alert;
                              exit;
                           end if;

                           if Msg_End > Plain_Len then
                              --  Message spans into next record.
                              --  Start reassembly. Free any prior
                              --  buffer first; the prover models
                              --  Reasm_Buf as potentially non-null,
                              --  so the explicit Free is required to
                              --  discharge the leak medium.
                              Free_Byte_Seq (HC.Reasm_Buf);
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
                           --  Bail on any terminal state — even if
                           --  Process_Handshake_Message returned
                           --  Has_Output (alert queued, output pending)
                           --  we must not keep processing further
                           --  packed messages from this same record.
                           if Result = Error_Alert
                             or else S.State = Error_State
                           then
                              exit;
                           end if;
                           Pos := Msg_End;
                           --  RFC 8446 §4.4.4: server Finished is the
                           --  last server handshake message. After we
                           --  dispatch it (state transitions out of
                           --  Wait_Server_Finished), any plaintext
                           --  remaining in this record is excess
                           --  handshake data → fatal unexpected_message
                           --  (BoGo TrailingDataWithFinished).
                           if S.State /= Wait_Server_Finished
                             and S.State /= Wait_Certificate
                             and S.State /= Wait_Certificate_Verify
                             and S.State /= Wait_Encrypted_Extensions
                             and S.State /= Wait_Certificate_Request
                             and S.State /= Idle
                             and S.State /= Closing
                             and S.State /= Closed
                             and S.State /= Error_State
                             and Pos < Plain_Len
                           then
                              --  BoGo TrailingDataWithFinished: stray
                              --  bytes after server's Finished →
                              --  fatal unexpected_message.
                              --
                              --  Derive_App_Keys_And_Send_Finished has
                              --  already run (state = Client_Finished_
                              --  _Sent), so the server's read key has
                              --  switched from server_handshake_traffic_
                              --  secret to client_application_traffic_
                              --  secret. Encrypting this alert under
                              --  HC.Client_HS would now be rejected as
                              --  bad_record_mac. Use the app-secret
                              --  helper.
                              Send_App_Encrypted_Alert
                                (S, Unexpected_Message, Result);
                              exit;
                           end if;
                        end;
                     end loop;

                     --  Tail handling: 1..3 stray bytes left in this
                     --  record (server fragmented the 4-byte HS header
                     --  itself, e.g. BoGo MaxHandshakeRecordLength=1).
                     --  Start reassembly with the header-pending
                     --  sentinel; the next record will fill it.
                     if Result /= Error_Alert
                       and Result /= Has_Output
                       and HC.Reasm_Need = 0
                       and Pos < Plain_Len
                       and Plain_Len - Pos < 4
                     then
                        declare
                           Avail : constant N32 := Plain_Len - Pos;
                        begin
                           --  Free any prior buffer first; same proof
                           --  rationale as above — the prover models
                           --  Reasm_Buf as potentially non-null even
                           --  when the if-condition implies otherwise.
                           Free_Byte_Seq (HC.Reasm_Buf);
                           HC.Reasm_Buf := new Byte_Seq'
                              (0 .. Max_HS_Msg - 1 => 0);
                           HC.Reasm_Need := 4;
                           HC.Reasm_Hdr_Pending := True;
                           HC.Reasm_Len := Avail;
                           HC.Reasm_Buf (0 .. Avail - 1) :=
                              Plaintext (Pos .. Pos + Avail - 1);
                        end;
                     end if;
                  end;
   end Process_Decrypted_Handshake_Bytes;

   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
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
                  --  RFC 8446 §5.2: AEAD decryption failure MUST emit
                  --  a fatal bad_record_mac alert. Encrypted under
                  --  HC.Client_HS via the helper.
                  Send_HS_Encrypted_Alert
                    (S, HC, Bad_Record_MAC, Result);
                  pragma Assert
                    (AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S));
                  return;
               end if;

               --  Inner type should be handshake (0x16)
               --  A single encrypted record may contain multiple
               --  handshake messages, or a single message may span
               --  multiple records. Use Reasm_Buf for cross-record
               --  reassembly.
               if Inner_Type = 16#16# then
                  Process_Decrypted_Handshake_Bytes
                    (S, HC, Plaintext, Plain_Len, Result);
               elsif Inner_Type = 16#15# then
                  --  Alert
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               else
                  Result := OK;
               end if;
            end;
   end Handle_Encrypted_App_Data;

   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      Result := OK;   --  default; overwritten by every code path below
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data  => S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Write_Pos - 1),
         Avail => Available (S.Input),
         Result => Rec);

      if Rec.Bad_Version then
         --  RFC 8446 §5.1 / RFC 5246 §6.2.1: legacy_record_version
         --  must be 0x03xx with minor in 1..4. Anything else
         --  (BoGo CheckRecordVersion: 0x03FF) → fatal
         --  protocol_version alert.
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      if Rec.Overflow then
         S.Last_Error := Record_Overflow;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            --  CCS for middlebox compatibility. RFC 5246 §7.1: the
            --  payload MUST be the single byte 0x01. RFC 8446 §5
            --  permits exactly one server CCS per connection (the
            --  middlebox-compat dummy); a second one is unexpected.
            declare
               CCS_Pos : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               CCS_OK  : constant Boolean :=
                  Rec.Fragment_Len = 1
                  and then S.Input.Data (CCS_Pos) = 16#01#;
            begin
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               if CCS_OK and then not HC.CCS_Received then
                  HC.CCS_Received := True;
                  Result := OK;
               else
                  Send_HS_Encrypted_Alert
                    (S, HC, Unexpected_Message, Result);
               end if;
            end;

         when Records.Content_Application_Data =>
            Handle_Encrypted_App_Data (S, HC, Rec, Result);

         when others =>
            --  Skip unexpected
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Encrypted_Handshake;

   --  NST helpers (extracted from Process_Connected/16#16# handler).
   --  RFC 8446 §4.6.1 NewSessionTicket parsing is structurally deep
   --  (header → fixed prefix → nonce → ticket → extensions); keeping
   --  it as nested if/declare in the connected-state loop made every
   --  small RFC nit (zero-length ticket, dup ext, malformed flags ext)
   --  cost two indent levels. Split into:
   --   * Walk_NST_Extensions  – iterate ext list, extract max_early_
   --                            data, detect duplicates / malformed
   --                            flags ext, return a status enum.
   --   * Process_NST_Message  – parse fixed prefix + nonce + ticket,
   --                            derive PSK, then call Walk_NST_Exts.
   --  The Process_Connected case branch reduces to a single call.

   type NST_Status is
     (NST_OK,
      NST_Decode_Err,
      NST_Illegal_Param);
   --  NST_Decode_Err  → caller sends Decode_Error alert.
   --  NST_Illegal_Param → caller sends Illegal_Parameter alert.

   procedure Walk_NST_Extensions
     (Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Start_Off : in     N32;
      Status    :    out NST_Status)
   with Pre => Plaintext'First = 0
               and Plaintext'Last < N32'Last
               and Plain_Len >= 0
               and Plain_Len <= N32 (Plaintext'Length)
               and Start_Off >= 0
               and Start_Off <= Plain_Len;

   procedure Walk_NST_Extensions
     (Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Start_Off : in     N32;
      Status    :    out NST_Status)
   is
      type Tag_Array is array (1 .. 16) of Unsigned_16;
      Seen_Tags : Tag_Array := (others => 0);
      Seen_N    : Natural   := 0;
      EP        : N32       := Start_Off;
   begin
      Status := NST_OK;

      if EP + 2 > Plain_Len then
         return;
      end if;

      declare
         Ext_Total : constant N32 :=
            N32 (Plaintext (EP)) * 256 + N32 (Plaintext (EP + 1));
         Ext_End   : constant N32 :=
            N32'Min (EP + 2 + Ext_Total, Plain_Len);
      begin
         EP := EP + 2;
         while EP + 4 <= Ext_End loop
            declare
               Tag : constant Unsigned_16 :=
                  Unsigned_16 (Plaintext (EP)) * 256
                  + Unsigned_16 (Plaintext (EP + 1));
               E_Len : constant N32 :=
                  N32 (Plaintext (EP + 2)) * 256
                  + N32 (Plaintext (EP + 3));
            begin
               --  RFC 8446 §4.2: duplicate extension types in any HS
               --  message are forbidden (BoGo TLS13-DuplicateTicket
               --  EarlyDataSupport).
               for K in 1 .. Seen_N loop
                  if Seen_Tags (K) = Tag then
                     Status := NST_Illegal_Param;
                     return;
                  end if;
               end loop;
               if Seen_N < Seen_Tags'Last then
                  Seen_N := Seen_N + 1;
                  Seen_Tags (Seen_N) := Tag;
               end if;

               --  draft-ietf-tls-tlsflags: flags ext (0x003E) body is
               --  `opaque flags<1..2^8-1>` — outer ext_data is
               --  inner_len(1) + inner_bytes with inner_len >= 1. So
               --  ext_data_len < 2, or inner_len = 0, is decode_error
               --  (BoGo TLS13-Client-EmptyTicketFlags).
               if Tag = 16#003E#
                 and then (E_Len < 2
                           or else (EP + 4 < Ext_End
                                    and then N32 (Plaintext (EP + 4)) = 0))
               then
                  Status := NST_Decode_Err;
                  return;
               end if;

               --  early_data ext (0x002A) in NST signals server
               --  willingness to accept 0-RTT on a future resume.
               --  We never offer 0-RTT (out of scope), so we just
               --  walk past the body without recording the limit.

               EP := EP + 4 + E_Len;
            end;
         end loop;
      end;
   end Walk_NST_Extensions;

   procedure Process_NST_Message
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App)
               and then Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
               and then Plain_Len >= 0
               and then Plain_Len <= N32 (Plaintext'Length);

   procedure Process_NST_Message
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   is
      P : N32 := 4;  --  skip handshake header (type + 3-byte len)
   begin
      Result := OK;

      --  RFC 8446 §4.6.1: NST = type(1)+len(3)+lifetime(4)+age_add(4)
      --  +nonce_len(1)+nonce(var)+ticket_len(2)+ticket(var)+exts.
      --  Need at least the fixed prefix: 4+4+1 = 9 past the HS header.
      if Plain_Len < 4 + 9 then
         return;
      end if;

      declare
         Lifetime : constant Unsigned_32 :=
            Unsigned_32 (Plaintext (P))     * 2**24
          + Unsigned_32 (Plaintext (P + 1)) * 2**16
          + Unsigned_32 (Plaintext (P + 2)) * 2**8
          + Unsigned_32 (Plaintext (P + 3));
         Age_Add : constant Unsigned_32 :=
            Unsigned_32 (Plaintext (P + 4)) * 2**24
          + Unsigned_32 (Plaintext (P + 5)) * 2**16
          + Unsigned_32 (Plaintext (P + 6)) * 2**8
          + Unsigned_32 (Plaintext (P + 7));
         Nonce_Len : constant N32 := N32 (Plaintext (P + 8));
      begin
         P := P + 9;
         if Nonce_Len = 0 or else P + Nonce_Len + 2 > Plain_Len then
            return;
         end if;

         declare
            Nonce    : constant Byte_Seq (0 .. Nonce_Len - 1) :=
               Plaintext (P .. P + Nonce_Len - 1);
            Tick_Len : N32;
         begin
            P := P + Nonce_Len;
            Tick_Len :=
               N32 (Plaintext (P)) * 256 + N32 (Plaintext (P + 1));
            P := P + 2;

            --  RFC 8446 §4.6.1: ticket field is opaque ticket<1..
            --  2^16-1>; a zero-length ticket is decode_error (BoGo
            --  SendEmptySessionTicket-TLS13).
            if Tick_Len = 0 then
               Send_App_Encrypted_Alert (S, Decode_Error, Result);
               return;
            end if;

            if P + Tick_Len > Plain_Len
              or else Tick_Len > Max_Ticket_Len
            then
               return;
            end if;

            S.Ticket.Ticket (0 .. Tick_Len - 1) :=
               Plaintext (P .. P + Tick_Len - 1);
            S.Ticket.Ticket_Len := Tick_Len;
            S.Ticket.Lifetime   := Lifetime;
            S.Ticket.Age_Add    := Age_Add;
            S.Ticket.Suite      := S.Negotiated_Suite;

            case S.Negotiated_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  declare
                     use SPARKTLSCrypto.HKDF384;
                     PSK_Out : OKM384_Seq (0 .. 47);
                  begin
                     Key_Schedule.Derive_PSK_384
                       (PSK_Out, S.Res_Master, Nonce);
                     S.Ticket.PSK     := Bytes_48 (PSK_Out);
                     S.Ticket.PSK_Len := 48;
                  end;
               when others =>
                  declare
                     PSK_Out : OKM_Seq (0 .. 31);
                  begin
                     Key_Schedule.Derive_PSK
                       (PSK_Out, S.Res_Master (0 .. 31), Nonce);
                     S.Ticket.PSK := (others => 0);
                     for I in N32 range 0 .. 31 loop
                        S.Ticket.PSK (I) := PSK_Out (I);
                     end loop;
                     S.Ticket.PSK_Len := 32;
                  end;
            end case;

            S.Ticket.Valid := True;

            --  Walk the NST extension list (ticket_flags, early_data,
            --  …). Errors (dup ext / malformed flags) un-install the
            --  ticket and emit the right alert. early_data ext bodies
            --  are walked-past — we don't offer 0-RTT, so the
            --  advertised limit is irrelevant.
            declare
               Status : NST_Status;
            begin
               Walk_NST_Extensions
                 (Plaintext => Plaintext,
                  Plain_Len => Plain_Len,
                  Start_Off => P + Tick_Len,
                  Status    => Status);
               case Status is
                  when NST_OK =>
                     null;
                  when NST_Decode_Err =>
                     S.Ticket.Valid := False;
                     Send_App_Encrypted_Alert
                       (S, Decode_Error, Result);
                  when NST_Illegal_Param =>
                     S.Ticket.Valid := False;
                     Send_App_Encrypted_Alert
                       (S, Illegal_Parameter, Result);
               end case;
            end;
         end;
      end;
   end Process_NST_Message;

   --  Process records in Connected state
   procedure Handle_Connected_App_Record
     (S      : in out Session;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
      Result := OK;
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

         --  RFC 8446 §5.4: "the full encoded TLSInnerPlaintext MUST
         --  NOT exceed 2^14 + 1 octets". TLSInnerPlaintext = content
         --  + type + zero pad. After AEAD this becomes the ciphertext
         --  minus the AEAD tag. Reject early to avoid even attempting
         --  the AEAD on an oversized record. BoGo
         --  LargePlaintext-TLS13-Padded-* sends e.g. 8192 plaintext +
         --  8193 padding => inner length 16386 > 16385.
         if Frag_Len - Records.Tag_Size > Max_Record_Plaintext + 1 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_App_Encrypted_Alert (S, Record_Overflow, Result);
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
            --  RFC 8446 §5.2: post-handshake AEAD failure → fatal
            --  bad_record_mac under client_application_traffic_secret.
            Send_App_Encrypted_Alert (S, Bad_Record_MAC, Result);
            pragma Assert
              (AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S));
            return;
         end if;

         --  RFC 8446 §5.4: TLSPlaintext.content after type+pad strip
         --  is at most 2^14 bytes.
         if Plain_Len > Max_Record_Plaintext then
            Send_App_Encrypted_Alert (S, Record_Overflow, Result);
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
                  --  Empty plaintext record. Count + cap to limit
                  --  DoS via flood (BoGo SendEmptyRecords: 33+ →
                  --  TOO_MANY_EMPTY_FRAGMENTS).
                  S.Empty_Records_Recvd :=
                     S.Empty_Records_Recvd + 1;
                  if S.Empty_Records_Recvd > 32 then
                     Send_App_Encrypted_Alert
                       (S, Unexpected_Message, Result);
                  else
                     Result := OK;
                  end if;
                  --  RFC 8446 §5.2 cap: ≤ 32 in live state, > 32
                  --  only after the alert is queued.
                  pragma Assert
                    (Empty_Records_Bounded_RFC_8446_5_2 (S));
               end if;

            when 16#16# =>
               --  Post-handshake handshake-record: today only NST is
               --  expected here (KeyUpdate not yet implemented). Hand
               --  off to Process_NST_Message which parses, installs
               --  the ticket, and queues the right alert on failure.
               if Plain_Len >= 4
                  and then Plaintext (0) = 16#04#  --  NewSessionTicket
               then
                  Process_NST_Message (S, Plaintext, Plain_Len, Result);
                  return;
               end if;
               Result := OK;

            when 16#15# =>
               --  RFC 8446 §6 / RFC 5246 §7.2 alert. The 2-byte
               --  payload is `level(1) | description(1)`. The level
               --  byte MUST be 1 (warning) or 2 (fatal); any other
               --  value (e.g. BoGo SendBogusAlertType: level 0x42)
               --  is a protocol violation — we MUST reply with a
               --  fatal illegal_parameter alert (47).
               if Plain_Len < 2 then
                  --  Truncated alert.
                  Send_App_Encrypted_Alert (S, Decode_Error, Result);
               elsif Plaintext (0) /= 1 and Plaintext (0) /= 2 then
                  --  Bogus alert level → fatal illegal_parameter.
                  Send_App_Encrypted_Alert (S, Illegal_Parameter, Result);
               elsif Plaintext (1) = 0 then
                  --  close_notify (warning, desc=0). Reply in kind.
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (Level     => 1,
                        Desc      => 0,
                        Keys      => S.Client_App,
                        Output    => S.Output,
                        Bytes_Out => A);
                  end;
                  Set_State (S, Closing);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
                  else
                     Result := Shutdown;
                  end if;
               elsif Plaintext (0) = 1 then
                  --  Warning-level alert other than close_notify.
                  --  RFC 8446 §6.1 deprecates TLS 1.3 warning alerts
                  --  but keeps user_canceled (90) for back-compat
                  --  (JDK11 misuses it as a half-duplex hint). Match
                  --  BoringSSL/NSS/OpenSSL: silently skip up to 4
                  --  user_canceled, fatal-decode_error every other
                  --  warning, and fatal too-many-warnings on the 5th.
                  if Plaintext (1) = 90 then
                     --  user_canceled — tolerate, with cap.
                     S.Warning_Alerts_Recvd :=
                        S.Warning_Alerts_Recvd + 1;
                     if S.Warning_Alerts_Recvd >= 5 then
                        Send_App_Encrypted_Alert (S, Decode_Error, Result);
                     else
                        Result := OK;
                     end if;
                     --  RFC 8446 §6.1 cap: invariant must hold on
                     --  every exit path. Either ≤ 4 (still tolerable)
                     --  or > 4 with State already advanced to
                     --  Error_State by the if-branch above.
                     pragma Assert
                       (Warning_Alerts_Bounded_RFC_8446_6_1 (S));
                  else
                     Send_App_Encrypted_Alert (S, Decode_Error, Result);
                  end if;
               else
                  --  Fatal alert from peer: close without replying
                  --  (RFC 8446 §6.2: don't send alerts about alerts).
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               end if;

            when others =>
               Result := OK;
         end case;
      end;
   end Handle_Connected_App_Record;

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

      if Rec.Bad_Version then
         --  RFC 8446 §5.1 / RFC 5246 §6.2.1: legacy_record_version
         --  must be 0x03xx with minor in 1..4. Anything else
         --  (BoGo CheckRecordVersion: 0x03FF) → fatal
         --  protocol_version alert.
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      if Rec.Overflow then
         Send_App_Encrypted_Alert (S, Record_Overflow, Result);
         return;
      end if;

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      --  RFC 8446 §5: in the Connected (post-handshake) TLS 1.3
      --  state, the only valid record content type is
      --  application_data (the outer type). Encrypted handshake
      --  records (post-handshake messages like NewSessionTicket,
      --  KeyUpdate) also arrive as outer type application_data —
      --  the inner type after AEAD decrypt is what distinguishes
      --  them. Anything else (CCS, alert, raw handshake) post-
      --  handshake is a state-machine violation. BoGo
      --  SendPostHandshakeChangeCipherSpec-TLS13.
      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
         return;
      end if;
      if Rec.Content /= Records.Content_Application_Data then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      Handle_Connected_App_Record (S, Rec, Result);
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
      --  See server-side comment: Set_State is a no-op when already
      --  Closing (avoids an invalid Closing → Closing transition).
      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Client;
