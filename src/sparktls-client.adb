with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;               use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HKDF;              use SPARKTLSCrypto.HKDF;

with SPARKTLS_Reassembly;   use SPARKTLS_Reassembly;
with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Client_Msgs;
with SPARKTLS.Handshake.Certs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Update;
with SPARKTLS.Tickets_12;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;
with SPARKTLS.HC_Alloc;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Client.TLS12;

with X509;

package body SPARKTLS.Client with
   SPARK_Mode => On
is
   --  Frame conditions here guard a ghost accessor with 'Old inside an
   --  implication, e.g. "if not Handled then Has_Context (S) =
   --  Has_Context (S)'Old". A potentially unevaluated 'Old must otherwise
   --  statically name an entity, which a function call does not -- and the
   --  alternatives are worse: 'Old on the pointer itself is illegal (a move
   --  on an owning access type), and there is no entity to name for
   --  "is the context still borrowed out". Same allowance already used in
   --  sparktls.ads, handshake-server_msgs.ads, handshake-tls12.ads and
   --  handshake-client_msgs.adb.
   pragma Unevaluated_Use_Of_Old (Allow);

   function Lower_ASCII (C : Character) return Character is
     (if C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Same_Hostname (Left, Right : Hostname_Buf) return Boolean is
   begin
      if Left.Len /= Right.Len then
         return False;
      end if;

      for I in 1 .. Left.Len loop
         if Lower_ASCII (Left.Data (I)) /= Lower_ASCII (Right.Data (I)) then
            return False;
         end if;
      end loop;

      return True;
   end Same_Hostname;

   procedure Check_Resume_Ticket_Usable
     (T     : Session_Ticket;
      Clock : Get_Time_Fn;
      Server_Name : Hostname_Buf;
      Usable : out Boolean)
   with
     Always_Terminates => False
   is
   begin
      if not T.Valid
        or else T.PSK_Len = 0
        or else T.Ticket_Len = 0
        or else T.Lifetime = 0
      then
         Usable := False;
         return;
      end if;

      if not T.Resumption_Across_Names
        and then not Same_Hostname (T.Server_Name, Server_Name)
      then
         Usable := False;
         return;
      end if;

      if Clock = null or else T.Received_At = 0 then
         Usable := True;
         return;
      end if;

      declare
         Now : constant Unsigned_64 :=
           SPARKTLS.Tickets_12.To_Unix_Seconds (Clock.all);
      begin
         Usable :=
           Now < T.Received_At
           or else Now - T.Received_At < Unsigned_64 (T.Lifetime);
      end;
   end Check_Resume_Ticket_Usable;

   --  First conjunct: certificate checking ON (not Skip_Verify) requires
   --  a CLOCK, with no exception for resumption.
   --
   --  Resumption used to excuse it, via the "or else Resume_Usable" arm
   --  below. That was wrong, because the PEER decides whether resumption
   --  happens: a server -- or an attacker in the path -- can decline the
   --  ticket and force a full handshake, and chain validation then needs
   --  a clock to check notBefore/notAfter. Without one the runtime guards
   --  fail closed (Bad_Certificate), so this was never a validation
   --  bypass, but it let an application build a config that only works
   --  while an attacker permits it. Reject at Init, where the operator
   --  sees it at startup rather than on the first declined ticket.
   --
   --  A missing TRUST STORE is deliberately NOT fatal here: a client that
   --  only ever resumes legitimately has no roots, and the second
   --  conjunct still lets it start. If such a client is forced into a
   --  full handshake it fails closed at the same runtime guard.
   function Client_Config_Can_Start
     (Cfg : Config;
      Resume_Usable : Boolean) return Boolean
   is
     (Cfg.Random /= null
      and then (Cfg.Skip_Verify or else Cfg.Get_Time /= null)
      and then
        (Cfg.Skip_Verify
         or else (Cfg.Trust /= null and then Cfg.Get_Time /= null)
         or else Resume_Usable));

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
           with
                Post => S.State = Error_State
                        and then S.Last_Error = Err
                                and then Result in Has_Output | Error_Alert
                        --  Frame: post-handshake app key is not touched (only
                --  the handshake-secret key is used to encrypt the
                --  alert). Pin so callers can preserve
                --  Nonce_Space_Available (S.Client_App).
                and then S.Client_App = S.Client_App'Old
                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
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
      S.State := Error_State;
      Result := (if A1 > 0 or else A2 > 0 or else Output_Pending (S) > 0
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
           with Post => S.State = Error_State
                and S.Last_Error = Err
                and Result in Has_Output | Error_Alert
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
      S.State := Error_State;
      Result := (if A > 0 or else Output_Pending (S) > 0
                 then Has_Output else Error_Alert);
   end Send_App_Encrypted_Alert;

   --  Forward declarations for internal procedures
   procedure Derive_Handshake_Keys
     (S  : in     Session;
      HC : in out Engaged_Context);

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
                        and Data'Last <= N32'Last - 16#1_0004#,
                                                        Post => S.State = S.State'Old
                                                                and then S.Negotiated_Suite = S.Negotiated_Suite'Old;
   --  OK = False signals a fatal protocol error. `Err` discriminates
   --  the alert kind so the caller picks the right alert code:
   --    Unsupported_Extension : server sent an EE extension we did
   --                            not offer in CH.
   --    Illegal_Parameter     : ALPN body malformed / doesn't match
   --                            offered protocol (RFC 7301 §3.2).
   procedure Send_Client_Certificate
     (S       : in out Session;
      HC      : in out Engaged_Context;
      Scratch : in out IO_Buffer;
      Result  :    out Action)
           with Pre => SPARKTLS_Transcript.Started (HC.TS)
                       and then
                         (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                       and then
                         True,
                        Post => (if Result = OK then
                                            S.State = S.State'Old
                                                    and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                            and then Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                            and then
                              True
                    and then
                                      (if HC.Cert_Request_Received
                                           and then HC.Cfg.Local /= null
                                           and then HC.Cfg.Local.Has_Identity
                                       then HC.Cfg.Random /= null
                                            and then HC.Cfg.Local.NaCl_Cert_Len
                                              in 1 .. N32 (Max_Cert_DER)
                                            and then Handshake.Sig_Algo_Compatible_With_Cert
                                              (HC.Negotiated_Sig_Algo,
                                               HC.Cfg.Local.Sign_Algo)
                                            and then
                                              (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                               then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
                                       else True));
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
           with Pre => S.State = Wait_Server_Finished
                       and then
                         (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                       and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                                   | Suite_AES_256_GCM_SHA384
                                                                   | Suite_CHACHA20_POLY1305_SHA256
                                       and then
                                         True,
                                Post => (if Result = Has_Output then
                                            Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old))
                        and then Result in Has_Output | Error_Alert;
   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
                   with Pre  => Data'First = 0
                                and then Data'Length >= 4
                                and then Data'Last < N32'Last - 4
                                and then Data'Last < Transcript_Capacity
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                       and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                    | Suite_AES_256_GCM_SHA384
                                                    | Suite_CHACHA20_POLY1305_SHA256
                                        and then
                                          True,
        Post => Result in OK | Has_Output | Error_Alert
                and then (if Result = OK
                       and then S.State in Wait_Encrypted_Extensions
                                           | Wait_Certificate_Request
                                           | Wait_Certificate
                                           | Wait_Certificate_Verify
                                           | Wait_Server_Finished
                                   then SPARKTLS_Transcript.Started (HC.TS)
                        and then S.Negotiated_Suite
                          in Suite_AES_128_GCM_SHA256
                           | Suite_AES_256_GCM_SHA384
                           | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          True);
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
   with Pre => True
                       and then
                         (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512));
   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                   | Suite_AES_256_GCM_SHA384
                                   | Suite_CHACHA20_POLY1305_SHA256
               and then
                 (if HC.Cert_Request_Received
                                      and then HC.Cfg.Local /= null
                                      and then HC.Cfg.Local.Has_Identity
                                  then HC.Cfg.Random /= null
                                       and then HC.Cfg.Local.NaCl_Cert_Len
                                         in 1 .. N32 (Max_Cert_DER)
                                       and then Handshake.Sig_Algo_Compatible_With_Cert
                                         (HC.Negotiated_Sig_Algo,
                                          HC.Cfg.Local.Sign_Algo)
                                       and then
                                         (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                          then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                       and then Rec.OK
               and then Rec.Content = Records.Content_Application_Data
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Fragment_Len >= 1
               and then Rec.Fragment_Len
                        <= Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Record_Len =
                        Rec.Fragment_Pos + Rec.Fragment_Len
               and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
               and then S.Input.Read_Pos + Rec.Record_Len
                        <= S.Input.Write_Pos
               and then S.Input.Read_Pos + Rec.Record_Len
                        <= IO_Buffer_Capacity;
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                   | Suite_AES_256_GCM_SHA384
                                                   | Suite_CHACHA20_POLY1305_SHA256
                               and then
                                 True
                               and then Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
                                       and then Plain_Len <= N32 (Plaintext'Length)
                               and then
                                 (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512));

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   with Pre => Msg'First = 0
                       and then Msg'Length >= 4
                       and then Msg'Last < N32'Last - 4
                                        and then
                                          (if HC.Cert_Request_Received
                                               and then HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity
                                           then HC.Cfg.Random /= null
                                                and then HC.Cfg.Local.NaCl_Cert_Len
                                                  in 1 .. N32 (Max_Cert_DER)
                                                and then Handshake.Sig_Algo_Compatible_With_Cert
                                                  (HC.Negotiated_Sig_Algo,
                                                   HC.Cfg.Local.Sign_Algo)
                                                and then
                                                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                        and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                            | Suite_AES_256_GCM_SHA384
                                                            | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          True,
        Post => (if Result = OK
                      and then S.State in Wait_Encrypted_Extensions
                                          | Wait_Certificate_Request
                                          | Wait_Certificate
                                          | Wait_Certificate_Verify
                                          | Wait_Server_Finished
                 then
                                                            SPARKTLS_Transcript.Started (HC.TS)
                            and then S.Negotiated_Suite
                               in Suite_AES_128_GCM_SHA256
                                | Suite_AES_256_GCM_SHA384
                                | Suite_CHACHA20_POLY1305_SHA256
                            and then
                              True)
                and then Result in OK | Has_Output | Error_Alert;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       :    out N32;
      Result    :    out Action)
   with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                   | Suite_AES_256_GCM_SHA384
                                                   | Suite_CHACHA20_POLY1305_SHA256
                               and then
                                 True
                               and then Plaintext'First = 0
                                       and then Plaintext'Last < IO_Buffer_Capacity
                                               and then Plain_Len <= N32 (Plaintext'Length)
               and then
                 (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)),
                                                        Post => Pos <= Plain_Len
                                                        and then (if Result = OK
                                                                      and then S.State
                                                                in Wait_Encrypted_Extensions
                                                         | Wait_Certificate_Request
                                                         | Wait_Certificate
                                                         | Wait_Certificate_Verify
                                                         | Wait_Server_Finished
                                                          then SPARKTLS_Transcript.Started (HC.TS)
                                                               and then S.Negotiated_Suite
                                                         in Suite_AES_128_GCM_SHA256
                                                          | Suite_AES_256_GCM_SHA384
                                                          | Suite_CHACHA20_POLY1305_SHA256
                                                       and then
                                                         True);

   procedure Fill_Decrypted_HS_Reassembly
     (HC            : in out Engaged_Context;
      Plaintext     : in     Byte_Seq;
      Plain_Len     : in     N32;
      Pos           :    out N32;
      Decode_Failed :    out Boolean)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
               and then Plain_Len <= N32 (Plaintext'Length)
                                       and then
                                 (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)),
                        Post => Pos <= Plain_Len
                                        and then Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                                        and then HC.Client_HS = HC.Client_HS'Old
                                and then HC.Cert_Request_Received =
                                         HC.Cert_Request_Received'Old
                                        and then (if HC.Cfg.Local'Old /= null
                                                  then HC.Cfg.Local /= null)
                                        and then (if HC.Cfg.Local'Old /= null
                                                  then HC.Cfg.Local.Has_Identity =
                                                       HC.Cfg.Local'Old.Has_Identity
                                                    and then HC.Cfg.Local.Sign_Algo =
                                                      HC.Cfg.Local'Old.Sign_Algo
                                                    and then HC.Cfg.Local.RSA_Mod_Len =
                                                      HC.Cfg.Local'Old.RSA_Mod_Len
                                                    and then HC.Cfg.Local.NaCl_Cert_Len =
                                                      HC.Cfg.Local'Old.NaCl_Cert_Len)
                                and then (if HC.Cfg.Local /= null
                                          then HC.Cfg.Local'Old /= null)
                                and then (if HC.Cfg.Local'Old /= null
                                               and then HC.Cfg.Local'Old.Has_Identity
                                          then HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity)
                                and then (if HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity
                                          then HC.Cfg.Local'Old /= null
                                               and then HC.Cfg.Local'Old.Has_Identity)
                                                and then (if HC.Cfg.Random'Old /= null
                                                          then HC.Cfg.Random /= null)
                                                and then HC.Negotiated_Sig_Algo =
                                                  HC.Negotiated_Sig_Algo'Old
                                                and then
                                          (if HC.Cert_Request_Received
                                               and then HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity
                                           then HC.Cfg.Random /= null
                                                and then HC.Cfg.Local.NaCl_Cert_Len
                                                  in 1 .. N32 (Max_Cert_DER)
                                                and then Handshake.Sig_Algo_Compatible_With_Cert
                                                  (HC.Negotiated_Sig_Algo,
                                                   HC.Cfg.Local.Sign_Algo)
                                                and then
                                                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                and then (if Decode_Failed then
                                            Used (HC.Reasm) = 0);

   procedure Copy_Decrypted_Reasm_Bytes
     (HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      From      : in     N32;
      Take      : in     N32)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
               and then Take > 0
               and then Take <= Free_Space (HC.Reasm)
                               and then From <= N32 (Plaintext'Length)
                               and then Take <= N32 (Plaintext'Length) - From
                       and then
                         (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)),
                        Post => Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                                        and then HC.Client_HS = HC.Client_HS'Old
                        and then HC.Cert_Request_Received =
                                 HC.Cert_Request_Received'Old
                        and then (if HC.Cfg.Local'Old /= null
                                  then HC.Cfg.Local /= null)
                        and then (if HC.Cfg.Local'Old /= null
                                  then HC.Cfg.Local.Has_Identity =
                                       HC.Cfg.Local'Old.Has_Identity
                                    and then HC.Cfg.Local.Sign_Algo =
                                      HC.Cfg.Local'Old.Sign_Algo
                                    and then HC.Cfg.Local.RSA_Mod_Len =
                                      HC.Cfg.Local'Old.RSA_Mod_Len
                                    and then HC.Cfg.Local.NaCl_Cert_Len =
                                      HC.Cfg.Local'Old.NaCl_Cert_Len)
                        and then (if HC.Cfg.Local /= null
                                  then HC.Cfg.Local'Old /= null)
                        and then (if HC.Cfg.Local'Old /= null
                                       and then HC.Cfg.Local'Old.Has_Identity
                                  then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity)
                        and then (if HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                  then HC.Cfg.Local'Old /= null
                                       and then HC.Cfg.Local'Old.Has_Identity)
                                and then (if HC.Cfg.Random'Old /= null
                                          then HC.Cfg.Random /= null)
                                and then HC.Negotiated_Sig_Algo =
                                          HC.Negotiated_Sig_Algo'Old;

   procedure Check_Declared_Message_Size
     (HC            : in out Engaged_Context;
      Decode_Failed :    out Boolean)
   with Pre => Header_Ready (HC.Reasm)
                       and then
                         (if HC.Cert_Request_Received
                              and then HC.Cfg.Local /= null
                              and then HC.Cfg.Local.Has_Identity
                          then HC.Cfg.Random /= null
                               and then HC.Cfg.Local.NaCl_Cert_Len
                                 in 1 .. N32 (Max_Cert_DER)
                               and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (HC.Negotiated_Sig_Algo,
                                  HC.Cfg.Local.Sign_Algo)
                               and then
                                 (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                  then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)),
                        Post => Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                                        and then HC.Client_HS = HC.Client_HS'Old
                                and then HC.Cert_Request_Received =
                                         HC.Cert_Request_Received'Old
                                and then (if HC.Cfg.Local'Old /= null
                                          then HC.Cfg.Local /= null)
                                and then (if HC.Cfg.Local'Old /= null
                                          then HC.Cfg.Local.Has_Identity =
                                               HC.Cfg.Local'Old.Has_Identity
                                            and then HC.Cfg.Local.Sign_Algo =
                                              HC.Cfg.Local'Old.Sign_Algo
                                            and then HC.Cfg.Local.RSA_Mod_Len =
                                              HC.Cfg.Local'Old.RSA_Mod_Len
                                            and then HC.Cfg.Local.NaCl_Cert_Len =
                                              HC.Cfg.Local'Old.NaCl_Cert_Len)
                                and then (if HC.Cfg.Local'Old /= null
                                          then HC.Cfg.Local.Has_Identity =
                                               HC.Cfg.Local'Old.Has_Identity
                                            and then HC.Cfg.Local.Sign_Algo =
                                              HC.Cfg.Local'Old.Sign_Algo
                                            and then HC.Cfg.Local.RSA_Mod_Len =
                                              HC.Cfg.Local'Old.RSA_Mod_Len
                                            and then HC.Cfg.Local.NaCl_Cert_Len =
                                              HC.Cfg.Local'Old.NaCl_Cert_Len)
                                and then (if HC.Cfg.Local'Old /= null
                                          then HC.Cfg.Local.Has_Identity =
                                               HC.Cfg.Local'Old.Has_Identity
                                            and then HC.Cfg.Local.Sign_Algo =
                                              HC.Cfg.Local'Old.Sign_Algo
                                            and then HC.Cfg.Local.RSA_Mod_Len =
                                              HC.Cfg.Local'Old.RSA_Mod_Len
                                            and then HC.Cfg.Local.NaCl_Cert_Len =
                                              HC.Cfg.Local'Old.NaCl_Cert_Len)
                                and then (if HC.Cfg.Local /= null
                                          then HC.Cfg.Local'Old /= null)
                                and then (if HC.Cfg.Local'Old /= null
                                               and then HC.Cfg.Local'Old.Has_Identity
                                          then HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity)
                                and then (if HC.Cfg.Local /= null
                                               and then HC.Cfg.Local.Has_Identity
                                          then HC.Cfg.Local'Old /= null
                                               and then HC.Cfg.Local'Old.Has_Identity)
                                and then (if HC.Cfg.Random'Old /= null
                                          then HC.Cfg.Random /= null)
                                and then HC.Negotiated_Sig_Algo =
                                  HC.Negotiated_Sig_Algo'Old
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                and then (if Decode_Failed then
                                            Used (HC.Reasm) = 0);

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    :    out Action)
             with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                   | Suite_AES_256_GCM_SHA384
                                                   | Suite_CHACHA20_POLY1305_SHA256
                               and then
                                 True
                               and then
                                 (if HC.Cert_Request_Received
                                      and then HC.Cfg.Local /= null
                                      and then HC.Cfg.Local.Has_Identity
                                  then HC.Cfg.Random /= null
                                       and then HC.Cfg.Local.NaCl_Cert_Len
                                         in 1 .. N32 (Max_Cert_DER)
                                       and then Handshake.Sig_Algo_Compatible_With_Cert
                                         (HC.Negotiated_Sig_Algo,
                                          HC.Cfg.Local.Sign_Algo)
                                       and then
                                         (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                          then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                               and then Plain_Len <= N32'Last
               and then Pos <= Plain_Len
                       and then Has_Message (HC.Reasm),
                                       Post => Pos <= Plain_Len
                                        and then (if Result = OK
                                              and then S.State in Wait_Encrypted_Extensions
                                                          | Wait_Certificate_Request
                                                          | Wait_Certificate
                                                          | Wait_Certificate_Verify
                                                          | Wait_Server_Finished
                                  then SPARKTLS_Transcript.Started (HC.TS)
                                       and then S.Negotiated_Suite
                                         in Suite_AES_128_GCM_SHA256
                                          | Suite_AES_256_GCM_SHA384
                                          | Suite_CHACHA20_POLY1305_SHA256
                                       and then
                                         True);

   procedure Process_Decrypted_HS_Packed_Messages
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    : in out Action)
   with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                   | Suite_AES_256_GCM_SHA384
                                                   | Suite_CHACHA20_POLY1305_SHA256
                               and then
                                 True
                                       and then Plaintext'First = 0
                       and then Plaintext'Last < IO_Buffer_Capacity
                       and then Plain_Len <= N32 (Plaintext'Length)
                               and then Pos <= Plain_Len,
                                                        Post => Pos <= Plain_Len
                                                    and then (if Result = OK
                                                      and then S.State
                                                        in Wait_Encrypted_Extensions
                                                         | Wait_Certificate_Request
                                                         | Wait_Certificate
                                                         | Wait_Certificate_Verify
                                                         | Wait_Server_Finished
                                                  then SPARKTLS_Transcript.Started (HC.TS)
                                                       and then S.Negotiated_Suite
                                                         in Suite_AES_128_GCM_SHA256
                                                          | Suite_AES_256_GCM_SHA384
                                                          | Suite_CHACHA20_POLY1305_SHA256
                                                               and then
                                                                 True);

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    : in out Action)
   with Pre => Result = OK
               and then S.State in Wait_Encrypted_Extensions
                                   | Wait_Certificate_Request
                                   | Wait_Certificate
                                   | Wait_Certificate_Verify
                                   | Wait_Server_Finished
                       and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                   | Suite_AES_256_GCM_SHA384
                                                   | Suite_CHACHA20_POLY1305_SHA256
                               and then
                                 True
                       and then Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
                               and then Plain_Len <= N32 (Plaintext'Length)
                               and then Pos <= N32'Last - 4
                                       and then Pos + 4 <= Plain_Len,
                                Post => Pos <= Plain_Len
                and then (if Result = OK
                                                  and then S.State in Wait_Encrypted_Extensions
                                                              | Wait_Certificate_Request
                                                              | Wait_Certificate
                                                              | Wait_Certificate_Verify
                                                      | Wait_Server_Finished then
                                             Pos > Pos'Old
                                     and then S.Negotiated_Suite
                                       in Suite_AES_128_GCM_SHA256
                                        | Suite_AES_256_GCM_SHA384
                                        | Suite_CHACHA20_POLY1305_SHA256
                                     and then
                                       True);


   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.App_Data_Len <= Max_Record_Plaintext
               and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
               and then S.Empty_Records_Recvd <= Max_Empty_Records;
   procedure Handle_Connected_App_Record
     (S      : in out Session;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.App_Data_Len <= Max_Record_Plaintext
               and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
               and then S.Empty_Records_Recvd <= Max_Empty_Records
               and then Rec.OK
               and then Rec.Content = Records.Content_Application_Data
               and then Rec.Fragment_Len >= 1
               and then Rec.Fragment_Len <=
                          Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Record_Len >= Rec.Fragment_Pos
               and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
               and then Rec.Record_Len <= Available (S.Input);
   procedure Set_Traffic_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Supported_Suite)
   with Post => TK.Counter = 0
                and then TK.Suite = Suite;

   --  Advance the handshake state machine (operates on dereferenced HC).
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action);
   procedure Handle_WSH_Frame_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
                           with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
;
   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
                   with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)

                       and then Rec.OK
               and then Rec.Content = Records.Content_Handshake
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Fragment_Len >= 1
               and then Rec.Fragment_Len
                        <= Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Record_Len =
                        Rec.Fragment_Pos + Rec.Fragment_Len
               and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                       and then S.Input.Read_Pos + Rec.Record_Len
                                <= S.Input.Write_Pos
                       and then S.Input.Read_Pos + Rec.Record_Len
                                <= IO_Buffer_Capacity;
   procedure Parse_SH_From_Reasm_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello
                       and then Has_Message (HC.Reasm)
                       and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
                Post => (if Result = OK then
                                    SPARKTLS_Transcript.Started (HC.TS)
                                                                                            and then
                                                                                              (if S.State = Wait_Server_Hello
                                                                                               then HC.HRR_Cookie_Len <=
                                                                                                 N32 (HC.HRR_Cookie'Length))
                                                                    and then
                                                                      (if S.State = Wait_Server_Hello
                                                                   and then HC.Version = TLS_1_3
                                                       then S.Negotiated_Suite in
                                                         Suite_AES_128_GCM_SHA256
                                               | Suite_AES_256_GCM_SHA384
                                               | Suite_CHACHA20_POLY1305_SHA256));

   procedure Finalize_SH_Processing
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
                   with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then
                                 (if HC.Version = TLS_1_3
                          then S.Negotiated_Suite in
                            Suite_AES_128_GCM_SHA256
                          | Suite_AES_256_GCM_SHA384
                          | Suite_CHACHA20_POLY1305_SHA256);

   procedure Reassemble_For_SH
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
                   with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Rec.OK
               and then Rec.Content = Records.Content_Handshake
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Fragment_Len >= 1
               and then Rec.Fragment_Len
                        <= Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Record_Len =
                        Rec.Fragment_Pos + Rec.Fragment_Len
               and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                       and then S.Input.Read_Pos + Rec.Record_Len
                                        <= S.Input.Write_Pos
                               and then S.Input.Read_Pos + Rec.Record_Len
                                                <= IO_Buffer_Capacity,
                Post => (if Result = OK then
                                    S.State = Wait_Server_Hello
                                            and then HC.Cfg.Random /= null
                                                    and then HC.HRR_Cookie_Len <=
                                                      N32 (HC.HRR_Cookie'Length));
   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Rec        : in     Records.Parse_Result;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Result     :    out Action)
                   with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Rec.OK
               and then Rec.Content = Records.Content_Handshake
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Fragment_Len = Frag_Len
               and then Frag_Len >= 1
               and then Frag_Len
                        <= Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Record_Len =
                        Rec.Fragment_Pos + Rec.Fragment_Len
               and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
               and then S.Input.Read_Pos + Rec.Record_Len
                        <= S.Input.Write_Pos
               and then S.Input.Read_Pos + Rec.Record_Len
                        <= IO_Buffer_Capacity
               and then Frag_Start = S.Input.Read_Pos + Rec.Fragment_Pos
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then (if Frag_Len >= 4
                         then Frag_Start <= IO_Buffer_Capacity - 4),
                Post => (if Result = OK then
                            S.State = Wait_Server_Hello
                            and then HC.Cfg.Random /= null
                                                    and then HC.HRR_Cookie_Len <=
                                                      N32 (HC.HRR_Cookie'Length));









   --  Append handshake message bytes to the transcript.
   --  RFC 5246 §7.4.9 / RFC 8446 §4.4.1: the transcript drives
   --  Finished verify_data, so it is append-only — losing bytes
   --  desyncs from the peer.

   function Transcript_Hash_256 (HC : Engaged_Context) return Digest
   is
      H : Digest;
   begin
      SPARKTLS_Transcript.Current_256 (HC.TS, H);
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (HC : Engaged_Context)
      return SPARKNaCl.Hashing.SHA384.Digest
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKTLS_Transcript.Current_384 (HC.TS, H);
      return H;
   end Transcript_Hash_384;

   ----------------------------------------------------------------------------
   --  Extract_ALPN_From_EE — see forward decl above for contract.
   --
   --  All offsets are computed against P, kept invariant by the
   --  outer guard `P + 4 <= Ext_End and P + 4 + E_Len <= Ext_End`
   --  before the inner read. Ext_End is the absolute index just
   --  past the last extension byte; computed once from the 2-byte
   --  ext_total_len read at fixed offset Body+0..1.
   ----------------------------------------------------------------------------
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
                  and Q <= Ext_End
                  and Q + 4 <= Ext_End
                  and Ext_End <= N32'Last - 16#1_0003#
                          and Ext_End <= Data'Last + 1
                          and S.State = S.State'Loop_Entry
                          and S.Client_App = S.Client_App'Loop_Entry
                          and S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry
                          and Seen_Count <= 32);
               declare
                  T : constant N32 :=
                     N32 (Data (Q)) * 256 + N32 (Data (Q + 1));
                  L : constant N32 :=
                     N32 (Data (Q + 2)) * 256 + N32 (Data (Q + 3));
               begin
                  pragma Assert (L <= 16#FFFF#);
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
                and P <= Ext_End
                and P + 4 <= Ext_End
                and Ext_End <= N32'Last - 16#1_0003#
                        and Ext_End <= Data'Last + 1
                        and S.State = S.State'Loop_Entry
                        and S.Client_App = S.Client_App'Loop_Entry
                        and S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            declare
               Tag : constant N32 :=
                  N32 (Data (P)) * 256 + N32 (Data (P + 1));
               E_Len : constant N32 :=
                  N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
            begin
               pragma Assert (E_Len <= 16#FFFF#);
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
     (S                    : out Client_Session;
      Hostname             : String;
      Trust                : Trust_Store_Access;
      Random               : Random_Bytes_Fn;
      Clock                : Get_Time_Fn;
      Local                : Valid_Identity_Access := null;
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
      Cfg.Skip_Verify := Skip_Verify;
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

   procedure Initialize_Client_Handshake
     (S   : in out Session;
      HC  : in out Handshake_Context;
      OK  :    out Boolean)
   with Post => --  Frame. Without these the caller (Init) must assume this
                --  procedure may have re-pointed S.HC_Ptr and changed
                --  S.Role, which turns the borrow's restore into an
                --  apparent memory leak and loses Init's own postcondition.
                --  Nothing here touches either: the only writer of S is
                --  Set_State, which frames both.
                not Has_Context (S)
                and then S.Role = Role_Client
                and then S.State in Client_Hello_Sent | Error_State
                --  Staying in Client_Hello_Sent means both the build and
                --  the record write succeeded, so output is queued. Every
                --  failure path sets Error_State first.
                and then (if S.State = Client_Hello_Sent
                          then Output_Pending (S) > 0),
        Pre => --  The caller borrows the context out before calling, so the
               --  field is null on entry and must be null on return for the
               --  restore to be leak-free. Not Constrained: the actual is
               --  the borrowed HC_Box component, so the Engage aggregate
               --  below may change the Phase discriminant.
               not HC'Constrained
               and then not Has_Context (S)
               and then S.State = Client_Hello_Sent
               and then S.Role = Role_Client
               and then HC.Cfg.Random /= null
           is
      CH_Buf    : Byte_Seq (0 .. Handshake.Client_Msgs.Max_Client_Hello - 1);
      CH_Len    : N32;
      Rec_Out   : N32;
   begin
      OK := False;
      Handshake.Client_Msgs.Build_Client_Hello (S, HC, CH_Buf, CH_Len);

      if CH_Len = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         return;
      end if;

      --  ENGAGE (phase carve): the client's own ClientHello starts the
      --  transcript; the context leaves Setup here and never returns.
      declare
         L : SPARKTLS_Transcript.Transcript_State;
      begin
      SPARKTLS_Transcript.Start (L);
      SPARKTLS_Transcript.Append (L, CH_Buf (0 .. CH_Len - 1));
      HC := (Phase => Engaged,
             TS => L,
             Version => HC.Version,
             Cfg => HC.Cfg,
             Peer_SNI => HC.Peer_SNI,
             Client_Random => HC.Client_Random,
             Server_Random => HC.Server_Random,
             Client_Has_X25519 => HC.Client_Has_X25519,
             Client_Has_P256 => HC.Client_Has_P256,
             Client_Has_P384 => HC.Client_Has_P384,
             Client_Saw_Key_Share => HC.Client_Saw_Key_Share,
             Client_Saw_Supported_Groups => HC.Client_Saw_Supported_Groups,
             Client_Supports_X25519 => HC.Client_Supports_X25519,
             Client_Supports_P256 => HC.Client_Supports_P256,
             Client_Supports_P384 => HC.Client_Supports_P384,
             KE => HC.KE,
             HRR_Sent => HC.HRR_Sent,
             Got_HRR => HC.Got_HRR,
             HRR_Cipher_Suite => HC.HRR_Cipher_Suite,
             HRR_Selected_Group => HC.HRR_Selected_Group,
             HRR_Cookie_Len => HC.HRR_Cookie_Len,
             HRR_Cookie => HC.HRR_Cookie,
             Sent_HRR_CCS => HC.Sent_HRR_CCS,
             CH_Ext_Hash => HC.CH_Ext_Hash,
             CH_Ext_Count => HC.CH_Ext_Count,
             Seen_Ext_Tags => HC.Seen_Ext_Tags,
             Seen_Ext_Count => HC.Seen_Ext_Count,
             Client_HS => HC.Client_HS,
             Server_HS => HC.Server_HS,
             Client_HS_Secret => HC.Client_HS_Secret,
             Server_HS_Secret => HC.Server_HS_Secret,
             Handshake_Secret => HC.Handshake_Secret,
             Master_Secret => HC.Master_Secret,
             Neg => HC.Neg,
             Peer_Leaf => HC.Peer_Leaf,
             Peer_Ints => HC.Peer_Ints,
             Peer_Int_Count => HC.Peer_Int_Count,
             Legacy_Session_ID => HC.Legacy_Session_ID,
             Legacy_Session_ID_Len => HC.Legacy_Session_ID_Len,
             Peer_Sig_Algos => HC.Peer_Sig_Algos,
             Peer_Sig_Algo_Count => HC.Peer_Sig_Algo_Count,
             Negotiated_Sig_Algo => HC.Negotiated_Sig_Algo,
             CCS_Received => HC.CCS_Received,
             T12 => HC.T12,
             PSK => HC.PSK,
             Cert_Request_Received => HC.Cert_Request_Received,
             Has_TLS_1_3 => HC.Has_TLS_1_3,
             Saw_Supported_Versions => HC.Saw_Supported_Versions,
             SV_Has_Acceptable => HC.SV_Has_Acceptable,
             CKE_Received_12 => HC.CKE_Received_12,
             Use_EMS => HC.Use_EMS,
             EMS_Session_Hash => HC.EMS_Session_Hash,
             EMS_Hash_Taken => HC.EMS_Hash_Taken,
             Saw_Reneg_Info => HC.Saw_Reneg_Info,
             Ext_Parse_Err => HC.Ext_Parse_Err,
             Client_ALPN => HC.Client_ALPN,
             Client_ALPN_List => HC.Client_ALPN_List,
             Client_ALPN_Count => HC.Client_ALPN_Count,
             Master_Secret_12 => HC.Master_Secret_12,
             Client_Write_IV_12 => HC.Client_Write_IV_12,
             Server_Write_IV_12 => HC.Server_Write_IV_12,
             MS_Derivation => HC.MS_Derivation,
             Using_PSK => HC.Using_PSK,
             Early_Data_Offered => HC.Early_Data_Offered,
             Skipped_Early_Data_Records => HC.Skipped_Early_Data_Records,
             Reasm => HC.Reasm,
             Heap_Used => HC.Heap_Used);
      end;

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
      else
         OK := True;
      end if;
   end Initialize_Client_Handshake;

   procedure Init
     (S   :    out Client_Session;
      Cfg : in     Config)
   is
      OK : Boolean;
      Resume_Usable : Boolean := False;
   begin
      S := (State     => Client_Hello_Sent,
            Role      => Role_Client,
            others    => <>);
      S.Get_Time := Cfg.Get_Time;
      S.Server_Name := Cfg.Server_Name;

      if Cfg.Random /= null then
         Check_Resume_Ticket_Usable
           (Cfg.Resume_Ticket, Cfg.Get_Time, Cfg.Server_Name, Resume_Usable);
      end if;

      if not Client_Config_Can_Start (Cfg, Resume_Usable) then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         return;
      end if;

      S.HC_Ptr := HC_Alloc.Allocate;
      if S.HC_Ptr = null then
         S.State := Error_State;
         S.Last_Error := Internal_Error;
         pragma Assert (Role (S) = Role_Client);
         pragma Assert (State (S) = Error_State);
         return;
      end if;

      --  Fresh transcript for this handshake. The hash contexts also
      --  carry correct defaults (see SHA256.Context), but the explicit
      --  Start documents the lifecycle and resets Choice/Has_Data if
      --  the allocator ever recycles contexts.
      S.HC_Ptr.C.Cfg := Cfg;

      --  RFC 8446 §4.6.1: if the caller passed a previously-saved
      --  resumption ticket via Cfg, copy it into S.Ticket before
      --  Build_Client_Hello so the CH carries the pre_shared_key
      --  extension and the binder is computed from the ticket's PSK.
      if Resume_Usable then
         S.Ticket := Cfg.Resume_Ticket;
      end if;

      --  BORROW: S and S.HC_Ptr.C would alias (SPARK RM 6.4.2). Move the
      --  context out for the duration of the call, then hand it back.
      declare
         HC : Handshake_Context_Access := S.HC_Ptr;
      begin
         S.HC_Ptr := null;
         Initialize_Client_Handshake (S, HC.C, OK);
         S.HC_Ptr := HC;
      end;
      if not OK then
         HC_Alloc.Free (S.HC_Ptr);
      end if;
      --  DIAG: the postcondition is one VC, so the sub-term named in the
      --  message is not attributable. Probe each conjunct separately.
      pragma Assert (Role (S) = Role_Client);                        --  P1
      pragma Assert (State (S) in Client_Hello_Sent | Error_State);  --  P2
   end Init;

   --  Process a decrypted handshake message during the handshake
   --  RFC 8446 §4.3.1 client-side EncryptedExtensions handler.
   --  Body shape check (≥ 2-byte ext-len prefix), ALPN extraction
   --  per RFC 7301, transition to Wait_Server_Finished (PSK path)
   --  or Wait_Certificate (full handshake).
   procedure Handle_EE_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                                        and then Data'Length <= Transcript_Capacity
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                        and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                            | Suite_AES_256_GCM_SHA384
                                                            | Suite_CHACHA20_POLY1305_SHA256
                                                and then True,
                                Post => (if Result = OK
                                                         then HC.Client_HS = HC.Client_HS'Old
                                              and then S.Negotiated_Suite
                                         in Suite_AES_128_GCM_SHA256
                                          | Suite_AES_256_GCM_SHA384
                                          | Suite_CHACHA20_POLY1305_SHA256
                                      and then
                                        True)
                and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_EE_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
              SPARKTLS_Transcript.Append (HC.TS, Data);

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
      HC     : in out Engaged_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => Data'First = 0
                        and then Data'Length >= 4
                                and then Data'Last < N32'Last - 4
                                and then Data'Length <= Transcript_Capacity
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                            | Suite_AES_256_GCM_SHA384
                                                    | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          True,
                Post => (if S.State /= Error_State
                                                         then SPARKTLS_Transcript.Started (HC.TS)
                                      and then S.Negotiated_Suite
                                 in Suite_AES_128_GCM_SHA256
                                  | Suite_AES_256_GCM_SHA384
                                  | Suite_CHACHA20_POLY1305_SHA256
                              and then
                                True)
                        and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_CertReq_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
              SPARKTLS_Transcript.Append (HC.TS, Data);
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
                                   pragma Loop_Invariant
                                     (S.State not in Idle | Closing | Closed
                                                   | Error_State);
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
                                            Handshake.Pick_Sig_Algo_With_Prefs
                                              (Data (P + 6 ..
                                                     P + 5 + List_Len),
                                               HC.Cfg.Local.Sign_Algo,
                                               HC.Cfg.Sign_Sig_Algos,
                                               HC.Cfg.Sign_Sig_Algo_Count);
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
                                                  pragma Loop_Invariant
                                                    (S.State not in Idle | Closing
                                                                  | Closed
                                                                  | Error_State);
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
      HC     : in out Engaged_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State = Wait_Certificate
                and then Data'First = 0
                        and then Data'Length >= 4
                        and then Data'Last < N32'Last - 4
                        and then Data'Length <= Transcript_Capacity
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                    | Suite_AES_256_GCM_SHA384
                                                    | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          True,
                Post => (if S.State /= Error_State
                                                 then S.Client_App = S.Client_App'Old
                                      and then S.Negotiated_Suite
                                 in Suite_AES_128_GCM_SHA256
                                  | Suite_AES_256_GCM_SHA384
                                  | Suite_CHACHA20_POLY1305_SHA256
                              and then
                                True)
                        and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_Cert_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
      SPARKTLS_Transcript.Append (HC.TS, Data);

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
        and then HC.Peer_Leaf.Present
              then
                 pragma Assert
                   (X509.Spans_Valid
                      (HC.Peer_Leaf.Cert, HC.Peer_Leaf.DER_Len - 1));
                 declare
                    Cert_DER_Len_C : constant N32 := N32 (HC.Peer_Leaf.DER_Len);
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (Cert_DER_Len_C) - 1) := (others => 0);
         begin
            for I in N32 range 0 .. Cert_DER_Len_C - 1 loop
               Cert_X (X509.N32 (I)) :=
                  HC.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            if not X509.Matches_Hostname
                    (HC.Peer_Leaf.Cert, Cert_X,
                     HC.Cfg.Server_Name.Data
                       (1 .. HC.Cfg.Server_Name.Len))
            then
               Send_HS_Encrypted_Alert (S, HC, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;

      if not HC.Cfg.Skip_Verify and then HC.Peer_Leaf.Present then
         if HC.Cfg.Trust = null or else HC.Cfg.Get_Time = null then
            S.Last_Error := Bad_Certificate;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         pragma Assert
           (X509.Spans_Valid
              (HC.Peer_Leaf.Cert, HC.Peer_Leaf.DER_Len - 1));
         declare
            Cert_DER_Len_Const : constant N32 := N32 (HC.Peer_Leaf.DER_Len);
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (Cert_DER_Len_Const) - 1) := (others => 0);
            VR : Validation_Result;
         begin
            for I in N32 range 0 .. Cert_DER_Len_Const - 1 loop
               Cert_X (X509.N32 (I)) :=
                  HC.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            VR := Validate_Chain
              (Leaf_DER   => Cert_X,
               Leaf       => HC.Peer_Leaf.Cert,
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
      HC      : in out Engaged_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => S.State = Wait_Certificate_Verify
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
                        and then Data'Length <= Transcript_Capacity
                        and then Msg_Len <= N32 (Data'Length) - 4
                and then
                  True
                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                            | Suite_AES_256_GCM_SHA384
                                            | Suite_CHACHA20_POLY1305_SHA256,
        Post => (if S.State /= Error_State
                         then HC.Client_HS = HC.Client_HS'Old
                              and then S.Client_App = S.Client_App'Old
                                      and then S.Negotiated_Suite
                                 in Suite_AES_128_GCM_SHA256
                                  | Suite_AES_256_GCM_SHA384
                                  | Suite_CHACHA20_POLY1305_SHA256
                              and then
                                True)
                and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_CV_13
     (S       : in out Session;
      HC      : in out Engaged_Context;
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
         H_Len   : constant N32 := Hash_Len (HC.Neg);
         CV_Hash : Byte_Seq (0 .. H_Len - 1);
              begin
                 --  Dispatch on the type-derived hash width (#117): the
                 --  384 branch is exactly H_Len = 48, so the callee's
                 --  width Pre discharges locally.
                 if H_Len = 48 then
                    CV_Hash := Transcript_Hash_384 (HC);
                 else
                    declare
                       H256 : constant Digest := Transcript_Hash_256 (HC);
                    begin
                       CV_Hash := H256;
                    end;
                 end if;

         SPARKTLS_Transcript.Append (HC.TS, Data);

         if not HC.Peer_Leaf.Present then
            Send_HS_Encrypted_Alert (S, HC, Decode_Error, Result);
            return;
         end if;

         if X509.Has_Key_Usage (HC.Peer_Leaf.Cert)
           and then not X509.KU_Digital_Signature (HC.Peer_Leaf.Cert)
         then
            Send_HS_Encrypted_Alert (S, HC, Bad_Certificate, Result);
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
                     Send_HS_Encrypted_Alert
                       (S, HC, Illegal_Parameter, Result);
                     return;
                  end if;

                  if HC.Cfg.Verify_Sig_Algo_Count > 0
                    and then not Sig_Scheme_In_List
                                   (Sig_Scheme,
                                    HC.Cfg.Verify_Sig_Algos,
                                    HC.Cfg.Verify_Sig_Algo_Count)
                  then
                     Send_HS_Encrypted_Alert
                       (S, HC, Illegal_Parameter, Result);
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
                           Cert       => HC.Peer_Leaf.Cert,
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
      HC      : in out Engaged_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Data'First = 0
                        and then Data'Length >= 4
                        and then Data'Last < N32'Last - 4
                        and then Data'Length <= Transcript_Capacity
                                and then
                                  (if HC.Cert_Request_Received
                                       and then HC.Cfg.Local /= null
                                       and then HC.Cfg.Local.Has_Identity
                                   then HC.Cfg.Random /= null
                                        and then HC.Cfg.Local.NaCl_Cert_Len
                                          in 1 .. N32 (Max_Cert_DER)
                                        and then Handshake.Sig_Algo_Compatible_With_Cert
                                          (HC.Negotiated_Sig_Algo,
                                           HC.Cfg.Local.Sign_Algo)
                                        and then
                                          (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
                                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                                            | Suite_AES_256_GCM_SHA384
                                                    | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          True,
        --  Handle_Finished installs the app traffic secret via
        --  Derive_App_Keys_And_Send_Finished, so S.Client_App is
        --  replaced (not pinned to 'Old). Nonce headroom is guaranteed
        --  because the new key starts with Counter = 0.
                                                Post => Result in Has_Output | Error_Alert
                                                 and then Result in Has_Output | Error_Alert;

   procedure Handle_Finished_13
     (S       : in out Session;
      HC      : in out Engaged_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
              Result  :    out Action)
           is
              Initial_Suite : constant Supported_Suite := S.Negotiated_Suite
                with Ghost;
           begin
      Result := OK;
      if S.State /= Wait_Server_Finished then
         Send_HS_Encrypted_Alert (S, HC, Unexpected_Message, Result);
         return;
      end if;
      if Msg_Len /= Hash_Len (HC.Neg) then
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
                  SPARKTLS_Transcript.Append (HC.TS, Data);
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
                  SPARKTLS_Transcript.Append (HC.TS, Data);
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

                 pragma Assert
                   (if HC.Cert_Request_Received
                         and then HC.Cfg.Local /= null
                         and then HC.Cfg.Local.Has_Identity
                    then HC.Cfg.Random /= null);

                 if not Verified then
                    S.Last_Error := Handshake_Failure;
                    Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      end;

              Derive_App_Keys_And_Send_Finished (S, HC, Result);
                              pragma Assert
                                (if Result = Has_Output
                                 then
                                   (if Initial_Suite = Suite_AES_256_GCM_SHA384
                                    then Hash_Len (HC.Neg) = 48
                                    else Hash_Len (HC.Neg) = 32));
                   end Handle_Finished_13;

   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
                    if S.State /= Wait_Certificate then
                       Send_HS_Encrypted_Alert
                         (S, HC, Unexpected_Message, Result);
                       return;
                    end if;
                            Handle_Cert_13 (S, HC, Data, Result);
                                    if Result /= OK then
                                       return;
                                    end if;

                         when Handshake.HT_Certificate_Verify =>
                    if S.State /= Wait_Certificate_Verify then
                       Send_HS_Encrypted_Alert
                         (S, HC, Unexpected_Message, Result);
                       return;
                    end if;
                    if Msg_Len > N32 (Data'Length) - 4 then
                       Send_HS_Encrypted_Alert
                         (S, HC, Decode_Error, Result);
                       return;
                    end if;
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
              HC      : in out Engaged_Context;
              Scratch : in out IO_Buffer;
              Result  :    out Action)
           is
      Enc_Out : N32;
      Cert_Suite    : constant Supported_Suite := S.Negotiated_Suite;
      Cert_Hash_Len : constant N32 := Hash_Len (HC.Neg);
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

            SPARKTLS_Transcript.Append (HC.TS, Empty_Cert);
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

      if HC.Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
        or else HC.Cfg.Local.Int_Count > Max_Pool_Size
        or else
          (for some I in 0 .. Max_Pool_Size - 1 =>
             HC.Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
      then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      --  Send our Certificate chain (leaf + configured intermediates).
      declare
         --  Max: leaf + 8 intermediates, each up to 8 KB + 5 bytes overhead.
         Cert_Buf : Byte_Seq (0 .. 9 * (Max_Cert_DER_Len + 5) + 10);
         Cert_Len : N32;
      begin
         Handshake.Certs.Build_Certificate_Chain
           (Id     => HC.Cfg.Local.all,
            Result => Cert_Buf,
            Len    => Cert_Len);
         if Cert_Len = 0
           or else Cert_Len >= Transcript_Capacity
           or else Cert_Len > Max_Fragment
         then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         pragma Assert (Cert_Len < Transcript_Capacity);
         pragma Assert (Cert_Len <= Max_Fragment);
         if Cert_Len > 0 then
            SPARKTLS_Transcript.Append (HC.TS, Cert_Buf (0 .. Cert_Len - 1));
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
            H_Len : constant N32 := Cert_Hash_Len;
            CV_Hash : Byte_Seq (0 .. H_Len - 1);
         begin
            --  Dispatch on the type-derived hash width (#117).
            if H_Len = 48 then
               CV_Hash := Transcript_Hash_384 (HC);
            else
               declare
                  H : constant Digest := Transcript_Hash_256 (HC);
               begin
                  CV_Hash := H;
               end;
            end if;

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
                  SPARKTLS_Transcript.Append (HC.TS, CV_Buf (0 .. CV_Len - 1));
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

   procedure Build_Client_Finished_384
     (S               : in out Session;
      HC              : in out Engaged_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in     Key_Schedule.Digest_384;
      Result          :    out Action)
   with Pre => S.Negotiated_Suite = Suite_AES_256_GCM_SHA384,
                Post => Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                        and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_384
     (S               : in out Session;
      HC              : in out Engaged_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in     Key_Schedule.Digest_384;
      Result          :    out Action)
   is
      use HKDF384;
      TS_Hash          : constant Key_Schedule.Digest_384 :=
         Transcript_Hash_384 (HC);
      Finished_Key_384 : OKM384_Seq (0 .. 47);
      Verify_48        : Bytes_48;
      Master           : Key_Schedule.Digest_384;
      Client_App_Sec   : OKM384_Seq (0 .. 47);
      Server_App_Sec   : OKM384_Seq (0 .. 47);
      Exporter         : OKM384_Seq (0 .. 47);
      Enc_Out          : N32;
   begin
      Result := OK;

      Key_Schedule.Derive_Finished_Key_384
        (Finished_Key_384, HC.Client_HS_Secret);

      HMAC384.HMAC_SHA_384
        (Output => Verify_48,
         M      => TS_Hash,
         K      => Byte_Seq (Finished_Key_384));

      declare
         Big_Finished : Byte_Seq (0 .. 51) := (others => 0);
      begin
         Big_Finished (0) := Handshake.HT_Finished;
         Big_Finished (1) := 16#00#;
         Big_Finished (2) := 16#00#;
         Big_Finished (3) := 16#30#;
         Big_Finished (4 .. 51) := Verify_48;

         SPARKTLS_Transcript.Append (HC.TS, Big_Finished);

         Records.Build_Encrypted_Record
           (Plaintext  => Big_Finished,
            Inner_Type => 16#16#,
            Keys       => HC.Client_HS,
            Output     => Scratch,
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
        (Client_App_Sec, Server_App_Sec, Master, App_TS_Hash_384);
      Key_Schedule.Derive_Exporter_Master_Secret_384
        (Exporter, Master, App_TS_Hash_384);

      HC.Master_Secret := Bytes_48 (Master);
      S.Exporter_Secret := Bytes_48 (Exporter);
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := HC.Client_Random;
      S.Exporter_Server_Random := HC.Server_Random;
      HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
      Set_Traffic_Keys
        (S.Client_App, Bytes_48 (Byte_Seq (Client_App_Sec)),
         S.Negotiated_Suite);
      Set_Traffic_Keys
        (S.Server_App, Bytes_48 (Byte_Seq (Server_App_Sec)),
         S.Negotiated_Suite);

      --  RFC 8446 §4.6.3: retain the secrets themselves, not just the
      --  derived key/IV, so KeyUpdate can ratchet to the next generation.
      S.Client_App_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
      S.Server_App_Secret := Bytes_48 (Byte_Seq (Server_App_Sec));
      S.App_Secret_Len    := 48;
   end Build_Client_Finished_384;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      HC              : in out Engaged_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in     Digest;
      Result          :    out Action)
   with Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                           | Suite_CHACHA20_POLY1305_SHA256,
                Post => Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
                        and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      HC              : in out Engaged_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in     Digest;
      Result          :    out Action)
   is
      Finished_Buf       : Byte_Seq (0 .. 35);
      Finished_Len       : N32;
      TS_Hash            : constant Digest := Transcript_Hash_256 (HC);
      Client_Finished_Key : OKM_Seq (0 .. 31);
      Client_Verify      : Digest;
      Master             : Digest;
      Client_App_Sec     : OKM_Seq (0 .. 31);
      Server_App_Sec     : OKM_Seq (0 .. 31);
      Exporter           : OKM_Seq (0 .. 31);
      Enc_Out            : N32;
   begin
      Result := OK;

      Key_Schedule.Derive_Finished_Key
        (Client_Finished_Key, HC.Client_HS_Secret (0 .. 31));

      HMAC_SHA_256
        (Output => Client_Verify,
         M      => TS_Hash,
         K      => Byte_Seq (Client_Finished_Key));

      Handshake.Build_Finished
        (Client_Verify, Finished_Buf, Finished_Len);

      SPARKTLS_Transcript.Append (HC.TS, Finished_Buf (0 .. Finished_Len - 1));

      Records.Build_Encrypted_Record
        (Plaintext  => Finished_Buf (0 .. Finished_Len - 1),
         Inner_Type => 16#16#,
         Keys       => HC.Client_HS,
         Output     => Scratch,
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
        (Client_App_Sec, Server_App_Sec, Master, App_TS_Hash_256);
      Key_Schedule.Derive_Exporter_Master_Secret
        (Exporter, Master, App_TS_Hash_256);

      HC.Master_Secret := (others => 0);
      HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));
      S.Exporter_Secret := (others => 0);
      S.Exporter_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Exporter));
      S.Exporter_Secret_Len := 32;
      S.Exporter_Client_Random := HC.Client_Random;
      S.Exporter_Server_Random := HC.Server_Random;

      declare
         CS48 : Bytes_48 := (others => 0);
         SS48 : Bytes_48 := (others => 0);
      begin
         CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
         SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
         Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
         Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);

         --  RFC 8446 §4.6.3: retain the secrets for the KeyUpdate ratchet.
         S.Client_App_Secret := CS48;
         S.Server_App_Secret := SS48;
         S.App_Secret_Len    := 32;
      end;
   end Build_Client_Finished_256;

   --  After verifying server Finished, derive app keys and send client Finished
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
   is
      Cert_Result  : Action;
      --  Atomic flight assembly: client mTLS flight is
      --  [Cert + CertVerify] (optional) + CCS + Finished. We build into
      --  Scratch and only commit once everything fits, so the peer
      --  never sees a half-flight. Each Build_Encrypted_Record call
      --  advances HC.Client_HS.Counter; we save it and restore on any
      --  failure to keep AEAD nonces in sync with what the peer saw.
      Scratch   : IO_Buffer;
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
         declare
            Pre_CCS_Out : N32;
         begin
            Records.Build_CCS_Record (Scratch, Pre_CCS_Out);
            if Pre_CCS_Out = 0 then
               S.Last_Error := Insufficient_Buffer;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;
         end;
      end if;

      --  mTLS: send client certificate before Finished if requested
      Send_Client_Certificate (S, HC, Scratch, Cert_Result);
      if Cert_Result /= OK then
         if S.State = Wait_Server_Finished then
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
         end if;
         Result := Error_Alert;
         return;
      end if;

      if S.State /= Wait_Server_Finished then
         Result := Error_Alert;
         return;
      end if;

      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         Build_Client_Finished_384
           (S, HC, Scratch, App_TS_Hash_384, Result);
         if Result /= OK then
            return;
         end if;
      when others =>
         pragma Assert
           (S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                | Suite_CHACHA20_POLY1305_SHA256);
         Build_Client_Finished_256
           (S, HC, Scratch, App_TS_Hash_256, Result);
         if Result /= OK then
            return;
         end if;
      end case;

      if S.State /= Wait_Server_Finished then
         Result := Error_Alert;
         return;
      end if;

      --  Atomic commit: full client flight assembled in Scratch.
      if Free_Space (S.Output) < Scratch.Write_Pos then
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
   procedure Copy_Input_Fragment
             (S    : in     Session;
                      HC   : in out Engaged_Context;
                      From : in     N32;
                      Len  : in     N32)
           with Pre => HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Len in 1 .. Max_HS_Msg
               and then From <= N32'Last - Len
               and then From + Len <= IO_Buffer_Capacity,
                Post => Used (HC.Reasm) = Len
                        and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                        and then
                  (if HC.Cfg.Random'Old /= null
                   then HC.Cfg.Random /= null);

   procedure Copy_Input_Fragment
     (S    : in     Session;
              HC   : in out Engaged_Context;
              From : in     N32;
              Len  : in     N32)
   is
   begin
      --  Start a fresh reassembly from this fragment. Callers used to set the
      --  Phase/Len/Need triple themselves and then call this to move the
      --  bytes -- two half-updates that had to agree. Now the bytes ARE the
      --  state.
      Reset (HC.Reasm);
      Append (HC.Reasm, S.Input.Data (From .. From + Len - 1));
   end Copy_Input_Fragment;

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
           with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Frag_Len in 1 .. 3
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then Next_Read <= S.Input.Write_Pos,
                Post => Result = OK
                        and then S.State = Wait_Server_Hello
                                and then HC.Cfg.Random /= null
                                        and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
;

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
   is
   begin
                              Copy_Input_Fragment
                                (S, HC, Frag_Start, Frag_Len);
                      S.Input.Read_Pos := Next_Read;
                      Result := OK;
                      pragma Assert (HC.Cfg.Random /= null);
                   end Start_Pending_SH_Reassembly;

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
           with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Frag_Len >= 4
                       and then HS_Total > Frag_Len
                       and then HS_Total <= 131072
                       and then HS_Total <= Transcript_Capacity
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then Next_Read <= S.Input.Write_Pos,
                Post => Result = OK
                        and then S.State = Wait_Server_Hello
                                        and then HC.Cfg.Random /= null
                                                        and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length);

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
   is
   begin
                              Copy_Input_Fragment
                                (S, HC, Frag_Start, Frag_Len);
                      S.Input.Read_Pos := Next_Read;
                      Result := OK;
                      pragma Assert (HC.Cfg.Random /= null);
                   end Start_Spanning_SH_Reassembly;

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size)
           with Pre => S.State = Wait_Server_Hello
                               and then HC.Cfg.Random /= null
                               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
                               and then Frag_Len >= 4
                       and then HS_Total >= 4
                       and then HS_Total <= Frag_Len
                       and then HS_Total <= Transcript_Capacity
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then Next_Read <= S.Input.Write_Pos,
                        Post => S.State = Wait_Server_Hello
                                and then HC.Cfg.Random /= null
                                                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length);

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size)
   is
   begin
                              Copy_Input_Fragment
                                (S, HC, Frag_Start, Frag_Len);
                      S.Input.Read_Pos := Next_Read;
                      pragma Assert (HC.Cfg.Random /= null);
                   end Start_Complete_SH_Reassembly;

   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      HC         : in out Engaged_Context;
      Rec        : in     Records.Parse_Result;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Result     :    out Action)
   is
      Next_Read : constant Buffer_Size := S.Input.Read_Pos + Rec.Record_Len;
   begin
      Result := OK;
                           --  Fresh record. Frag_Len < 4 → start
                           --  reassembly with Hdr_Pending sentinel.
                           if Frag_Len < 4 then
                              Start_Pending_SH_Reassembly
                                (S, HC, Frag_Len, Frag_Start,
                                 Next_Read, Result);
                              return;
                           end if;

                           --  Header is in this fragment. Decode
                           --  HS_Total; if msg spans, start reassembly.
                           declare
                              pragma Assert
                                (Frag_Start + 3 <= S.Input.Data'Last);
                              HS_Len : constant N32 :=
                                 N32 (S.Input.Data (Frag_Start + 1))
                                   * 65536 +
                                 N32 (S.Input.Data (Frag_Start + 2))
                                   * 256 +
                                 N32 (S.Input.Data (Frag_Start + 3));
                              HS_Total : constant N32 := HS_Len + 4;
                           begin
                                      if HS_Total > Max_HS_Msg
                                        or else HS_Total > Transcript_Capacity
                                      then
                                 S.Input.Read_Pos := Next_Read;
                                 S.Last_Error := Decode_Error;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                              if HS_Total > Frag_Len then
                                 Start_Spanning_SH_Reassembly
                                   (S, HC, Frag_Len, Frag_Start, HS_Total,
                                    Next_Read, Result);
                                 return;
                              end if;
                              --  Single-record happy path: buffer the
                              --  WHOLE record fragment (which may include
                              --  trailing packed messages per BoGo's
                              --  PackHandshakeFlight). The buffer reports
                              --  one message at a time, so the TLS 1.2
                              --  Process_Server_Flight drains the rest.
                              Start_Complete_SH_Reassembly
                                (S, HC, Frag_Len, Frag_Start, HS_Total,
                                 Next_Read);
                           end;
   end Reasm_Fresh_Fragment;

   procedure Reassemble_For_SH
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
      Frag_Len : constant N32 := Rec.Fragment_Len;
      Frag_Start : constant N32 :=
         S.Input.Read_Pos + Rec.Fragment_Pos;
   begin
      Result := OK;
                                   if Used (HC.Reasm) > 0
                                then
                                   if Has_Message (HC.Reasm) then
                                      Result := OK;
                              pragma Assert (S.State = Wait_Server_Hello);
                              pragma Assert (HC.Cfg.Random /= null);
                                      return;
                                   end if;

                           declare
                              Take : constant HS_Msg_Len :=
                                 N32'Min (N32'Min (Wanted (HC.Reasm),
                                                   Frag_Len),
                                          Free_Space (HC.Reasm));
                           begin
                              if Take > 0 then
                                 Append
                                   (HC.Reasm,
                                    S.Input.Data
                                      (Frag_Start ..
                                       Frag_Start + Take - 1));
                              end if;
                           end;
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;

                           --  Header just arrived: validate the peer's
                           --  declared size. Nothing is stored -- the size is
                           --  read from the bytes themselves.
                           if Header_Ready (HC.Reasm) then
                              if Message_Too_Large (HC.Reasm)
                                or else Declared_Size (HC.Reasm) >
                                          Transcript_Capacity
                              then
                                 Reset (HC.Reasm);
                                 S.Last_Error := Decode_Error;
                                 Set_State (S, Error_State);
                                 Result := Error_Alert;
                                 return;
                              end if;
                           end if;

                                   if not Has_Message (HC.Reasm) then
                                      Result := OK;
                              pragma Assert (S.State = Wait_Server_Hello);
                              pragma Assert (HC.Cfg.Random /= null);
                                      return;  --  need more fragments
                                   end if;
                        else
                                   Reasm_Fresh_Fragment
                                     (S, HC, Rec, Frag_Len, Frag_Start, Result);
                           pragma Assert
                             (if Result = OK then S.State = Wait_Server_Hello);
                                   pragma Assert
                                     (if Result = OK then HC.Cfg.Random /= null);
                                        end if;
           end Reassemble_For_SH;

   procedure Finalize_SH_Processing
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
                          and then Has_Message (HC.Reasm)
                        then
                           --  Drop the ServerHello and keep whatever the peer
                           --  packed behind it, so the next
                           --  Process_Server_Flight call drains it. That is
                           --  exactly Consume: the shift, the tail clear, the
                           --  next header decode and the re-derivation of the
                           --  following message's size were all this one
                           --  operation open-coded, with nine bounds asserts
                           --  to justify the arithmetic.
                           Consume (HC.Reasm);

                           --  The NEXT message's declared size is peer data,
                           --  so it is validated here rather than trusted.
                           if Header_Ready (HC.Reasm)
                             and then (Message_Too_Large (HC.Reasm)
                                       or else Declared_Size (HC.Reasm) >
                                                 Transcript_Capacity)
                           then
                              Reset (HC.Reasm);
                              S.Last_Error := Decode_Error;
                              Set_State (S, Error_State);
                              Result := Error_Alert;
                              return;
                           end if;
                        else
                           Reset (HC.Reasm);
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
                           if HC.T12.Sent_Ticket_Ext
                             and then HC.T12.Server_Will_Issue
                             and then HC.Cfg.TLS12_Resume_Ticket.Valid
                             and then HC.Cfg.TLS12_Resume_Ticket.Suite
                                        = Wire_Of (S.Negotiated_Suite_12)
                           then
                              HC.T12.Resuming := True;
                                      HC.Master_Secret_12 :=
                                         HC.Cfg.TLS12_Resume_Ticket.Master_Secret;
                                   end if;
                                   S.State := Wait_Server_Finished;
                        end if;
                        Result := OK;
   end Finalize_SH_Processing;

   procedure Parse_SH_From_Reasm_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Result :    out Action)
   is
   begin
                        Result := OK;
                        --  Full ServerHello reassembled.
                        declare
                           Frag : constant Message_Bytes := Message (HC.Reasm);
         pragma Assert (Has_Message (HC.Reasm));  --  PROBE-T8
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
                             (S, HC, Byte_Seq (Frag), Parse_OK);

                                   if not Parse_OK
                                     and then S.Last_Error = No_Error
                                   then
                                      HC.Version := TLS_1_2;
                                      Handshake.TLS12.Parse_Server_Hello_12
                                        (S, HC, Byte_Seq (Frag), Parse_OK);
                                      pragma Assert
                                        (if Parse_OK then HC.Version = TLS_1_2);
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
                                 Ignored_A : N32;
                              begin
                                 Records.Build_Plaintext_Alert
                                   (Level     => 2,
                                    Desc      =>
                                       Alert_Desc (S.Last_Error),
                                    Output    => S.Output,
                                    Bytes_Out => Ignored_A);
                              end;
                                      S.State := Error_State;
                                      Result := (if Output_Pending (S) > 0
                                         then Has_Output else Error_Alert);
                              Reset (HC.Reasm);
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
                              if Used (HC.Reasm) > Message_Length (HC.Reasm) then
      pragma Assert (Has_Message (HC.Reasm));  --  PROBE-T8
                                 declare
                                    Ignored_A : N32;
                                 begin
                                    Records.Build_Plaintext_Alert
                                      (Level     => 2,
                                       Desc      =>
                                         Alert_Desc (Unexpected_Message),
                                       Output    => S.Output,
                                       Bytes_Out => Ignored_A);
                                 end;
                                 S.Last_Error := Unexpected_Message;
                                 S.State := Error_State;
                                 Result := (if Output_Pending (S) > 0
                                            then Has_Output
                                            else Error_Alert);
                                 Reset (HC.Reasm);
                                 return;
                              end if;

                              --  RFC 8446 4.4.1 via the streaming ADT.
                              --  The HRR names the suite, so select the
                              --  digest first; the OLD code hard-coded
                              --  SHA-256 here, wrong for 384 suites.
                              SPARKTLS_Transcript.Select_Hash
                                (HC.TS,
                                 (if S.Negotiated_Suite =
                                        Suite_AES_256_GCM_SHA384
                                  then SPARKTLS_Transcript.Only_384
                                  else SPARKTLS_Transcript.Only_256));
                              SPARKTLS_Transcript.Reset_For_HRR (HC.TS);
                                              SPARKTLS_Transcript.Append (HC.TS, Byte_Seq (Frag));
                                                      if HC.Cfg.Random = null
                                                        or else HC.HRR_Cookie_Len >
                                                          N32 (HC.HRR_Cookie'Length)
                                                        or else
                                                          (HC.Cfg.TLS12_Resume_Ticket.Valid
                                                           and then
                                                             HC.Cfg.TLS12_Resume_Ticket
                                                               .Ticket_Len >
                                                                 Max_TLS12_Ticket_Len)
                                                              then
                                                         S.Last_Error := Internal_Error;
                                                         S.State := Error_State;
                                                 Result := Error_Alert;
                                                 Reset (HC.Reasm);
                                                         return;
                                                      end if;
                                                      pragma Assert
                                                        (HC.HRR_Cookie_Len <=
                                                           N32 (HC.HRR_Cookie'Length));
                                                      --  Build and send CH2.
                                      declare
                                 CH2_Buf : Byte_Seq
                                   (0 .. Handshake.Client_Msgs
                                            .Max_Client_Hello - 1);
                                 CH2_Len : N32;
                                 Ignored_Rec_Out : N32;
                              begin
                                 Handshake.Client_Msgs.Build_Client_Hello
                                   (S, HC, CH2_Buf, CH2_Len,
                                    Retry_Mode => True);
                                         if CH2_Len = 0
                                           or else CH2_Len >
                                             N32 (CH2_Buf'Length)
                                         then
                                            S.Last_Error := Internal_Error;
                                            S.State := Error_State;
                                            Result := Error_Alert;
                                    Reset (HC.Reasm);
                                    return;
                                 end if;
                                         SPARKTLS_Transcript.Append (HC.TS, CH2_Buf (0 .. CH2_Len - 1));
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
                                    Ignored_CCS_Bytes : N32;
                                 begin
                                    Records.Build_CCS_Record
                                      (S.Output, Ignored_CCS_Bytes);
                                 end;
                                         HC.Sent_HRR_CCS := True;
                                 Records.Build_Handshake_Record
                                   (CH2_Buf (0 .. CH2_Len - 1),
                                    S.Output, Ignored_Rec_Out);
                                      end;
                              --  Reset Has_TLS_1_3 so the next SH
                              --  parse re-derives it; without this,
                              --  the second SH's matrix lookup uses
                              --  a stale Where.
                              Reset (HC.Reasm);
                                                      HC.Has_TLS_1_3 := False;
                                                              Result := Has_Output;
                                              return;
                                           end if;

                                                           SPARKTLS_Transcript.Append (HC.TS, Byte_Seq (Frag));
                                           pragma Assert
                                             (if HC.Version = TLS_1_3
                                              then S.Negotiated_Suite in
                                                Suite_AES_128_GCM_SHA256
                                              | Suite_AES_256_GCM_SHA384
                                              | Suite_CHACHA20_POLY1305_SHA256);
                                           pragma Assert
                                             (HC.HRR_Cookie_Len <=
                                                N32 (HC.HRR_Cookie'Length));
                                                        end;
   end Parse_SH_From_Reasm_13;

   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
      if not Has_Message (HC.Reasm) then return; end if;

      Parse_SH_From_Reasm_13 (S, HC, Result);
      if Result /= OK then return; end if;
      if S.State /= Wait_Server_Hello then return; end if;

      --  Pre guarantees HC.Cfg.Random /= null at entry, but the fact is
      --  not carried through the in out reassembly calls above.
      --  Semantically unreachable; fail closed (same pattern as
      --  Server.TLS12's Ready_Config membership guards).
      if HC.Cfg.Random = null then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      Finalize_SH_Processing (S, HC, Result);
   end Handle_WSH_HS_Frame;

   procedure Handle_WSH_Frame_13
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
                                      pragma Assert (A <= N32 (S.Output.Data'Length));
                                   end;
                           S.Last_Error := Unexpected_Message;
                           Set_State (S, Error_State);
                           Result := (if Output_Pending (S) > 0
                                      then Has_Output else Error_Alert);
                        end if;
                     end;

                          when Records.Content_Alert =>
                             --  Plaintext alert before keys are established
                             --  (e.g. server's close_notify, warning alert,
                             --  or fatal alert). TLS 1.2 peers may send
                             --  warning-level unrecognized_name before
                             --  ServerHello; tolerate bounded warning alerts
                             --  like the later TLS 1.2 alert-handling paths.
                             declare
                                Alert_Pos : constant N32 :=
                                   S.Input.Read_Pos + Rec.Fragment_Pos;
                             begin
                                S.Input.Read_Pos :=
                                   S.Input.Read_Pos + Rec.Record_Len;
                                if Rec.Fragment_Len /= 2 then
                                   S.Last_Error := Decode_Error;
                                   Set_State (S, Error_State);
                                   Result := Error_Alert;
                                elsif S.Input.Data (Alert_Pos) = 1
                                  and then S.Input.Data (Alert_Pos + 1) /= 0
                                then
                                   if S.Warning_Alerts_Recvd >= Max_Warning_Alerts
                                   then
                                      S.Last_Error := Decode_Error;
                                      Set_State (S, Error_State);
                                      Result := Error_Alert;
                                   else
                                      S.Warning_Alerts_Recvd :=
                                         S.Warning_Alerts_Recvd + 1;
                                      Result := OK;
                                   end if;
                                elsif S.Input.Data (Alert_Pos + 1) = 0 then
                                   --  close_notify before ServerHello: the peer
                                   --  hung up mid-handshake. Unchanged behaviour.
                                   S.Last_Error := Unexpected_Message;
                                   Set_State (S, Error_State);
                                   Result := Error_Alert;
                                else
                                   --  Fatal alert. Reflect the peer's description
                                   --  instead of discarding it: the server has
                                   --  just told us why it rejected the handshake
                                   --  (e.g. handshake_failure when no signature
                                   --  algorithm is shared), and reporting
                                   --  "unexpected message" hides that. No alert
                                   --  is queued in reply -- we are reacting to
                                   --  the peer's alert, not raising our own.
                                   S.Last_Error :=
                                      Error_From_Alert (S.Input.Data (Alert_Pos + 1));
                                   Set_State (S, Error_State);
                                   Result := Error_Alert;
                                end if;
                             end;

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
      HC     : in out Engaged_Context;
      Result :    out Action)
   is
   begin
      --  Fail closed: a null RNG or an empty transcript here means the
      --  session was never initialised properly (Connect appends the
      --  ClientHello and validates the config). The handler Pres below
      --  all rely on these two facts; establish them by dominance
      --  instead of threading them through every caller.
      if HC.Cfg.Random = null then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

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
            elsif HC.Cfg.Random = null then
               --  Fail closed: both are OUR-logic invariants (the
               --  transcript accumulated the whole handshake to get here;
               --  Init's gate requires Random). Unreachable, and the one
               --  guard discharges the four hash/ticket Pres below.
               S.Last_Error := Internal_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
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

   procedure Scrub_Handshake_Context (HC : in out Handshake_Context)
   is
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
      if HC.Phase = Engaged then
         SPARKTLS_Transcript.Wipe (HC.TS);
      end if;
      HC.T12.Resumed_Master_Secret := (others => 0);
      HC.EMS_Session_Hash := (others => 0);
      HC.PSK.Value := (others => 0);
      HC.PSK.Binder := (others => 0);
      HC.PSK.Offer_ID := (others => 0);
      HC.Client_Random := (others => 0);
      HC.Server_Random := (others => 0);
      Reset (HC.Reasm);
   end Scrub_Handshake_Context;

   procedure Advance_Client_Non_Handshake
     (S       : in out Session;
      Result  :    out Action;
      Handled :    out Boolean)
   with Pre => S.Role = Role_Client
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
               and then Empty_Records_Bounded_RFC_8446_5_2 (S),
                --  Frame, scoped deliberately to the not-Handled path.
                --
                --  That is the only path Advance continues on, and it is the
                --  "others" branch here, which assigns nothing but Result and
                --  Handled. So this is provable locally, WITHOUT pushing frame
                --  conditions down into Process_Connected / Process_Connected_12
                --  and the rest of the TLS 1.3 handler chain -- threading frames
                --  through that chain previously turned one finding into six and
                --  had to be reverted, so it is avoided here on purpose.
                Post => (if not Handled then
                           S.State = S.State'Old
                           and then S.Role = S.Role'Old
                           and then Has_Context (S) = Has_Context (S)'Old)
           is
   begin
      Handled := True;
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
            elsif Input_Available (S) > 0 then
               if S.Negotiated_Version = TLS_1_2 then
                  SPARKTLS.Client.TLS12.Process_Connected_12 (S, Result);
               else
                  Process_Connected (S, Result);
               end if;
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

         when Closed =>
            --  The connection is finished. A peer may still have records
            --  in flight -- BoGo's Shutdown-Shim-* tests drain after
            --  close_notify with -check-close-notify, and a real
            --  application may call Advance again for the same reason.
            --  Report Shutdown idempotently and discard anything that
            --  arrives: the traffic keys have already been zeroed, so
            --  there is nothing left to decrypt with, and nothing useful
            --  a late record could tell us.
            --
            --  Before 2026-08-17 this fell through to "others", which set
            --  Handled := False and let Advance reach its "HC_Ptr = null"
            --  branch -- reporting Internal_Error for the entirely normal
            --  act of calling Advance on a closed session.
            S.Input.Read_Pos  := 0;
            S.Input.Write_Pos := 0;
            Result := Shutdown;

         when others =>
            Handled := False;
            Result := Need_Input;
      end case;
   end Advance_Client_Non_Handshake;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   is
      Handled : Boolean;
   begin
      Advance_Client_Non_Handshake (S, Result, Handled);
      if not Handled then
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
         --
         --  BORROW: the handshake handlers take both S and the context.
         --  Passing S and S.HC_Ptr.C together is aliasing (SPARK RM
         --  6.4.2, reported as "high" by flow analysis -- note that
         --  --mode=check_all does NOT catch this, since aliasing is a flow
         --  check rather than a legality one). Move the pointer out of S
         --  for the duration of the call so S no longer reaches the
         --  context, then hand ownership back.
         declare
            HC : Handshake_Context_Access := S.HC_Ptr;
         begin
            S.HC_Ptr := null;

            --  State-phase coupling: the client context is Engaged from
            --  Initialize_Client_Handshake onward (a failed CH build
            --  fail-closes the session before we can get here). The two
            --  Engaged_Context conversions below each carry a residual
            --  discriminant VC -- no invariant ties S.State to the heap
            --  box's contents; both die with #106 (co-locate HC with the
            --  session, state the coupling as a session predicate).
            if HC.C.Version = TLS_1_2
               and S.State /= Client_Hello_Sent
               and S.State /= Wait_Server_Hello
            then
               SPARKTLS.Client.TLS12.Advance_Handshake_12
                 (S, HC.C, Result);
            else
               Advance_Handshake (S, HC.C, Result);
            end if;

            S.HC_Ptr := HC;
         end;

         if S.State = Connected or S.State = Error_State then
            S.Peer_Cert_Valid := S.HC_Ptr.C.Peer_Leaf.Present;
            S.Use_EMS := S.HC_Ptr.C.Use_EMS;
            --  Persist resumption flags out of HC before free.
            S.Resumed_From_PSK := S.HC_Ptr.C.Using_PSK;
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
            Scrub_Handshake_Context (S.HC_Ptr.C);
            HC_Alloc.Free (S.HC_Ptr);
         end if;
      end if;
   end Advance;

   --  Helper: derive key/IV and set Traffic_Keys based on suite.
   --  Suite must be one of the three RFC 8446 TLS-1.3 / RFC 5288/7905
   --  TLS-1.2 negotiable AEAD suites — matches the Traffic_Keys
   --  Predicate at sparktls.ads:770.
   procedure Set_Traffic_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Supported_Suite)
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
               Key_Schedule.Derive_Traffic_Key_IV
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
      HC : in out Engaged_Context)
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
            if (HC.KE.Negotiated and then HC.KE.Curve = 16#0018#) then
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, Byte_Seq (HC.KE.Shared), Early);
            else
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, HC.KE.Shared (0 .. 31), Early);
            end if;

            HC.Handshake_Secret := Bytes_48 (HS_Secret);
            HC.Neg := (Suite => S.Negotiated_Suite);

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
            if (HC.KE.Negotiated and then HC.KE.Curve = 16#0018#) then
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, Byte_Seq (HC.KE.Shared), Early);
            else
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, HC.KE.Shared (0 .. 31), Early);
            end if;

            HC.Handshake_Secret := (others => 0);
            HC.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
            HC.Neg := (Suite => S.Negotiated_Suite);

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

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   is
   begin
      Process_Handshake_Message (S, HC, Msg, Result);
   end Dispatch_Decrypted_HS_Message;

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    :    out Action)
   is
   begin
              declare
                 Full : constant Message_Bytes := Message (HC.Reasm);
              begin
                 Reset (HC.Reasm);
                 Dispatch_Decrypted_HS_Message (S, HC, Byte_Seq (Full), Result);
              end;
                      pragma Assert
                (if Result = OK
                                   and then Pos < Plain_Len
                                   and then S.State in Wait_Encrypted_Extensions
                                 | Wait_Certificate_Request
                                 | Wait_Certificate
                                 | Wait_Certificate_Verify
                                 | Wait_Server_Finished
         then
            S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                | Suite_AES_256_GCM_SHA384
                                | Suite_CHACHA20_POLY1305_SHA256);
              pragma Assert
                (if Result = OK
             and then S.State in Wait_Encrypted_Extensions
                                 | Wait_Certificate_Request
                                 | Wait_Certificate
                                 | Wait_Certificate_Verify
                                 | Wait_Server_Finished
         then
            S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                | Suite_AES_256_GCM_SHA384
                                | Suite_CHACHA20_POLY1305_SHA256);
              if Result = Error_Alert then
                 Pos := Plain_Len;  --  skip rest
              end if;
              pragma Assert
                (if Result = OK
             and then S.State in Wait_Encrypted_Extensions
                                 | Wait_Certificate_Request
                                 | Wait_Certificate
                                 | Wait_Certificate_Verify
                                 | Wait_Server_Finished
         then
            S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                | Suite_AES_256_GCM_SHA384
                                | Suite_CHACHA20_POLY1305_SHA256);
   end Dispatch_Completed_Decrypted_Reasm;

   procedure Copy_Decrypted_Reasm_Bytes
     (HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      From      : in     N32;
      Take      : in     N32)
   is
   begin
      Append (HC.Reasm, Plaintext (From .. From + Take - 1));
   end Copy_Decrypted_Reasm_Bytes;

   procedure Check_Declared_Message_Size
     (HC            : in out Engaged_Context;
      Decode_Failed :    out Boolean)
   is
   begin
      --  Nothing to "decode" any more: the buffer derives the declared size
      --  from its own bytes 1 .. 3, so there is no second copy to keep in
      --  step. What remains is the peer-controlled bound check, which is a
      --  protocol decision rather than accounting.
      Decode_Failed := Message_Too_Large (HC.Reasm);
      if Decode_Failed then
         Reset (HC.Reasm);
      end if;
   end Check_Declared_Message_Size;

   procedure Fill_Decrypted_HS_Reassembly
     (HC            : in out Engaged_Context;
      Plaintext     : in     Byte_Seq;
      Plain_Len     : in     N32;
      Pos           :    out N32;
      Decode_Failed :    out Boolean)
   is
   begin
      Decode_Failed := False;
      Pos           := 0;

      --  Two rounds, for one reason: until four bytes are in, the buffer only
      --  wants the rest of the HEADER and the body size is still unknown. The
      --  first round completes the header, the second drains body bytes from
      --  the same record. BoGo SplitHandshakeRecords (1-byte fragments)
      --  exercises that boundary.
      --
      --  No "Need - Len" and no buffer-bound asserts: Wanted computes the
      --  shortfall inside the module, where each branch makes its own
      --  subtraction safe, and Append's precondition falls out of the Min
      --  against Free_Space.
      for Round in 1 .. 2 loop
         exit when Message_Too_Large (HC.Reasm);

         declare
            Take : constant HS_Msg_Len :=
               N32'Min (N32'Min (Wanted (HC.Reasm), Plain_Len - Pos),
                        Free_Space (HC.Reasm));
         begin
            if Take > 0 then
               Append (HC.Reasm,
                       Plaintext (Plaintext'First + Pos ..
                                  Plaintext'First + Pos + Take - 1));
               Pos := Pos + Take;
            end if;
         end;

         --  The peer's declared size becomes readable the moment the header
         --  lands, so the bound check belongs between the two rounds.
         if Round = 1 and then Header_Ready (HC.Reasm) then
            Check_Declared_Message_Size (HC, Decode_Failed);
            if Decode_Failed then
               return;
            end if;
         end if;
      end loop;
   end Fill_Decrypted_HS_Reassembly;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       :    out N32;
      Result    :    out Action)
   is
   begin
      Result := OK;
      Pos := 0;

      if Used (HC.Reasm) > 0 then
         if not Has_Message (HC.Reasm) then
            declare
               Decode_Failed : Boolean;
            begin
               Fill_Decrypted_HS_Reassembly
                 (HC, Plaintext, Plain_Len, Pos, Decode_Failed);

               if Decode_Failed then
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;
            end;
         end if;

         if Has_Message (HC.Reasm) then
            --  The message has to fit the transcript we are about to append
            --  it to. Peer-declared, so it is checked rather than trusted.
            if Message_Length (HC.Reasm) > Transcript_Capacity then
               Reset (HC.Reasm);
               S.Last_Error := Decode_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Dispatch_Completed_Decrypted_Reasm
              (S, HC, Plain_Len, Pos, Result);
         else
            --  Still need more data
            Pos := Plain_Len;  --  consumed all
         end if;
      end if;
   end Continue_Decrypted_HS_Reassembly;

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    : in out Action)
   is
   begin
      declare
         HS_Len : constant N32 :=
            N32 (Plaintext (Pos + 1)) * 65536 +
            N32 (Plaintext (Pos + 2)) * 256 +
            N32 (Plaintext (Pos + 3));
         Msg_Total : constant N32 := 4 + HS_Len;
         Msg_End   : constant N32 := Pos + Msg_Total;
      begin
         --  PHM.Pre requires Data'Length <= Transcript_Capacity.
         --  Reject oversize HS messages early so we do not allocate
         --  beyond what we can transcript.
         if Msg_Total > Transcript_Capacity then
            S.Last_Error := Decode_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            Pos := Plain_Len;
            return;
         end if;

                 if Msg_End > Plain_Len then
                    --  Message spans into the next record: keep what this
                    --  one carries. The declared size comes back out of the
                    --  buffer's own header, so it is not recorded twice.
                    Reset (HC.Reasm);
                    Append (HC.Reasm, Plaintext (Pos .. Plain_Len - 1));
                    Pos := Plain_Len;
                    return;
                 end if;

                 --  Complete message -- process it.
                 if HC.Cert_Request_Received
                   and then HC.Cfg.Local /= null
                   and then HC.Cfg.Local.Has_Identity
                   and then
                     (HC.Cfg.Random = null
                              or else HC.Cfg.Local.NaCl_Cert_Len
                                not in 1 .. N32 (Max_Cert_DER)
                              or else not
                                (HC.Negotiated_Sig_Algo = 0
                                 or else
                                   (case HC.Cfg.Local.Sign_Algo is
                                       when Sign_Ed25519 =>
                                          HC.Negotiated_Sig_Algo = 16#0807#,
                                       when Sign_ECDSA_P256 =>
                                          HC.Negotiated_Sig_Algo = 16#0403#,
                                       when Sign_ECDSA_P384 =>
                                          HC.Negotiated_Sig_Algo = 16#0503#,
                                       when Sign_RSA_PSS =>
                                          HC.Negotiated_Sig_Algo in
                                            16#0804# | 16#0805# | 16#0806#,
                                       when Sign_None =>
                                          False))
                      or else
                        (HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                         and then HC.Cfg.Local.RSA_Mod_Len not in 64 .. 512)
                      or else HC.Client_HS.Counter > Unsigned_64'Last - 2)
                 then
                    S.Last_Error := Internal_Error;
                    Set_State (S, Error_State);
                    Result := Error_Alert;
                    Pos := Plain_Len;
                    return;
                 end if;

                 declare
                    Msg_Copy : Byte_Seq (0 .. Msg_Total - 1);
                 begin
                    Msg_Copy := Plaintext (Pos .. Msg_End - 1);
                    Dispatch_Decrypted_HS_Message (S, HC, Msg_Copy, Result);
                 end;

         Pos := Msg_End;

         --  Has_Output is either a fatal alert flight or the successful
         --  client Finished flight. In either case this record must not
         --  contain another server handshake message.
         if Result /= OK then
                    if Result = Has_Output
                      and then S.State not in Idle | Closing | Closed | Error_State
                      and then Pos < Plain_Len
                    then
                       Send_App_Encrypted_Alert
                            (S, Unexpected_Message, Result);
                    end if;
                    return;
         end if;

         if S.State = Error_State then
            return;
         end if;

         --  RFC 8446 §4.4.4: server Finished is the last server
         --  handshake message. After dispatch moves us out of the
         --  expected server-handshake states, any trailing plaintext is
         --  excess handshake data.
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
                    Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
                 end if;
      end;
   end Process_One_Decrypted_HS_Message;

   procedure Process_Decrypted_HS_Packed_Messages
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    : in out Action)
   is
   begin
      --  Process complete messages in this record. Loop condition
      --  includes state sanity so the loop exits cleanly after PHM
      --  moves us to Error_State.
      while Pos + 4 <= Plain_Len
        and then Result = OK
        and then S.State in Wait_Encrypted_Extensions
                            | Wait_Certificate_Request
                            | Wait_Certificate
                            | Wait_Certificate_Verify
                            | Wait_Server_Finished
      loop
                 pragma Loop_Invariant
                   (Pos >= 0 and then Pos + 4 <= Plain_Len
                    and then Result = OK
                    and then Plain_Len <= N32 (Plaintext'Length)
                    and then Plaintext'First = 0
                    and then Plaintext'Last < IO_Buffer_Capacity
            and then S.State in Wait_Encrypted_Extensions
                                | Wait_Certificate_Request
                                | Wait_Certificate
                                | Wait_Certificate_Verify
                                | Wait_Server_Finished
                    and then S.Negotiated_Suite
                       in Suite_AES_128_GCM_SHA256
                        | Suite_AES_256_GCM_SHA384
                        | Suite_CHACHA20_POLY1305_SHA256
                            and then
                                      True);
                                 Process_One_Decrypted_HS_Message
                           (S, HC, Plaintext, Plain_Len, Pos, Result);
      end loop;
   end Process_Decrypted_HS_Packed_Messages;

   --  Process encrypted handshake records (post-ServerHello)
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      HC        : in out Engaged_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   is
   begin
      Result := OK;
      declare
         Pos : N32;
      begin
         Continue_Decrypted_HS_Reassembly
           (S, HC, Plaintext, Plain_Len, Pos, Result);

         if Result = Error_Alert then
            return;
         end if;

         if Result = OK
           and then S.State in Wait_Encrypted_Extensions
                               | Wait_Certificate_Request
                               | Wait_Certificate
                               | Wait_Certificate_Verify
                               | Wait_Server_Finished
         then
            Process_Decrypted_HS_Packed_Messages
              (S, HC, Plaintext, Plain_Len, Pos, Result);
         end if;

                     --  Tail handling: 1..3 stray bytes left in this
                     --  record (server fragmented the 4-byte HS header
                     --  itself, e.g. BoGo MaxHandshakeRecordLength=1).
                     --  Start reassembly with the header-pending
                     --  sentinel; the next record will fill it.
                     if Result /= Error_Alert
                       and Result /= Has_Output
                       and Used (HC.Reasm) = 0
                       and Pos < Plain_Len
                       and Plain_Len - Pos < 4
                     then
                        Reset (HC.Reasm);
                        Append (HC.Reasm, Plaintext (Pos .. Plain_Len - 1));
                             end if;
      end;
   end Process_Decrypted_Handshake_Bytes;

   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      HC     : in out Engaged_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
            --  This is an encrypted handshake record
            declare
               Frag_Len : constant N32 := Rec.Fragment_Len;
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               Next_Read : constant Buffer_Size :=
                  S.Input.Read_Pos + Rec.Record_Len;
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
                       Server_HS_Copy : Traffic_Keys := HC.Server_HS;
                       Saved_Suite : constant Supported_Suite := S.Negotiated_Suite;
                    begin
                       pragma Assert
                         (Saved_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256);
                       if Frag_Len <= Records.Tag_Size then
                  S.Last_Error := Decode_Error;
                  S.Input.Read_Pos := Next_Read;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;

                       Records.Decrypt_Record
                         (Encrypted  => Encrypted,
                          Record_Hdr => Hdr,
                          Keys       => Server_HS_Copy,
                          Plaintext  => Plaintext,
                          Plain_Len  => Plain_Len,
                          Inner_Type => Inner_Type,
                          Valid      => Dec_Valid);

                       if not Dec_Valid then
                          HC.Server_HS := Server_HS_Copy;
                          S.Input.Read_Pos := Next_Read;
                          --  RFC 8446 §5.2: AEAD decryption failure MUST emit
                          --  a fatal bad_record_mac alert. Encrypted under
                  --  HC.Client_HS via the helper.
                  Send_HS_Encrypted_Alert
                    (S, HC, Bad_Record_MAC, Result);
                  pragma Assert (S.Last_Error = Bad_Record_MAC);
                  if Output_Pending (S) > 0 then
                     pragma Assert
                       (AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S));
                          end if;
                          return;
                       end if;
                       S.Input.Read_Pos := Next_Read;
                       S.Negotiated_Suite := Saved_Suite;

                       --  Inner type should be handshake (0x16)
               --  A single encrypted record may contain multiple
               --  handshake messages, or a single message may span
               --  multiple records; the reassembly buffer handles both.
                               if Inner_Type = 16#16# then
                                  Process_Decrypted_Handshake_Bytes
                                    (S, HC, Plaintext, Plain_Len, Result);
               elsif Inner_Type = 16#15# then
                  --  Alert
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                       else
                  --  RFC 8446 5.2: if the decrypted inner content type
                  --  is not one we expect here, the receiver MUST
                  --  terminate with unexpected_message. In particular a
                  --  0x17 (application_data) inner type mid-handshake is
                  --  not "nothing to do" -- 0-RTT is not supported, so
                  --  there is no legitimate way to reach this.
                  --
                  --  This used to be `Result := OK`, which let a peer
                  --  feed us records we neither processed nor rejected.
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                               end if;
                               HC.Server_HS := Server_HS_Copy;
                            end;
   end Handle_Encrypted_App_Data;

   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Engaged_Context;
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
            --  Once TLS 1.3 handshake traffic keys are active, handshake
            --  messages must arrive as encrypted application_data records.
            --  A plaintext record in this epoch is equivalent to a failed
            --  protected record.
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_HS_Encrypted_Alert (S, HC, Bad_Record_MAC, Result);
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
      Resumption_Across_Names : out Boolean;
      Status    :    out NST_Status)
   with Pre => Plaintext'First = 0
               and Plaintext'Last < N32'Last / 2
               and Plain_Len <= Max_Record_Plaintext
               and (if Plain_Len > 0 then Plain_Len - 1 <= Plaintext'Last)
               and Start_Off >= 0
               and Start_Off <= Plain_Len;

   procedure Walk_NST_Extensions
     (Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Start_Off : in     N32;
      Resumption_Across_Names : out Boolean;
      Status    :    out NST_Status)
   is
      type Tag_Array is array (1 .. 16) of Unsigned_16;
      Seen_Tags : Tag_Array := (others => 0);
      Seen_N    : Natural   := 0;
      EP        : N32       := Start_Off;
   begin
      Status := NST_OK;
      Resumption_Across_Names := False;

      if EP + 2 > Plain_Len then
         return;
      end if;
      pragma Assert (EP <= Plain_Len);
      pragma Assert (Plain_Len <= Max_Record_Plaintext);

      declare
         Ext_Total : constant N32 :=
            N32 (Plaintext (EP)) * 256 + N32 (Plaintext (EP + 1));
         Ext_End   : constant N32 := EP + 2 + Ext_Total;
      begin
         if Ext_End > Plain_Len then
            Status := NST_Decode_Err;
            return;
         end if;

         EP := EP + 2;
         pragma Assert (EP <= Ext_End);
         pragma Assert (Ext_End <= Plain_Len);
         while EP + 4 <= Ext_End loop
            pragma Loop_Invariant (EP <= Ext_End);
            pragma Loop_Invariant (Ext_End <= Plain_Len);
            pragma Loop_Invariant (Plain_Len <= Max_Record_Plaintext);
            pragma Loop_Invariant (Seen_N <= Seen_Tags'Last);
            declare
               Tag : constant Unsigned_16 :=
                  Unsigned_16 (Plaintext (EP)) * 256
                  + Unsigned_16 (Plaintext (EP + 1));
               E_Len : constant N32 :=
                  N32 (Plaintext (EP + 2)) * 256
                  + N32 (Plaintext (EP + 3));
            begin
               if E_Len > Ext_End - (EP + 4) then
                  Status := NST_Decode_Err;
                  return;
               end if;

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
                           or else N32 (Plaintext (EP + 4)) = 0
                           or else N32 (Plaintext (EP + 4)) /= E_Len - 1)
               then
                  Status := NST_Decode_Err;
                  return;
               end if;

               if Tag = 16#003E# then
                  declare
                     Inner_Len : constant N32 := N32 (Plaintext (EP + 4));
                  begin
                     if Inner_Len >= 2
                       and then
                         (Plaintext (EP + 4 + Inner_Len) and 16#01#) /= 0
                     then
                        Resumption_Across_Names := True;
                     end if;
                  end;
               end if;

               --  early_data ext (0x002A) in NST signals server
               --  willingness to accept 0-RTT on a future resume.
               --  We never offer 0-RTT (out of scope), so we just
               --  walk past the body without recording the limit.

               EP := EP + 4 + E_Len;
            end;
         end loop;
         if EP /= Ext_End then
            Status := NST_Decode_Err;
         end if;
      end;
   end Walk_NST_Extensions;

   procedure Process_NST_Message
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
               and then Plain_Len <= Max_Record_Plaintext
               and then Plain_Len <= N32 (Plaintext'Length),
        Post => (if Result = OK
                 then S.State = S.State'Old
                   and then Post_HS_Reasm."=" (S.Post_HS, S.Post_HS'Old));

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
            S.Ticket.Received_At :=
              (if S.Get_Time /= null
               then SPARKTLS.Tickets_12.To_Unix_Seconds (S.Get_Time.all)
               else 0);
            S.Ticket.Suite      := Wire_Of (S.Negotiated_Suite);
            S.Ticket.Server_Name := S.Server_Name;
            S.Ticket.Resumption_Across_Names := False;

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
               Across_Names : Boolean;
            begin
               Walk_NST_Extensions
                 (Plaintext => Plaintext,
                  Plain_Len => Plain_Len,
                  Start_Off => P + Tick_Len,
                  Resumption_Across_Names => Across_Names,
                  Status    => Status);
               case Status is
                  when NST_OK =>
                     S.Ticket.Resumption_Across_Names := Across_Names;
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

   procedure Reset_Post_HS_Reasm (S : in out Session)
   with Post => Post_HS_Reasm.Used (S.Post_HS) = 0
                and then S.State = S.State'Old
                and then S.Client_App = S.Client_App'Old;

   procedure Reset_Post_HS_Reasm (S : in out Session) is
   begin
      Post_HS_Reasm.Reset (S.Post_HS);
   end Reset_Post_HS_Reasm;

   procedure Dispatch_Post_HS_Message
     (S      : in out Session;
      Result :    out Action)
   with Pre => Post_HS_Reasm.Has_Message (S.Post_HS),
        Post => Post_HS_Reasm.Used (S.Post_HS) = 0;

   --  RFC 8446 §4.6.3. A KeyUpdate from the peer rotates the peer's WRITE
   --  key, which is our READ key -- for a client that is S.Server_App. If
   --  the peer set request_update we must rotate our own write key
   --  (S.Client_App) and tell them, before our next Application Data
   --  record.
   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   with Pre  => Msg'First = 0
                and then S.App_Secret_Len in 32 | 48
                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                            | Suite_AES_256_GCM_SHA384
                                            | Suite_CHACHA20_POLY1305_SHA256;

   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   is
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
            Send_App_Encrypted_Alert (S, Decode_Error, Result);
            return;

         when Key_Update.Parse_Bad_Value =>
            --  RFC 8446 4.6.3: a well-formed KeyUpdate whose
            --  request_update is outside {0,1} MUST be illegal_parameter.
            Send_App_Encrypted_Alert (S, Illegal_Parameter, Result);
            return;
      end case;

      --  Leaky bucket, drained by work actually done under the previous
      --  key. S.Server_App.Counter is our READ counter: it counts records
      --  read since the last rotation, so a peer that rekeyed after real
      --  traffic refunds a token here and can rekey indefinitely, while a
      --  peer spamming KeyUpdates back-to-back (counter ~0) refunds
      --  nothing and drains the bucket. See Max_Key_Updates in sparktls.ads
      --  for why a lifetime cap would be an interop bug.
      if S.Server_App.Counter >= Rekey_Refill_Records
        and then S.Key_Updates_Recvd > 0
      then
         S.Key_Updates_Recvd := S.Key_Updates_Recvd - 1;
      end if;

      if S.Key_Updates_Recvd >= Max_Key_Updates then
         Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
         return;
      end if;
      S.Key_Updates_Recvd := S.Key_Updates_Recvd + 1;

      --  Rotate the READ direction. The peer has already switched, so every
      --  record after this one arrives under the new key.
      Key_Update.Update_Secret
        (Secret => S.Server_App_Secret,
         Len    => S.App_Secret_Len,
         TK     => S.Server_App,
         Suite  => S.Negotiated_Suite);

      if not Request then
         Result := OK;
         return;
      end if;

      --  RFC 8446 §4.6.3 requires a reply "prior to sending its next
      --  Application Data record" -- the obligation is per-write, not
      --  per-message. Defer it: a burst of requests collapses to a single
      --  KeyUpdate, which is what the peer expects. Replying inline would
      --  make every reply after the first look unsolicited.
      S.Key_Update_Pending := True;
      Result := OK;
   end Process_Key_Update_Message;

   procedure Dispatch_Post_HS_Message
     (S      : in out Session;
      Result :    out Action)
   is
      Msg_Len : constant N32 := Post_HS_Reasm.Message_Length (S.Post_HS);
      Msg     : constant Byte_Seq (0 .. Msg_Len - 1) :=
        Byte_Seq (Post_HS_Reasm.Message (S.Post_HS));
   begin
      if Msg (0) = 16#04# then
         Process_NST_Message (S, Msg, Msg_Len, Result);
      elsif Msg (0) = Key_Update.HS_Key_Update then
         if S.App_Secret_Len in 32 | 48
           and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256
         then
            Process_Key_Update_Message (S, Msg, Result);
         else
            --  KeyUpdate is TLS 1.3 only; there is no retained secret to
            --  ratchet in a TLS 1.2 session.
            Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
         end if;
      else
         --  RFC 8446 4.6: the only post-handshake messages a client may
         --  receive are NewSessionTicket (4) and KeyUpdate (24), both
         --  handled above.
         --
         --  CertificateRequest (13) is the notable case: we never send
         --  the post_handshake_auth extension, and 4.6.2 says a client
         --  that receives CertificateRequest without having sent it
         --  MUST reply with unexpected_message. Everything else --
         --  Certificate, CertificateVerify, Finished, a second
         --  ClientHello -- is equally out of place here.
         --
         --  This used to be `Result := OK`, silently swallowing every
         --  unhandled type. The server side of this same dispatcher was
         --  corrected on 2026-08-17; the client was missed because the
         --  failing test at the time only exercised the server.
         Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
      end if;
      Reset_Post_HS_Reasm (S);
   end Dispatch_Post_HS_Message;

   procedure Process_Post_HS_Handshake_Bytes
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < IO_Buffer_Capacity
               and then Plain_Len <= Max_Record_Plaintext
               and then Plain_Len <= N32 (Plaintext'Length);
               --  No Post_HS conjuncts: the Len/Need relation is
               --  STRUCTURAL inside Post_HS_Reasm.Buffer (#90 carve).

   procedure Process_Post_HS_Handshake_Bytes
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   is
      Pos : N32 := 0;
   begin
      Result := OK;

      while Pos < Plain_Len loop
         pragma Loop_Invariant (Pos <= Plain_Len);
         pragma Loop_Invariant (Plain_Len <= Max_Record_Plaintext);

         --  The ADT derives everything the old Len/Need bookkeeping
         --  tracked: Wanted is header-remainder or body-remainder, and
         --  the phase flip at 4 bytes is Declared_Size becoming readable.
         declare
            use Post_HS_Reasm;
            Take : constant N32 :=
              N32'Min (N32'Min (Wanted (S.Post_HS),
                                Free_Space (S.Post_HS)),
                       Plain_Len - Pos);
         begin
            if Take > 0 then
               Append (S.Post_HS, Plaintext (Pos .. Pos + Take - 1));
               Pos := Pos + Take;
            end if;

            if Message_Too_Large (S.Post_HS)
              or else (Take = 0 and then not Has_Message (S.Post_HS))
            then
               --  Declared size exceeds a record plaintext: the old
               --  Msg_Total > Max_Record_Plaintext decode_error, now
               --  reported by the type (Capacity = 16_384).
               Reset (S.Post_HS);
               Send_App_Encrypted_Alert (S, Decode_Error, Result);
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

   --  Process records in Connected state
   procedure Handle_Connected_App_Record
     (S      : in out Session;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   is
   begin
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
               if Post_HS_Reasm.Used (S.Post_HS) > 0 then
                  --  RFC 8446 5.1: "Handshake messages MUST NOT be
                  --  interleaved with other record types." A
                  --  post-handshake handshake message is mid-reassembly
                  --  (Post_HS_Need > 0), so an application_data record
                  --  arriving now splits it. Reject rather than buffer
                  --  the data and resume reassembly afterwards.
                  --
                  --  Caught by tlsfuzzer test-tls13-keyupdate.py cases
                  --  "1/4 fragmented keyupdate msg, appdata between" and
                  --  "3/2 fragmented keyupdate msg, appdata between",
                  --  which we had never run.
                  Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
               elsif S.State = Closing and then Plain_Len > 0 then
                  Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
               elsif Plain_Len > 0 and then
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
                  --  Check BEFORE incrementing: the counter then never exceeds the
                  --  cap, so the bound holds BY CONSTRUCTION rather than being
                  --  asserted. Behaviour is identical (the same alert/record
                  --  triggers the error either way) and it is what makes the
                  --  narrowed field subtype and its AoRTE check provable.
                  if S.Empty_Records_Recvd >= Max_Empty_Records then
                     Send_App_Encrypted_Alert
                       (S, Unexpected_Message, Result);
                  else
                     S.Empty_Records_Recvd :=
                        S.Empty_Records_Recvd + 1;
                     Result := OK;
                  end if;
                  --  RFC 8446 §5.2 cap: ≤ 32 in live state, > 32
                  --  only after the alert is queued.
                  pragma Assert
                    (Empty_Records_Bounded_RFC_8446_5_2 (S));
               end if;

                    when 16#16# =>
                       --  Post-handshake handshake-record: NewSessionTicket
                       --  or KeyUpdate (RFC 8446 4.6). The handshake message
                       --  itself may be split across multiple encrypted
                       --  records, so it is reassembled before dispatch.
                       --  Must also run while Closing: the peer rotates its
                       --  write key when it sends a KeyUpdate, so skipping it
                       --  during shutdown leaves us unable to decrypt the
                       --  close_notify we are waiting for (BoGo
                       --  Shutdown-Shim-KeyUpdate).
                       if S.State in Connected | Closing then
                          Process_Post_HS_Handshake_Bytes
                            (S, Plaintext, Plain_Len, Result);
                       else
                          Send_App_Encrypted_Alert
                            (S, Unexpected_Message, Result);
                       end if;
                       return;

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
                  --
                  --  RFC 8446 §6.1: record that the peer closed in an
                  --  orderly way. Without this the application cannot
                  --  distinguish a finished stream from one an attacker
                  --  truncated by cutting the transport.
                  S.Peer_Closed_Cleanly := True;
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
                          if S.State = Connected then
                             Set_State (S, Closing);
                          end if;
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
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                        Send_App_Encrypted_Alert (S, Decode_Error, Result);
                     else
                        S.Warning_Alerts_Recvd :=
                           S.Warning_Alerts_Recvd + 1;
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
               --  RFC 8446 §5.4: after decryption, the inner
               --  content type must be application_data, alert, or
               --  handshake. Encrypted CCS and any other value are
               --  unexpected post-handshake records.
               Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
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

   procedure Close_Notify (S : in out Session) is
      Ignored_Alert_Out : N32;
   begin
      --  See the server-side twin. Advance zeroes the traffic keys and
      --  sets Closed once both directions have closed, but reports it with
      --  the same Shutdown result used for a half-duplex close, so an
      --  application cannot tell them apart. Encrypting here would build
      --  an alert under the all-zero scrubbed key and burn a sequence
      --  number on a dead session.
      if S.State not in Connected | Closing then
         return;
      end if;
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Alert_Record_12
           (Level       => 1,
            Desc        => 0,
            Keys        => S.Client_App,
            Implicit_IV => S.Client_IV_12,
            Output      => S.Output,
            Bytes_Out   => Ignored_Alert_Out);
      else
         Records.Build_Alert_Record
           (Level     => 1,
            Desc      => 0,
            Keys      => S.Client_App,
            Output    => S.Output,
            Bytes_Out => Ignored_Alert_Out);
      end if;
      --  See server-side comment: Set_State is a no-op when already
      --  Closing (avoids an invalid Closing → Closing transition).
      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Client;
