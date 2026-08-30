with Interfaces;                    use Interfaces;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA256; use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;            use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HKDF;           use SPARKTLSCrypto.HKDF;

with SPARKTLS_Reassembly;  use SPARKTLS_Reassembly;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;     use SPARKTLS.Records;
with SPARKTLS.Cert_Verify; use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS13;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Update;
with SPARKTLS.Tickets_12;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;

with X509;

package body SPARKTLS.Client.TLS13
  with SPARK_Mode => On
is
   pragma Unevaluated_Use_Of_Old (Allow);

   procedure Send_HS_Encrypted_Alert
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Err    : Error_Code;
      Result : out Action)
   with
     Post =>
       S.State = Error_State
       and then S.Last_Error = Err
       and then Result in
                  Has_Output
                  | Error_Alert
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
         Keys      => S.HC.Client_HS,
         Output    => S.Output,
         Bytes_Out => A2);
      S.Last_Error := Err;
      S.State := Error_State;
      Result :=
        (if A1 > 0 or else A2 > 0 or else Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_HS_Encrypted_Alert;

   --  Send a fatal alert encrypted under the client_application_
   --  traffic_secret. Used on every TLS 1.3 client reject path that
   --  fires AFTER the handshake completes (post-handshake messages,
   --  AEAD-failure on app records, bogus peer alerts). No CCS prefix
   --   the legacy middlebox-compat CCS was already emitted as part
   --  of the client flight, and a duplicate would be a protocol
   --  violation per RFC 8446 D.4.
   procedure Send_App_Encrypted_Alert (S : in out Session; Err : Error_Code; Result : out Action)
   with Post => S.State = Error_State and S.Last_Error = Err and Result in Has_Output | Error_Alert
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
      Result := (if A > 0 or else Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_App_Encrypted_Alert;

   --  Forward declarations for internal procedures
   procedure Derive_Handshake_Keys (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data);

   --  RFC 8446 4.3.1 / RFC 7301: scan a TLS 1.3 EncryptedExtensions
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
     (Data : in Byte_Seq;
      D    : in SPARKTLS.HS_Pool.HS_Data;
      S    : in out Session;
      OK   : out Boolean;
      Err  : out Error_Code)
   with
     Pre => Data'Length >= 4 and Data'Last < N32'Last and Data'Last <= N32'Last - 16#1_0004#,
     Post => S.State = S.State'Old and then S.Negotiated_Suite = S.Negotiated_Suite'Old;

   --  OK = False signals a fatal protocol error. `Err` discriminates
   --  the alert kind so the caller picks the right alert code:
   --    Unsupported_Extension : server sent an EE extension we did
   --                            not offer in CH.
   --    Illegal_Parameter     : ALPN body malformed / doesn't match
   --                            offered protocol (RFC 7301 3.2).
   procedure Send_Client_Certificate
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   with
     Pre =>
       SPARKTLS_Transcript.Started (S.HC.TS)
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then True,
     Post =>
       (if Result = OK
        then
          S.State = S.State'Old
          and then S.Negotiated_Suite = S.Negotiated_Suite'Old
          and then Hash_Len (S.HC.Neg) = Hash_Len (S.HC.Neg'Old)
          and then True
          and then (if S.HC.Cert_Request_Received
                      and then S.HC.Cfg.Local /= null
                      and then S.HC.Cfg.Local.Has_Identity
                    then
                      S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                      and then Handshake.Sig_Algo_Compatible_With_Cert
                                 (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                      and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                                then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
                    else True));

   procedure Derive_App_Keys_And_Send_Finished
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre =>
       S.State = Wait_Server_Finished
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite
       and then True,
     Post =>
       (if Result = Has_Output then Hash_Len (S.HC.Neg) = Hash_Len (S.HC.Neg'Old))
       and then Result in Has_Output | Error_Alert;

   procedure Process_Handshake_Message
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Last < Transcript_Capacity
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK
                   and then S.State in
                              Wait_Encrypted_Extensions
                              | Wait_Certificate_Request
                              | Wait_Certificate
                              | Wait_Certificate_Verify
                              | Wait_Server_Finished
                 then S.Negotiated_Suite in TLS13_Suite);

   procedure Process_Encrypted_Handshake
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre =>
       True
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512));
   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   with
     Pre =>
       S.Negotiated_Suite in TLS13_Suite
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then Rec.OK
       and then Rec.Content = Records.Content_Application_Data
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Fragment_Len >= 1
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
       and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity;
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Result    : out Action)
   with
     Pre =>
       S.Negotiated_Suite in TLS13_Suite
       and then Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length)
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512));

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Msg    : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       Msg'First = 0
       and then Msg'Length >= 4
       and then Msg'Last < N32'Last - 4
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite,
     Post =>
       (if Result = OK
          and then S.State in
                     Wait_Encrypted_Extensions
                     | Wait_Certificate_Request
                     | Wait_Certificate
                     | Wait_Certificate_Verify
                     | Wait_Server_Finished
        then S.Negotiated_Suite in TLS13_Suite)
       and then Result in OK | Has_Output | Error_Alert;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : out N32;
      Result    : out Action)
   with
     Pre =>
       S.Negotiated_Suite in TLS13_Suite
       and then Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length)
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)),
     Post =>
       Pos <= Plain_Len
       and then (if Result = OK
                   and then S.State in
                              Wait_Encrypted_Extensions
                              | Wait_Certificate_Request
                              | Wait_Certificate
                              | Wait_Certificate_Verify
                              | Wait_Server_Finished
                 then
                   S.Negotiated_Suite in TLS13_Suite);

   procedure Fill_Decrypted_HS_Reassembly
     (D             : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext     : in Byte_Seq;
      Plain_Len     : in N32;
      Pos           : out N32;
      Decode_Failed : out Boolean)
   with
     Pre =>
       Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length),
     Post => Pos <= Plain_Len;

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : out Action)
   with
     Pre =>
       S.Negotiated_Suite in TLS13_Suite
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then Plain_Len <= N32'Last
       and then Pos <= Plain_Len
       and then Has_Message (D.Reasm),
     Post =>
       Pos <= Plain_Len
       and then (if Result = OK
                   and then S.State in
                              Wait_Encrypted_Extensions
                              | Wait_Certificate_Request
                              | Wait_Certificate
                              | Wait_Certificate_Verify
                              | Wait_Server_Finished
                 then S.Negotiated_Suite in TLS13_Suite);

   procedure Process_Decrypted_HS_Packed_Messages
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : in out Action)
   with
     Pre =>
       S.Negotiated_Suite in TLS13_Suite
       and then Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length)
       and then Pos <= Plain_Len,
     Post =>
       Pos <= Plain_Len
       and then (if Result = OK
                   and then S.State in
                              Wait_Encrypted_Extensions
                              | Wait_Certificate_Request
                              | Wait_Certificate
                              | Wait_Certificate_Verify
                              | Wait_Server_Finished
                 then S.Negotiated_Suite in TLS13_Suite);

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : in out Action)
   with
     Pre =>
       Result = OK
       and then S.State in
                  Wait_Encrypted_Extensions
                  | Wait_Certificate_Request
                  | Wait_Certificate
                  | Wait_Certificate_Verify
                  | Wait_Server_Finished
       and then S.Negotiated_Suite in TLS13_Suite
       and then Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= N32 (Plaintext'Length)
       and then Pos <= N32'Last - 4
       and then Pos + 4 <= Plain_Len,
     Post =>
       Pos <= Plain_Len
       and then (if Result = OK
                   and then S.State in
                              Wait_Encrypted_Extensions
                              | Wait_Certificate_Request
                              | Wait_Certificate
                              | Wait_Certificate_Verify
                              | Wait_Server_Finished
                 then
                   Pos > Pos'Old
                   and then S.Negotiated_Suite in TLS13_Suite);

   procedure Handle_Connected_App_Record
     (S : in out Session; Rec : in Records.Parse_Result; Result : out Action)
   with
     Pre =>
       S.App_Data_Len <= Max_Record_Plaintext
       and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
       and then S.Empty_Records_Recvd <= Max_Empty_Records
       and then Rec.OK
       and then Rec.Content = Records.Content_Application_Data
       and then Rec.Fragment_Len >= 1
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Record_Len >= Rec.Fragment_Pos
       and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
       and then Rec.Record_Len <= Available (S.Input);
   procedure Set_Traffic_Keys
     (TK : out Traffic_Keys; Secret : in Bytes_48; Suite : in Supported_Suite)
   with Post => TK.Counter = 0 and then TK.Suite = Suite;

   --  Advance the handshake state machine (operates on dereferenced HC).

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

   ----------------------------------------------------------------------------
   --  Extract_ALPN_From_EE  see forward decl above for contract.
   --
   --  All offsets are computed against P, kept invariant by the
   --  outer guard `P + 4 <= Ext_End and P + 4 + E_Len <= Ext_End`
   --  before the inner read. Ext_End is the absolute index just
   --  past the last extension byte; computed once from the 2-byte
   --  ext_total_len read at fixed offset Body+0..1.
   ----------------------------------------------------------------------------
   procedure Extract_ALPN_From_EE
     (Data : in Byte_Seq;
      D    : in SPARKTLS.HS_Pool.HS_Data;
      S    : in out Session;
      OK   : out Boolean;
      Err  : out Error_Code)
   is
      ALPN_Tag   : constant N32 := 16#0010#;
      Body_Start : constant N32 := Data'First + 4;
   begin
      OK := True;
      Err := Illegal_Parameter;  --  default for ALPN-shape failures

      --  Need at least HS hdr + 2-byte ext_total_len = 6 bytes.
      if N32 (Data'Length) < 6 then
         return;
      end if;

      declare
         Ext_Total : constant N32 := N32 (Data (Body_Start)) * 256 + N32 (Data (Body_Start + 1));
         Ext_End   : constant N32 := Body_Start + 2 + Ext_Total;
         P         : N32 := Body_Start + 2;
      begin
         --  Bound: extensions fit within the EE message.
         if Ext_End > Data'Last + 1 then
            return;
         end if;

         --  RFC 8446 4.2 priority: structural checks (duplicates)
         --  take precedence over semantic checks (matrix policy).
         --  BoGo DuplicateExtensionClient-* expects decode_error
         --  even when the duplicated tag is also not in
         --  Allowed_EE. We must therefore detect ALL duplicates
         --  before running ANY policy validation  single-pass
         --  merging would short-circuit on the first instance with
         --  unsupported_extension before its duplicate is reached.
         declare
            subtype Seen_Range is N32 range 1 .. 32;
            Seen_Tags  : array (Seen_Range) of N32 := (others => 0);
            Seen_Count : N32 := 0;
            Q          : N32 := P;
         begin
            while Q + 4 <= Ext_End loop
               pragma
                 Loop_Invariant
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
                  T : constant N32 := N32 (Data (Q)) * 256 + N32 (Data (Q + 1));
                  L : constant N32 := N32 (Data (Q + 2)) * 256 + N32 (Data (Q + 3));
               begin
                  pragma Assert (L <= 16#FFFF#);
                  exit when Q + 4 + L > Ext_End;
                  for I in N32 range 1 .. Seen_Count loop
                     pragma Loop_Invariant (Seen_Count <= 32);
                     if Seen_Tags (I) = T then
                        OK := False;
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
            pragma
              Loop_Invariant
                (P >= Body_Start + 2
                   and P <= Ext_End
                   and P + 4 <= Ext_End
                   and Ext_End <= N32'Last - 16#1_0003#
                   and Ext_End <= Data'Last + 1
                   and S.State = S.State'Loop_Entry
                   and S.Client_App = S.Client_App'Loop_Entry
                   and S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            declare
               Tag   : constant N32 := N32 (Data (P)) * 256 + N32 (Data (P + 1));
               E_Len : constant N32 := N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
            begin
               pragma Assert (E_Len <= 16#FFFF#);
               --  Skip if extension overflows what's left.
               exit when P + 4 + E_Len > Ext_End;

               --  RFC 8446 4.2 matrix policy: rejects extensions
               --  not allowed in EE, ones we didn't offer in CH, and
               --  ones with non-empty body where RFC mandates empty
               --  (RFC 6066 3 server_name ack). BoGo
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
                     HC       => S.HC,
                     OK       => V_OK,
                     Err      => V_Err);
                  if not V_OK then
                     OK := False;
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
                        HC         => S.HC,
                        ALPN       => S.Negotiated_ALPN,
                        OK         => A_OK,
                        Err        => A_Err);
                     if not A_OK then
                        OK := False;
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

   procedure Handle_EE_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Length <= Transcript_Capacity
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite,
     Post =>
       (if Result = OK
        then
          S.HC.Client_HS = S.HC.Client_HS'Old
          and then S.Negotiated_Suite in TLS13_Suite)
       and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_EE_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action) is
   begin
      Result := OK;
      --  Defense-in-depth: EE only legal in Wait_Encrypted_Extensions.
      if S.State /= Wait_Encrypted_Extensions then
         Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
         return;
      end if;
      if N32 (Data'Length) < 6 then
         Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
         return;
      end if;
      declare
         Ext_Tot_Decl  : constant N32 :=
           N32 (Data (Data'First + 4)) * 256 + N32 (Data (Data'First + 5));
         Expected_Body : constant N32 := 2 + Ext_Tot_Decl;
      begin
         if N32 (Data'Length) - 4 /= Expected_Body then
            Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
            return;
         end if;
      end;
      SPARKTLS_Transcript.Append (S.HC.TS, Data);

      declare
         ALPN_OK  : Boolean;
         ALPN_Err : Error_Code;
      begin
         Extract_ALPN_From_EE (Data, D, S, ALPN_OK, ALPN_Err);
         if not ALPN_OK then
            Send_HS_Encrypted_Alert (S, D, ALPN_Err, Result);
            return;
         end if;
      end;

      if S.HC.Using_PSK then
         Set_State (S, Wait_Server_Finished);
      else
         Set_State (S, Wait_Certificate);
      end if;
   end Handle_EE_13;

   --  RFC 8446 4.3.2 client-side CertificateRequest handler. Body
   --  length-validation (ctx_len(1) + ctx + ext_len(2) + extensions),
   --  per-RFC-4.2 extension-policy gating, signature_algorithms
   --  required, picks a compatible S.HC.Negotiated_Sig_Algo.
   procedure Handle_CertReq_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Length <= Transcript_Capacity
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite,
     Post =>
       (if S.State /= Error_State
        then
          SPARKTLS_Transcript.Started (S.HC.TS)
          and then S.Negotiated_Suite in TLS13_Suite)
       and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_CertReq_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action) is
   begin
      Result := OK;
      if S.HC.Using_PSK then
         Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
         return;
      end if;
      if Data'Length >= 7 then
         declare
            Ctx_Len_Decl : constant N32 := N32 (Data (Data'First + 4));
            Ext_Off_Decl : constant N32 := Data'First + 5 + Ctx_Len_Decl;
            Body_OK      : Boolean := False;
         begin
            if Ctx_Len_Decl /= 0 then
               Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
               return;
            end if;
            if Ext_Off_Decl + 1 <= Data'Last then
               declare
                  Ext_Tot  : constant N32 :=
                    N32 (Data (Ext_Off_Decl)) * 256 + N32 (Data (Ext_Off_Decl + 1));
                  Expected : constant N32 := 1 + Ctx_Len_Decl + 2 + Ext_Tot;
               begin
                  Body_OK := N32 (Data'Length) - 4 = Expected;
               end;
            end if;
            if not Body_OK then
               Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      SPARKTLS_Transcript.Append (S.HC.TS, Data);
      S.HC.Cert_Request_Received := True;
      declare
         Picked    : Maybe_Sig_Scheme := Scheme_None;
         Sig_Found : Boolean := False;
      begin
         if Data'Length >= 7 then
            declare
               Ctx_Len : constant N32 := N32 (Data (Data'First + 4));
               Ext_Off : constant N32 := Data'First + 5 + Ctx_Len;
            begin
               if Ext_Off + 1 <= Data'Last then
                  declare
                     Ext_Tot : constant N32 :=
                       N32 (Data (Ext_Off)) * 256 + N32 (Data (Ext_Off + 1));
                     Ext_End : constant N32 := Ext_Off + 2 + Ext_Tot;
                     P       : N32 := Ext_Off + 2;
                  begin
                     if Ext_End <= Data'Last + 1 then
                        while P + 4 <= Ext_End loop
                           pragma
                             Loop_Invariant
                               (P >= Ext_Off + 2 and P + 4 <= Ext_End and Ext_End <= Data'Last + 1);
                           pragma
                             Loop_Invariant (S.State not in Idle | Closing | Closed | Error_State);
                           declare
                              Tag   : constant N32 := N32 (Data (P)) * 256 + N32 (Data (P + 1));
                              E_Len : constant N32 := N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
                              V_OK  : Boolean;
                              V_Err : Error_Code;
                           begin
                              exit when P + 4 + E_Len > Ext_End;
                              Validate_Server_Ext
                                (Where    => E_CR,
                                 Tag      => Unsigned_16 (Tag),
                                 Body_Len => E_Len,
                                 HC       => S.HC,
                                 OK       => V_OK,
                                 Err      => V_Err);
                              if not V_OK then
                                 Send_HS_Encrypted_Alert (S, D, V_Err, Result);
                                 return;
                              end if;
                              if Tag = 16#000D# and E_Len >= 4 then
                                 declare
                                    List_Len : constant N32 :=
                                      N32 (Data (P + 4)) * 256 + N32 (Data (P + 5));
                                 begin
                                    if List_Len + 2 = E_Len and List_Len >= 2 then
                                       Sig_Found := True;
                                       if S.HC.Cfg.Local /= null then
                                          Picked :=
                                            Handshake.Pick_Sig_Algo_With_Prefs
                                              (Data (P + 6 .. P + 5 + List_Len),
                                               S.HC.Cfg.Local.Sign_Algo,
                                               S.HC.Cfg.Sign_Sig_Algos,
                                               S.HC.Cfg.Sign_Sig_Algo_Count);
                                       end if;
                                    end if;
                                 end;
                              elsif Tag = 16#002F# and E_Len >= 2 then
                                 declare
                                    Outer_Len : constant N32 :=
                                      N32 (Data (P + 4)) * 256 + N32 (Data (P + 5));
                                    DN_P      : N32 := P + 6;
                                    DN_End    : constant N32 := P + 6 + Outer_Len;
                                    Bad       : Boolean := False;
                                 begin
                                    if 2 + Outer_Len /= E_Len or DN_End > Ext_End or Outer_Len = 0
                                    then
                                       Bad := True;
                                    else
                                       while not Bad and then DN_P < DN_End loop
                                          pragma Loop_Invariant (DN_P <= DN_End);
                                          pragma
                                            Loop_Invariant
                                              (S.State not in
                                                 Idle
                                                 | Closing
                                                 | Closed
                                                 | Error_State);
                                          pragma Loop_Variant (Increases => DN_P);
                                          if DN_P + 2 > DN_End then
                                             Bad := True;
                                          else
                                             declare
                                                DN_Len : constant N32 :=
                                                  N32 (Data (DN_P)) * 256 + N32 (Data (DN_P + 1));
                                             begin
                                                if DN_P + 2 + DN_Len > DN_End or DN_Len = 0 then
                                                   Bad := True;
                                                else
                                                   DN_P := DN_P + 2 + DN_Len;
                                                end if;
                                             end;
                                          end if;
                                       end loop;
                                    end if;
                                    if Bad then
                                       Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
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
            Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
            return;
         end if;

         if S.HC.Cfg.Local /= null then
            S.HC.Negotiated_Sig_Algo := Picked;
         end if;
      end;
   end Handle_CertReq_13;

   --  RFC 8446 4.4.2 client-side Certificate handler. Parses chain
   --  via Parse_Certificate_Chain_13, runs hostname binding (RFC 6125
   --  6.4) and trust-chain validation, transitions to
   --  Wait_Certificate_Verify.
   procedure Handle_Cert_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action)
   with
     Pre =>
       S.State = Wait_Certificate
       and then Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Length <= Transcript_Capacity
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in TLS13_Suite,
     Post =>
       (if S.State /= Error_State
        then
          S.Client_App = S.Client_App'Old
          and then S.Negotiated_Suite in TLS13_Suite)
       and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_Cert_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action) is
   begin
      Result := OK;
      if S.HC.Using_PSK then
         Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
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
                    N32 (Data (List_Off)) * 65536 + N32 (Data (List_Off + 1)) * 256
                    + N32 (Data (List_Off + 2));
                  Expected   : constant N32 := 1 + Ctx_Len_D + 3 + List_Len_D;
               begin
                  Body_OK := N32 (Data'Length) - 4 = Expected;
               end;
            end if;
            if not Body_OK then
               Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      SPARKTLS_Transcript.Append (S.HC.TS, Data);

      declare
         Parse_OK  : Boolean;
         Parse_Err : Error_Code;
      begin
         Handshake.TLS13.Parse_Certificate_Chain_13
           (HC                     => S.HC,
            D                      => D,
            HS_Msg                 => Data,
            Reject_Cert_Extensions => True,
            OK                     => Parse_OK,
            Err                    => Parse_Err);
         if not Parse_OK then
            Send_HS_Encrypted_Alert (S, D, Parse_Err, Result);
            return;
         end if;
      end;

      if S.HC.Cfg.Server_Name.Len > 0
        and then not S.HC.Cfg.Skip_Hostname_Verify
        and then D.Peer_Leaf.Present
      then
         pragma Assert (X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
         declare
            Cert_DER_Len_C : constant N32 := N32 (D.Peer_Leaf.DER_Len);
            Cert_X         : X509.Byte_Seq (0 .. X509.N32 (Cert_DER_Len_C) - 1) := (others => 0);
         begin
            for I in N32 range 0 .. Cert_DER_Len_C - 1 loop
               Cert_X (X509.N32 (I)) := D.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            if not X509.Matches_Hostname
                     (D.Peer_Leaf.Cert,
                      Cert_X,
                      S.HC.Cfg.Server_Name.Data (1 .. S.HC.Cfg.Server_Name.Len))
            then
               Send_HS_Encrypted_Alert (S, D, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;

      if not S.HC.Cfg.Skip_Verify and then D.Peer_Leaf.Present then
         if S.HC.Cfg.Trust = null or else S.HC.Cfg.Get_Time = null then
            S.Last_Error := Bad_Certificate;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         pragma Assert (X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
         declare
            Cert_DER_Len_Const : constant N32 := N32 (D.Peer_Leaf.DER_Len);
            Cert_X             : X509.Byte_Seq (0 .. X509.N32 (Cert_DER_Len_Const) - 1) :=
              (others => 0);
            VR                 : Validation_Result;
         begin
            for I in N32 range 0 .. Cert_DER_Len_Const - 1 loop
               Cert_X (X509.N32 (I)) := D.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            VR :=
              Validate_Chain
                (Leaf_DER   => Cert_X,
                 Leaf       => D.Peer_Leaf.Cert,
                 Ints       => D.Peer_Ints,
                 Int_Count  => D.Peer_Int_Count,
                 Roots      => S.HC.Cfg.Trust.Roots,
                 Root_Count => S.HC.Cfg.Trust.Root_Count,
                 Now        => S.HC.Cfg.Get_Time.all,
                 Hostname   => S.HC.Cfg.Server_Name.Data (1 .. S.HC.Cfg.Server_Name.Len),
                 Purpose    => S.HC.Cfg.Verify_Purpose,
                 Mode       => S.HC.Cfg.Verify_Mode);
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

   --  RFC 8446 4.4.3 client-side CertificateVerify handler.
   --  Re-hashes the transcript (suite-dependent), verifies the
   --  signature over the canonical CV content, transitions to
   --  Wait_Server_Finished. Also enforces RFC 8446 4.2.3 (no
   --  rsa_pkcs1_* in TLS 1.3) and RFC 8446 4.4.2.2 (leaf
   --  keyUsage=digitalSignature).
   procedure Handle_CV_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre =>
       S.State = Wait_Certificate_Verify
       and then Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Length <= Transcript_Capacity
       and then Msg_Len <= N32 (Data'Length) - 4
       and then True
       and then S.Negotiated_Suite in
                  Suite_AES_128_GCM_SHA256
                  | Suite_AES_256_GCM_SHA384
                  | Suite_CHACHA20_POLY1305_SHA256,
     Post =>
       (if S.State /= Error_State
        then
          S.HC.Client_HS = S.HC.Client_HS'Old
          and then S.Client_App = S.Client_App'Old
          and then S.Negotiated_Suite in
                     Suite_AES_128_GCM_SHA256
                     | Suite_AES_256_GCM_SHA384
                     | Suite_CHACHA20_POLY1305_SHA256
          and then True)
       and then Result in OK | Has_Output | Error_Alert;

   procedure Handle_CV_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action) is
   begin
      Result := OK;
      if Data'Length >= 8 then
         declare
            Sig_Len : constant N32 :=
              N32 (Data (Data'First + 6)) * 256 + N32 (Data (Data'First + 7));
         begin
            if N32 (Data'Length) - 4 /= 4 + Sig_Len then
               Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
               return;
            end if;
         end;
      end if;
      declare
         H_Len   : constant N32 := Hash_Len (S.HC.Neg);
         CV_Hash : Byte_Seq (0 .. H_Len - 1);
      begin
         --  Dispatch on the type-derived hash width (#117): the
         --  384 branch is exactly H_Len = 48, so the callee's
         --  width Pre discharges locally.
         if H_Len = 48 then
            CV_Hash := Transcript_Hash_384 (S.HC);
         else
            declare
               H256 : constant Digest := Transcript_Hash_256 (S.HC);
            begin
               CV_Hash := H256;
            end;
         end if;

         SPARKTLS_Transcript.Append (S.HC.TS, Data);

         if not D.Peer_Leaf.Present then
            Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
            return;
         end if;

         if X509.Has_Key_Usage (D.Peer_Leaf.Cert)
           and then not X509.KU_Digital_Signature (D.Peer_Leaf.Cert)
         then
            Send_HS_Encrypted_Alert (S, D, Bad_Certificate, Result);
            return;
         end if;

         declare
            Context_Str : constant String := "TLS 1.3, server CertificateVerify";
            Content_Len : constant N32 := 64 + N32 (Context_Str'Length) + 1 + H_Len;
            Content     : Byte_Seq (0 .. Content_Len - 1) := (others => 0);
         begin
            Content (0 .. 63) := (others => 16#20#);
            for I in Context_Str'Range loop
               Content (64 + N32 (I - Context_Str'First)) := Byte (Character'Pos (Context_Str (I)));
            end loop;
            Content (64 + N32 (Context_Str'Length)) := 16#00#;
            Content (64 + N32 (Context_Str'Length) + 1 .. 64 + N32 (Context_Str'Length) + H_Len) :=
              CV_Hash;

            if Msg_Len >= 8 then
               declare
                  Sig_Scheme : constant Maybe_Sig_Scheme :=
                    Scheme_From_Wire
                      (Unsigned_16 (Data (4)) * 256 + Unsigned_16 (Data (5)));
                  Sig_Len    : constant N32 := N32 (Data (6)) * 256 + N32 (Data (7));
                  Sig_Start  : constant N32 := 8;
               begin
                  if Sig_Scheme in
                       Sig_RSA_PKCS1_SHA256 | Sig_RSA_PKCS1_SHA384 | Sig_RSA_PKCS1_SHA512
                  then
                     Send_HS_Encrypted_Alert (S, D, Illegal_Parameter, Result);
                     return;
                  end if;

                  if S.HC.Cfg.Verify_Sig_Algo_Count > 0
                    and then not Sig_Scheme_In_List
                                   (Sig_Scheme,
                                    S.HC.Cfg.Verify_Sig_Algos,
                                    S.HC.Cfg.Verify_Sig_Algo_Count)
                  then
                     Send_HS_Encrypted_Alert (S, D, Illegal_Parameter, Result);
                     return;
                  end if;

                  if Sig_Len > 0 and then Sig_Start + Sig_Len <= N32 (Data'Length) then
                     declare
                        Sig : Byte_Seq (0 .. Sig_Len - 1);
                     begin
                        Sig := Data (Sig_Start .. Sig_Start + Sig_Len - 1);

                        if not Cert_Verify.Verify_Signature
                                 (Data       => Content,
                                  Sig        => Sig,
                                  Cert       => D.Peer_Leaf.Cert,
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

   --  RFC 8446 4.4.4 client-side Finished handler. Verifies server
   --  Finished verify_data with the suite-appropriate HMAC, then
   --  triggers app-key derivation + client Finished emission.
   procedure Handle_Finished_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre =>
       Data'First = 0
       and then Data'Length >= 4
       and then Data'Last < N32'Last - 4
       and then Data'Length <= Transcript_Capacity
       and then (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                 then
                   S.HC.Cfg.Local.NaCl_Cert_Len in 1 .. N32 (Max_Cert_DER)
                   and then Handshake.Sig_Algo_Compatible_With_Cert
                              (S.HC.Negotiated_Sig_Algo, S.HC.Cfg.Local.Sign_Algo)
                   and then (if S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                             then S.HC.Cfg.Local.RSA_Mod_Len in 64 .. 512))
       and then S.Negotiated_Suite in
                  Suite_AES_128_GCM_SHA256
                  | Suite_AES_256_GCM_SHA384
                  | Suite_CHACHA20_POLY1305_SHA256
       and then True,
     --  Handle_Finished installs the app traffic secret via
     --  Derive_App_Keys_And_Send_Finished, so S.Client_App is
     --  replaced (not pinned to 'Old). Nonce headroom is guaranteed
     --  because the new key starts with Counter = 0.
     Post => Result in Has_Output | Error_Alert and then Result in Has_Output | Error_Alert;

   procedure Handle_Finished_13
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Data    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      Initial_Suite : constant Supported_Suite := S.Negotiated_Suite
      with Ghost;
   begin
      Result := OK;
      if S.State /= Wait_Server_Finished then
         Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
         return;
      end if;
      if Msg_Len /= Hash_Len (S.HC.Neg) then
         Send_HS_Encrypted_Alert (S, D, Certificate_Verify_Failed, Result);
         return;
      end if;
      declare
         Verified : Boolean := False;
      begin
         case S.Negotiated_Suite is
            when Suite_AES_256_GCM_SHA384 =>
               declare
                  use HKDF384;
                  Pre_Hash : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
                  Fin_Key  : OKM384_Seq (0 .. 47);
                  Expected : Bytes_48;
               begin
                  SPARKTLS_Transcript.Append (S.HC.TS, Data);
                  Key_Schedule.Derive_Finished_Key_384 (Fin_Key, S.HC.Server_HS_Secret);
                  HMAC384.HMAC_SHA_384 (Output => Expected, M => Pre_Hash, K => Byte_Seq (Fin_Key));

                  if Msg_Len = 48 and then N32 (Data'Length) >= 52 then
                     if Equal (Expected, Bytes_48 (Data (4 .. 51))) then
                        Verified := True;
                     end if;
                  end if;
               end;

            when others =>
               declare
                  Pre_Hash : constant Digest := Transcript_Hash_256 (S.HC);
                  Fin_Key  : OKM_Seq (0 .. 31);
                  Expected : Digest;
               begin
                  SPARKTLS_Transcript.Append (S.HC.TS, Data);
                  Key_Schedule.Derive_Finished_Key (Fin_Key, S.HC.Server_HS_Secret (0 .. 31));
                  HMAC_SHA_256 (Output => Expected, M => Pre_Hash, K => Byte_Seq (Fin_Key));

                  if Msg_Len = 32 and then N32 (Data'Length) >= 36 then
                     if Equal (Expected, Bytes_32 (Data (4 .. 35))) then
                        Verified := True;
                     end if;
                  end if;
               end;
         end case;

         pragma
           Assert
             (if S.HC.Cert_Request_Received
                  and then S.HC.Cfg.Local /= null
                  then S.HC.Cfg.Local.Has_Identity);

         if not Verified then
            S.Last_Error := Handshake_Failure;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      end;

      Derive_App_Keys_And_Send_Finished (S, D, Result);
      pragma
        Assert
          (if Result = Has_Output
             then
               (if Initial_Suite = Suite_AES_256_GCM_SHA384 then Hash_Len (S.HC.Neg) = 48
                else Hash_Len (S.HC.Neg) = 32));
   end Handle_Finished_13;

   procedure Process_Handshake_Message
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Data   : in Byte_Seq;
      Result : out Action)
   is
      Msg_Type : Maybe_HS_Msg;
      Msg_Len  : N32;
      Parse_OK : Boolean;
   begin
      Result := OK;

      Handshake.Parse_Handshake_Header (Data, Msg_Type, Msg_Len, Parse_OK);
      if not Parse_OK then
         --  Distinguish "unknown message type" (BoGo WrongMessageType
         --  injects type+42) from "malformed length / shape" so we
         --  emit the right alert. Pre-condition: handshake records
         --  are decrypted under S.HC.Client_HS  we're post-SH.
         declare
            Raw_Type : constant Byte := (if Data'Length >= 1 then Data (Data'First) else 0);
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
            Send_HS_Encrypted_Alert
              (S, D, (if Is_Known then Decode_Error else Unexpected_Message), Result);
         end;
         return;
      end if;

      case Msg_Type is
         when HT_Encrypted_Extensions =>
            Handle_EE_13 (S, D, Data, Result);
            if Result /= OK then
               return;
            end if;

         when HT_Certificate_Request =>
            Handle_CertReq_13 (S, D, Data, Result);
            if Result /= OK then
               return;
            end if;

         when HT_Certificate =>
            if S.State /= Wait_Certificate then
               Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
               return;
            end if;
            Handle_Cert_13 (S, D, Data, Result);
            if Result /= OK then
               return;
            end if;

         when HT_Certificate_Verify =>
            if S.State /= Wait_Certificate_Verify then
               Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
               return;
            end if;
            if Msg_Len > N32 (Data'Length) - 4 then
               Send_HS_Encrypted_Alert (S, D, Decode_Error, Result);
               return;
            end if;
            Handle_CV_13 (S, D, Data, Msg_Len, Result);
            if Result /= OK then
               return;
            end if;

         when HT_Finished =>
            Handle_Finished_13 (S, D, Data, Msg_Len, Result);
            if Result /= OK then
               return;
            end if;

         when others =>
            --  RFC 8446 4: unknown handshake type â unexpected_message.
            --  BoGo's WrongMessageType-TLS13-* injects `type + 42` here.
            Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
      end case;
   end Process_Handshake_Message;

   --  mTLS: send client Certificate + CertificateVerify if requested.
   --  Called before sending Client Finished.
   procedure Send_Client_Certificate
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   is
      Enc_Out       : N32;
      Cert_Suite    : constant Supported_Suite := S.Negotiated_Suite;
      Cert_Hash_Len : constant N32 := Hash_Len (S.HC.Neg);
   begin
      Result := OK;

      if not S.HC.Cert_Request_Received then
         return;
      end if;

      --  RFC 8446 4.4.2: when we have NO identity, send an empty
      --  Certificate. When we DO have an identity but it can't sign
      --  with any algorithm in the server's offered list, send a
      --  fatal handshake_failure alert  BoringSSL emits
      --  `:NO_COMMON_SIGNATURE_ALGORITHMS:` here, which BoGo's
      --  Client-SignDefault tests use as the expected outcome.
      if S.HC.Cfg.Local /= null
        and then S.HC.Cfg.Local.Has_Identity
        and then S.HC.Negotiated_Sig_Algo = Scheme_None
      then
         Send_HS_Encrypted_Alert (S, D, Handshake_Failure, Result);
         return;
      end if;

      if S.HC.Cfg.Local = null or else not S.HC.Cfg.Local.Has_Identity then
         --  Server requested cert but we have none.
         --  Send empty Certificate message (allowed by RFC 8446 S.4.4.2).
         declare
            Empty_Cert : Byte_Seq (0 .. 7) := (others => 0);
         begin
            --  HS header: type=Certificate(0x0B), length=4
            Empty_Cert (0) := HS_Msg_Wire (HT_Certificate);
            Empty_Cert (1) := 0;
            Empty_Cert (2) := 0;
            Empty_Cert (3) := 4;
            --  Body: context_len=0, cert_list_len=0
            Empty_Cert (4) := 0;  --  context length
            Empty_Cert (5) := 0;  --  list length (3 bytes)
            Empty_Cert (6) := 0;
            Empty_Cert (7) := 0;

            SPARKTLS_Transcript.Append (S.HC.TS, Empty_Cert);
            Records.Build_Encrypted_Record
              (Plaintext  => Empty_Cert,
               Inner_Type => 16#16#,
               Keys       => S.HC.Client_HS,
               Output     => Scratch,
               Bytes_Out  => Enc_Out);
            if Enc_Out = 0 then
               Result := Error_Alert;
            end if;
         end;
         return;
      end if;

      if S.HC.Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
        or else S.HC.Cfg.Local.Int_Count > Max_Pool_Size
        or else (for some I in 0 .. Max_Pool_Size - 1
                 => S.HC.Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
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
         Handshake.TLS13.Build_Certificate_Chain
           (Id => S.HC.Cfg.Local.all, Result => Cert_Buf, Len => Cert_Len);
         if Cert_Len = 0 or else Cert_Len >= Transcript_Capacity or else Cert_Len > Max_Fragment
         then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         pragma Assert (Cert_Len < Transcript_Capacity);
         pragma Assert (Cert_Len <= Max_Fragment);
         if Cert_Len > 0 then
            SPARKTLS_Transcript.Append (S.HC.TS, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Encrypted_Record
              (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
               Inner_Type => 16#16#,
               Keys       => S.HC.Client_HS,
               Output     => Scratch,
               Bytes_Out  => Enc_Out);
            if Enc_Out = 0 then
               Result := Error_Alert;
               return;
            end if;
         end if;
      end;

      --  Send CertificateVerify (RFC 8446 4.4.3). Required after
      --  any non-empty client Certificate to prove possession of
      --  the private key. Was Ed25519-only  RSA-PSS / ECDSA certs
      --  skipped the CV entirely, so the runner saw [Cert, Finished]
      --  and rejected with "unexpected handshake message of type
      --  finishedMsg when waiting for certificateVerifyMsg".
      if S.HC.Cfg.Local.Sign_Algo in Sign_Ed25519 | Sign_RSA_PSS | Sign_ECDSA_P256 | Sign_ECDSA_P384
      then
         declare
            H_Len   : constant N32 := Cert_Hash_Len;
            CV_Hash : Byte_Seq (0 .. H_Len - 1);
         begin
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

            declare
               CV_Buf : Byte_Seq (0 .. 523);
               CV_Len : N32;
            begin
               Handshake.TLS13.Build_Certificate_Verify
                 (Transcript_Hash => CV_Hash,
                  Id              => S.HC.Cfg.Local.all,
                  Sig_Algo_Wire   => S.HC.Negotiated_Sig_Algo,
                  Role            => Role_Client,
                  Random          => S.HC.Cfg.Random,
                  Result          => CV_Buf,
                  Len             => CV_Len);
               if CV_Len > 0 then
                  SPARKTLS_Transcript.Append (S.HC.TS, CV_Buf (0 .. CV_Len - 1));
                  Records.Build_Encrypted_Record
                    (Plaintext  => CV_Buf (0 .. CV_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => S.HC.Client_HS,
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
      D               : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in Key_Schedule.Digest_384;
      Result          : out Action)
   with
     Pre => S.Negotiated_Suite = Suite_AES_256_GCM_SHA384,
     Post => Hash_Len (S.HC.Neg) = Hash_Len (S.HC.Neg'Old) and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_384
     (S               : in out Session;
      D               : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in Key_Schedule.Digest_384;
      Result          : out Action)
   is
      use HKDF384;
      TS_Hash          : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
      Finished_Key_384 : OKM384_Seq (0 .. 47);
      Verify_48        : Bytes_48;
      Master           : Key_Schedule.Digest_384;
      Client_App_Sec   : OKM384_Seq (0 .. 47);
      Server_App_Sec   : OKM384_Seq (0 .. 47);
      Exporter         : OKM384_Seq (0 .. 47);
      Enc_Out          : N32;
   begin
      Result := OK;

      Key_Schedule.Derive_Finished_Key_384 (Finished_Key_384, S.HC.Client_HS_Secret);

      HMAC384.HMAC_SHA_384 (Output => Verify_48, M => TS_Hash, K => Byte_Seq (Finished_Key_384));

      declare
         Big_Finished : Byte_Seq (0 .. 51) := (others => 0);
      begin
         Big_Finished (0) := HS_Msg_Wire (HT_Finished);
         Big_Finished (1) := 16#00#;
         Big_Finished (2) := 16#00#;
         Big_Finished (3) := 16#30#;
         Big_Finished (4 .. 51) := Verify_48;

         SPARKTLS_Transcript.Append (S.HC.TS, Big_Finished);

         Records.Build_Encrypted_Record
           (Plaintext  => Big_Finished,
            Inner_Type => 16#16#,
            Keys       => S.HC.Client_HS,
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
        (Master, Key_Schedule.Digest_384 (S.HC.Handshake_Secret));

      Key_Schedule.Derive_App_Traffic_Secrets_384
        (Client_App_Sec, Server_App_Sec, Master, App_TS_Hash_384);
      Key_Schedule.Derive_Exporter_Master_Secret_384 (Exporter, Master, App_TS_Hash_384);

      S.HC.Master_Secret := Bytes_48 (Master);
      S.Exporter_Secret := Bytes_48 (Exporter);
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;
      S.HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
      Set_Traffic_Keys (S.Client_App, Bytes_48 (Byte_Seq (Client_App_Sec)), S.Negotiated_Suite);
      Set_Traffic_Keys (S.Server_App, Bytes_48 (Byte_Seq (Server_App_Sec)), S.Negotiated_Suite);

      --  RFC 8446 4.6.3: retain the secrets themselves, not just the
      --  derived key/IV, so KeyUpdate can ratchet to the next generation.
      S.Client_App_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
      S.Server_App_Secret := Bytes_48 (Byte_Seq (Server_App_Sec));
      S.App_Secret_Len := 48;
   end Build_Client_Finished_384;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      D               : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in Digest;
      Result          : out Action)
   with
     Pre => S.Negotiated_Suite in Suite_AES_128_GCM_SHA256 | Suite_CHACHA20_POLY1305_SHA256,
     Post => Hash_Len (S.HC.Neg) = Hash_Len (S.HC.Neg'Old) and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      D               : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in Digest;
      Result          : out Action)
   is
      Finished_Buf        : Byte_Seq (0 .. 35);
      Finished_Len        : N32;
      TS_Hash             : constant Digest := Transcript_Hash_256 (S.HC);
      Client_Finished_Key : OKM_Seq (0 .. 31);
      Client_Verify       : Digest;
      Master              : Digest;
      Client_App_Sec      : OKM_Seq (0 .. 31);
      Server_App_Sec      : OKM_Seq (0 .. 31);
      Exporter            : OKM_Seq (0 .. 31);
      Enc_Out             : N32;
   begin
      Result := OK;

      Key_Schedule.Derive_Finished_Key (Client_Finished_Key, S.HC.Client_HS_Secret (0 .. 31));

      HMAC_SHA_256 (Output => Client_Verify, M => TS_Hash, K => Byte_Seq (Client_Finished_Key));

      Handshake.TLS13.Build_Finished (Client_Verify, Finished_Buf, Finished_Len);

      SPARKTLS_Transcript.Append (S.HC.TS, Finished_Buf (0 .. Finished_Len - 1));

      Records.Build_Encrypted_Record
        (Plaintext  => Finished_Buf (0 .. Finished_Len - 1),
         Inner_Type => 16#16#,
         Keys       => S.HC.Client_HS,
         Output     => Scratch,
         Bytes_Out  => Enc_Out);

      if Enc_Out = 0 then
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      Key_Schedule.Derive_Master_Secret (Master, Digest (S.HC.Handshake_Secret (0 .. 31)));

      Key_Schedule.Derive_App_Traffic_Secrets
        (Client_App_Sec, Server_App_Sec, Master, App_TS_Hash_256);
      Key_Schedule.Derive_Exporter_Master_Secret (Exporter, Master, App_TS_Hash_256);

      S.HC.Master_Secret := (others => 0);
      S.HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));
      S.Exporter_Secret := (others => 0);
      S.Exporter_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Exporter));
      S.Exporter_Secret_Len := 32;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;

      declare
         CS48 : Bytes_48 := (others => 0);
         SS48 : Bytes_48 := (others => 0);
      begin
         CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
         SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
         Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
         Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);

         --  RFC 8446 4.6.3: retain the secrets for the KeyUpdate ratchet.
         S.Client_App_Secret := CS48;
         S.Server_App_Secret := SS48;
         S.App_Secret_Len := 32;
      end;
   end Build_Client_Finished_256;

   --  After verifying server Finished, derive app keys and send client Finished
   procedure Derive_App_Keys_And_Send_Finished
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Cert_Result     : Action;
      --  Atomic flight assembly: client mTLS flight is
      --  [Cert + CertVerify] (optional) + CCS + Finished. We build into
      --  Scratch and only commit once everything fits, so the peer
      --  never sees a half-flight. Each Build_Encrypted_Record call
      --  advances S.HC.Client_HS.Counter; we save it and restore on any
      --  failure to keep AEAD nonces in sync with what the peer saw.
      Scratch         : IO_Buffer;
      --  RFC 8446 7.1: client_application_traffic_secret_0 uses
      --  the transcript hash through SERVER's Finished  NOT
      --  including any subsequent client Cert/CV. Snapshot the
      --  hash BEFORE Send_Client_Certificate appends our Cert,
      --  so App keys match what the peer derives. Was: re-hashed
      --  AFTER Send_Client_Certificate had appended the empty Cert,
      --  producing keys that diverged from the peer's, leading to
      --  "bad record MAC" on the first post-handshake record.
      App_TS_Hash_256 : constant Digest := Transcript_Hash_256 (S.HC);
      App_TS_Hash_384 : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
   begin
      --  RFC 8446 D.4: middlebox-compatibility CCS goes FIRST
      --  in the client's post-server-Finished flight, BEFORE any
      --  encrypted record. Otherwise the runner-side Go TLS stack
      --  rejects with "invalid TLS 1.3 ChangeCipherSpec" because
      --  it expects a CCS where it sees an app_data record.
      --
      --  If we already emitted the dummy CCS between HRR and CH2
      --  (S.HC.Sent_HRR_CCS), skip  the server's
      --  expectChangeCipherSpec was cleared by that one and a
      --  second CCS would be rejected as unexpected.
      if not S.HC.Sent_HRR_CCS then
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
      Send_Client_Certificate (S, D, Scratch, Cert_Result);
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
            Build_Client_Finished_384 (S, D, Scratch, App_TS_Hash_384, Result);
            if Result /= OK then
               return;
            end if;

         when others =>
            pragma
              Assert
                (S.Negotiated_Suite in Suite_AES_128_GCM_SHA256 | Suite_CHACHA20_POLY1305_SHA256);
            Build_Client_Finished_256 (S, D, Scratch, App_TS_Hash_256, Result);
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
      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
        Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;

      Set_State (S, Client_Finished_Sent);
      Result := Has_Output;
   end Derive_App_Keys_And_Send_Finished;

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
            --  ChaCha20-Poly1305: 32-byte key
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

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data) is
   begin
      case S.Negotiated_Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               use HKDF384;
               Hello_Hash : Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
               Early      : Key_Schedule.Digest_384;
               HS_Secret  : Key_Schedule.Digest_384;
               --  RFC 8446 7.1: Early_Secret = HKDF-Extract(0, PSK).
               --  PSK = ticket-derived secret iff the server actually
               --  selected our PSK (S.HC.Using_PSK) AND the ticket was
               --  bound to the same suite (PSK_Len matches the hash
               --  output size). Otherwise PSK = all-zeros, which is
               --  the 7.1 "fresh full handshake" sentinel.
               PSK_Bytes  : Bytes_48 :=
                 (if S.HC.Using_PSK and then S.Ticket.PSK_Len = 48 then S.Ticket.PSK
                  else (others => 0));
               Client_Sec : OKM384_Seq (0 .. 47);
               Server_Sec : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Early_Secret_384 (Early, PSK_Bytes);
               --  Use full 48 bytes if P-384 ECDHE, else first 32
               if (S.HC.KE.Negotiated and then S.HC.KE.Curve = Group_Secp384r1) then
                  Key_Schedule.Derive_Handshake_Secret_384
                    (HS_Secret, Byte_Seq (S.HC.KE.Shared), Early);
               else
                  Key_Schedule.Derive_Handshake_Secret_384
                    (HS_Secret, S.HC.KE.Shared (0 .. 31), Early);
               end if;

               S.HC.Handshake_Secret := Bytes_48 (HS_Secret);
               S.HC.Neg := (Suite => S.Negotiated_Suite);

               Key_Schedule.Derive_HS_Traffic_Secrets_384
                 (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

               S.HC.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_Sec));
               S.HC.Server_HS_Secret := Bytes_48 (Byte_Seq (Server_Sec));

               Set_Traffic_Keys (S.HC.Client_HS, S.HC.Client_HS_Secret, S.Negotiated_Suite);
               Set_Traffic_Keys (S.HC.Server_HS, S.HC.Server_HS_Secret, S.Negotiated_Suite);
            end;

         when others =>
            --  SHA-256 suites (0x1301, 0x1303)
            declare
               Hello_Hash : Digest := Transcript_Hash_256 (S.HC);
               Early      : Digest;
               HS_Secret  : Digest;
               --  See SHA-384 branch above for PSK rationale.
               PSK_Bytes  : Bytes_32 :=
                 (if S.HC.Using_PSK and then S.Ticket.PSK_Len = 32
                  then Bytes_32 (S.Ticket.PSK (0 .. 31))
                  else (others => 0));
               Client_Sec : OKM_Seq (0 .. 31);
               Server_Sec : OKM_Seq (0 .. 31);
            begin
               Key_Schedule.Derive_Early_Secret (Early, PSK_Bytes);
               --  Pass full shared secret: 48 bytes for P-384, 32 for others
               if (S.HC.KE.Negotiated and then S.HC.KE.Curve = Group_Secp384r1) then
                  Key_Schedule.Derive_Handshake_Secret
                    (HS_Secret, Byte_Seq (S.HC.KE.Shared), Early);
               else
                  Key_Schedule.Derive_Handshake_Secret (HS_Secret, S.HC.KE.Shared (0 .. 31), Early);
               end if;

               S.HC.Handshake_Secret := (others => 0);
               S.HC.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
               S.HC.Neg := (Suite => S.Negotiated_Suite);

               Key_Schedule.Derive_HS_Traffic_Secrets
                 (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

               S.HC.Client_HS_Secret := (others => 0);
               S.HC.Client_HS_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Client_Sec));
               S.HC.Server_HS_Secret := (others => 0);
               S.HC.Server_HS_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Server_Sec));

               Set_Traffic_Keys (S.HC.Client_HS, S.HC.Client_HS_Secret, S.Negotiated_Suite);
               Set_Traffic_Keys (S.HC.Server_HS, S.HC.Server_HS_Secret, S.Negotiated_Suite);
            end;
      end case;
   end Derive_Handshake_Keys;

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Msg    : in Byte_Seq;
      Result : out Action) is
   begin
      Process_Handshake_Message (S, D, Msg, Result);
   end Dispatch_Decrypted_HS_Message;

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : out Action) is
   begin
      declare
         Full : constant Message_Bytes := Message (D.Reasm);
      begin
         Reset (D.Reasm);
         Dispatch_Decrypted_HS_Message (S, D, Byte_Seq (Full), Result);
      end;
      pragma
        Assert
          (if Result = OK
               and then Pos < Plain_Len
               and then S.State in
                          Wait_Encrypted_Extensions
                          | Wait_Certificate_Request
                          | Wait_Certificate
                          | Wait_Certificate_Verify
                          | Wait_Server_Finished
             then
               S.Negotiated_Suite in
                 Suite_AES_128_GCM_SHA256
                 | Suite_AES_256_GCM_SHA384
                 | Suite_CHACHA20_POLY1305_SHA256);
      pragma
        Assert
          (if Result = OK
               and then S.State in
                          Wait_Encrypted_Extensions
                          | Wait_Certificate_Request
                          | Wait_Certificate
                          | Wait_Certificate_Verify
                          | Wait_Server_Finished
             then
               S.Negotiated_Suite in
                 Suite_AES_128_GCM_SHA256
                 | Suite_AES_256_GCM_SHA384
                 | Suite_CHACHA20_POLY1305_SHA256);
      if Result = Error_Alert then
         Pos := Plain_Len;  --  skip rest

      end if;
      pragma
        Assert
          (if Result = OK
               and then S.State in
                          Wait_Encrypted_Extensions
                          | Wait_Certificate_Request
                          | Wait_Certificate
                          | Wait_Certificate_Verify
                          | Wait_Server_Finished
             then
               S.Negotiated_Suite in
                 Suite_AES_128_GCM_SHA256
                 | Suite_AES_256_GCM_SHA384
                 | Suite_CHACHA20_POLY1305_SHA256);
   end Dispatch_Completed_Decrypted_Reasm;

   procedure Fill_Decrypted_HS_Reassembly
     (D             : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext     : in Byte_Seq;
      Plain_Len     : in N32;
      Pos           : out N32;
      Decode_Failed : out Boolean) is
   begin
      Decode_Failed := False;
      Pos := 0;

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
         exit when Message_Too_Large (D.Reasm);

         declare
            Take : constant HS_Msg_Len :=
              N32'Min (N32'Min (Wanted (D.Reasm), Plain_Len - Pos), Free_Space (D.Reasm));
         begin
            if Take > 0 then
               Append
                 (D.Reasm, Plaintext (Plaintext'First + Pos .. Plaintext'First + Pos + Take - 1));
               Pos := Pos + Take;
            end if;
         end;

         --  The peer's declared size becomes readable the moment the header
         --  lands, so the bound check belongs between the two rounds.
         if Round = 1
           and then Header_Ready (D.Reasm)
           and then Message_Too_Large (D.Reasm)
         then
            Reset (D.Reasm);
            Decode_Failed := True;
            return;
         end if;
      end loop;
   end Fill_Decrypted_HS_Reassembly;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : out N32;
      Result    : out Action) is
   begin
      Result := OK;
      Pos := 0;

      if Used (D.Reasm) > 0 then
         if not Has_Message (D.Reasm) then
            declare
               Decode_Failed : Boolean;
            begin
               Fill_Decrypted_HS_Reassembly (D, Plaintext, Plain_Len, Pos, Decode_Failed);

               if Decode_Failed then
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
                  return;
               end if;
            end;
         end if;

         if Has_Message (D.Reasm) then
            --  The message has to fit the transcript we are about to append
            --  it to. Peer-declared, so it is checked rather than trusted.
            if Message_Length (D.Reasm) > Transcript_Capacity then
               Reset (D.Reasm);
               S.Last_Error := Decode_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;

            Dispatch_Completed_Decrypted_Reasm (S, D, Plain_Len, Pos, Result);
         else
            --  Still need more data
            Pos := Plain_Len;  --  consumed all
         end if;
      end if;
   end Continue_Decrypted_HS_Reassembly;

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : in out Action) is
   begin
      declare
         HS_Len    : constant N32 :=
           N32 (Plaintext (Pos + 1)) * 65536 + N32 (Plaintext (Pos + 2)) * 256
           + N32 (Plaintext (Pos + 3));
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
            Reset (D.Reasm);
            Append (D.Reasm, Plaintext (Pos .. Plain_Len - 1));
            Pos := Plain_Len;
            return;
         end if;

         --  Complete message -- process it.
         if S.HC.Cert_Request_Received
           and then S.HC.Cfg.Local /= null
           and then S.HC.Cfg.Local.Has_Identity
           and then (S.HC.Cfg.Local.NaCl_Cert_Len not in 1 .. N32 (Max_Cert_DER)
                     or else not (S.HC.Negotiated_Sig_Algo = Scheme_None
                                  or else (case S.HC.Cfg.Local.Sign_Algo is
                                             when Sign_Ed25519 =>
                                               S.HC.Negotiated_Sig_Algo = Sig_Ed25519,
                                             when Sign_ECDSA_P256 =>
                                               S.HC.Negotiated_Sig_Algo = Sig_ECDSA_P256_SHA256,
                                             when Sign_ECDSA_P384 =>
                                               S.HC.Negotiated_Sig_Algo = Sig_ECDSA_P384_SHA384,
                                             when Sign_RSA_PSS =>
                                               S.HC.Negotiated_Sig_Algo in
                                                 Sig_RSA_PSS_SHA256
                                                 | Sig_RSA_PSS_SHA384
                                                 | Sig_RSA_PSS_SHA512,
                                             when Sign_None => False))
                     or else (S.HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                              and then S.HC.Cfg.Local.RSA_Mod_Len not in 64 .. 512)
                     or else S.HC.Client_HS.Counter > Unsigned_64'Last - 2)
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
            Dispatch_Decrypted_HS_Message (S, D, Msg_Copy, Result);
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
               Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
            end if;
            return;
         end if;

         if S.State = Error_State then
            return;
         end if;

         --  RFC 8446 4.4.4: server Finished is the last server
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
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Pos       : in out N32;
      Result    : in out Action) is
   begin
      --  Process complete messages in this record. Loop condition
      --  includes state sanity so the loop exits cleanly after PHM
      --  moves us to Error_State.
      while Pos + 4 <= Plain_Len
        and then Result = OK
        and then S.State in
                   Wait_Encrypted_Extensions
                   | Wait_Certificate_Request
                   | Wait_Certificate
                   | Wait_Certificate_Verify
                   | Wait_Server_Finished
      loop
         pragma
           Loop_Invariant
             (Pos >= 0
                and then Pos + 4 <= Plain_Len
                and then Result = OK
                and then Plain_Len <= N32 (Plaintext'Length)
                and then Plaintext'First = 0
                and then Plaintext'Last < IO_Buffer_Capacity
                and then S.State in
                           Wait_Encrypted_Extensions
                           | Wait_Certificate_Request
                           | Wait_Certificate
                           | Wait_Certificate_Verify
                           | Wait_Server_Finished
                and then S.Negotiated_Suite in
                           Suite_AES_128_GCM_SHA256
                           | Suite_AES_256_GCM_SHA384
                           | Suite_CHACHA20_POLY1305_SHA256
                and then True);
         Process_One_Decrypted_HS_Message (S, D, Plaintext, Plain_Len, Pos, Result);
      end loop;
   end Process_Decrypted_HS_Packed_Messages;

   --  Process encrypted handshake records (post-ServerHello)
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      Plain_Len : in N32;
      Result    : out Action) is
   begin
      Result := OK;
      declare
         Pos : N32;
      begin
         Continue_Decrypted_HS_Reassembly (S, D, Plaintext, Plain_Len, Pos, Result);

         if Result = Error_Alert then
            return;
         end if;

         if Result = OK
           and then S.State in
                      Wait_Encrypted_Extensions
                      | Wait_Certificate_Request
                      | Wait_Certificate
                      | Wait_Certificate_Verify
                      | Wait_Server_Finished
         then
            Process_Decrypted_HS_Packed_Messages (S, D, Plaintext, Plain_Len, Pos, Result);
         end if;

         --  Tail handling: 1..3 stray bytes left in this
         --  record (server fragmented the 4-byte HS header
         --  itself, e.g. BoGo MaxHandshakeRecordLength=1).
         --  Start reassembly with the header-pending
         --  sentinel; the next record will fill it.
         if Result /= Error_Alert
           and Result /= Has_Output
           and Used (D.Reasm) = 0
           and Pos < Plain_Len
           and Plain_Len - Pos < 4
         then
            Reset (D.Reasm);
            Append (D.Reasm, Plaintext (Pos .. Plain_Len - 1));
         end if;
      end;
   end Process_Decrypted_Handshake_Bytes;

   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action) is
   begin
      --  This is an encrypted handshake record
      declare
         Frag_Len       : constant N32 := Rec.Fragment_Len;
         Frag_Start     : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Next_Read      : constant Buffer_Size := S.Input.Read_Pos + Rec.Record_Len;
         --  Copy to 0-indexed locals (Decrypt_Record requires
         --  0-indexed inputs)
         Encrypted      : Byte_Seq (0 .. Frag_Len - 1) :=
           S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
         Hdr            : Byte_Seq (0 .. 4) :=
           S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext      : Byte_Seq (0 .. Frag_Len - 1);
         Plain_Len      : N32;
         Inner_Type     : Byte;
         Dec_Valid      : Boolean;
         Server_HS_Copy : Traffic_Keys := S.HC.Server_HS;
         Saved_Suite    : constant Supported_Suite := S.Negotiated_Suite;
      begin
         pragma
           Assert
             (Saved_Suite in
                Suite_AES_128_GCM_SHA256
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
            S.HC.Server_HS := Server_HS_Copy;
            S.Input.Read_Pos := Next_Read;
            --  RFC 8446 5.2: AEAD decryption failure MUST emit
            --  a fatal bad_record_mac alert. Encrypted under
            --  S.HC.Client_HS via the helper.
            Send_HS_Encrypted_Alert (S, D, Bad_Record_MAC, Result);
            pragma Assert (S.Last_Error = Bad_Record_MAC);
            if Output_Pending (S) > 0 then
               pragma Assert (AEAD_Failure_Alert_Queued_RFC_8446_5_2 (S));
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
            Process_Decrypted_Handshake_Bytes (S, D, Plaintext, Plain_Len, Result);
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
         S.HC.Server_HS := Server_HS_Copy;
      end;
   end Handle_Encrypted_App_Data;

   procedure Process_Encrypted_Handshake
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

      if Rec.Bad_Version then
         --  RFC 8446 5.1 / RFC 5246 6.2.1: legacy_record_version
         --  must be 0x03xx with minor in 1..4. Anything else
         --  (BoGo CheckRecordVersion: 0x03FF) â fatal
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
            --  CCS for middlebox compatibility. RFC 5246 7.1: the
            --  payload MUST be the single byte 0x01. RFC 8446 5
            --  permits exactly one server CCS per connection (the
            --  middlebox-compat dummy); a second one is unexpected.
            declare
               CCS_Pos : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               CCS_OK  : constant Boolean :=
                 Rec.Fragment_Len = 1 and then S.Input.Data (CCS_Pos) = 16#01#;
            begin
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               if CCS_OK and then not S.HC.CCS_Received then
                  S.HC.CCS_Received := True;
                  Result := OK;
               else
                  Send_HS_Encrypted_Alert (S, D, Unexpected_Message, Result);
               end if;
            end;

         when Records.Content_Application_Data =>
            Handle_Encrypted_App_Data (S, D, Rec, Result);

         when others =>
            --  Once TLS 1.3 handshake traffic keys are active, handshake
            --  messages must arrive as encrypted application_data records.
            --  A plaintext record in this epoch is equivalent to a failed
            --  protected record.
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_HS_Encrypted_Alert (S, D, Bad_Record_MAC, Result);
      end case;
   end Process_Encrypted_Handshake;

   --  NST helpers (extracted from Process_Connected/16#16# handler).
   --  RFC 8446 4.6.1 NewSessionTicket parsing is structurally deep
   --  (header â fixed prefix â nonce â ticket â extensions); keeping
   --  it as nested if/declare in the connected-state loop made every
   --  small RFC nit (zero-length ticket, dup ext, malformed flags ext)
   --  cost two indent levels. Split into:
   --   * Walk_NST_Extensions  â iterate ext list, extract max_early_
   --                            data, detect duplicates / malformed
   --                            flags ext, return a status enum.
   --   * Process_NST_Message  â parse fixed prefix + nonce + ticket,
   --                            derive PSK, then call Walk_NST_Exts.
   --  The Process_Connected case branch reduces to a single call.

   type NST_Status is (NST_OK, NST_Decode_Err, NST_Illegal_Param);
   --  NST_Decode_Err  â caller sends Decode_Error alert.
   --  NST_Illegal_Param â caller sends Illegal_Parameter alert.

   procedure Walk_NST_Extensions
     (Plaintext               : in Byte_Seq;
      Plain_Len               : in N32;
      Start_Off               : in N32;
      Resumption_Across_Names : out Boolean;
      Status                  : out NST_Status)
   with
     Pre =>
       Plaintext'First = 0
       and Plaintext'Last < N32'Last / 2
       and Plain_Len <= Max_Record_Plaintext
       and (if Plain_Len > 0 then Plain_Len - 1 <= Plaintext'Last)
       and Start_Off >= 0
       and Start_Off <= Plain_Len;

   procedure Walk_NST_Extensions
     (Plaintext               : in Byte_Seq;
      Plain_Len               : in N32;
      Start_Off               : in N32;
      Resumption_Across_Names : out Boolean;
      Status                  : out NST_Status)
   is
      type Tag_Array is array (1 .. 16) of Unsigned_16;
      Seen_Tags : Tag_Array := (others => 0);
      Seen_N    : Natural := 0;
      EP        : N32 := Start_Off;
   begin
      Status := NST_OK;
      Resumption_Across_Names := False;

      if EP + 2 > Plain_Len then
         return;
      end if;
      pragma Assert (EP <= Plain_Len);
      pragma Assert (Plain_Len <= Max_Record_Plaintext);

      declare
         Ext_Total : constant N32 := N32 (Plaintext (EP)) * 256 + N32 (Plaintext (EP + 1));
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
               Tag   : constant Unsigned_16 :=
                 Unsigned_16 (Plaintext (EP)) * 256 + Unsigned_16 (Plaintext (EP + 1));
               E_Len : constant N32 := N32 (Plaintext (EP + 2)) * 256 + N32 (Plaintext (EP + 3));
            begin
               if E_Len > Ext_End - (EP + 4) then
                  Status := NST_Decode_Err;
                  return;
               end if;

               --  RFC 8446 4.2: duplicate extension types in any HS
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
               --  `opaque flags<1..2^8-1>`  outer ext_data is
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
                     if Inner_Len >= 2 and then (Plaintext (EP + 4 + Inner_Len) and 16#01#) /= 0
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
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
   with
     Pre =>
       Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= Max_Record_Plaintext
       and then Plain_Len <= N32 (Plaintext'Length),
     Post =>
       (if Result = OK
        then S.State = S.State'Old and then Post_HS_Reasm."=" (S.Post_HS, S.Post_HS'Old));

   procedure Process_NST_Message
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
   is
      P : N32 := 4;  --  skip handshake header (type + 3-byte len)
   begin
      Result := OK;

      --  RFC 8446 4.6.1: NST = type(1)+len(3)+lifetime(4)+age_add(4)
      --  +nonce_len(1)+nonce(var)+ticket_len(2)+ticket(var)+exts.
      --  Need at least the fixed prefix: 4+4+1 = 9 past the HS header.
      if Plain_Len < 4 + 9 then
         return;
      end if;

      declare
         Lifetime  : constant Unsigned_32 :=
           Unsigned_32 (Plaintext (P)) * 2 ** 24 + Unsigned_32 (Plaintext (P + 1)) * 2 ** 16
           + Unsigned_32 (Plaintext (P + 2)) * 2 ** 8
           + Unsigned_32 (Plaintext (P + 3));
         Age_Add   : constant Unsigned_32 :=
           Unsigned_32 (Plaintext (P + 4)) * 2 ** 24 + Unsigned_32 (Plaintext (P + 5)) * 2 ** 16
           + Unsigned_32 (Plaintext (P + 6)) * 2 ** 8
           + Unsigned_32 (Plaintext (P + 7));
         Nonce_Len : constant N32 := N32 (Plaintext (P + 8));
      begin
         P := P + 9;
         if Nonce_Len = 0 or else P + Nonce_Len + 2 > Plain_Len then
            return;
         end if;

         declare
            Nonce    : constant Byte_Seq (0 .. Nonce_Len - 1) := Plaintext (P .. P + Nonce_Len - 1);
            Tick_Len : N32;
         begin
            P := P + Nonce_Len;
            Tick_Len := N32 (Plaintext (P)) * 256 + N32 (Plaintext (P + 1));
            P := P + 2;

            --  RFC 8446 4.6.1: ticket field is opaque ticket<1..
            --  2^16-1>; a zero-length ticket is decode_error (BoGo
            --  SendEmptySessionTicket-TLS13).
            if Tick_Len = 0 then
               Send_App_Encrypted_Alert (S, Decode_Error, Result);
               return;
            end if;

            if P + Tick_Len > Plain_Len or else Tick_Len > Max_Ticket_Len then
               return;
            end if;

            S.Ticket.Ticket (0 .. Tick_Len - 1) := Plaintext (P .. P + Tick_Len - 1);
            S.Ticket.Ticket_Len := Tick_Len;
            S.Ticket.Lifetime := Lifetime;
            S.Ticket.Age_Add := Age_Add;
            S.Ticket.Received_At :=
              (if S.Get_Time /= null then SPARKTLS.Tickets_12.To_Unix_Seconds (S.Get_Time.all)
               else 0);
            S.Ticket.Suite := Wire_Of (S.Negotiated_Suite);
            S.Ticket.Server_Name := S.Server_Name;
            S.Ticket.Resumption_Across_Names := False;

            case S.Negotiated_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  declare
                     use SPARKTLSCrypto.HKDF384;
                     PSK_Out : OKM384_Seq (0 .. 47);
                  begin
                     Key_Schedule.Derive_PSK_384 (PSK_Out, S.Res_Master, Nonce);
                     S.Ticket.PSK := Bytes_48 (PSK_Out);
                     S.Ticket.PSK_Len := 48;
                  end;

               when others =>
                  declare
                     PSK_Out : OKM_Seq (0 .. 31);
                  begin
                     Key_Schedule.Derive_PSK (PSK_Out, S.Res_Master (0 .. 31), Nonce);
                     S.Ticket.PSK := (others => 0);
                     for I in N32 range 0 .. 31 loop
                        S.Ticket.PSK (I) := PSK_Out (I);
                     end loop;
                     S.Ticket.PSK_Len := 32;
                  end;
            end case;

            S.Ticket.Valid := True;

            --  Walk the NST extension list (ticket_flags, early_data,
            --  â¦). Errors (dup ext / malformed flags) un-install the
            --  ticket and emit the right alert. early_data ext bodies
            --  are walked-past  we don't offer 0-RTT, so the
            --  advertised limit is irrelevant.
            declare
               Status       : NST_Status;
               Across_Names : Boolean;
            begin
               Walk_NST_Extensions
                 (Plaintext               => Plaintext,
                  Plain_Len               => Plain_Len,
                  Start_Off               => P + Tick_Len,
                  Resumption_Across_Names => Across_Names,
                  Status                  => Status);
               case Status is
                  when NST_OK =>
                     S.Ticket.Resumption_Across_Names := Across_Names;

                  when NST_Decode_Err =>
                     S.Ticket.Valid := False;
                     Send_App_Encrypted_Alert (S, Decode_Error, Result);

                  when NST_Illegal_Param =>
                     S.Ticket.Valid := False;
                     Send_App_Encrypted_Alert (S, Illegal_Parameter, Result);
               end case;
            end;
         end;
      end;
   end Process_NST_Message;

   procedure Reset_Post_HS_Reasm (S : in out Session)
   with
     Post =>
       Post_HS_Reasm.Used (S.Post_HS) = 0
       and then S.State = S.State'Old
       and then S.Client_App = S.Client_App'Old;

   procedure Reset_Post_HS_Reasm (S : in out Session) is
   begin
      Post_HS_Reasm.Reset (S.Post_HS);
   end Reset_Post_HS_Reasm;

   procedure Dispatch_Post_HS_Message (S : in out Session; Result : out Action)
   with Pre => Post_HS_Reasm.Has_Message (S.Post_HS), Post => Post_HS_Reasm.Used (S.Post_HS) = 0;

   --  RFC 8446 4.6.3. A KeyUpdate from the peer rotates the peer's WRITE
   --  key, which is our READ key -- for a client that is S.Server_App. If
   --  the peer set request_update we must rotate our own write key
   --  (S.Client_App) and tell them, before our next Application Data
   --  record.
   procedure Process_Key_Update_Message (S : in out Session; Msg : in Byte_Seq; Result : out Action)
   with
     Pre =>
       Msg'First = 0
       and then S.App_Secret_Len in 32 | 48
       and then S.Negotiated_Suite in
                  Suite_AES_128_GCM_SHA256
                  | Suite_AES_256_GCM_SHA384
                  | Suite_CHACHA20_POLY1305_SHA256;

   procedure Process_Key_Update_Message (S : in out Session; Msg : in Byte_Seq; Result : out Action)
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
      if S.Server_App.Counter >= Rekey_Refill_Records and then S.Key_Updates_Recvd > 0 then
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

      --  RFC 8446 4.6.3 requires a reply "prior to sending its next
      --  Application Data record" -- the obligation is per-write, not
      --  per-message. Defer it: a burst of requests collapses to a single
      --  KeyUpdate, which is what the peer expects. Replying inline would
      --  make every reply after the first look unsolicited.
      S.Key_Update_Pending := True;
      Result := OK;
   end Process_Key_Update_Message;

   procedure Dispatch_Post_HS_Message (S : in out Session; Result : out Action) is
      Msg_Len : constant N32 := Post_HS_Reasm.Message_Length (S.Post_HS);
      Msg     : constant Byte_Seq (0 .. Msg_Len - 1) :=
        Byte_Seq (Post_HS_Reasm.Message (S.Post_HS));
   begin
      if Msg (0) = 16#04# then
         Process_NST_Message (S, Msg, Msg_Len, Result);
      elsif Msg (0) = Key_Update.HS_Key_Update then
         if S.App_Secret_Len in 32 | 48
           and then S.Negotiated_Suite in
                      Suite_AES_128_GCM_SHA256
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
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
   with
     Pre =>
       Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then Plain_Len <= Max_Record_Plaintext
       and then Plain_Len <= N32 (Plaintext'Length);
   --  No Post_HS conjuncts: the Len/Need relation is
   --  STRUCTURAL inside Post_HS_Reasm.Buffer (#90 carve).

   procedure Process_Post_HS_Handshake_Bytes
     (S : in out Session; Plaintext : in Byte_Seq; Plain_Len : in N32; Result : out Action)
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
              N32'Min (N32'Min (Wanted (S.Post_HS), Free_Space (S.Post_HS)), Plain_Len - Pos);
         begin
            if Take > 0 then
               Append (S.Post_HS, Plaintext (Pos .. Pos + Take - 1));
               Pos := Pos + Take;
            end if;

            if Message_Too_Large (S.Post_HS) or else (Take = 0 and then not Has_Message (S.Post_HS))
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
     (S : in out Session; Rec : in Records.Parse_Result; Result : out Action) is
   begin
      declare
         Frag_Len   : constant N32 := Rec.Fragment_Len;
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Frag_Len - 1) :=
           S.Input.Data (Frag_Start .. Frag_Start + Frag_Len - 1);
         Hdr        : Byte_Seq (0 .. 4) := S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
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

         --  RFC 8446 5.4: "the full encoded TLSInnerPlaintext MUST
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
            --  RFC 8446 5.2: post-handshake AEAD failure â fatal
            --  bad_record_mac under client_application_traffic_secret.
            Send_App_Encrypted_Alert (S, Bad_Record_MAC, Result);
            return;
         end if;

         --  RFC 8446 5.4: TLSPlaintext.content after type+pad strip
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
               elsif Plain_Len > 0 and then S.App_Data_Len + Plain_Len <= S.App_Data'Length then
                  S.App_Data (S.App_Data_Len .. S.App_Data_Len + Plain_Len - 1) :=
                    Plaintext (0 .. Plain_Len - 1);
                  S.App_Data_Len := S.App_Data_Len + Plain_Len;
                  S.Empty_Records_Recvd := 0;
                  Result := Plaintext_Ready;
               else
                  --  Empty plaintext record. Count + cap to limit
                  --  DoS via flood (BoGo SendEmptyRecords: 33+ â
                  --  TOO_MANY_EMPTY_FRAGMENTS).
                  --  Check BEFORE incrementing: the counter then never exceeds the
                  --  cap, so the bound holds BY CONSTRUCTION rather than being
                  --  asserted. Behaviour is identical (the same alert/record
                  --  triggers the error either way) and it is what makes the
                  --  narrowed field subtype and its AoRTE check provable.
                  if S.Empty_Records_Recvd >= Max_Empty_Records then
                     Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
                  else
                     S.Empty_Records_Recvd := S.Empty_Records_Recvd + 1;
                     Result := OK;
                  end if;
                  --  RFC 8446 5.2 cap: â¤ 32 in live state, > 32
                  --  only after the alert is queued.
                  pragma Assert (Empty_Records_Bounded_RFC_8446_5_2 (S));
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
                  Process_Post_HS_Handshake_Bytes (S, Plaintext, Plain_Len, Result);
               else
                  Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
               end if;
               return;

            when 16#15# =>
               --  RFC 8446 6 / RFC 5246 7.2 alert. The 2-byte
               --  payload is `level(1) | description(1)`. The level
               --  byte MUST be 1 (warning) or 2 (fatal); any other
               --  value (e.g. BoGo SendBogusAlertType: level 0x42)
               --  is a protocol violation  we MUST reply with a
               --  fatal illegal_parameter alert (47).
               if Plain_Len < 2 then
                  --  Truncated alert.
                  Send_App_Encrypted_Alert (S, Decode_Error, Result);
               elsif Plaintext (0) /= 1 and Plaintext (0) /= 2 then
                  --  Bogus alert level â fatal illegal_parameter.
                  Send_App_Encrypted_Alert (S, Illegal_Parameter, Result);
               elsif Plaintext (1) = 0 then
                  --  close_notify (warning, desc=0). Reply in kind.
                  --
                  --  RFC 8446 6.1: record that the peer closed in an
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
                  --  RFC 8446 6.1 deprecates TLS 1.3 warning alerts
                  --  but keeps user_canceled (90) for back-compat
                  --  (JDK11 misuses it as a half-duplex hint). Match
                  --  BoringSSL/NSS/OpenSSL: silently skip up to 4
                  --  user_canceled, fatal-decode_error every other
                  --  warning, and fatal too-many-warnings on the 5th.
                  if Plaintext (1) = 90 then
                     --  user_canceled  tolerate, with cap.
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                        Send_App_Encrypted_Alert (S, Decode_Error, Result);
                     else
                        S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
                        Result := OK;
                     end if;
                     --  RFC 8446 6.1 cap: invariant must hold on
                     --  every exit path. Either â¤ 4 (still tolerable)
                     --  or > 4 with State already advanced to
                     --  Error_State by the if-branch above.
                     pragma Assert (Warning_Alerts_Bounded_RFC_8446_6_1 (S));
                  else
                     Send_App_Encrypted_Alert (S, Decode_Error, Result);
                  end if;
               else
                  --  Fatal alert from peer: close without replying
                  --  (RFC 8446 6.2: don't send alerts about alerts).
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
               end if;

            when others =>
               --  RFC 8446 5.4: after decryption, the inner
               --  content type must be application_data, alert, or
               --  handshake. Encrypted CCS and any other value are
               --  unexpected post-handshake records.
               Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
         end case;
      end;
   end Handle_Connected_App_Record;

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

      if Rec.Bad_Version then
         --  RFC 8446 5.1 / RFC 5246 6.2.1: legacy_record_version
         --  must be 0x03xx with minor in 1..4. Anything else
         --  (BoGo CheckRecordVersion: 0x03FF) â fatal
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

      --  RFC 8446 5: in the Connected (post-handshake) TLS 1.3
      --  state, the only valid record content type is
      --  application_data (the outer type). Encrypted handshake
      --  records (post-handshake messages like NewSessionTicket,
      --  KeyUpdate) also arrive as outer type application_data
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
   end Process_Connected_13;

   procedure Complete_Server_Hello_13
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data) is
   begin
      if S.Negotiated_Suite not in TLS13_Suite then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         return;
      end if;

      Derive_Handshake_Keys (S, D);
      Set_State (S, Wait_Encrypted_Extensions);
   end Complete_Server_Hello_13;

   procedure Advance_Handshake_13
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      --  The suite is established at the ServerHello negotiation boundary.
      --  Keep the defensive check here rather than exporting that derived
      --  fact as a precondition on every TLS 1.3 entry point.
      if S.Negotiated_Suite not in TLS13_Suite then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      case S.State is
         when Wait_Encrypted_Extensions
            | Wait_Certificate
            | Wait_Certificate_Verify
            | Wait_Server_Finished
         =>
            Process_Encrypted_Handshake (S, D, Result);

         when Client_Finished_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               --  Derive the resumption master secret before HC is freed.
               case S.Negotiated_Suite is
                  when Suite_AES_256_GCM_SHA384 =>
                     declare
                        use SPARKTLSCrypto.HKDF384;
                        Full_Hash : constant Key_Schedule.Digest_384 := Transcript_Hash_384 (S.HC);
                        Res       : OKM384_Seq (0 .. 47);
                     begin
                        Key_Schedule.Derive_Resumption_Master_Secret_384
                          (Res, S.HC.Master_Secret (0 .. 47), Full_Hash);
                        S.Res_Master := Bytes_48 (Res);
                        S.Res_Master_Len := 48;
                     end;

                  when Suite_AES_128_GCM_SHA256 | Suite_CHACHA20_POLY1305_SHA256 =>
                     declare
                        Full_Hash : constant Digest := Transcript_Hash_256 (S.HC);
                        Res       : OKM_Seq (0 .. 31);
                     begin
                        Key_Schedule.Derive_Resumption_Master_Secret
                          (Res, Digest (S.HC.Master_Secret (0 .. 31)), Full_Hash);
                        S.Res_Master := (others => 0);
                        for I in N32 range 0 .. 31 loop
                           S.Res_Master (I) := Res (I);
                        end loop;
                        S.Res_Master_Len := 32;
                     end;

                  when others =>
                     pragma Assert (False);
               end case;

               Set_State (S, Connected);
               Result := Handshake_Done;
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake_13;

end SPARKTLS.Client.TLS13;
