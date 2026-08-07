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

   function Client_Config_Can_Start
     (Cfg : Config;
      Resume_Usable : Boolean) return Boolean
   is
     (Cfg.Random /= null
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
	   with Pre  => Nonce_Space_Available (HC.Client_HS)
		                and then S.State not in Idle | Closing | Closed | Error_State
					                and then Reasm_Coherent (HC),
	        Post => S.State = Error_State
	                and then S.Last_Error = Err
		                and then Result in Has_Output | Error_Alert
				                and then Reasm_Coherent (HC)
				                and then HC.Reasm_Len = HC.Reasm_Len'Old
	                and then HC.Reasm_Need = HC.Reasm_Need'Old
	                and then HC.Reasm_Hdr_Pending =
	                  HC.Reasm_Hdr_Pending'Old
		                and then
		                  (if HC.Reasm_Len'Old <= HC.Reasm_Need'Old
		                   then Reasm_Building (HC))
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
	   with Pre  => Nonce_Space_Available (S.Client_App)
	                and S.State not in Idle | Closed | Error_State,
        Post => S.State = Error_State
                and S.Last_Error = Err
                and Result in Has_Output | Error_Alert
                and (if Free_Space (S.Output'Old) >=
                         Records.Record_Header_Size + 3 + Records.Tag_Size
                     then Output_Pending (S) > 0)
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
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and then HC.Transcript_Len <= Transcript_Capacity
               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
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
	                and Data'Last <= N32'Last - 16#1_0004#
	                and Data'First >= 0,
						        Post => S.State = S.State'Old
						                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
		                                and then
		                                  (if Nonce_Space_Available (S.Client_App'Old)
		                                   then Nonce_Space_Available (S.Client_App));
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
	               and then Reasm_Coherent (HC)
		               and then Nonce_Space_Available (HC.Client_HS)
	               and then HC.Transcript_Len > 0
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2
	                       and then SPARKTLSCrypto.P384.Field.Initialized
	                       and then SPARKTLSCrypto.P384.ECDSA.Initialized)
	               and then
	                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                  then HC.Hash_Len = 48
	                  else HC.Hash_Len = 32),
		        Post => (if Result = OK then
			                    S.State = S.State'Old
				                    and then S.Negotiated_Suite = S.Negotiated_Suite'Old
		                    and then HC.Transcript_Len > 0
	                    and then HC.Hash_Len = HC.Hash_Len'Old
		            and then
		              (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		               then HC.Hash_Len = 48
		               else HC.Hash_Len = 32)
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
			               else True))
                and then Reasm_Coherent (HC);
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
	   with Pre => S.State = Wait_Server_Finished
			               and then Reasm_Coherent (HC)
		               and then Nonce_Space_Available (HC.Client_HS)
	               and then HC.Transcript_Len > 0
	               and then SPARKTLSCrypto.P384.Field.Initialized
	               and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2)
			               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
			                                           | Suite_AES_256_GCM_SHA384
			                                           | Suite_CHACHA20_POLY1305_SHA256
			               and then SPARKTLSCrypto.P384.Field.Initialized
			               and then SPARKTLSCrypto.P384.ECDSA.Initialized
			               and then
			                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                  then HC.Hash_Len = 48
	                  else HC.Hash_Len = 32),
			        Post => (if Result = Has_Output then
			                    Nonce_Space_Available (S.Client_App)
					                    and then S.Negotiated_Suite = S.Negotiated_Suite'Old
				                    and then HC.Hash_Len = HC.Hash_Len'Old
			                    and then
			                      (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
			                       then HC.Hash_Len = 48
		                       else HC.Hash_Len = 32)
			                    and then SPARKTLSCrypto.P384.Field.Initialized
		                    and then SPARKTLSCrypto.P384.ECDSA.Initialized)
	                and then Result in Has_Output | Error_Alert
	                and then Reasm_Coherent (HC);
   procedure Process_Handshake_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
		   with Pre  => S.State not in Idle | Closing | Closed | Error_State
		                and then Data'First = 0
		                and then Data'Length >= 4
		                and then Data'Last < N32'Last - 4
		                and then Data'Last < Transcript_Capacity
	                                            and then Reasm_Coherent (HC)
							                and then HC.Transcript_Len > 0
		                and then Nonce_Space_Available (HC.Client_HS)
		                and then Nonce_Space_Available (S.Client_App)
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
	               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                            | Suite_AES_256_GCM_SHA384
	                                            | Suite_CHACHA20_POLY1305_SHA256
			                and then
			                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                   then HC.Hash_Len = 48
		                   else HC.Hash_Len = 32),
        Post => Result in OK | Has_Output | Error_Alert
                and then Reasm_Coherent (HC)
                and then
                  (if Result = OK
                       and then S.State in Wait_Encrypted_Extensions
                                           | Wait_Certificate_Request
                                           | Wait_Certificate
                                           | Wait_Certificate_Verify
                                           | Wait_Server_Finished
		                   then Nonce_Space_Available (HC.Client_HS)
		                        and then Nonce_Space_Available (S.Client_App)
		                        and then HC.Transcript_Len > 0
                        and then S.Negotiated_Suite
                          in Suite_AES_128_GCM_SHA256
                           | Suite_AES_256_GCM_SHA384
                           | Suite_CHACHA20_POLY1305_SHA256
                        and then
                          (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                           then HC.Hash_Len = 48
                           else HC.Hash_Len = 32));
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
	               and then Nonce_Space_Available (HC.Server_HS)
	               and then Nonce_Space_Available (S.Client_App)
		               and then HC.Transcript_Len > 0
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
		               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
	               and then
	                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                  then HC.Hash_Len = 48
	                  else HC.Hash_Len = 32)
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2)
		               and then Reasm_Coherent (HC)
				               and then (HC.Reasm_Buf = null
			                         or else (HC.Reasm_Buf'First = 0
                                  and then HC.Reasm_Buf'Last
                                     in 0 .. 131071
                                  and then HC.Reasm_Len
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then HC.Reasm_Need
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then (if HC.Reasm_Need > 0 then
                                               HC.Reasm_Need >= 4)));
   procedure Handle_Encrypted_App_Data
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
	               and then Nonce_Space_Available (HC.Client_HS)
	               and then Nonce_Space_Available (HC.Server_HS)
	               and then Nonce_Space_Available (S.Client_App)
		               and then HC.Transcript_Len > 0
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
		               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
		                                           | Suite_AES_256_GCM_SHA384
		                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
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
		                       and then HC.Client_HS.Counter
		                         <= Unsigned_64'Last - 2)
			               and then Reasm_Coherent (HC)
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
                        <= IO_Buffer_Capacity
               and then (HC.Reasm_Buf = null
                         or else (HC.Reasm_Buf'First = 0
                                  and then HC.Reasm_Buf'Last
                                     in 0 .. 131071
                                  and then HC.Reasm_Len
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then HC.Reasm_Need
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then (if HC.Reasm_Need > 0 then
                                               HC.Reasm_Need >= 4)));
   procedure Process_Decrypted_Handshake_Bytes
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App)
			               and then HC.Transcript_Len > 0
			               and then SPARKTLSCrypto.P384.Field.Initialized
			               and then SPARKTLSCrypto.P384.ECDSA.Initialized
			               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
		               and then Plaintext'First = 0
               and then Plain_Len >= 0
               and then Plaintext'Last < N32'Last / 2
			               and then Plain_Len <= N32 (Plaintext'Length)
                           and then Reasm_Coherent (HC)
                           and then Reasm_Buffer_Shaped (HC)
					               and then (HC.Reasm_Buf = null
			                         or else (HC.Reasm_Buf'First = 0
		                                  and then HC.Reasm_Buf'Last in 0 .. 131071
		                                  and then HC.Reasm_Len
		                                     <= N32 (HC.Reasm_Buf'Length)
		                                  and then HC.Reasm_Need
		                                     <= N32 (HC.Reasm_Buf'Length)
		                                  and then (if HC.Reasm_Need > 0 then
		                                               HC.Reasm_Need >= 4)))
		               and then
		                 (if HC.Reasm_Buf /= null and then HC.Reasm_Need > 0
		                  then Reasm_Building (HC))
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2),
        Post => Reasm_Coherent (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then Result in OK | Has_Output | Error_Alert;

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Msg'First = 0
	               and then Msg'Length >= 4
	               and then Msg'Last < N32'Last - 4
		               and then Msg'Last < Transcript_Capacity
		                                            and then Reasm_Coherent (HC)
                                 and then Reasm_Buffer_Shaped (HC)
				                and then HC.Transcript_Len > 0
		               and then Nonce_Space_Available (HC.Client_HS)
			                and then Nonce_Space_Available (S.Client_App)
			                and then SPARKTLSCrypto.P384.Field.Initialized
			                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
			                        and then HC.Client_HS.Counter
			                          <= Unsigned_64'Last - 2)
			                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
		                                            | Suite_AES_256_GCM_SHA384
		                                            | Suite_CHACHA20_POLY1305_SHA256
	                and then
	                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                   then HC.Hash_Len = 48
	                   else HC.Hash_Len = 32),
        Post => Reasm_Coherent (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then
                (if Result = OK
                      and then S.State in Wait_Encrypted_Extensions
                                          | Wait_Certificate_Request
                                          | Wait_Certificate
                                          | Wait_Certificate_Verify
                                          | Wait_Server_Finished
                 then
					                    Nonce_Space_Available (HC.Client_HS)
					                    and then Nonce_Space_Available (S.Client_App)
				                    and then HC.Transcript_Len > 0
	                    and then S.Negotiated_Suite
	                       in Suite_AES_128_GCM_SHA256
	                        | Suite_AES_256_GCM_SHA384
	                        | Suite_CHACHA20_POLY1305_SHA256
	                    and then
	                      (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                       then HC.Hash_Len = 48
	                       else HC.Hash_Len = 32))
                and then Result in OK | Has_Output | Error_Alert;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       :    out N32;
      Result    :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App)
               and then HC.Transcript_Len > 0
	               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
		               and then Plaintext'First = 0
			               and then Plaintext'Last < N32'Last / 2
				               and then Plain_Len <= N32 (Plaintext'Length)
				               and then Reasm_Coherent (HC)
	               and then (HC.Reasm_Buf = null
	                         or else (HC.Reasm_Buf'First = 0
                                  and then HC.Reasm_Buf'Last in 0 .. 131071
                                  and then HC.Reasm_Len
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then HC.Reasm_Need
                                     <= N32 (HC.Reasm_Buf'Length)
                                  and then (if HC.Reasm_Need > 0 then
                                               HC.Reasm_Need >= 4)))
               and then
                 (if HC.Reasm_Buf /= null and then HC.Reasm_Need > 0
	                  then Reasm_Buffer_Shaped (HC)
	                       and then Reasm_Building (HC)
	                       and then
	                         (if HC.Reasm_Hdr_Pending then HC.Reasm_Len <= 4))
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
		                       and then HC.Client_HS.Counter
		                         <= Unsigned_64'Last - 2),
					        Post => Pos <= Plain_Len
					                and then Result in OK | Has_Output | Error_Alert
				                and then (if Result = OK
				                              and then S.State
			                                in Wait_Encrypted_Extensions
			                                 | Wait_Certificate_Request
			                                 | Wait_Certificate
			                                 | Wait_Certificate_Verify
			                                 | Wait_Server_Finished
				                          then Nonce_Space_Available (HC.Client_HS)
				                               and then Nonce_Space_Available
				                                 (S.Client_App)
                            and then Reasm_Coherent (HC)
                            and then
                              (if HC.Reasm_Buf /= null
                                   and then HC.Reasm_Need > 0
                               then Reasm_Building (HC))
			                and then HC.Transcript_Len > 0
				                               and then S.Negotiated_Suite
			                                 in Suite_AES_128_GCM_SHA256
			                                  | Suite_AES_256_GCM_SHA384
			                                  | Suite_CHACHA20_POLY1305_SHA256
			                               and then
			                                 (if S.Negotiated_Suite =
			                                       Suite_AES_256_GCM_SHA384
			                                  then HC.Hash_Len = 48
			                                  else HC.Hash_Len = 32));

   procedure Fill_Decrypted_HS_Reassembly
     (HC            : in out Handshake_Context;
      Plaintext     : in     Byte_Seq;
      Plain_Len     : in     N32;
      Pos           :    out N32;
      Decode_Failed :    out Boolean)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
               and then Plain_Len <= N32 (Plaintext'Length)
               and then Nonce_Space_Available (HC.Client_HS)
               and then HC.Transcript_Len > 0
               and then HC.Reasm_Buf /= null
               and then HC.Reasm_Buf'First = 0
               and then HC.Reasm_Buf'Last in 0 .. 131071
               and then HC.Reasm_Need > 0
	               and then HC.Reasm_Need >= 4
		               and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
				               and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                           and then Reasm_Coherent (HC)
                           and then
                             (if HC.Reasm_Buf /= null
                                  and then HC.Reasm_Need > 0
                              then Reasm_Building (HC))
				               and then
				                 (if HC.Reasm_Hdr_Pending
			                  then HC.Reasm_Buf'Length = Max_HS_Msg
			                       and then HC.Reasm_Need = 4
				                       and then HC.Reasm_Len <= 4)
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2),
		        Post => Pos <= Plain_Len
			                and then HC.Hash_Len = HC.Hash_Len'Old
			                and then Nonce_Space_Available (HC.Client_HS)
			                and then HC.Client_HS = HC.Client_HS'Old
			                and then HC.Transcript_Len > 0
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
			                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
			                        and then HC.Client_HS.Counter
			                          <= Unsigned_64'Last - 2)
		                and then (if Decode_Failed then
	                             HC.Reasm_Buf = null
	                             and then HC.Reasm_Len = 0
                             and then HC.Reasm_Need = 0)
	                and then (if not Decode_Failed then
	                             HC.Reasm_Buf /= null
	                             and then HC.Reasm_Buf'First = 0
	                             and then HC.Reasm_Buf'Last in 0 .. 131071
	                             and then HC.Reasm_Len
	                                <= N32 (HC.Reasm_Buf'Length)
	                             and then HC.Reasm_Need
	                                <= N32 (HC.Reasm_Buf'Length)
		                             and then (if HC.Reasm_Need > 0 then
		                                          HC.Reasm_Need >= 4)
		                             and then
		                               (if HC.Reasm_Hdr_Pending
		                                then HC.Reasm_Buf'Length = Max_HS_Msg
		                                     and then HC.Reasm_Need = 4
			                                     and then HC.Reasm_Len <= 4)
				                             and then Reasm_Building (HC)
				                             and then Reasm_Buffer_Shaped (HC)
				                             and then Reasm_Coherent (HC));

   procedure Copy_Decrypted_Reasm_Bytes
     (HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      From      : in     N32;
      Take      : in     N32)
   with Pre => Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
               and then Nonce_Space_Available (HC.Client_HS)
               and then HC.Transcript_Len > 0
               and then HC.Reasm_Buf /= null
	               and then HC.Reasm_Buf'First = 0
		               and then HC.Reasm_Buf'Last in 0 .. 131071
								                and then Reasm_Coherent (HC)
						                and then
		                 (if HC.Reasm_Hdr_Pending then
		                    HC.Reasm_Buf'Length = Max_HS_Msg)
		               and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
	               and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
	               and then Take > 0
	               and then HC.Reasm_Len <= N32'Last - Take
	               and then HC.Reasm_Len + Take <= HC.Reasm_Need
	               and then Take <= N32 (HC.Reasm_Buf'Length) - HC.Reasm_Len
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
	                          then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2),
		        Post => HC.Reasm_Buf /= null
		                and then HC.Reasm_Buf'First = 0
			                and then HC.Hash_Len = HC.Hash_Len'Old
			                and then Nonce_Space_Available (HC.Client_HS)
			                and then HC.Client_HS = HC.Client_HS'Old
		                and then HC.Transcript_Len > 0
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
			                and then HC.Reasm_Buf'Last in 0 .. 131071
		                and then HC.Reasm_Len = HC.Reasm_Len'Old + Take
                and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
		                and then HC.Reasm_Need = HC.Reasm_Need'Old
		                and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
		                and then HC.Reasm_Hdr_Pending = HC.Reasm_Hdr_Pending'Old
		                and then (if HC.Reasm_Hdr_Pending
		                               and then HC.Reasm_Len < 4
	                          then HC.Reasm_Buf'Length = Max_HS_Msg);

   procedure Decode_Decrypted_Reasm_Header
     (HC            : in out Handshake_Context;
      Decode_Failed :    out Boolean)
   with Pre => Nonce_Space_Available (HC.Client_HS)
               and then HC.Transcript_Len > 0
               and then HC.Reasm_Buf /= null
               and then HC.Reasm_Buf'First = 0
               and then HC.Reasm_Buf'Last in 0 .. 131071
               and then HC.Reasm_Len = 4
	               and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
	               and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
	               and then HC.Reasm_Hdr_Pending
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
	                       and then HC.Client_HS.Counter
	                         <= Unsigned_64'Last - 2),
		        Post => Nonce_Space_Available (HC.Client_HS)
			                and then HC.Hash_Len = HC.Hash_Len'Old
			                and then HC.Client_HS = HC.Client_HS'Old
			                and then HC.Transcript_Len > 0
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
		                           then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
		                and then (if Decode_Failed then
	                             HC.Reasm_Buf = null
                             and then HC.Reasm_Len = 0
                             and then HC.Reasm_Need = 0)
	                and then (if not Decode_Failed then
	                             HC.Reasm_Buf /= null
	                             and then HC.Reasm_Buf'First = 0
	                             and then HC.Reasm_Buf'Last in 0 .. 131071
	                             and then HC.Reasm_Len
	                                <= N32 (HC.Reasm_Buf'Length)
	                             and then HC.Reasm_Need
	                                <= N32 (HC.Reasm_Buf'Length)
	                             and then HC.Reasm_Need >= 4
	                             and then not HC.Reasm_Hdr_Pending
	                             and then Reasm_Building (HC));

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    :    out Action)
	     with Pre => S.State not in Idle | Closing | Closed | Error_State
	               and then Nonce_Space_Available (HC.Client_HS)
	               and then Nonce_Space_Available (S.Client_App)
               and then HC.Transcript_Len > 0
	               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                       and then HC.Client_HS.Counter
		                         <= Unsigned_64'Last - 2)
		               and then Plain_Len <= N32'Last
               and then Pos <= Plain_Len
               and then HC.Reasm_Buf /= null
	               and then HC.Reasm_Buf'First = 0
	               and then HC.Reasm_Need in 4 .. Transcript_Capacity
	               and then HC.Reasm_Need - 1 <= HC.Reasm_Buf'Last
	               and then HC.Reasm_Len >= HC.Reasm_Need
	               and then Reasm_Coherent (HC),
				       Post => Pos <= Plain_Len
				                and then HC.Reasm_Len = 0
				                and then HC.Reasm_Need = 0
	                                and then Reasm_Coherent (HC)
	                                and then Reasm_Buffer_Shaped (HC)
	                                and then
                                  (if HC.Reasm_Buf /= null
                                       and then HC.Reasm_Need > 0
                                   then Reasm_Building (HC))
			                and then (if Result = OK
		                              and then S.State in Wait_Encrypted_Extensions
	                                                  | Wait_Certificate_Request
	                                                  | Wait_Certificate
	                                                  | Wait_Certificate_Verify
	                                                  | Wait_Server_Finished
	                          then Nonce_Space_Available (HC.Client_HS)
	                               and then Nonce_Space_Available (S.Client_App)
	                               and then HC.Transcript_Len > 0
	                               and then S.Negotiated_Suite
	                                 in Suite_AES_128_GCM_SHA256
	                                  | Suite_AES_256_GCM_SHA384
	                                  | Suite_CHACHA20_POLY1305_SHA256
	                               and then
	                                 (if S.Negotiated_Suite =
	                                       Suite_AES_256_GCM_SHA384
	                                  then HC.Hash_Len = 48
	                                  else HC.Hash_Len = 32));

   procedure Process_Decrypted_HS_Packed_Messages
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    : in out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App)
               and then HC.Transcript_Len > 0
	               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
		               and then SPARKTLSCrypto.P384.Field.Initialized
			               and then SPARKTLSCrypto.P384.ECDSA.Initialized
	                                            and then Reasm_Coherent (HC)
                                 and then Reasm_Buffer_Shaped (HC)
                                 and then
                                   (if HC.Reasm_Buf /= null
                                        and then HC.Reasm_Need > 0
                                    then Reasm_Building (HC))
			               and then Plaintext'First = 0
	               and then Plaintext'Last < N32'Last / 2
	               and then Plain_Len <= N32 (Plaintext'Length)
		               and then Pos <= Plain_Len,
						        Post => Pos <= Plain_Len
	                                            and then Reasm_Coherent (HC)
	                                            and then Result in
	                                              OK | Has_Output | Error_Alert
						                and then (if Result = OK
			                              and then S.State
			                                in Wait_Encrypted_Extensions
			                                 | Wait_Certificate_Request
			                                 | Wait_Certificate
			                                 | Wait_Certificate_Verify
			                                 | Wait_Server_Finished
			                          then Nonce_Space_Available (HC.Client_HS)
			                               and then Nonce_Space_Available
			                                 (S.Client_App)
			                               and then HC.Transcript_Len > 0
			                               and then S.Negotiated_Suite
			                                 in Suite_AES_128_GCM_SHA256
			                                  | Suite_AES_256_GCM_SHA384
			                                  | Suite_CHACHA20_POLY1305_SHA256
				                               and then
				                                 (if S.Negotiated_Suite =
				                                       Suite_AES_256_GCM_SHA384
				                                  then HC.Hash_Len = 48
				                                  else HC.Hash_Len = 32));

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      HC        : in out Handshake_Context;
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
               and then Nonce_Space_Available (HC.Client_HS)
               and then Nonce_Space_Available (S.Client_App)
               and then HC.Transcript_Len > 0
	               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                           | Suite_AES_256_GCM_SHA384
	                                           | Suite_CHACHA20_POLY1305_SHA256
		               and then
		                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                  then HC.Hash_Len = 48
		                  else HC.Hash_Len = 32)
		               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then SPARKTLSCrypto.P384.ECDSA.Initialized
	               and then Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
		               and then Plain_Len <= N32 (Plaintext'Length)
		               and then Pos <= N32'Last - 4
			               and then Pos + 4 <= Plain_Len
	                           and then Reasm_Coherent (HC)
                              and then Reasm_Buffer_Shaped (HC)
                           and then
                             (if HC.Reasm_Buf /= null
                                  and then HC.Reasm_Need > 0
                              then Reasm_Building (HC)),
			        Post => Pos <= Plain_Len
                and then Reasm_Coherent (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then
                  (if Result = OK
                       and then HC.Reasm_Buf /= null
                       and then HC.Reasm_Need > 0
                   then Reasm_Building (HC))
		                and then (if Result = OK
		                          and then S.State in Wait_Encrypted_Extensions
	                                              | Wait_Certificate_Request
	                                              | Wait_Certificate
	                                              | Wait_Certificate_Verify
	                                              | Wait_Server_Finished then
		                             Pos > Pos'Old
		                             and then Nonce_Space_Available (HC.Client_HS)
	                             and then Nonce_Space_Available (S.Client_App)
	                             and then HC.Transcript_Len > 0
	                             and then S.Negotiated_Suite
	                               in Suite_AES_128_GCM_SHA256
	                                | Suite_AES_256_GCM_SHA384
	                                | Suite_CHACHA20_POLY1305_SHA256
	                             and then
	                               (if S.Negotiated_Suite =
	                                     Suite_AES_256_GCM_SHA384
	                                then HC.Hash_Len = 48
	                                else HC.Hash_Len = 32));


   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State in Connected | Closing
               and then Nonce_Space_Available (S.Client_App)
               and then Nonce_Space_Available (S.Server_App)
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
               and then S.Empty_Records_Recvd <= Max_Empty_Records
               and then S.Post_HS_Len <= Max_Record_Plaintext
               and then S.Post_HS_Need <= Max_Record_Plaintext
               and then
                 (if S.Post_HS_Need = 0
                  then S.Post_HS_Len = 0
                  else S.Post_HS_Need >= 4
                    and then S.Post_HS_Len <= S.Post_HS_Need)
               and then Free_Space (S.Output) >=
                          Records.Record_Header_Size + 3 + Records.Tag_Size;
   procedure Handle_Connected_App_Record
     (S      : in out Session;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State in Connected | Closing
               and then Nonce_Space_Available (S.Client_App)
               and then Nonce_Space_Available (S.Server_App)
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
               and then S.Empty_Records_Recvd <= Max_Empty_Records
               and then S.Post_HS_Len <= Max_Record_Plaintext
               and then S.Post_HS_Need <= Max_Record_Plaintext
               and then
                 (if S.Post_HS_Need = 0
                  then S.Post_HS_Len = 0
                  else S.Post_HS_Need >= 4
                    and then S.Post_HS_Len <= S.Post_HS_Need)
               and then Free_Space (S.Output) >=
                          Records.Record_Header_Size + 3 + Records.Tag_Size
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
      Suite  : in     Unsigned_16)
   with Pre => Suite in Suite_AES_128_GCM_SHA256
                      | Suite_AES_256_GCM_SHA384
                      | Suite_CHACHA20_POLY1305_SHA256,
        Post => TK.Counter = 0
                and then TK.Suite = Suite
                and then Nonce_Space_Available (TK);

   --  Advance the handshake state machine (operates on dereferenced HC).
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre =>
      S.State in Client_Hello_Sent
               | Wait_Server_Hello
               | Wait_Encrypted_Extensions
               | Wait_Certificate_Request
               | Wait_Certificate
               | Wait_Certificate_Verify
               | Wait_Server_Finished
               | Client_Certificate_Sent
               | Client_Cert_Verify_Sent
               | Client_Finished_Sent
		      and then (if S.State = Wait_Server_Hello
		                then Reasm_Coherent (HC)
	                     and then HC.Cfg.Random /= null
	                     and then SPARKTLSCrypto.P384.Field.Initialized
	                     and then HC.Transcript_Len > 0
		                     and then HC.Transcript_Len <= Transcript_Capacity
		                     and then HC.HRR_Cookie_Len
		                       <= N32 (HC.HRR_Cookie'Length)
		                     and then WSH_Reasm_Shape (HC)
		                     and then
		                       (if HC.Reasm_Buf /= null
	                            and then HC.Reasm_Need > 0
	                        then HC.Reasm_Need - 1 <
	                             Transcript_Capacity))
      and then (if S.State in Wait_Encrypted_Extensions
                            | Wait_Certificate
                            | Wait_Certificate_Verify
                            | Wait_Server_Finished
                then Nonce_Space_Available (HC.Client_HS)
	                     and then Nonce_Space_Available (HC.Server_HS)
	                     and then Nonce_Space_Available (S.Client_App)
	                     and then HC.Transcript_Len > 0
		                     and then SPARKTLSCrypto.P384.Field.Initialized
		                     and then SPARKTLSCrypto.P384.ECDSA.Initialized
		                     and then S.Negotiated_Suite
	                        in Suite_AES_128_GCM_SHA256
	                         | Suite_AES_256_GCM_SHA384
	                         | Suite_CHACHA20_POLY1305_SHA256
		                     and then
		                       (if S.Negotiated_Suite =
		                             Suite_AES_256_GCM_SHA384
		                        then HC.Hash_Len = 48
		                        else HC.Hash_Len = 32)
		                     and then
		                       (if HC.Cert_Request_Received
		                            and then HC.Cfg.Local /= null
		                            and then HC.Cfg.Local.Has_Identity
		                        then HC.Cfg.Random /= null
		                             and then HC.Cfg.Local.NaCl_Cert_Len
		                               in 1 .. N32 (Max_Cert_DER)
			                             and then Handshake
			                               .Sig_Algo_Compatible_With_Cert
			                                 (HC.Negotiated_Sig_Algo,
			                                  HC.Cfg.Local.Sign_Algo)
		                             and then
		                               (if HC.Cfg.Local.Sign_Algo =
		                                     Sign_RSA_PSS
		                                then HC.Cfg.Local.RSA_Mod_Len
		                                     in 64 .. 512)
			                             and then HC.Client_HS.Counter
			                               <= Unsigned_64'Last - 2)
			                     and then Reasm_Coherent (HC)
		                     and then Reasm_Buffer_Shaped (HC)
		                     and then (HC.Reasm_Buf = null
	                               or else (HC.Reasm_Buf'First = 0
                                        and then HC.Reasm_Buf'Last
                                           in 0 .. 131071
                                        and then HC.Reasm_Len
                                           <= N32 (HC.Reasm_Buf'Length)
                                        and then HC.Reasm_Need
                                           <= N32 (HC.Reasm_Buf'Length)
                                        and then (if HC.Reasm_Need > 0
                                                  then HC.Reasm_Need >= 4))))
      and then (if S.State = Client_Finished_Sent
                then HC.Transcript_Len > 0
	            and then S.Negotiated_Suite
	               in Suite_AES_128_GCM_SHA256
	                | Suite_AES_256_GCM_SHA384
	                | Suite_CHACHA20_POLY1305_SHA256
		            and then
			              (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
			               then HC.Hash_Len = 48
			               else HC.Hash_Len = 32));
   procedure Handle_WSH_Frame_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
			   with Pre => S.State = Wait_Server_Hello
			               and then Reasm_Coherent (HC)
			               and then WSH_Reasm_Shape (HC)
		               and then HC.Cfg.Random /= null
	               and then SPARKTLSCrypto.P384.Field.Initialized
	               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
		               and then WSH_Reasm_Shape (HC)
		               and then
		                 (if HC.Reasm_Buf /= null
		                      and then HC.Reasm_Need > 0
	                  then HC.Reasm_Need - 1 < Transcript_Capacity);
   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
		   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
	               and then HC.Cfg.Random /= null
	               and then SPARKTLSCrypto.P384.Field.Initialized
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
		               and then WSH_Reasm_Shape (HC)
		               and then
		                 (if HC.Reasm_Buf /= null
		                      and then HC.Reasm_Need > 0
	                  then HC.Reasm_Need - 1 < Transcript_Capacity)
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
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Server_Hello
	               and then HC.Cfg.Random /= null
	               and then SPARKTLSCrypto.P384.Field.Initialized
                and then Reasm_Coherent (HC)
                and then HC.Reasm_Buf /= null
		               and then HC.Reasm_Need > 0
		               and then HC.Reasm_Buf'First = 0
	               and then HC.Reasm_Need - 1 <= HC.Reasm_Buf'Last
		               and then HC.Reasm_Need - 1 < Transcript_Capacity
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
	        Post => (if Result = OK then
		                    Reasm_Coherent (HC)
						                    and then HC.Cfg.Random /= null
							                    and then HC.Transcript_Len > 0
							                    and then HC.Transcript_Len <= Transcript_Capacity
								                    and then
								                      (if S.State = Wait_Server_Hello
								                       then HC.HRR_Cookie_Len <=
								                         N32 (HC.HRR_Cookie'Length)
								                         and then WSH_Reasm_Shape (HC))
						                    and then
						                      (if S.State = Wait_Server_Hello
					                           and then HC.Version = TLS_1_3
				                       then S.Negotiated_Suite in
				                         Suite_AES_128_GCM_SHA256
			                       | Suite_AES_256_GCM_SHA384
			                       | Suite_CHACHA20_POLY1305_SHA256));
   function WSH_Reasm_Shape (HC : Handshake_Context) return Boolean is
     (HC.Reasm_Buf = null
      or else
        (HC.Reasm_Buf'First = 0
         and then HC.Reasm_Buf'Length <= Max_HS_Msg
         and then HC.Reasm_Buf'Length <= N32'Last
         and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
         and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
         and then HC.Reasm_Need - 1 < Transcript_Capacity
         and then
           (if HC.Reasm_Hdr_Pending then
              HC.Reasm_Buf'Length = Max_HS_Msg
              and then HC.Reasm_Need = 4
              and then HC.Reasm_Len <= 4)))
   with Ghost;

   procedure Finalize_SH_Processing
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
		   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
	               and then HC.Cfg.Random /= null
	               and then SPARKTLSCrypto.P384.Field.Initialized
	               and then HC.Transcript_Len > 0
	               and then HC.Transcript_Len <= Transcript_Capacity
	               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
	               and then WSH_Reasm_Shape (HC)
	               and then
	                 (if HC.Version = TLS_1_3
	                  then S.Negotiated_Suite in
	                    Suite_AES_128_GCM_SHA256
	                  | Suite_AES_256_GCM_SHA384
	                  | Suite_CHACHA20_POLY1305_SHA256);

   procedure Reassemble_For_SH
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
		   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
		               and then HC.Cfg.Random /= null
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
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
			                        <= IO_Buffer_Capacity
			               and then WSH_Reasm_Shape (HC)
			               and then
			                 (if HC.Reasm_Buf /= null
			                       and then HC.Reasm_Need > 0
			                  then HC.Reasm_Need - 1 < Transcript_Capacity),
	        Post => (if Result = OK then
		                    S.State = Wait_Server_Hello
			                    and then Reasm_Coherent (HC)
			                    and then HC.Cfg.Random /= null
				                    and then HC.Transcript_Len > 0
				                    and then HC.Transcript_Len <= Transcript_Capacity
				                    and then HC.HRR_Cookie_Len <=
				                      N32 (HC.HRR_Cookie'Length)
				                    and then WSH_Reasm_Shape (HC)
				                    and then
			                      (if HC.Reasm_Len >= HC.Reasm_Need then
			                         HC.Reasm_Buf /= null
		                         and then HC.Reasm_Need > 0
		                         and then HC.Reasm_Need - 1 <
		                           Transcript_Capacity
		                         and then Reasm_Coherent (HC)));
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
		               and then HC.Cfg.Random /= null
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
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
                         then Frag_Start <= IO_Buffer_Capacity - 4)
               and then Max_HS_Msg = 131072,
	        Post => (if Result = OK then
	                    S.State = Wait_Server_Hello
	                    and then Reasm_Coherent (HC)
		                    and then HC.Cfg.Random /= null
			                    and then HC.Transcript_Len > 0
				                    and then HC.Transcript_Len <= Transcript_Capacity
				                    and then HC.HRR_Cookie_Len <=
				                      N32 (HC.HRR_Cookie'Length)
			                    and then WSH_Reasm_Shape (HC)
			                    and then (if HC.Reasm_Len >= HC.Reasm_Need then
			                                 HC.Reasm_Buf /= null
	                                 and then HC.Reasm_Need > 0
	                                 and then HC.Reasm_Need - 1 <
	                                   Transcript_Capacity));







   procedure Append_Transcript_Bytes
     (Transcript     : in out Byte_Seq;
      Transcript_Len : in out N32;
      Data           : in     Byte_Seq)
   with Pre  => Transcript'First = 0
                and then Transcript'Last = Transcript_Capacity - 1
                and then Transcript_Len <= Transcript_Capacity
                and then
                  (if Data'First <= Data'Last then
                     Data'Last - Data'First < Transcript_Capacity),
        Post => Transcript_Len >= Transcript_Len'Old
                and then Transcript_Len <= Transcript_Capacity
                and then
                  (if Transcript_Len'Old > 0
                     or else Data'First <= Data'Last
                   then Transcript_Len > 0);

   procedure Append_Transcript_Bytes
     (Transcript     : in out Byte_Seq;
      Transcript_Len : in out N32;
      Data           : in     Byte_Seq)
   is
   begin
      if Data'First <= Data'Last then
         declare
            Len : constant N32 := Data'Last - Data'First + 1;
         begin
            if Transcript_Len <= Transcript_Capacity - Len then
               Transcript (Transcript_Len .. Transcript_Len + Len - 1) :=
                 Data;
               Transcript_Len := Transcript_Len + Len;
            end if;
         end;
      end if;
   end Append_Transcript_Bytes;

   --  Append handshake message bytes to the transcript.
   --  RFC 5246 §7.4.9 / RFC 8446 §4.4.1: the transcript drives
   --  Finished verify_data, so it is append-only — losing bytes
   --  desyncs from the peer.
   procedure Append_Transcript
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq)
	   with Pre  => (if Data'First <= Data'Last then
						                    Data'Last - Data'First < Transcript_Capacity)
						                and then HC.Transcript_Len <= Transcript_Capacity
						                and then Reasm_Coherent (HC),
        Post => HC.Transcript_Len >= HC.Transcript_Len'Old
                and then HC.Transcript_Len <= Transcript_Capacity
                and then
                  (if HC.Transcript_Len'Old > 0
                     or else Data'First <= Data'Last
                   then HC.Transcript_Len > 0)
                and then HC.Client_HS = HC.Client_HS'Old
                and then (if HC.Cfg.Local'Old /= null
                          then HC.Cfg.Local /= null
                            and then HC.Cfg.Local.Has_Identity =
                              HC.Cfg.Local'Old.Has_Identity
                            and then HC.Cfg.Local.Sign_Algo =
                              HC.Cfg.Local'Old.Sign_Algo
                            and then HC.Cfg.Local.RSA_Mod_Len =
                              HC.Cfg.Local'Old.RSA_Mod_Len
                            and then HC.Cfg.Local.NaCl_Cert_Len =
                              HC.Cfg.Local'Old.NaCl_Cert_Len)
                and then (if HC.Cfg.Local /= null
                          then HC.Cfg.Local'Old /= null
                            and then
                              (if HC.Cfg.Local.Has_Identity
                               then HC.Cfg.Local'Old.Has_Identity))
                and then (if HC.Cfg.Random'Old /= null
                          then HC.Cfg.Random /= null)
                and then HC.Cert_Request_Received =
                  HC.Cert_Request_Received'Old
	                and then HC.Negotiated_Sig_Algo =
	                  HC.Negotiated_Sig_Algo'Old
	                and then HC.Version = HC.Version'Old
	                and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
                and then (if HC.HRR_Cookie_Len'Old <=
                            N32 (HC.HRR_Cookie'Length)
                          then HC.HRR_Cookie_Len <=
                            N32 (HC.HRR_Cookie'Length))
					                and then HC.Hash_Len = HC.Hash_Len'Old
									                and then Reasm_Coherent (HC)
									                and then
									                  (if HC.Reasm_Len'Old <=
									                        HC.Reasm_Need'Old
									                   then Reasm_Building (HC))
					                and then
				                  HC.Reasm_Len = HC.Reasm_Len'Old
			                and then HC.Reasm_Need = HC.Reasm_Need'Old
			                and then HC.Reasm_Hdr_Pending =
			                  HC.Reasm_Hdr_Pending'Old
			                and then
			                  (if HC.Reasm_Len'Old <= HC.Reasm_Need'Old
			                   then HC.Reasm_Len <= HC.Reasm_Need)
		   is
   begin
      Append_Transcript_Bytes
        (Transcript     => HC.Transcript,
         Transcript_Len => HC.Transcript_Len,
         Data           => Data);
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
   with Pre => S.State = Client_Hello_Sent
               and then S.Role = Role_Client
               and then HC.Cfg.Random /= null
	               and then SPARKTLSCrypto.P384.Field.Initialized
	               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
               and then
                 (if HC.Cfg.TLS12_Resume_Ticket.Valid
                  then HC.Cfg.TLS12_Resume_Ticket.Ticket_Len
	                       <= Max_TLS12_Ticket_Len)
	               and then Reasm_Coherent (HC)
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

      Append_Transcript (HC, CH_Buf (0 .. CH_Len - 1));

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
     (S   :    out Session;
      Cfg : in     Config)
   with SPARK_Mode => Off
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
         return;
      end if;

      S.HC_Ptr.Cfg := Cfg;

      --  RFC 8446 §4.6.1: if the caller passed a previously-saved
      --  resumption ticket via Cfg, copy it into S.Ticket before
      --  Build_Client_Hello so the CH carries the pre_shared_key
      --  extension and the binder is computed from the ticket's PSK.
      if Resume_Usable then
         S.Ticket := Cfg.Resume_Ticket;
      end if;

      Initialize_Client_Handshake (S, S.HC_Ptr.all, OK);
      if not OK then
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
		                                            and then Reasm_Coherent (HC)
	            and then HC.Transcript_Len > 0
	                and then Nonce_Space_Available (HC.Client_HS)
		                and then Nonce_Space_Available (S.Client_App)
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
			                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
		                                            | Suite_AES_256_GCM_SHA384
		                                            | Suite_CHACHA20_POLY1305_SHA256
				                and then Reasm_Coherent (HC)
		                and then
		                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                   then HC.Hash_Len = 48
	                   else HC.Hash_Len = 32),
			        Post => (if Result = OK
					                 then HC.Client_HS = HC.Client_HS'Old
					                      and then Nonce_Space_Available (S.Client_App)
					                      and then HC.Transcript_Len > 0
			                      and then S.Negotiated_Suite
		                         in Suite_AES_128_GCM_SHA256
		                          | Suite_AES_256_GCM_SHA384
		                          | Suite_CHACHA20_POLY1305_SHA256
		                      and then
		                        (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                         then HC.Hash_Len = 48
		                         else HC.Hash_Len = 32))
                and then Reasm_Coherent (HC)
                and then Result in OK | Has_Output | Error_Alert;

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
	                                            and then Reasm_Coherent (HC)
				                and then HC.Transcript_Len > 0
	                and then Nonce_Space_Available (HC.Client_HS)
		                and then Nonce_Space_Available (S.Client_App)
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
		                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
		                                            | Suite_AES_256_GCM_SHA384
	                                            | Suite_CHACHA20_POLY1305_SHA256
	                and then
	                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                   then HC.Hash_Len = 48
	                   else HC.Hash_Len = 32),
	        Post => (if S.State /= Error_State
					                 then Nonce_Space_Available (HC.Client_HS)
					                      and then Nonce_Space_Available
					                        (S.Client_App)
					                      and then HC.Transcript_Len > 0
		                      and then S.Negotiated_Suite
	                         in Suite_AES_128_GCM_SHA256
	                          | Suite_AES_256_GCM_SHA384
	                          | Suite_CHACHA20_POLY1305_SHA256
	                      and then
	                        (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                         then HC.Hash_Len = 48
	                         else HC.Hash_Len = 32))
	                and then Reasm_Coherent (HC)
	                and then Result in OK | Has_Output | Error_Alert;

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
	      pragma Assert (Reasm_Coherent (HC));
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
      HC     : in out Handshake_Context;
      Data   : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State = Wait_Certificate
                and then Data'First = 0
	                and then Data'Length >= 4
	                and then Data'Last < N32'Last - 4
	                and then Data'Length <= Transcript_Capacity
                                            and then Reasm_Coherent (HC)
				                and then HC.Transcript_Len > 0
		                and then Nonce_Space_Available (HC.Client_HS)
		                and then Nonce_Space_Available (S.Client_App)
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
		                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                            | Suite_AES_256_GCM_SHA384
	                                            | Suite_CHACHA20_POLY1305_SHA256
	                and then
	                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                   then HC.Hash_Len = 48
	                   else HC.Hash_Len = 32),
	        Post => (if S.State /= Error_State
				                 then Nonce_Space_Available (HC.Client_HS)
				                      and then S.Client_App = S.Client_App'Old
				                      and then HC.Transcript_Len > 0
		                      and then S.Negotiated_Suite
	                         in Suite_AES_128_GCM_SHA256
	                          | Suite_AES_256_GCM_SHA384
	                          | Suite_CHACHA20_POLY1305_SHA256
	                      and then
	                        (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                         then HC.Hash_Len = 48
	                         else HC.Hash_Len = 32))
	                and then Reasm_Coherent (HC)
	                and then Result in OK | Has_Output | Error_Alert;

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
	         pragma Assert
	           (HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len);
	         pragma Assert
	           (X509.Spans_Valid
	              (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1));
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

      if not HC.Cfg.Skip_Verify and then HC.Peer_Cert_Valid then
         if HC.Cfg.Trust = null or else HC.Cfg.Get_Time = null then
            S.Last_Error := Bad_Certificate;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         pragma Assert
           (HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len);
         pragma Assert
           (X509.Spans_Valid
              (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1));
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
   with Pre  => S.State = Wait_Certificate_Verify
                and then Data'First = 0
                and then Data'Length >= 4
                and then Data'Last < N32'Last - 4
	                and then Data'Length <= Transcript_Capacity
	                and then Msg_Len <= N32 (Data'Length) - 4
					                and then Reasm_Coherent (HC)
				                and then HC.Transcript_Len > 0
                and then Nonce_Space_Available (HC.Client_HS)
                and then Nonce_Space_Available (S.Client_App)
                and then
                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                   then HC.Hash_Len = 48
                   else HC.Hash_Len = 32)
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized
                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                            | Suite_AES_256_GCM_SHA384
                                            | Suite_CHACHA20_POLY1305_SHA256,
        Post => (if S.State /= Error_State
	                 then HC.Client_HS = HC.Client_HS'Old
	                      and then S.Client_App = S.Client_App'Old
		                      and then HC.Transcript_Len > 0
		                      and then S.Negotiated_Suite
	                         in Suite_AES_128_GCM_SHA256
	                          | Suite_AES_256_GCM_SHA384
	                          | Suite_CHACHA20_POLY1305_SHA256
	                      and then
	                        (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                         then HC.Hash_Len = 48
	                         else HC.Hash_Len = 32))
                and then Reasm_Coherent (HC)
                and then
                  True
                and then Result in OK | Has_Output | Error_Alert;

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
               pragma Assert (H_Len = 48);
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
				                and then Reasm_Coherent (HC)
			                and then HC.Transcript_Len > 0
	                and then Nonce_Space_Available (HC.Client_HS)
		                and then Nonce_Space_Available (S.Client_App)
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then SPARKTLSCrypto.P384.ECDSA.Initialized
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
		                        and then HC.Client_HS.Counter
		                          <= Unsigned_64'Last - 2)
		                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
		                                            | Suite_AES_256_GCM_SHA384
	                                            | Suite_CHACHA20_POLY1305_SHA256
	                and then
	                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	                   then HC.Hash_Len = 48
	                   else HC.Hash_Len = 32),
        --  Handle_Finished installs the app traffic secret via
        --  Derive_App_Keys_And_Send_Finished, so S.Client_App is
        --  replaced (not pinned to 'Old). Nonce headroom is guaranteed
        --  because the new key starts with Counter = 0.
					        Post => Result in Has_Output | Error_Alert
			                         and then Reasm_Coherent (HC)
				                         and then Result in Has_Output | Error_Alert;

   procedure Handle_Finished_13
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Data    : in     Byte_Seq;
      Msg_Len : in     N32;
	      Result  :    out Action)
	   is
	      Initial_Suite : constant Unsigned_16 := S.Negotiated_Suite
	        with Ghost;
	   begin
      Result := OK;
      if S.State /= Wait_Server_Finished then
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

	         pragma Assert
	           (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
	            then HC.Hash_Len = 48
	            else HC.Hash_Len = 32);
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
		           (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		            then HC.Hash_Len = 48
		            else HC.Hash_Len = 32));
		      pragma Assert
		        ((if Result = Has_Output
		          then Nonce_Space_Available (S.Client_App)
		               and then S.Negotiated_Suite = Initial_Suite
			               and then
			                 (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
			                  then HC.Hash_Len = 48
			                  else HC.Hash_Len = 32))
			         and then Result in Has_Output | Error_Alert);
			      pragma Assert
			        (if Result = Has_Output
			         then
			           (if Initial_Suite = Suite_AES_256_GCM_SHA384
			            then HC.Hash_Len = 48
			            else HC.Hash_Len = 32));
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
	      HC      : in out Handshake_Context;
	      Scratch : in out IO_Buffer;
	      Result  :    out Action)
	   is
      Enc_Out : N32;
      Cert_Suite    : constant Unsigned_16 := S.Negotiated_Suite;
      Cert_Hash_Len : constant N32 := HC.Hash_Len;
   begin
      Result := OK;

      if not HC.Cert_Request_Received then
         pragma Assert (Reasm_Coherent (HC));
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
         pragma Assert (Reasm_Coherent (HC));
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
	         pragma Assert (Reasm_Coherent (HC));
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
         pragma Assert (Reasm_Coherent (HC));
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
         pragma Assert (Reasm_Coherent (HC));

         if Cert_Len = 0
           or else Cert_Len >= Transcript_Capacity
           or else Cert_Len > Max_Fragment
         then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            pragma Assert (Reasm_Coherent (HC));
            return;
         end if;

         pragma Assert (Cert_Len < Transcript_Capacity);
         pragma Assert (Cert_Len <= Max_Fragment);
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
               pragma Assert (Reasm_Coherent (HC));
               return;
            end if;
            pragma Assert (Reasm_Coherent (HC));
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
            case Cert_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  pragma Assert (H_Len = 48);
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
               pragma Assert (Reasm_Coherent (HC));

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
                     pragma Assert (Reasm_Coherent (HC));
                     return;
                  end if;
                  pragma Assert (Reasm_Coherent (HC));
               end if;
	            end;
	         end;
	      end if;
	      pragma Assert (Reasm_Coherent (HC));
   end Send_Client_Certificate;

   procedure Build_Client_Finished_384
     (S               : in out Session;
      HC              : in out Handshake_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in     Key_Schedule.Digest_384;
      Saved_Ctr       : in     Unsigned_64;
      Result          :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then HC.Transcript_Len > 0
               and then Reasm_Coherent (HC)
               and then S.Negotiated_Suite = Suite_AES_256_GCM_SHA384,
	        Post => (if Result = OK then
	                    Nonce_Space_Available (S.Client_App))
	                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
	                and then HC.Hash_Len = HC.Hash_Len'Old
	                and then Reasm_Coherent (HC)
	                and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_384
     (S               : in out Session;
      HC              : in out Handshake_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_384 : in     Key_Schedule.Digest_384;
      Saved_Ctr       : in     Unsigned_64;
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

         Append_Transcript (HC, Big_Finished);

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
   end Build_Client_Finished_384;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      HC              : in out Handshake_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in     Digest;
      Saved_Ctr       : in     Unsigned_64;
      Result          :    out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
               and then Nonce_Space_Available (HC.Client_HS)
               and then HC.Transcript_Len > 0
               and then Reasm_Coherent (HC)
               and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                           | Suite_CHACHA20_POLY1305_SHA256,
	        Post => (if Result = OK then
	                    Nonce_Space_Available (S.Client_App))
	                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
	                and then HC.Hash_Len = HC.Hash_Len'Old
	                and then Reasm_Coherent (HC)
	                and then Result in OK | Error_Alert;

   procedure Build_Client_Finished_256
     (S               : in out Session;
      HC              : in out Handshake_Context;
      Scratch         : in out IO_Buffer;
      App_TS_Hash_256 : in     Digest;
      Saved_Ctr       : in     Unsigned_64;
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

      Append_Transcript (HC, Finished_Buf (0 .. Finished_Len - 1));

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
      end;
   end Build_Client_Finished_256;

   --  After verifying server Finished, derive app keys and send client Finished
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
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
      Saved_Ctr : constant Unsigned_64 := HC.Client_HS.Counter;
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
         HC.Client_HS.Counter := Saved_Ctr;
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

      if not Nonce_Space_Available (HC.Client_HS) then
         HC.Client_HS.Counter := Saved_Ctr;
         S.Last_Error := Insufficient_Buffer;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         Build_Client_Finished_384
           (S, HC, Scratch, App_TS_Hash_384, Saved_Ctr, Result);
         if Result /= OK then
            return;
         end if;
      when others =>
         pragma Assert
           (S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                | Suite_CHACHA20_POLY1305_SHA256);
         Build_Client_Finished_256
           (S, HC, Scratch, App_TS_Hash_256, Saved_Ctr, Result);
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
   procedure Copy_Input_Fragment
	     (S    : in     Session;
		      HC   : in out Handshake_Context;
		      From : in     N32;
		      Len  : in     N32;
		      Buf_Len : in N32)
	   with Pre => HC.Reasm_Buf /= null
	               and then HC.Reasm_Buf'First = 0
		               and then HC.Reasm_Buf'Length <= Max_HS_Msg
                       and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
		               and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
		               and then
		                 (if HC.Reasm_Hdr_Pending then
		                    HC.Reasm_Buf'Length = Max_HS_Msg)
		               and then Reasm_Coherent (HC)
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
		               and then HC.Reasm_Buf'Length = Buf_Len
		               and then Len >= 1
               and then Len - 1 <= HC.Reasm_Buf'Last
               and then From <= N32'Last - Len
               and then From + Len <= IO_Buffer_Capacity,
	        Post => Reasm_Coherent (HC)
	                and then HC.Reasm_Len = HC.Reasm_Len'Old
	                and then HC.Reasm_Need = HC.Reasm_Need'Old
	                and then HC.Reasm_Hdr_Pending = HC.Reasm_Hdr_Pending'Old
						                and then HC.Reasm_Buf /= null
						                and then HC.Reasm_Buf'First = 0
						                and then HC.Reasm_Buf'Length = Buf_Len
						                and then HC.Reasm_Buf'Length <= Max_HS_Msg
                                and then HC.Reasm_Len <=
                                  N32 (HC.Reasm_Buf'Length)
				                and then HC.Reasm_Need <=
				                  N32 (HC.Reasm_Buf'Length)
				                and then
				                  (if HC.Reasm_Hdr_Pending then
		                     HC.Reasm_Buf'Length = Max_HS_Msg)
		                and then HC.Transcript_Len > 0
	                and then HC.Transcript_Len <= Transcript_Capacity
	                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
	                and then
                  (if HC.Cfg.Random'Old /= null
                   then HC.Cfg.Random /= null);

   procedure Copy_Input_Fragment
     (S    : in     Session;
	      HC   : in out Handshake_Context;
	      From : in     N32;
	      Len  : in     N32;
	      Buf_Len : in N32)
   is
   begin
      pragma Assert (From + Len - 1 <= S.Input.Data'Last);
      pragma Assert (Len - 1 <= HC.Reasm_Buf'Last);
      HC.Reasm_Buf (0 .. Len - 1) :=
         S.Input.Data (From .. From + Len - 1);
   end Copy_Input_Fragment;

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Max_HS_Msg : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
	   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
		               and then HC.Cfg.Random /= null
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
		               and then Frag_Len in 1 .. 3
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then Next_Read <= S.Input.Write_Pos
               and then Max_HS_Msg = 131072,
	        Post => Result = OK
	                and then S.State = Wait_Server_Hello
		                and then Reasm_Coherent (HC)
		                and then HC.Cfg.Random /= null
			                and then HC.Transcript_Len > 0
			                and then HC.Transcript_Len <= Transcript_Capacity
			                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
			                and then WSH_Reasm_Shape (HC)
			                and then HC.Reasm_Len < HC.Reasm_Need;

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Max_HS_Msg : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
   is
   begin
      Free_Byte_Seq (HC.Reasm_Buf);
      HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
      HC.Reasm_Need := 4;
      HC.Reasm_Hdr_Pending := True;
      HC.Reasm_Len := Frag_Len;
	      pragma Assert (Frag_Len - 1 <= HC.Reasm_Buf'Last);
			      Copy_Input_Fragment
			        (S, HC, Frag_Start, Frag_Len, Max_HS_Msg);
	      pragma Assert (HC.Reasm_Buf /= null);
	      pragma Assert (HC.Reasm_Buf'First = 0);
	      pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
	      pragma Assert (HC.Reasm_Need = 4);
	      pragma Assert (HC.Reasm_Len <= 4);
	      pragma Assert (HC.Reasm_Need - 1 < Transcript_Capacity);
		      S.Input.Read_Pos := Next_Read;
		      Result := OK;
		      pragma Assert (HC.Cfg.Random /= null);
		   end Start_Pending_SH_Reassembly;

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
	   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
		               and then HC.Cfg.Random /= null
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
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
			                and then Reasm_Coherent (HC)
			                and then HC.Cfg.Random /= null
				                and then HC.Transcript_Len > 0
					                and then HC.Transcript_Len <= Transcript_Capacity
					                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
					                and then WSH_Reasm_Shape (HC)
					                and then HC.Reasm_Buf /= null
					                and then HC.Reasm_Buf'First = 0
					                and then HC.Reasm_Buf'Length = HS_Total
					                and then HC.Reasm_Buf'Length <= Max_HS_Msg
					                and then HC.Reasm_Len <=
					                  N32 (HC.Reasm_Buf'Length)
					                and then HC.Reasm_Need <=
					                  N32 (HC.Reasm_Buf'Length)
					                and then HC.Reasm_Len < HC.Reasm_Need
				                and then HC.Reasm_Need - 1 < Transcript_Capacity;

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size;
      Result     :    out Action)
   is
   begin
      Free_Byte_Seq (HC.Reasm_Buf);
      HC.Reasm_Buf := new Byte_Seq'(0 .. HS_Total - 1 => 0);
      HC.Reasm_Need := HS_Total;
      HC.Reasm_Hdr_Pending := False;
      HC.Reasm_Len := Frag_Len;
	      pragma Assert (Frag_Len - 1 <= HC.Reasm_Buf'Last);
			      Copy_Input_Fragment
			        (S, HC, Frag_Start, Frag_Len, HS_Total);
		      pragma Assert (HC.Reasm_Buf /= null);
		      pragma Assert (HC.Reasm_Buf'First = 0);
		      pragma Assert (HC.Reasm_Buf'Length = HS_Total);
			      pragma Assert (HC.Reasm_Need = HS_Total);
	      pragma Assert (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
	      pragma Assert (HC.Reasm_Need - 1 < Transcript_Capacity);
		      S.Input.Read_Pos := Next_Read;
		      Result := OK;
		      pragma Assert (HC.Cfg.Random /= null);
		   end Start_Spanning_SH_Reassembly;

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size)
	   with Pre => S.State = Wait_Server_Hello
		               and then Reasm_Coherent (HC)
		               and then HC.Cfg.Random /= null
		               and then HC.Transcript_Len > 0
		               and then HC.Transcript_Len <= Transcript_Capacity
		               and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
		               and then Frag_Len >= 4
	               and then HS_Total >= 4
	               and then HS_Total <= Frag_Len
	               and then HS_Total <= Transcript_Capacity
               and then Frag_Start <= N32'Last - Frag_Len
               and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
               and then Next_Read <= S.Input.Write_Pos,
		        Post => S.State = Wait_Server_Hello
		                and then Reasm_Coherent (HC)
			                and then HC.Cfg.Random /= null
				                and then HC.Transcript_Len > 0
				                and then HC.Transcript_Len <= Transcript_Capacity
				                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
				                and then WSH_Reasm_Shape (HC)
				                and then HC.Reasm_Buf /= null
			                and then HC.Reasm_Need > 0
		                and then HC.Reasm_Need - 1 < Transcript_Capacity;

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      HS_Total   : in     N32;
      Next_Read  : in     Buffer_Size)
   is
   begin
      Free_Byte_Seq (HC.Reasm_Buf);
      HC.Reasm_Buf := new Byte_Seq'(0 .. Frag_Len - 1 => 0);
      HC.Reasm_Need := HS_Total;
      HC.Reasm_Hdr_Pending := False;
	      HC.Reasm_Len := Frag_Len;
		      pragma Assert (Frag_Len - 1 <= HC.Reasm_Buf'Last);
			      Copy_Input_Fragment
			        (S, HC, Frag_Start, Frag_Len, Frag_Len);
	      pragma Assert (HC.Reasm_Buf /= null);
	      pragma Assert (HC.Reasm_Buf'First = 0);
		      pragma Assert (HC.Reasm_Need = HS_Total);
	      pragma Assert (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
	      pragma Assert (HC.Reasm_Need - 1 < Transcript_Capacity);
		      S.Input.Read_Pos := Next_Read;
		      pragma Assert (HC.Cfg.Random /= null);
		   end Start_Complete_SH_Reassembly;

   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      HC         : in out Handshake_Context;
      Rec        : in     Records.Parse_Result;
      Frag_Len   : in     N32;
      Frag_Start : in     N32;
      Max_HS_Msg : in     N32;
      Result     :    out Action)
   is
      Next_Read : constant Buffer_Size := S.Input.Read_Pos + Rec.Record_Len;
   begin
      Result := OK;
                           --  Fresh record. Frag_Len < 4 → start
                           --  reassembly with Hdr_Pending sentinel.
                           if Frag_Len < 4 then
                              Start_Pending_SH_Reassembly
                                (S, HC, Frag_Len, Frag_Start, Max_HS_Msg,
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
                              --  Single-record happy path: copy the
                              --  WHOLE record fragment (could include
                              --  trailing packed messages per BoGo's
                              --  PackHandshakeFlight) into Reasm_Buf.
                              --  Set Reasm_Need to just the SH size so
                              --  dispatch sees one message; the
                              --  TLS 1.2 Process_Server_Flight will
                              --  drain trailing leftover bytes.
                              Start_Complete_SH_Reassembly
                                (S, HC, Frag_Len, Frag_Start, HS_Total,
                                 Next_Read);
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
	                           if HC.Reasm_Len >= HC.Reasm_Need then
	                              Result := OK;
                              pragma Assert (S.State = Wait_Server_Hello);
                              pragma Assert (Reasm_Coherent (HC));
                              pragma Assert (HC.Cfg.Random /= null);
	                              return;
	                           end if;

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
	                                   or else HS_Total > Max_HS_Msg
	                                   or else HS_Total > Transcript_Capacity
	                                 then
	                                    Free_Byte_Seq (HC.Reasm_Buf);
	                                    HC.Reasm_Len := 0;
	                                    HC.Reasm_Need := 0;
                                    S.Last_Error := Decode_Error;
                                    Set_State (S, Error_State);
	                                    Result := Error_Alert;
	                                    return;
	                                 end if;
	                                 pragma Assert
	                                   (HC.Reasm_Buf /= null
	                                    and then HC.Reasm_Buf'Length =
	                                      Max_HS_Msg
	                                    and then HS_Total <=
	                                      N32 (HC.Reasm_Buf'Length));
	                                 HC.Reasm_Need := HS_Total;
	                                 pragma Assert
	                                   (HC.Reasm_Need - 1 <
	                                      Transcript_Capacity);
	                              end;
                           end if;

	                           if HC.Reasm_Len < HC.Reasm_Need then
	                              Result := OK;
                              pragma Assert (S.State = Wait_Server_Hello);
                              pragma Assert (Reasm_Coherent (HC));
                              pragma Assert (HC.Cfg.Random /= null);
	                              return;  --  need more fragments
	                           end if;
                        else
	                           Reasm_Fresh_Fragment
	                             (S, HC, Rec, Frag_Len, Frag_Start,
	                              Max_HS_Msg, Result);
                           pragma Assert
                             (if Result = OK then S.State = Wait_Server_Hello);
                           pragma Assert
                             (if Result = OK then Reasm_Coherent (HC));
	                           pragma Assert
	                             (if Result = OK then HC.Cfg.Random /= null);
		                        end if;
	      pragma Assert
	        (if Result = OK
	           and then HC.Reasm_Len >= HC.Reasm_Need
	         then HC.Reasm_Need > 0
	              and then HC.Reasm_Need - 1 < Transcript_Capacity);
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
                              pragma Assert (HC.Reasm_Buf /= null);
                              pragma Assert (HC.Reasm_Buf'First = 0);
                              pragma Assert
                                (HC.Reasm_Len <=
                                   N32 (HC.Reasm_Buf'Length));
                              pragma Assert (Old_Need < HC.Reasm_Len);
                              pragma Assert (Leftover > 0);
                              pragma Assert (Leftover <= HC.Reasm_Len);
                              pragma Assert
                                (Leftover <= N32 (HC.Reasm_Buf'Length));
                              pragma Assert
                                (Leftover - 1 <= HC.Reasm_Buf'Last);
                              pragma Assert (Old_Need <= HC.Reasm_Buf'Last);
                              pragma Assert
                                (HC.Reasm_Len - 1 <= HC.Reasm_Buf'Last);
                              HC.Reasm_Buf (0 .. Leftover - 1) :=
                                 HC.Reasm_Buf
                                   (Old_Need .. HC.Reasm_Len - 1);
                              HC.Reasm_Len := Leftover;
                              if Leftover < 4 then
                                 declare
                                    New_Buf : Byte_Seq_Access :=
                                       new Byte_Seq'
                                         (0 .. Max_HS_Msg - 1 => 0);
                                 begin
                                    pragma Assert (New_Buf /= null);
                                    pragma Assert (New_Buf'First = 0);
                                    pragma Assert
                                      (New_Buf'Length = Max_HS_Msg);
                                    pragma Assert (HC.Reasm_Buf /= null);
                                    pragma Assert
                                      (Leftover <= N32 (HC.Reasm_Buf'Length));
                                    for I in N32 range 0 .. Leftover - 1 loop
                                       pragma Loop_Invariant
                                         (I <= Leftover - 1);
                                       pragma Loop_Invariant
                                         (New_Buf /= null);
                                       pragma Loop_Invariant
                                         (New_Buf'First = 0);
                                       pragma Loop_Invariant
                                         (New_Buf'Length = Max_HS_Msg);
                                       pragma Loop_Invariant
                                         (HC.Reasm_Buf /= null);
                                       pragma Loop_Invariant
                                         (HC.Reasm_Buf'First = 0);
                                       pragma Loop_Invariant
                                         (Leftover <=
                                            N32 (HC.Reasm_Buf'Length));
                                       New_Buf (I) := HC.Reasm_Buf (I);
                                    end loop;
                                    Free_Byte_Seq (HC.Reasm_Buf);
                                    HC.Reasm_Buf := New_Buf;
                                 end;
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
	                           S.State := Wait_Server_Finished;
                        end if;
                        Result := OK;
   end Finalize_SH_Processing;

   procedure Parse_SH_From_Reasm_13
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
                        Result := OK;
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
	                              HC.Version := TLS_1_2;
	                              Handshake.TLS12.Parse_Server_Hello_12
	                                (S, HC, Frag, Parse_OK);
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
                              if HC.Reasm_Len > HC.Reasm_Need then
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
                                 Free_Byte_Seq (HC.Reasm_Buf);
                                 HC.Reasm_Len := 0;
                                 HC.Reasm_Need := 0;
                                 HC.Reasm_Hdr_Pending := False;
                                 return;
                              end if;

                              declare
                                 H : SPARKTLSCrypto.Hashing.SHA256.Digest;
                              begin
                                 SPARKTLSCrypto.Hashing.SHA256.Hash
                                   (H,
                                    HC.Transcript
                                      (0 .. HC.Transcript_Len - 1));
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
		                                 Free_Byte_Seq (HC.Reasm_Buf);
		                                 HC.Reasm_Len := 0;
		                                 HC.Reasm_Need := 0;
		                                 HC.Reasm_Hdr_Pending := False;
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
                                    Free_Byte_Seq (HC.Reasm_Buf);
                                    HC.Reasm_Len := 0;
                                    HC.Reasm_Need := 0;
                                    HC.Reasm_Hdr_Pending := False;
                                    return;
                                 end if;
	                                 Append_Transcript
	                                   (HC, CH2_Buf (0 .. CH2_Len - 1));
	                                 pragma Assert (HC.Transcript_Len > 0);
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
                              Free_Byte_Seq (HC.Reasm_Buf);
                              HC.Reasm_Len := 0;
                              HC.Reasm_Need := 0;
                              HC.Reasm_Hdr_Pending := False;
                              --  Reset Has_TLS_1_3 so the next SH
                              --  parse re-derives it; without this,
                              --  the second SH's matrix lookup uses
                              --  a stale Where.
			                              HC.Has_TLS_1_3 := False;
				                              Result := Has_Output;
		                              return;
		                           end if;

				                           Append_Transcript (HC, Frag);
				                           pragma Assert (HC.Transcript_Len > 0);
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
      if Result /= OK then return; end if;
      if S.State /= Wait_Server_Hello then return; end if;

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
	                        else
	                           S.Last_Error := Unexpected_Message;
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

   procedure Scrub_Handshake_Context (HC : in out Handshake_Context)
   is
   begin
      HC.Shared_Secret := (others => 0);
      HC.Client_HS_Secret := (others => 0);
      HC.Server_HS_Secret := (others => 0);
      HC.Handshake_Secret := (others => 0);
      HC.Master_Secret := (others => 0);
      HC.Master_Secret_12 := (others => 0);
      HC.Local_SK := (others => 0);
      HC.P256_Local_SK := (others => 0);
      HC.P384_Local_SK := (others => 0);
      HC.Transcript := (others => 0);
      HC.Transcript_Len := 0;
      HC.PSK_Value := (others => 0);
      HC.PSK_Binder := (others => 0);
      HC.PSK_Ticket_ID := (others => 0);
      HC.Client_Random := (others => 0);
      HC.Server_Random := (others => 0);
      Free_Byte_Seq (HC.Reasm_Buf);
   end Scrub_Handshake_Context;

   procedure Advance_Client_Non_Handshake
     (S       : in out Session;
      Result  :    out Action;
      Handled :    out Boolean)
   with Pre => S.Role = Role_Client
               and then Nonce_Space_Available (S.Client_App)
	               and then Nonce_Space_Available (S.Server_App)
	               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                 (S.Client_Seq_12)
	               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                 (S.Server_Seq_12)
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
               and then Empty_Records_Bounded_RFC_8446_5_2 (S)
               and then S.Post_HS_Len <= Max_Record_Plaintext
	               and then S.Post_HS_Need <= Max_Record_Plaintext
	               and then
	                 (if S.Post_HS_Need = 0
	                  then S.Post_HS_Len = 0
	                  else S.Post_HS_Need >= 4
	                    and then S.Post_HS_Len <= S.Post_HS_Need)
	               and then Free_Space (S.Output) >=
	                          Records.Record_Header_Size + 3 + Records.Tag_Size
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
            Handled := False;
            Result := Need_Input;
      end case;
   end Advance_Client_Non_Handshake;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with SPARK_Mode => Off
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
            Scrub_Handshake_Context (S.HC_Ptr.all);
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

   procedure Dispatch_Decrypted_HS_Message
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   is
   begin
      Process_Handshake_Message (S, HC, Msg, Result);
   end Dispatch_Decrypted_HS_Message;

   procedure Dispatch_Completed_Decrypted_Reasm
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plain_Len : in     N32;
      Pos       : in out N32;
      Result    :    out Action)
   is
   begin
	      declare
	         Reasm_Need_Const : constant N32 := HC.Reasm_Need;
	         Full : constant Byte_Seq :=
	            HC.Reasm_Buf (0 .. Reasm_Need_Const - 1);
	      begin
	         Free_Byte_Seq (HC.Reasm_Buf);
	         HC.Reasm_Len := 0;
	         HC.Reasm_Need := 0;
	         pragma Assert (Reasm_Building (HC));
	         Dispatch_Decrypted_HS_Message (S, HC, Full, Result);
	      end;
	      Free_Byte_Seq (HC.Reasm_Buf);
	      HC.Reasm_Len := 0;
		      HC.Reasm_Need := 0;
		      HC.Reasm_Hdr_Pending := False;
		      pragma Assert (Reasm_Buffer_Shaped (HC));

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
	      pragma Assert (Reasm_Building (HC));
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
     (HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      From      : in     N32;
      Take      : in     N32)
   is
   begin
      HC.Reasm_Buf
        (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
         Plaintext (From .. From + Take - 1);
      HC.Reasm_Len := HC.Reasm_Len + Take;
   end Copy_Decrypted_Reasm_Bytes;

   procedure Decode_Decrypted_Reasm_Header
     (HC            : in out Handshake_Context;
      Decode_Failed :    out Boolean)
   is
      Max_HS_Msg : constant N32 := 131072;
   begin
      Decode_Failed := False;
      pragma Assert (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
      pragma Assert (HC.Reasm_Buf'Length >= 4);
      pragma Assert (HC.Reasm_Buf'Last >= 3);

      declare
         HS_Total : constant N32 :=
            N32 (HC.Reasm_Buf (1)) * 65536
            + N32 (HC.Reasm_Buf (2)) * 256
            + N32 (HC.Reasm_Buf (3)) + 4;
      begin
         HC.Reasm_Hdr_Pending := False;
         if HS_Total > Max_HS_Msg
           or else HS_Total > N32 (HC.Reasm_Buf'Length)
         then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0;
            HC.Reasm_Need := 0;
            Decode_Failed := True;
            return;
         end if;
         HC.Reasm_Need := HS_Total;
      end;
   end Decode_Decrypted_Reasm_Header;

   procedure Fill_Decrypted_HS_Reassembly
     (HC            : in out Handshake_Context;
      Plaintext     : in     Byte_Seq;
      Plain_Len     : in     N32;
      Pos           :    out N32;
      Decode_Failed :    out Boolean)
   is
   begin
      Decode_Failed := False;

	      declare
	         Remaining : constant N32 :=
	            HC.Reasm_Need - HC.Reasm_Len;
	         Copy_Len  : constant N32 :=
	            N32'Min (Plain_Len, Remaining);
	      begin
	         if Copy_Len > 0 then
	            pragma Assert (HC.Reasm_Len + Copy_Len <= HC.Reasm_Need);
	            pragma Assert
	              (HC.Reasm_Len + Copy_Len <= N32 (HC.Reasm_Buf'Length));
	            Copy_Decrypted_Reasm_Bytes
	              (HC, Plaintext, 0, Copy_Len);
	         else
	            pragma Assert (HC.Reasm_Len <= HC.Reasm_Need);
		         end if;
	         Pos := Copy_Len;
	      end;
	      pragma Assert (Reasm_Building (HC));

	      --  Header-pending sentinel: once 4 bytes are in, decode the
      --  real HS_Total. BoGo's SplitHandshakeRecords (1-byte
      --  fragments) exercises this.
      if HC.Reasm_Hdr_Pending
        and then HC.Reasm_Len >= 4
      then
         Decode_Decrypted_Reasm_Header (HC, Decode_Failed);
	         if Decode_Failed then
	            return;
	         end if;
	         pragma Assert (Reasm_Building (HC));

	         --  Now that Reasm_Need is real, drain more body bytes from
         --  this same record if any.
         if HC.Reasm_Len < HC.Reasm_Need
           and Pos < Plain_Len
         then
            declare
               Need2 : constant N32 :=
                  HC.Reasm_Need - HC.Reasm_Len;
               Take2 : constant N32 :=
                  N32'Min (Need2, Plain_Len - Pos);
            begin
               if Take2 > 0
                 and then HC.Reasm_Len + Take2 <=
                     N32 (HC.Reasm_Buf'Length)
               then
                  pragma Assert (HC.Reasm_Buf'Last in 0 .. 131071);
                  Copy_Decrypted_Reasm_Bytes
                    (HC, Plaintext, Pos, Take2);
               end if;
               Pos := Pos + Take2;
	               pragma Assert
	                 (HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
	               pragma Assert (Reasm_Building (HC));
	            end;
	         end if;
	         pragma Assert (Reasm_Building (HC));
	      end if;
	      pragma Assert
	        (if not Decode_Failed then
	            HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
	      if HC.Reasm_Hdr_Pending then
		         pragma Assert (HC.Reasm_Need = 4);
		         pragma Assert (HC.Reasm_Len < 4);
		         pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
	      end if;
		      pragma Assert (Reasm_Building (HC));
		      pragma Assert (Reasm_Coherent (HC));
		   end Fill_Decrypted_HS_Reassembly;

   procedure Continue_Decrypted_HS_Reassembly
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Pos       :    out N32;
      Result    :    out Action)
   is
   begin
      Result := OK;
      Pos := 0;

      if HC.Reasm_Need > 0 and HC.Reasm_Buf /= null then
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
            pragma Assert (Reasm_Building (HC));
         end;

         if HC.Reasm_Len >= HC.Reasm_Need then
            --  Full message reassembled. Belt-and-braces bound check:
            --  Reasm_Need is always set to 4 (header sentinel) or
            --  HS_Total >= 4, so this is unreachable in practice but
            --  the prover doesn't know without an explicit guard before
            --  slicing for PHM.
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

            Dispatch_Completed_Decrypted_Reasm
              (S, HC, Plain_Len, Pos, Result);
         else
            --  Still need more data
            Pos := Plain_Len;  --  consumed all
            pragma Assert (Reasm_Building (HC));
         end if;
      end if;
      pragma Assert
        (if HC.Reasm_Buf /= null and then HC.Reasm_Need > 0
         then Reasm_Building (HC));
   end Continue_Decrypted_HS_Reassembly;

   procedure Process_One_Decrypted_HS_Message
     (S         : in out Session;
      HC        : in out Handshake_Context;
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
	            --  Message spans into next record.
		            Free_Byte_Seq (HC.Reasm_Buf);
		            HC.Reasm_Buf := new Byte_Seq'(0 .. Msg_Total - 1 => 0);
		            HC.Reasm_Need := Msg_Total;
		            HC.Reasm_Hdr_Pending := False;
		            pragma Assert (HC.Reasm_Buf /= null);
		            pragma Assert (HC.Reasm_Buf'First = 0);
		            pragma Assert (HC.Reasm_Buf'Length = Msg_Total);
		            pragma Assert (HC.Reasm_Need = Msg_Total);
		            pragma Assert (not HC.Reasm_Hdr_Pending);
	            pragma Assert (HC.Reasm_Need in 4 .. Transcript_Capacity);
	            declare
	               Avail : constant N32 := Plain_Len - Pos;
	            begin
	               pragma Assert (Avail < Msg_Total);
	               pragma Assert (Avail <= HC.Reasm_Need);
	               HC.Reasm_Buf (0 .. Avail - 1) :=
	                  Plaintext (Pos .. Plain_Len - 1);
	               HC.Reasm_Len := Avail;
	            end;
	            pragma Assert (HC.Reasm_Buf /= null);
	            pragma Assert (HC.Reasm_Buf'First = 0);
		            pragma Assert (HC.Reasm_Buf'Length = Msg_Total);
		            pragma Assert (not HC.Reasm_Hdr_Pending);
		            pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
	            pragma Assert (HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
	            pragma Assert (HC.Reasm_Len <= HC.Reasm_Need);
	            pragma Assert (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
	            pragma Assert (Reasm_Coherent (HC));
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
	               if Nonce_Space_Available (S.Client_App) then
	                  Send_App_Encrypted_Alert
	                    (S, Unexpected_Message, Result);
	               else
	                  S.Last_Error := Insufficient_Buffer;
	                  Set_State (S, Error_State);
	                  Result := Error_Alert;
	               end if;
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
	            if Nonce_Space_Available (S.Client_App) then
	               Send_App_Encrypted_Alert (S, Unexpected_Message, Result);
	            else
	               S.Last_Error := Insufficient_Buffer;
	               Set_State (S, Error_State);
	               Result := Error_Alert;
	            end if;
	         end if;
      end;
   end Process_One_Decrypted_HS_Message;

   procedure Process_Decrypted_HS_Packed_Messages
     (S         : in out Session;
      HC        : in out Handshake_Context;
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
	            and then Plaintext'Last < N32'Last / 2
            and then S.State in Wait_Encrypted_Extensions
                                | Wait_Certificate_Request
                                | Wait_Certificate
                                | Wait_Certificate_Verify
                                | Wait_Server_Finished
            and then Nonce_Space_Available (HC.Client_HS)
            and then Nonce_Space_Available (S.Client_App)
            and then Reasm_Coherent (HC)
            and then HC.Transcript_Len > 0
	            and then S.Negotiated_Suite
	               in Suite_AES_128_GCM_SHA256
	                | Suite_AES_256_GCM_SHA384
	                | Suite_CHACHA20_POLY1305_SHA256
		            and then
			              (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
				               then HC.Hash_Len = 48
				               else HC.Hash_Len = 32));
	               pragma Loop_Invariant
	                 (if HC.Reasm_Buf /= null and then HC.Reasm_Need > 0
	                  then Reasm_Building (HC));
	               pragma Loop_Invariant (Reasm_Buffer_Shaped (HC));

		         Process_One_Decrypted_HS_Message
	           (S, HC, Plaintext, Plain_Len, Pos, Result);
      end loop;
   end Process_Decrypted_HS_Packed_Messages;

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
         Pos : N32;
         Max_HS_Msg : constant N32 := 131072;
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
	               Saved_Transcript_Len : constant N32 := HC.Transcript_Len;
	               Saved_Suite : constant Unsigned_16 := S.Negotiated_Suite;
	            begin
	               pragma Assert (Saved_Transcript_Len > 0);
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
	               HC.Transcript_Len := Saved_Transcript_Len;

	               if not Dec_Valid then
	                  HC.Server_HS.Counter := Server_HS_Copy.Counter;
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
               --  multiple records. Use Reasm_Buf for cross-record
	               --  reassembly.
	               if Inner_Type = 16#16# then
	                  HC.Transcript_Len := Saved_Transcript_Len;
	                  pragma Assert (HC.Transcript_Len > 0);
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
		               HC.Server_HS.Counter := Server_HS_Copy.Counter;
		            end;
   end Handle_Encrypted_App_Data;

   procedure Process_Encrypted_Handshake
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
               and Plain_Len >= 0
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
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App)
               and then Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
               and then Plain_Len >= 0
               and then Plain_Len <= Max_Record_Plaintext
               and then Plain_Len <= N32 (Plaintext'Length),
        Post => (if Result = OK
                 then S.State = S.State'Old
                   and then Nonce_Space_Available (S.Client_App)
                   and then S.Post_HS_Len = S.Post_HS_Len'Old
                   and then S.Post_HS_Need = S.Post_HS_Need'Old);

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
            S.Ticket.Suite      := S.Negotiated_Suite;
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
   with Post => S.Post_HS_Len = 0
                and then S.Post_HS_Need = 0
                and then S.State = S.State'Old
                and then S.Client_App = S.Client_App'Old
                and then
                  (Nonce_Space_Available (S.Client_App) =
                   Nonce_Space_Available (S.Client_App'Old));

   procedure Reset_Post_HS_Reasm (S : in out Session) is
   begin
      S.Post_HS_Len := 0;
      S.Post_HS_Need := 0;
   end Reset_Post_HS_Reasm;

   procedure Dispatch_Post_HS_Message
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App)
               and then S.Post_HS_Need in 4 .. Max_Record_Plaintext
               and then S.Post_HS_Len = S.Post_HS_Need,
        Post => S.Post_HS_Len = 0
                and then S.Post_HS_Need = 0
                and then
                  (if Result = OK
                   then S.State = S.State'Old
                     and then Nonce_Space_Available (S.Client_App));

   procedure Dispatch_Post_HS_Message
     (S      : in out Session;
      Result :    out Action)
   is
      Msg_Len : constant N32 := S.Post_HS_Need;
      Msg     : constant Byte_Seq (0 .. Msg_Len - 1) :=
        S.Post_HS_Buf (0 .. Msg_Len - 1);
   begin
      if Msg (0) = 16#04# then
         Process_NST_Message (S, Msg, Msg_Len, Result);
      else
         Result := OK;
      end if;
      Reset_Post_HS_Reasm (S);
   end Dispatch_Post_HS_Message;

   procedure Process_Post_HS_Handshake_Bytes
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.State = Connected
               and then Nonce_Space_Available (S.Client_App)
               and then Plaintext'First = 0
               and then Plaintext'Last < N32'Last / 2
               and then Plain_Len >= 0
               and then Plain_Len <= Max_Record_Plaintext
               and then Plain_Len <= N32 (Plaintext'Length)
               and then S.Post_HS_Len <= Max_Record_Plaintext
               and then S.Post_HS_Need <= Max_Record_Plaintext
               and then
                 (if S.Post_HS_Need = 0
                  then S.Post_HS_Len = 0
                  else S.Post_HS_Need >= 4
                    and then S.Post_HS_Len <= S.Post_HS_Need);

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
         pragma Loop_Invariant (S.State = Connected);
         pragma Loop_Invariant (Nonce_Space_Available (S.Client_App));
         pragma Loop_Invariant (S.Post_HS_Len <= Max_Record_Plaintext);
         pragma Loop_Invariant (S.Post_HS_Need <= Max_Record_Plaintext);
         pragma Loop_Invariant
           (if S.Post_HS_Need = 0
            then S.Post_HS_Len = 0
            else S.Post_HS_Need >= 4
              and then S.Post_HS_Len <= S.Post_HS_Need);

         if S.Post_HS_Need = 0 then
            S.Post_HS_Len := 0;
            S.Post_HS_Need := 4;
         end if;

         declare
            Need : constant N32 := S.Post_HS_Need - S.Post_HS_Len;
            Take : constant N32 := N32'Min (Need, Plain_Len - Pos);
         begin
            if Take > 0 then
               pragma Assert (Pos + Take <= Plain_Len);
               pragma Assert (S.Post_HS_Len + Take <= S.Post_HS_Need);
               S.Post_HS_Buf (S.Post_HS_Len .. S.Post_HS_Len + Take - 1) :=
                 Plaintext (Pos .. Pos + Take - 1);
               S.Post_HS_Len := S.Post_HS_Len + Take;
               Pos := Pos + Take;
            end if;
         end;

         if S.Post_HS_Len = S.Post_HS_Need then
            if S.Post_HS_Need = 4 then
               declare
                  Msg_Total : constant N32 :=
                    N32 (S.Post_HS_Buf (1)) * 65536
                    + N32 (S.Post_HS_Buf (2)) * 256
                    + N32 (S.Post_HS_Buf (3)) + 4;
               begin
                  if Msg_Total < 4
                    or else Msg_Total > Max_Record_Plaintext
                  then
                     Reset_Post_HS_Reasm (S);
                     Send_App_Encrypted_Alert (S, Decode_Error, Result);
                     return;
                  end if;
                  S.Post_HS_Need := Msg_Total;
               end;
            end if;

            if S.Post_HS_Len = S.Post_HS_Need then
               Dispatch_Post_HS_Message (S, Result);
               if Result /= OK then
                  return;
               end if;
            end if;
         end if;
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
               if S.State = Closing and then Plain_Len > 0 then
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
	               --  expected here (KeyUpdate not yet implemented). The
	               --  handshake message itself may be split across multiple
	               --  encrypted records.
	               if S.State = Connected then
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
                  declare
                     A : N32;
                  begin
                     Records.Build_Alert_Record
                       (Level     => 1,
                        Desc      => 0,
                        Keys      => S.Client_App,
                        Output    => S.Output,
                        Bytes_Out => A);
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
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Alert_Record_12
           (Level       => 1,
            Desc        => 0,
            Keys        => S.Client_App,
            Implicit_IV => S.Client_IV_12,
            Seq_Num     => S.Client_Seq_12,
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
