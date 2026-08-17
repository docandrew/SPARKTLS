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
with SPARKTLS.Key_Update;
with SPARKTLS.HC_Alloc;
with X509;
use type X509.Algorithm_ID;
use type X509.Certificate;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;
with SPARKTLS.Ticket_Cache;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Server.TLS12;
with SPARKTLS.Handshake.TLS12;

package body SPARKTLS.Server with
   SPARK_Mode => On
is
   function Server_Config_Can_Start (Cfg : Config) return Boolean is
     (Cfg.Local /= null
      and then Cfg.Local.Has_Identity
      and then Cfg.Random /= null
      and then
        (not Cfg.Request_Client_Cert
         or else Cfg.Skip_Verify
         or else (Cfg.Trust /= null and then Cfg.Get_Time /= null)));

   function Server_Configured (HC : Handshake_Context) return Boolean is
     (HC.Cfg.Local /= null
      and then HC.Cfg.Local.Has_Identity
      and then HC.Cfg.Random /= null)
   with Ghost;

	   function Server_Active (S : Session) return Boolean is
	     (S.Role = Role_Server
		      and then S.State not in Idle | Closing | Closed | Error_State)
		   with Ghost;

   function Wait_Client_Hello_Post
     (S  : Session;
      HC : Handshake_Context) return Boolean is
     ((if S.State in Wait_Client_Hello
                    | Wait_Client_Hello_Retry
                    | Server_Hello_Sent
                    | Wait_Client_Finished
       then Server_Configured (HC))
      and then
        (if S.State = Wait_Client_Hello
         then Reasm_Building (HC))
      and then
        (if S.State = Wait_Client_Hello and then HC.Reasm_Need > 0
         then HC.Reasm_Len < HC.Reasm_Need))
   with Ghost;

	   function Handshake_Record_Fragment_Ready
	     (Rec : Records.Parse_Result) return Boolean is
     (Rec.OK
	      and then Rec.Content = Records.Content_Handshake
	      and then Rec.Fragment_Pos = Records.Record_Header_Size
	      and then Rec.Fragment_Len >= 1
	      and then Rec.Record_Len >= Rec.Fragment_Pos
	      and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
	      and then Rec.Fragment_Len <=
	        Records.Max_Fragment + Max_Record_Overhead
	      and then Rec.Fragment_Len < Transcript_Capacity)
	   with Ghost;

		   function Server_State_Keys_Ready
     (S  : Session;
      HC : Handshake_Context) return Boolean is
     ((if S.State in Wait_Client_Certificate
                    | Wait_Client_Cert_Verify
                    | Wait_Client_Finished
       then Nonce_Space_Available (S.Server_App))
	      and then
	      (if S.State in Wait_Client_Hello | Wait_Client_Hello_Retry
				         then Nonce_Space_Available (HC.Server_HS)
				              and then Nonce_Space_Available (S.Server_App)
				              and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
			                (HC.Server_Seq_12)
			              and then SPARKTLSCrypto.P384.Field.Initialized
			              and then SPARKTLSCrypto.P384.ECDSA.Initialized)
	      and then
		        (if S.State = Wait_Client_Hello and then HC.Version = TLS_1_2
		         then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
		                (HC.Server_Seq_12))
	      and then
	        (if S.State = Wait_Client_Hello_Retry
	         then HC.Version = TLS_1_3
	              and then HC.HRR_Sent
	              and then Server_Configured (HC)
		              and then HC.Cfg.Local.NaCl_Cert_Len
		                <= N32 (Max_Cert_DER)
		              and then HC.Cfg.Local.Int_Count <= Max_Pool_Size
		              and then
		                (for all I in 0 .. Max_Pool_Size - 1 =>
		                   HC.Cfg.Local.Ints (I).DER_Len
	                     <= X509.N32 (Max_Cert_DER))
	              and then
	                (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
		                 then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
		              and then Nonce_Space_Available (HC.Server_HS)
		              and then Nonce_Space_Available (S.Server_App)
		              and then SPARKTLSCrypto.P384.Field.Initialized
		              and then SPARKTLSCrypto.P384.ECDSA.Initialized)
	      and then
	        (if S.State = Wait_Client_Finished and then HC.Version = TLS_1_3
	         then Nonce_Space_Available (HC.Client_HS)
	              and then Nonce_Space_Available (S.Server_App)
	              and then HC.Transcript_Len > 0
              and then Free_Space (S.Output) >=
                Records.Record_Header_Size + 3 + Records.Tag_Size)
      and then
        (if S.State in Wait_Client_Certificate | Wait_Client_Cert_Verify
         then Nonce_Space_Available (S.Server_App)
              and then Nonce_Space_Available (HC.Client_HS)
              and then HC.Hash_Len in 32 | 48
              and then
                (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                 then HC.Hash_Len = 48
                 else HC.Hash_Len = 32)
	              and then HC.Transcript_Len > 0
	              and then
	                (if S.State = Wait_Client_Certificate
	                 then Reasm_Buffer_Shaped (HC))
	              and then
	                (if S.State = Wait_Client_Cert_Verify then
                   HC.Peer_Cert_Valid
                   and then HC.Peer_Cert_DER_Len > 0
                   and then HC.Peer_Cert_DER_Len <= Max_Cert_DER_Len
                   and then
                     X509.N32 (HC.Peer_Cert_DER_Len) - 1 <
                       X509.N32'Last
                   and then X509.Spans_Valid
                     (HC.Peer_Cert,
                      X509.N32 (HC.Peer_Cert_DER_Len) - 1)
                   and then SPARKTLSCrypto.P384.Field.Initialized
                   and then SPARKTLSCrypto.P384.ECDSA.Initialized)
              and then Free_Space (S.Output) >=
                Records.Record_Header_Size + 3 + Records.Tag_Size)
	      and then
	        (if S.State = Wait_Client_Finished and then HC.Version = TLS_1_2
	         then HC.Cfg.Local /= null
	              and then HC.Cfg.Local.Has_Identity
	              and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                (HC.Cfg.Local)
	              and then SPARKTLS.Handshake.TLS12.Valid_TLS12_Suite
	                (S.Negotiated_Suite)
	              and then SPARKTLS.Handshake.TLS12.Valid_ECDHE_Group
                (HC.Selected_Group)
              and then SPARKTLSCrypto.P384.Field.Initialized
              and then SPARKTLSCrypto.P384.ECDSA.Initialized
              and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                (HC.Client_Seq_12)
              and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                (HC.Server_Seq_12)
              and then Free_Space (S.Output) >= 7))
   with Ghost;

   --  Forward declarations
   procedure Advance_Handshake
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
		   with Pre  => Server_Active (S)
			                and then Server_Configured (HC)
			                and then Reasm_Building (HC)
			                and then HC.Legacy_Session_ID_Len in 0 .. 32
				                and then
						                  (if S.State = Wait_Client_Hello
					                     and then HC.Reasm_Need > 0
					                   then HC.Reasm_Len < HC.Reasm_Need
						                        and then Reasm_Buffer_Shaped (HC))
						                and then
							                  (if S.State = Wait_Client_Hello
							                     and then HC.Reasm_Need = 0
						                   then HC.Reasm_Buf = null)
					                and then
						                  (if S.State = Wait_Client_Hello_Retry
					                   then Reasm_Buffer_Shaped (HC))
					                and then
						                  (if S.State in Wait_Client_Certificate
						                               | Wait_Client_Cert_Verify
						                   then HC.Reasm_Len <= HC.Reasm_Need)
					                and then
					                  (if HC.Version = TLS_1_3
					                   and then S.State = Wait_Client_Certificate
					                   then Reasm_Buffer_Shaped (HC))
					                and then
						                  (if HC.Version = TLS_1_2
					                   and then S.State in Wait_Client_Certificate
					                                       | Wait_Client_Cert_Verify
					                                       | Wait_Client_Finished
						                   then SPARKTLS.Handshake.Server_Msgs
						                          .Local_Config_Valid (HC.Cfg.Local))
						                and then
								                  (if HC.Version = TLS_1_2
								                   and then S.State in Wait_Client_Certificate
								                                       | Wait_Client_Cert_Verify
								                                       | Wait_Client_Finished
								                   then Reasm_Buffer_Shaped (HC))
	                           and then
	                             (if HC.Version = TLS_1_3
	                              and then S.State = Wait_Client_Finished
	                              then Reasm_Buffer_Shaped (HC))
								                and then
							                  (if HC.Version = TLS_1_2
							                   and then S.State in Wait_Client_Cert_Verify
							                                       | Wait_Client_Finished
								                   then SPARKTLS.Handshake.TLS12
						                          .Valid_ECDHE_Group
						                             (HC.Selected_Group))
						                and then
						                  (if HC.Version = TLS_1_2
						                   and then S.State in Wait_Client_Cert_Verify
						                                       | Wait_Client_Finished
						                   then S.Negotiated_Suite in
						                      Suite_ECDHE_RSA_AES128_GCM_SHA256
						                    | Suite_ECDHE_RSA_AES256_GCM_SHA384
						                    | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
						                    | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
						                    | Suite_ECDHE_RSA_CHACHA20_SHA256
						                    | Suite_ECDHE_ECDSA_CHACHA20_SHA256)
					                and then Server_State_Keys_Ready (S, HC),
		        Post => S.State in Connection_State;


	   procedure Complete_Client_Hello_Retry
	     (S                      : in out Session;
	      HC                     : in out Handshake_Context;
	      Msg                    : in     Byte_Seq;
	      Consume_Current_Record : in     Boolean;
	      Record_Len             : in     N32;
	      Ready_To_Build         :    out Boolean;
	      Result                 :    out Action)
	   with Pre  => Server_Active (S)
	                and then S.State = Wait_Client_Hello_Retry
		                and then S.Role = Role_Server
		                and then Server_Configured (HC)
		                and then Reasm_Building (HC)
		                and then HC.Legacy_Session_ID_Len in 0 .. 32
		                and then Server_State_Keys_Ready (S, HC)
	                and then Msg'First = 0
	                and then Msg'Last <= N32 (Max_HS_Msg) - 1
	                and then
		                  (if Consume_Current_Record
		                   then Record_Len <= Available (S.Input)
		                        and then S.Input.Read_Pos <= N32'Last - Record_Len),
		        Post => (if Ready_To_Build
		                 then Server_Active (S)
		                   and then S.State = Wait_Client_Hello_Retry
		                   and then S.Role = Role_Server
		                   and then Result = OK
		                   and then Server_Configured (HC)
		                   and then HC.Cfg.Local.NaCl_Cert_Len
		                     <= N32 (Max_Cert_DER)
		                   and then
		                     (for all I in 0 .. Max_Pool_Size - 1 =>
		                        HC.Cfg.Local.Ints (I).DER_Len
		                          <= X509.N32 (Max_Cert_DER))
		                   and then HC.Cfg.Local.Int_Count <= Max_Pool_Size
		                   and then
		                     (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
		                      then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
		                   and then HC.Legacy_Session_ID_Len in 0 .. 32
					                and then HC.Transcript_Len > 0
					                and then Reasm_Building (HC)
					                and then Reasm_Buffer_Shaped (HC)
					                and then S.Negotiated_Suite in
		                     Suite_AES_128_GCM_SHA256
		                   | Suite_AES_256_GCM_SHA384
		                   | Suite_CHACHA20_POLY1305_SHA256
		                   and then Nonce_Space_Available (HC.Server_HS)
		                   and then Nonce_Space_Available (S.Server_App)
		                   and then SPARKTLSCrypto.P384.Field.Initialized
		                   and then SPARKTLSCrypto.P384.ECDSA.Initialized
		                   and then HC.HRR_Sent)
			                and then
			                  (if S.State not in Error_State | Closed
			                   then Reasm_Building (HC))
		                and then
		                  (if S.State = Wait_Client_Hello_Retry
		                      and then HC.Reasm_Need = 0
		                   then HC.Reasm_Buf = null)
				                and then
				                  (if S.State in Wait_Client_Hello_Retry
				                               | Server_Hello_Sent
		                               | Wait_Client_Finished
		                   then Server_Configured (HC))
			                and then
			                  (if S.State not in Error_State | Closed
			                   then Reasm_Building (HC));

	   procedure Validate_Client_Hello_Retry
	     (S     : in out Session;
	      HC    : in out Handshake_Context;
	      Msg   : in     Byte_Seq;
	      Valid :    out Boolean)
	   with Pre  => Server_Active (S)
	                and then S.State = Wait_Client_Hello_Retry
	                and then S.Role = Role_Server
	                and then Server_Configured (HC)
	                and then Reasm_Building (HC)
	                and then HC.Legacy_Session_ID_Len in 0 .. 32
	                and then Server_State_Keys_Ready (S, HC)
	                and then Msg'First = 0
	                and then Msg'Length > 0
	                and then Msg'Last <= N32 (Max_HS_Msg) - 1,
		        Post => Server_Active (S)
		                and then S.State = Wait_Client_Hello_Retry
		                and then S.Role = Role_Server
		                and then Server_Configured (HC)
		                and then Reasm_Building (HC)
		                and then S.Input.Read_Pos =
		                  S.Input.Read_Pos'Old
		                and then S.Input.Write_Pos =
		                  S.Input.Write_Pos'Old
				                and then HC.Legacy_Session_ID_Len in 0 .. 32
				                and then HC.HRR_Sent = HC.HRR_Sent'Old
				                and then Nonce_Space_Available (HC.Server_HS)
	                and then Nonce_Space_Available (S.Server_App)
	                and then
		                  (if Valid
		                   then HC.Version = TLS_1_3
		                     and then S.Negotiated_Suite in
		                       Suite_AES_128_GCM_SHA256
		                     | Suite_AES_256_GCM_SHA384
	                     | Suite_CHACHA20_POLY1305_SHA256
	                     and then HC.HRR_Sent);

   procedure Build_Server_Flight_After_Client_Hello_Retry
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre  => Server_Active (S)
	                and then S.State = Wait_Client_Hello_Retry
	                and then S.Role = Role_Server
	                and then HC.HRR_Sent
	                and then Server_Configured (HC)
	                and then HC.Cfg.Local.NaCl_Cert_Len
	                  <= N32 (Max_Cert_DER)
	                and then
	                  (for all I in 0 .. Max_Pool_Size - 1 =>
	                     HC.Cfg.Local.Ints (I).DER_Len
	                       <= X509.N32 (Max_Cert_DER))
	                and then HC.Cfg.Local.Int_Count <= Max_Pool_Size
	                and then
	                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
	                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
	                and then HC.Legacy_Session_ID_Len in 0 .. 32
                and then HC.Transcript_Len > 0
                and then Reasm_Building (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then S.Negotiated_Suite in
                  Suite_AES_128_GCM_SHA256
	                | Suite_AES_256_GCM_SHA384
	                | Suite_CHACHA20_POLY1305_SHA256
	                and then Nonce_Space_Available (HC.Server_HS)
	                and then Nonce_Space_Available (S.Server_App)
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
			        Post => S.State in Server_Hello_Sent | Error_State
			                and then
			                  (if S.State not in Error_State | Closed
			                   then Server_Configured (HC)
			                        and then Reasm_Building (HC));
	   procedure Handle_Client_Hello_Retry
	     (S      : in out Session;
	      HC     : in out Handshake_Context;
	      Result :    out Action)
	   with Pre  => Server_Active (S)
	                and then S.State = Wait_Client_Hello_Retry
	                and then S.Role = Role_Server
		                and then Server_Configured (HC)
                        and then Reasm_Building (HC)
                        and then Reasm_Buffer_Shaped (HC)
                        and then HC.Legacy_Session_ID_Len in 0 .. 32
		                and then Server_State_Keys_Ready (S, HC),
				        Post =>
			                  (if S.State in Wait_Client_Hello_Retry
			                               | Server_Hello_Sent
		                               | Wait_Client_Finished
		                   then Server_Configured (HC))
						                and then
							                  (if S.State = Wait_Client_Hello_Retry
							                   then Reasm_Building (HC))
						                and then
						                  (if S.State not in Error_State | Closed
						                   then Reasm_Building (HC));

   procedure Build_Server_Flight
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
	   with Pre  => Server_Active (S)
		                and then S.State in Wait_Client_Hello | Wait_Client_Hello_Retry
		                and then (if S.State = Wait_Client_Hello_Retry
		                          then HC.HRR_Sent)
		                and then Server_Configured (HC)
		                and then HC.Cfg.Local.NaCl_Cert_Len
		                  <= N32 (Max_Cert_DER)
		                and then
			                  (for all I in 0 .. Max_Pool_Size - 1 =>
			                     HC.Cfg.Local.Ints (I).DER_Len
			                       <= X509.N32 (Max_Cert_DER))
			                and then HC.Cfg.Local.Int_Count <= Max_Pool_Size
			                and then
			                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
			                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
			                and then HC.Legacy_Session_ID_Len in 0 .. 32
					                and then HC.Transcript_Len > 0
					                and then Reasm_Building (HC)
					                and then Reasm_Buffer_Shaped (HC)
					                and then S.Negotiated_Suite in
				                  Suite_AES_128_GCM_SHA256
			                  | Suite_AES_256_GCM_SHA384
			                  | Suite_CHACHA20_POLY1305_SHA256
			                and then Nonce_Space_Available (HC.Server_HS)
			                and then Nonce_Space_Available (S.Server_App)
			                and then SPARKTLSCrypto.P384.Field.Initialized
			                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
	        Post => (if S.State'Old = Wait_Client_Hello
	                  then S.State in Wait_Client_Hello_Retry
	                                  | Server_Hello_Sent
	                                  | Error_State
		                  else S.State in Server_Hello_Sent | Error_State)
										                and then (if S.State not in Error_State | Closed
										                          then Server_Configured (HC)
										                               and then Reasm_Building (HC))
						                and then
					                  (if S.State = Wait_Client_Hello
			                     and then HC.Reasm_Need > 0
			                   then HC.Reasm_Len < HC.Reasm_Need);

   procedure Build_Hello_Retry_Request
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Group     : in     Unsigned_16;
      HRR_Buf   :    out Byte_Seq;
	      HRR_Len   :    out N32;
	      Rec_Out   :    out N32)
	   with Pre  => Server_Active (S)
		                and then Server_Configured (HC)
		                and then Reasm_Building (HC)
		                and then Reasm_Buffer_Shaped (HC),
		        Post => (if HRR_Len > 0
		                 then HRR_Buf'First = 0
		                   and then HRR_Len - 1 <= HRR_Buf'Last)
			                and then S.State = S.State'Old
                and then (if S.State not in Error_State | Closed
                          then Server_Configured (HC))
		                and then (if HRR_Len > 0
			                          then HC.Transcript_Len > 0)
		                and then Reasm_Building (HC)
		                and then Reasm_Buffer_Shaped (HC);

   procedure Append_And_Encrypt_Server_HS
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Scratch   : in out IO_Buffer;
      Saved_Ctr : in     Unsigned_64;
      Result    :    out Action;
      Emitted   :    out Boolean)
   with Pre  => Server_Active (S)
	                and then Server_Configured (HC)
	                and then HC.Transcript_Len > 0
	                and then Reasm_Building (HC)
	                and then Reasm_Buffer_Shaped (HC)
	                and then Plaintext'Length > 0
                and then Plaintext'Length <= Max_Fragment
                and then Plaintext'Length < Transcript_Capacity
                and then Nonce_Space_Available (HC.Server_HS),
	        Post => (if Emitted
		                 then Server_Active (S)
		                  and then Server_Configured (HC)
		                  and then Reasm_Building (HC)
		                  and then Reasm_Buffer_Shaped (HC)
		                  and then HC.Transcript_Len > 0
                      and then S.State = S.State'Old
                      and then S.Role = S.Role'Old
                      and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                      and then HC.Server_HS.Counter =
                        HC.Server_HS.Counter'Old + 1
                      and then Result = OK)
		                and then (if not Emitted
			                          then S.State = Error_State
			                               and then Result = Error_Alert
			                               and then Reasm_Building (HC)
			                               and then HC.Server_HS.Counter = Saved_Ctr);

   procedure Append_And_Encrypt_Server_HS_Fragmented
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Scratch   : in out IO_Buffer;
      Saved_Ctr : in     Unsigned_64;
      Result    :    out Action;
      Emitted   :    out Boolean)
   with Pre  => Server_Active (S)
                and then Server_Configured (HC)
                and then HC.Transcript_Len > 0
                and then Reasm_Building (HC)
                and then Reasm_Buffer_Shaped (HC)
                and then Plaintext'First = 0
                and then Plaintext'Last in 0 .. N32 (Transcript_Capacity) - 2
                and then HC.Server_HS.Counter <= Unsigned_64'Last - 2,
	        Post => (if Emitted
		                 then Server_Active (S)
			                      and then Server_Configured (HC)
			                      and then Reasm_Building (HC)
			                      and then Reasm_Buffer_Shaped (HC)
			                      and then HC.Transcript_Len > 0
                      and then S.State = S.State'Old
                      and then S.Role = S.Role'Old
                      and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                      and then HC.Server_HS.Counter in
                        HC.Server_HS.Counter'Old + 1 ..
                        HC.Server_HS.Counter'Old + 2
                      and then Result = OK)
		                and then (if not Emitted
			                          then S.State = Error_State
				                               and then Result = Error_Alert
				                               and then Reasm_Building (HC)
				                               and then Reasm_Buffer_Shaped (HC)
				                               and then HC.Server_HS.Counter = Saved_Ctr);

   procedure Process_Client_Auth
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre  => S.State in Wait_Client_Certificate | Wait_Client_Cert_Verify
                and then S.Role = Role_Server
                and then Server_Configured (HC)
                and then Nonce_Space_Available (S.Server_App)
                and then Nonce_Space_Available (HC.Client_HS)
                and then HC.Hash_Len in 32 | 48
                and then
                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                   then HC.Hash_Len = 48
                   else HC.Hash_Len = 32)
			                and then HC.Transcript_Len > 0
			                and then Reasm_Building (HC)
			                and then
			                  (if S.State = Wait_Client_Certificate
			                   then Reasm_Buffer_Shaped (HC))
			                and then HC.Reasm_Len <= HC.Reasm_Need
		                and then
	                  (if S.State = Wait_Client_Cert_Verify then
                     HC.Peer_Cert_Valid
	                     and then HC.Peer_Cert_DER_Len > 0
	                     and then HC.Peer_Cert_DER_Len <= Max_Cert_DER_Len
	                     and then
	                       X509.N32 (HC.Peer_Cert_DER_Len) - 1 <
	                          X509.N32'Last
	                     and then X509.Spans_Valid
	                       (HC.Peer_Cert,
	                        X509.N32 (HC.Peer_Cert_DER_Len) - 1)
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized)
                and then Free_Space (S.Output) >=
                           Records.Record_Header_Size + 3 + Records.Tag_Size,
					        Post => (if S.State not in Error_State | Closed
				                          then Server_Configured (HC))
			                and then (if S.State not in Error_State | Closed
		                          then Reasm_Building (HC));

   procedure Process_Client_Finished
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Client_Finished
	               and then S.Role = Role_Server
	               and then Server_Configured (HC)
	               and then Nonce_Space_Available (S.Server_App)
		               and then Nonce_Space_Available (HC.Client_HS)
			               and then HC.Transcript_Len > 0
			               and then Reasm_Building (HC)
			               and then Reasm_Buffer_Shaped (HC)
		               and then Free_Space (S.Output) >=
                          Records.Record_Header_Size + 3 + Records.Tag_Size,
			        Post => (if S.State not in Error_State | Closed
				                          then Server_Configured (HC));
   procedure Handle_PCF_App_Data
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Rec    : in     Records.Parse_Result;
      Result :    out Action)
   with Pre => S.State = Wait_Client_Finished
               and then S.Role = Role_Server
               and then Rec.OK
               and then Rec.Content = Records.Content_Application_Data
	               and then Server_Configured (HC)
	               and then HC.Transcript_Len > 0
	               and then Nonce_Space_Available (HC.Client_HS)
	               and then Nonce_Space_Available (S.Server_App)
	               and then Free_Space (S.Output) >=
	                          Records.Record_Header_Size + 3 + Records.Tag_Size
               and then Rec.Fragment_Len >= 1
               and then Rec.Fragment_Len <=
                          Records.Max_Fragment + Max_Record_Overhead
               and then Rec.Fragment_Pos = Records.Record_Header_Size
               and then Rec.Record_Len >= Rec.Fragment_Pos
	               and then Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos
		               and then Rec.Record_Len <= Available (S.Input)
			               and then Reasm_Building (HC)
			               and then Reasm_Buffer_Shaped (HC)
	               ,
							        Post => (if S.State not in Error_State | Closed
						                          then Server_Configured (HC)
					                               and then Reasm_Building (HC)
					                               and then Reasm_Buffer_Shaped (HC));
   procedure Verify_Client_Finished
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Msg_Len   : in     N32;
      Result    :    out Action)
   with Pre => S.State = Wait_Client_Finished
	               and then S.Role = Role_Server
	               and then Server_Configured (HC)
		               and then Nonce_Space_Available (S.Server_App)
		               and then Plaintext'First = 0
		               and then Plain_Len > 0
		               and then Plaintext'Last < N32'Last
		               and then Plain_Len - 1 <= Plaintext'Last
					               and then HC.Transcript_Len > 0
					               and then Reasm_Building (HC)
					               and then Reasm_Buffer_Shaped (HC)
,
			        Post => (if S.State not in Error_State | Closed
						                          then Server_Configured (HC)
					                               and then Reasm_Building (HC)
					                               and then Reasm_Buffer_Shaped (HC));



   procedure Process_Connected (S : in out Session; Result : out Action)
   with Pre => S.State in Connected | Closing
               and then S.Role = Role_Server
               and then Nonce_Space_Available (S.Server_App)
               and then Nonce_Space_Available (S.Client_App)
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then S.Warning_Alerts_Recvd <= Max_Warning_Alerts
               and then S.Empty_Records_Recvd <= Max_Empty_Records
               and then Free_Space (S.Output) >=
                          Records.Record_Header_Size + 3 + Records.Tag_Size;

   procedure Derive_Handshake_Keys
     (S  : in     Session;
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
	               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                       | Suite_AES_256_GCM_SHA384
	                                       | Suite_CHACHA20_POLY1305_SHA256
		               and Server_Configured (HC)
			               and Reasm_Building (HC)
			               and Reasm_Buffer_Shaped (HC),
		        Post => Server_Configured (HC)
		                and HC.Transcript_Len = HC.Transcript_Len'Old
		                and HC.Server_HS.Counter = 0
		                and (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
		                     then HC.Hash_Len = 48
		                     else HC.Hash_Len = 32)
			                and Nonce_Space_Available (HC.Server_HS)
				                and Reasm_Building (HC)
				                and Reasm_Buffer_Shaped (HC);

   procedure Derive_App_Keys
     (S  : in out Session;
      HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
	               and S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                       | Suite_AES_256_GCM_SHA384
	                                       | Suite_CHACHA20_POLY1305_SHA256
	               and Server_Configured (HC)
	               and Reasm_Building (HC),
	        Post => Server_Configured (HC)
	                and HC.Transcript_Len = HC.Transcript_Len'Old
	                and S.State = S.State'Old
                and S.Role = S.Role'Old
	                and S.Negotiated_Suite = S.Negotiated_Suite'Old
	                and S.Server_App.Counter = 0
	                and Nonce_Space_Available (S.Server_App)
	                and Nonce_Space_Available (S.Client_App)
	                and Reasm_Building (HC);

   procedure Set_Traffic_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16)
   with Pre => Suite in Suite_AES_128_GCM_SHA256
                      | Suite_AES_256_GCM_SHA384
                      | Suite_CHACHA20_POLY1305_SHA256,
        Post => TK.Counter = 0
                and TK.Suite = Suite
                and Nonce_Space_Available (TK);

   --  Alert_Desc / Error_Code mapping is in the parent SPARKTLS
   --  package — child-unit visibility resolves call sites here.

   --  Send a fatal alert and set error state
   procedure Send_Alert_And_Error
     (S      : in out Session;
      Err    : Error_Code;
      Result : out Action)
	   with Pre => S.State not in Idle | Closed | Closing | Error_State,
			        Post => S.State = Error_State
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
	   with Pre => S.State not in Idle | Closed | Closing | Error_State,
	        Post => S.State = Error_State
	                and then Result in Has_Output | Error_Alert
	                and then S.Role = S.Role'Old
	                and then S.Input.Read_Pos = S.Input.Read_Pos'Old
	                and then S.Input.Write_Pos = S.Input.Write_Pos'Old;

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
	   with Pre  => S.State not in Idle | Closed | Error_State
                and then Alert_Desc (Err) /= 0
                and then Nonce_Space_Available (S.Server_App),
        Post => S.State = Error_State
                and then S.Last_Error = Err
                and then Result in Has_Output | Error_Alert
                and then (if Free_Space (S.Output'Old) >=
                            Records.Record_Header_Size + 3 + Records.Tag_Size
                          then Output_Pending (S) > 0)
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
			                and then HC.Transcript_Len <= Transcript_Capacity
,
	        Post => HC.Transcript_Len >= HC.Transcript_Len'Old
	                and HC.Transcript_Len <= Transcript_Capacity
                and (if HC.Transcript_Len'Old > 0
                       or else Data'First <= Data'Last
                     then HC.Transcript_Len > 0)
		                and (if Server_Configured (HC)'Old
		                     then Server_Configured (HC))
			                and
				                  (if HC.Cfg.Local'Old /= null
				                     and then
				                       Handshake.Server_Msgs.Local_Config_Valid
				                         (HC.Cfg.Local'Old)
				                   then HC.Cfg.Local /= null
				                     and then
				                       Handshake.Server_Msgs.Local_Config_Valid
				                         (HC.Cfg.Local))
			                and HC.Hash_Len = HC.Hash_Len'Old

			                and HC.Version = HC.Version'Old
		                and HC.Peer_Cert = HC.Peer_Cert'Old
		                and HC.Peer_Cert_Valid = HC.Peer_Cert_Valid'Old
		                and HC.Peer_Cert_DER_Len = HC.Peer_Cert_DER_Len'Old
		                and
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
			                and HC.HRR_Sent = HC.HRR_Sent'Old
			                and HC.Legacy_Session_ID_Len =
			                      HC.Legacy_Session_ID_Len'Old
					                and (if Reasm_Building (HC)'Old
					                     then Reasm_Building (HC))
						                and (if Reasm_Buffer_Shaped (HC)'Old
						                     then Reasm_Buffer_Shaped (HC))
						                and (if Reasm_Buffer_Shaped (HC)'Old
						                     then Reasm_Buffer_Shaped (HC))
						                and HC.Reasm_Len = HC.Reasm_Len'Old
					                and HC.Reasm_Need = HC.Reasm_Need'Old
						                and
					                  (if HC.Reasm_Len'Old <= HC.Reasm_Need'Old
				                   then HC.Reasm_Len <= HC.Reasm_Need)
				                and HC.Server_Seq_12 = HC.Server_Seq_12'Old
				                and HC.Server_HS.Counter = HC.Server_HS.Counter'Old
                and HC.Client_HS.Counter = HC.Client_HS.Counter'Old
                and HC.Server_HS.Suite = HC.Server_HS.Suite'Old
                and HC.Client_HS.Suite = HC.Client_HS.Suite'Old
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
      Local                 : Valid_Identity_Access;
      Random                : Random_Bytes_Fn;
      Trust                 : Trust_Store_Access := null;
      Request_Client_Cert   : Boolean := False;
      Require_Client_Cert   : Boolean := False;
      Store_Session         : Store_Session_Fn := null;
      Lookup_Session        : Lookup_Session_Fn := null;
      ALPN                  : String := "";
      Versions              : Version_Policy := Allow_Both;
      Get_Active_TEK        : Get_Active_TEK_Fn := null;
      Get_TEK_By_Id         : Get_TEK_By_Id_Fn := null;
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;
      Get_Time              : Get_Time_Fn := null;
      Select_Identity       : SNI_Cert_Selector := null)
   is
      Cfg : Config;
   begin
      Cfg.Random              := Random;
      Cfg.Local               := Local;
      Cfg.Trust               := Trust;
      Cfg.Request_Client_Cert := Request_Client_Cert;
      Cfg.Require_Client_Cert := Require_Client_Cert;
      Cfg.Store_Session       := Store_Session;
      Cfg.Lookup_Session      := Lookup_Session;
      Cfg.Versions            := Versions;
      Cfg.Get_Active_TEK      := Get_Active_TEK;
      Cfg.Get_TEK_By_Id       := Get_TEK_By_Id;
      Cfg.TLS12_Ticket_Lifetime := TLS12_Ticket_Lifetime;
      Cfg.Get_Time            := Get_Time;
      Cfg.Select_Identity     := Select_Identity;
      if ALPN'Length > 0 and then ALPN'Length <= Max_Hostname_Len then
         Cfg.ALPN.Data (1 .. ALPN'Length) := ALPN;
         Cfg.ALPN.Len := ALPN'Length;
      end if;
      Init (S, Cfg);
   end Configure;

   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   is
   begin
      --  The postcondition is a two-conjunct goal (Role and State). Left
      --  whole, the prover discharges one conjunct or the other depending
      --  on how its budget falls, and reports whichever it dropped -- the
      --  same one-at-a-time behaviour seen on VCs 1021/1023. Asserting both
      --  conjuncts at each exit decomposes the goal in place, so each is
      --  established from local facts instead of re-derived at the end.
      S := (State  => Wait_Client_Hello,
            Role   => Role_Server,
            others => <>);
      pragma Assert (Role (S) = Role_Server);
      pragma Assert (State (S) = Wait_Client_Hello);

      if not Server_Config_Can_Start (Cfg) then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         pragma Assert (Role (S) = Role_Server);
         pragma Assert (State (S) = Error_State);
         return;
      end if;

      S.HC_Ptr := HC_Alloc.Allocate;
      if S.HC_Ptr = null then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         pragma Assert (Role (S) = Role_Server);
         pragma Assert (State (S) = Error_State);
         return;
      end if;
      S.HC_Ptr.Cfg := Cfg;
      pragma Assert (Role (S) = Role_Server);
      pragma Assert (State (S) = Wait_Client_Hello);
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

   procedure Advance_Server_Non_Handshake
     (S       : in out Session;
      Result  :    out Action;
      Handled :    out Boolean)
   with Pre => S.Role = Role_Server
               and then Nonce_Space_Available (S.Server_App)
               and then Nonce_Space_Available (S.Client_App)
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                 (S.Client_Seq_12)
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                 (S.Server_Seq_12)
               and then S.App_Data_Len <= Max_Record_Plaintext
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
               and then Empty_Records_Bounded_RFC_8446_5_2 (S)
               and then Free_Space (S.Output) >=
                          Records.Record_Header_Size + 3 + Records.Tag_Size
   is
   begin
      Handled := True;
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
            elsif Input_Available (S) > 0 then
               if S.Negotiated_Version = TLS_1_2 then
                  SPARKTLS.Server.TLS12.Process_Connected_12 (S, Result);
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
            S.State := Error_State;
            Result := Error_Alert;

         when others =>
            Handled := False;
            Result := Need_Input;
      end case;
   end Advance_Server_Non_Handshake;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   is
      Handled : Boolean;
   begin
      Advance_Server_Non_Handshake (S, Result, Handled);
      if not Handled then
         if S.HC_Ptr = null then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         --  BORROW: Advance_Handshake takes both S and the context.
         --  Passing S and S.HC_Ptr.all together is aliasing (SPARK RM
         --  6.4.2) -- flow analysis reports it as "high", and note that
         --  --mode=check_all does NOT catch it, since aliasing is a flow
         --  check rather than a legality one. Move the pointer out of S
         --  for the duration of the call so S no longer reaches the
         --  context, then hand ownership back. Mirrors Client.Advance.
         declare
            HC : Handshake_Context_Access := S.HC_Ptr;
         begin
            S.HC_Ptr := null;
            Advance_Handshake (S, HC.all, Result);
            S.HC_Ptr := HC;
         end;

         if S.State in Connected | Error_State | Closed then
            S.Peer_Cert_Valid := S.HC_Ptr.Peer_Cert_Valid;
            --  Zero ALL key material before freeing HC.
            Scrub_Handshake_Context (S.HC_Ptr.all);
            HC_Alloc.Free (S.HC_Ptr);
         end if;
      end if;
   end Advance;

   procedure Complete_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => S.State = Wait_Client_Hello
               and then S.Role = Role_Server
               and then Server_Configured (HC)
	               and then HC.Legacy_Session_ID_Len in 0 .. 32
		               and then HC.Transcript_Len > 0
							                              and then Reasm_Building (HC)
					               and then HC.Reasm_Need = 0
					               and then HC.Reasm_Buf = null
					               and then SPARKTLSCrypto.P384.Field.Initialized
	               and then SPARKTLSCrypto.P384.ECDSA.Initialized,
					                       Post => Wait_Client_Hello_Post (S, HC);

   procedure Complete_Client_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      --  RFC 6066 §3 + RFC 8446 §4.4.2.4: SNI-based certificate
      --  selection. A null callback result means "no match"; use the
      --  default identity already in HC.Cfg.Local.
      if HC.Cfg.Select_Identity /= null
        and then HC.Peer_SNI.Len > 0
      then
         declare
            Picked : constant Selected_Identity_Access :=
              HC.Cfg.Select_Identity
                (HC.Peer_SNI.Data
                   (HC.Peer_SNI.Data'First ..
                    HC.Peer_SNI.Data'First + HC.Peer_SNI.Len - 1));
         begin
            if Picked /= null then
               HC.Cfg.Local := Picked;
	            end if;
	            pragma Assert (Server_Configured (HC));
	            pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
	         end;
	      else
	         pragma Assert (Server_Configured (HC));
	         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
	      end if;

	      if HC.Cfg.Local = null
	        or else not HC.Cfg.Local.Has_Identity
	        or else HC.Cfg.Random = null
	        or else HC.Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
	        or else HC.Cfg.Local.Int_Count > Max_Pool_Size
	        or else
	          (for some I in 0 .. Max_Pool_Size - 1 =>
	             HC.Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
	        or else
	          (HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
	           and then HC.Cfg.Local.RSA_Mod_Len not in 64 .. 512)
	      then
		         Send_Alert_And_Error (S, Handshake_Failure, Result);
		         return;
	      end if;

	      pragma Assert (Server_Configured (HC));
	      pragma Assert (HC.Cfg.Local.NaCl_Cert_Len <= N32 (Max_Cert_DER));
	      pragma Assert (HC.Cfg.Local.Int_Count <= Max_Pool_Size);
	      pragma Assert
	        (for all I in 0 .. Max_Pool_Size - 1 =>
	           HC.Cfg.Local.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER));
	      pragma Assert
	        (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
	         then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512);
	      pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
	      pragma Assert (HC.Transcript_Len > 0);

      declare
         Policy  : constant Version_Policy := HC.Cfg.Versions;
         Want_13 : constant Boolean :=
           HC.Version = TLS_1_3 and Policy /= TLS_1_2_Only;
         Want_12 : constant Boolean :=
           (HC.Version = TLS_1_2
            or (HC.Version = TLS_1_3 and Policy = TLS_1_2_Only))
           and Policy /= TLS_1_3_Only;
      begin
         if Want_13 then
            if S.Negotiated_Suite in
                 Suite_AES_128_GCM_SHA256
               | Suite_AES_256_GCM_SHA384
               | Suite_CHACHA20_POLY1305_SHA256
              and then
                (not HC.Client_Saw_Key_Share
                 or else not HC.Client_Saw_Supported_Groups)
            then
               Send_Alert_And_Error (S, Missing_Extension, Result);
               return;
            end if;

	            if S.Negotiated_Suite not in
	                 Suite_AES_128_GCM_SHA256
	               | Suite_AES_256_GCM_SHA384
	               | Suite_CHACHA20_POLY1305_SHA256
	              or else
	              not (HC.Client_Has_X25519 or
	                   HC.Client_Has_P256 or
                   HC.Client_Has_P384 or
                   HC.Client_Supports_X25519 or
                   HC.Client_Supports_P256 or
                   HC.Client_Supports_P384)
            then
               if Want_12 and S.Negotiated_Suite_12 /= 0 then
	                  HC.Version := TLS_1_2;
	                  pragma Assert
	                    (SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                       (HC.Server_Seq_12));
	                  pragma Assert
	                    (if HC.Reasm_Need = 0 then HC.Reasm_Buf = null);
	                  SPARKTLS.Server.TLS12.Build_Server_Flight_12
                    (S, HC, Result);
				            pragma Assert
				              (if S.State in Wait_Client_Hello
				                         | Wait_Client_Hello_Retry
                                 | Server_Hello_Sent
                                 | Wait_Client_Finished
                     then Server_Configured (HC));
				            pragma Assert
				              (if S.State = Wait_Client_Hello
				               then Reasm_Building (HC));
               else
                  Send_Alert_And_Error (S, Handshake_Failure, Result);
               end if;
            else
               pragma Assert
                 (S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                      | Suite_AES_256_GCM_SHA384
                                      | Suite_CHACHA20_POLY1305_SHA256);
	               if not Nonce_Space_Available (HC.Server_HS)
	                 or else not Nonce_Space_Available (S.Server_App)
	               then
		                  Send_Alert_And_Error (S, Internal_Error, Result);
		                  return;
		               end if;
	               Build_Server_Flight (S, HC, Result);
               pragma Assert
                 (if S.State in Wait_Client_Hello
                              | Wait_Client_Hello_Retry
                              | Server_Hello_Sent
                              | Wait_Client_Finished
                  then Server_Configured (HC));
	               pragma Assert
	                 (if S.State = Wait_Client_Hello
	                  then Reasm_Building (HC));
            end if;
            pragma Assert
              (if S.State in Wait_Client_Hello
                           | Wait_Client_Hello_Retry
                           | Server_Hello_Sent
                           | Wait_Client_Finished
               then Server_Configured (HC));
		            pragma Assert
		              (if S.State = Wait_Client_Hello
		               then Reasm_Building (HC));
	            return;
         elsif Want_12 and S.Negotiated_Suite_12 /= 0 then
	            HC.Version := TLS_1_2;
		            if HC.Server_Seq_12 = Unsigned_64'Last
		            then
		               Send_Alert_And_Error (S, Internal_Error, Result);
		               return;
		            end if;
			            pragma Assert (Reasm_Buffer_Shaped (HC));
			            SPARKTLS.Server.TLS12.Build_Server_Flight_12 (S, HC, Result);
            pragma Assert
              (if S.State in Wait_Client_Hello
                           | Wait_Client_Hello_Retry
                           | Server_Hello_Sent
                           | Wait_Client_Finished
               then Server_Configured (HC));
            pragma Assert
              (if S.State in Wait_Client_Hello
                           | Wait_Client_Hello_Retry
                           | Server_Hello_Sent
                           | Wait_Client_Finished
               then Reasm_Building (HC));
            pragma Assert
              (if S.State in Wait_Client_Hello
                           | Wait_Client_Hello_Retry
                           | Server_Hello_Sent
                           | Wait_Client_Finished
               then Server_Configured (HC));
	            pragma Assert
	              (if S.State in Wait_Client_Hello
	                           | Wait_Client_Hello_Retry
	                           | Server_Hello_Sent
	                           | Wait_Client_Finished
	               then Reasm_Building (HC));
	            return;
         else
            if (HC.Version = TLS_1_2 and Policy = TLS_1_3_Only)
              or else
               (HC.Version = TLS_1_3 and Policy = TLS_1_2_Only)
            then
               Send_Alert_And_Error (S, Protocol_Version, Result);
            else
               Send_Alert_And_Error (S, Handshake_Failure, Result);
            end if;
            pragma Assert
              (if S.State in Wait_Client_Hello
                           | Wait_Client_Hello_Retry
                           | Server_Hello_Sent
                           | Wait_Client_Finished
               then Server_Configured (HC));
	            pragma Assert
	              (if S.State in Wait_Client_Hello
	                           | Wait_Client_Hello_Retry
	                           | Server_Hello_Sent
	                           | Wait_Client_Finished
	               then Reasm_Building (HC));
	            return;
         end if;
      end;
   end Complete_Client_Hello;

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
	   with Pre => S.State = Wait_Client_Hello
		               and then S.Role = Role_Server
		               and then Server_Configured (HC)
				               and then Reasm_Building (HC)
                        and then
                          (if HC.Reasm_Need > 0
                           then Reasm_Buffer_Shaped (HC))
                        and then HC.Legacy_Session_ID_Len in 0 .. 32
		               and then
		                 (if HC.Reasm_Need > 0
		                  then HC.Reasm_Len < HC.Reasm_Need)
		               and then Server_State_Keys_Ready (S, HC),
	        Post => Wait_Client_Hello_Post (S, HC);

   procedure Handle_Wait_Client_Hello
	     (S      : in out Session;
	      HC     : in out Handshake_Context;
	      Result :    out Action)
	   is
	   begin
	            if Input_Available (S) = 0 then
	               Result := Need_Input;
		               pragma Assert (S.State = Wait_Client_Hello);
		               pragma Assert (Server_Configured (HC));
		               pragma Assert_And_Cut (Reasm_Building (HC));
		               pragma Assert (Wait_Client_Hello_Post (S, HC));
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
			                  pragma Assert (Wait_Client_Hello_Post (S, HC));
			                  return;
		               end if;

               if Rec.Bad_Version then
                  --  RFC 8446 §5.1: legacy_record_version must lie
	                  --  in {3,1}..{3,4}. Out-of-band → protocol_version.
		                  Send_Alert_And_Error (S, Protocol_Version, Result);
			                  pragma Assert (Wait_Client_Hello_Post (S, HC));
			                  return;
		               end if;

               if not Rec.OK then
                  if Rec.Record_Len > 0 then
	                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
		                     Send_Alert_And_Error (S, Unexpected_Message, Result);
                  else
                     Result := Need_Input;
	                     pragma Assert (S.State = Wait_Client_Hello);
	                     pragma Assert (Server_Configured (HC));
	                     pragma Assert (Reasm_Building (HC));
	                  end if;
	                  pragma Assert (Wait_Client_Hello_Post (S, HC));
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
		                  pragma Assert (Wait_Client_Hello_Post (S, HC));
		                  return;
               end if;

               if Rec.Content = Records.Content_Alert then
                  --  Plaintext alert before handshake — just close
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  S.Last_Error := Unexpected_Message;
	                  Set_State (S, Error_State);
	                  Result := Error_Alert;
		                  pragma Assert (Wait_Client_Hello_Post (S, HC));
		                  return;
               end if;

               if Rec.Content /= Records.Content_Handshake then
                  --  Application_data or unknown type before handshake
	                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	                  Send_Alert_And_Error (S, Unexpected_Message, Result);
		                  pragma Assert (Wait_Client_Hello_Post (S, HC));
		                  return;
               end if;

	               declare
	                  procedure Process_Handshake_Record
	                  with Pre => S.State = Wait_Client_Hello
	                              and then S.Role = Role_Server
	                              and then Server_Configured (HC)
				                              and then Reasm_Building (HC)
					                              and then
					                                (if HC.Reasm_Need > 0
					                                 then Reasm_Buffer_Shaped (HC))
					                              and then HC.Legacy_Session_ID_Len in 0 .. 32
	                              and then Server_State_Keys_Ready (S, HC)
		                              and then Handshake_Record_Fragment_Ready
		                                (Rec)
		                              and then Rec.Record_Len <=
		                                Available (S.Input)
                                      and then Wait_Client_Hello_Post (S, HC),
			                       Post => Wait_Client_Hello_Post (S, HC);

		                  procedure Process_Handshake_Record
		                  is
			                     Frag_Start : constant N32 :=
		                     S.Input.Read_Pos + Rec.Fragment_Pos;
		                     Frag_Len   : constant N32 := Rec.Fragment_Len;

		                  --  Maximum handshake message we'll reassemble (128 KB).
                  --  Larger messages are rejected.
                  Max_HS_Msg : constant N32 := 131072;

		                  procedure Free_Reasm
		                  with Pre  => Server_Active (S)
				                               and then Server_Configured (HC)
					                               and then HC.Legacy_Session_ID_Len
					                                 in 0 .. 32,
					                       Post => Server_Active (S)
					                               and then S.Role = S.Role'Old
					                               and then S.State = S.State'Old
					                               and then S.Negotiated_Suite =
					                                 S.Negotiated_Suite'Old
					                               and then S.Server_App.Counter =
					                                 S.Server_App.Counter'Old
					                               and then Server_Configured (HC)
					                               and then HC.Version = HC.Version'Old
					                               and then HC.Transcript_Len =
					                                 HC.Transcript_Len'Old
					                               and then HC.HRR_Sent =
					                                 HC.HRR_Sent'Old
					                               and then HC.Server_HS.Counter =
					                                 HC.Server_HS.Counter'Old
					                               and then HC.Legacy_Session_ID_Len
					                                 in 0 .. 32
				                               and then HC.Reasm_Buf = null
	                               and then HC.Reasm_Len = 0
	                               and then HC.Reasm_Need = 0
	                               and then not HC.Reasm_Hdr_Pending
	                               and then Reasm_Building (HC)
	   is
                  begin
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0;
                     HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                  end Free_Reasm;

			                  procedure Continue_Reassembly
		                  with Pre => S.State = Wait_Client_Hello
		                              and then S.Role = Role_Server
		                              and then Server_Configured (HC)
		                              and then Reasm_Building (HC)
		                              and then HC.Legacy_Session_ID_Len in 0 .. 32
		                              and then Server_State_Keys_Ready (S, HC)
	                              and then Handshake_Record_Fragment_Ready
	                                (Rec)
	                              and then Rec.Record_Len <=
	                                Available (S.Input)
	                              and then HC.Reasm_Need > 0
	                              and then HC.Reasm_Len < HC.Reasm_Need
			                              and then HC.Reasm_Buf /= null
			                              and then HC.Reasm_Buf'First = 0
			                              and then HC.Reasm_Buf'Last < N32'Last
			                                 and then HC.Reasm_Buf'Length <= Max_HS_Msg
			                                 and then
			                                   (if HC.Reasm_Hdr_Pending
			                                    then HC.Reasm_Need = 4
			                                         and then HC.Reasm_Len <= 4
			                                         and then HC.Reasm_Buf'Length =
			                                           Max_HS_Msg)
		                              and then HC.Reasm_Need <=
		                                N32 (HC.Reasm_Buf'Length)
	                              and then HC.Reasm_Len <=
	                                N32 (HC.Reasm_Buf'Length)
	                              and then Frag_Start <=
	                                S.Input.Write_Pos - 1
		                              and then Frag_Len <=
		                                S.Input.Write_Pos - Frag_Start,
			                       Post => Result in Action
			                               and then Wait_Client_Hello_Post (S, HC);

		                  procedure Continue_Reassembly
		                  is
		                     More_Input_Needed : Boolean;

			                     procedure Decode_Pending_Reassembly_Header
					                     with Pre => S.State = Wait_Client_Hello
					                                 and then S.Role = Role_Server
					                                 and then Server_Configured (HC)
					                                 and then HC.Legacy_Session_ID_Len
					                                   in 0 .. 32
							                                 and then HC.Reasm_Hdr_Pending
				                                 and then HC.Reasm_Len = 4
							                                 and then HC.Reasm_Need = 4
						                                 and then HC.Reasm_Buf /= null
						                                 and then HC.Reasm_Buf'First = 0
						                                 and then HC.Reasm_Buf'Length =
						                                   131072,
													                          Post =>
											                              S.State in Wait_Client_Hello | Error_State
										                              and then
										                                (if S.State = Wait_Client_Hello
										                                 then S.Role = Role_Server)
										                              and then
									                              (if S.State = Wait_Client_Hello
							                               then Server_Configured (HC)
							                                    and then Reasm_Building (HC)
							                                    and then
							                                      HC.Legacy_Session_ID_Len
							                                        in 0 .. 32
				                                    and then not HC.Reasm_Hdr_Pending
			                                 and then HC.Reasm_Buf /= null
			                                 and then HC.Reasm_Buf'First = 0
			                                 and then HC.Reasm_Buf'Last < N32'Last
			                                 and then HC.Reasm_Buf'Length <=
			                                   Max_HS_Msg
				                                    and then HC.Reasm_Len <=
				                                      N32 (HC.Reasm_Buf'Length));

	                     procedure Decode_Pending_Reassembly_Header
	                     is
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
			                           pragma Assert (S.State = Error_State);
			                           pragma Assert (S.Role = Role_Server);
								                        pragma Assert_And_Cut
									                          (S.State = Error_State
									                           and then S.State in
									                             Wait_Client_Hello | Error_State
					                              and then
					                                (if S.State /= Wait_Client_Hello
					                                 then S.State = Error_State)
					                              and then Server_Configured (HC)
				                              and then Reasm_Building (HC)
				                              and then HC.Legacy_Session_ID_Len
				                                in 0 .. 32
				                              and then not HC.Reasm_Hdr_Pending
				                              and then Wait_Client_Hello_Post
				                                (S, HC));
				                           return;
			                        end if;
		                        HC.Reasm_Need := HS_Total;
		                        pragma Assert (S.State = Wait_Client_Hello);
		                        pragma Assert (Server_Configured (HC));
		                        pragma Assert (HC.Reasm_Buf /= null);
		                        pragma Assert (HC.Reasm_Buf'First = 0);
		                        pragma Assert
		                          (HC.Reasm_Buf'Length = 131072);
		                        pragma Assert (HC.Reasm_Len = 4);
		                        pragma Assert (HC.Reasm_Need in 4 .. Max_HS_Msg);
		                        pragma Assert
		                          (HC.Reasm_Len <= HC.Reasm_Need);
		                        pragma Assert
		                          (HC.Reasm_Need <=
		                           N32 (HC.Reasm_Buf'Length));
		                        pragma Assert
		                          (HC.Reasm_Len <=
		                           N32 (HC.Reasm_Buf'Length));
			                        pragma Assert (Reasm_Building (HC));
					                        pragma Assert (not HC.Reasm_Hdr_Pending);
					                        pragma Assert (S.State = Wait_Client_Hello);
						                        pragma Assert_And_Cut
							                          (S.Role = Role_Server
							                           and then S.State =
							                             Wait_Client_Hello
							                           and then S.State in
							                             Wait_Client_Hello
							                           | Error_State
							                           and then Server_Configured (HC)
							                           and then Reasm_Building (HC)
						                           and then HC.Legacy_Session_ID_Len
						                             in 0 .. 32
								                           and then not HC.Reasm_Hdr_Pending
						                           and then HC.Reasm_Buf /= null
						                           and then HC.Reasm_Buf'First = 0
						                           and then HC.Reasm_Buf'Length <=
						                             Max_HS_Msg
						                           and then HC.Reasm_Buf'Length <=
						                             N32'Last
								                           and then HC.Reasm_Len <=
								                             N32 (HC.Reasm_Buf'Length));
								                        pragma Assert_And_Cut
									                          (S.Role = Role_Server
								                           and then
								                           (if S.State = Wait_Client_Hello
								                           then Server_Configured (HC)
								                                and then Reasm_Building (HC)
								                                and then HC.Legacy_Session_ID_Len
							                                  in 0 .. 32
							                                and then not HC.Reasm_Hdr_Pending
							                                and then HC.Reasm_Buf /= null
							                                and then HC.Reasm_Buf'First = 0
								                                and then HC.Reasm_Buf'Length <= Max_HS_Msg
									                                and then HC.Reasm_Buf'Length <= N32'Last
									                                and then HC.Reasm_Len <=
									                                  N32 (HC.Reasm_Buf'Length))
								                           and then S.State in
								                             Wait_Client_Hello | Error_State);
							                        pragma Assert (S.Role = Role_Server);
								                     end Decode_Pending_Reassembly_Header;

	                     procedure Append_Reassembly_Fragment
	   with Pre => S.State = Wait_Client_Hello
	                                 and then S.Role = Role_Server
				                              and then Server_Configured (HC)
				                              and then Reasm_Building (HC)
				                              and then HC.Legacy_Session_ID_Len
				                                in 0 .. 32
		                                 and then Handshake_Record_Fragment_Ready
	                                   (Rec)
		                                 and then Rec.Record_Len <=
		                                   Available (S.Input)
		                                 and then HC.Reasm_Need > 0
		                                 and then HC.Reasm_Len < HC.Reasm_Need
		                                 and then HC.Reasm_Buf /= null
		                                 and then HC.Reasm_Buf'First = 0
		                                 and then HC.Reasm_Buf'Last < N32'Last
		                                 and then HC.Reasm_Buf'Length <=
		                                   Max_HS_Msg
		                                 and then
		                                   (if HC.Reasm_Hdr_Pending
		                                    then HC.Reasm_Need = 4
		                                         and then HC.Reasm_Len <= 4
		                                         and then HC.Reasm_Buf'Length =
		                                           Max_HS_Msg)
		                                 and then HC.Reasm_Need <=
		                                   N32 (HC.Reasm_Buf'Length)
		                                 and then HC.Reasm_Len <=
		                                   N32 (HC.Reasm_Buf'Length)
		                                 and then Frag_Start <=
		                                   S.Input.Write_Pos - 1
		                                 and then Frag_Len <=
		                                   S.Input.Write_Pos - Frag_Start,
									                          Post =>
								                              (if S.State /= Wait_Client_Hello
								                                   or else More_Input_Needed
							                               then Wait_Client_Hello_Post (S, HC))
							                            and then
							                              (if S.State = Wait_Client_Hello
							                                   and then not More_Input_Needed
							                               then S.Role = Role_Server)
						                            and then
						                              (if S.State = Wait_Client_Hello
					                               then Server_Configured (HC)
				                                    and then Reasm_Building (HC)
				                                    and then
			                                      (if More_Input_Needed
			                                       then HC.Reasm_Len < HC.Reasm_Need
			                                       else HC.Reasm_Len >= HC.Reasm_Need
			                                            and then HC.Reasm_Buf /= null
			                                            and then HC.Reasm_Buf'First = 0
			                                            and then HC.Reasm_Buf'Last <
			                                              N32'Last
			                                            and then HC.Reasm_Buf'Length <=
			                                              Max_HS_Msg
					                                            and then HC.Reasm_Len <=
					                                              N32 (HC.Reasm_Buf'Length)
					                                            and then
					                                              HC.Legacy_Session_ID_Len
					                                                in 0 .. 32));

	                     procedure Append_Reassembly_Fragment
	                     is
		                     begin
		                        Result := OK;
		                        More_Input_Needed := False;
			                     pragma Assert (HC.Reasm_Len <= HC.Reasm_Need);
		                     pragma Assert (HC.Reasm_Buf /= null);
		                     pragma Assert (HC.Reasm_Buf'First = 0);
		                     pragma Assert
		                       (HC.Reasm_Buf'Length <= Max_HS_Msg);
		                     pragma Assert
		                       (HC.Reasm_Buf'Length <= N32'Last);
		                     pragma Assert
		                       (HC.Reasm_Need <=
		                          N32 (HC.Reasm_Buf'Length));
			                     pragma Assert
			                       (HC.Reasm_Len <=
			                          N32 (HC.Reasm_Buf'Length));
		                        pragma Assert
		                          (if HC.Reasm_Hdr_Pending
		                           then HC.Reasm_Need = 4
		                                and then HC.Reasm_Buf'Length =
		                                  Max_HS_Msg);
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
	                           pragma Assert
	                             (Frag_Start <= S.Input.Write_Pos - 1);
			                           pragma Assert
			                             (Copy_Len <= Frag_Len);
		                           pragma Assert
		                             (Frag_Start + Copy_Len - 1 <=
		                                S.Input.Write_Pos - 1);
	                           HC.Reasm_Buf
	                             (HC.Reasm_Len ..
                              HC.Reasm_Len + Copy_Len - 1) :=
                              S.Input.Data (Frag_Start ..
                                            Frag_Start + Copy_Len - 1);
                           HC.Reasm_Len := HC.Reasm_Len + Copy_Len;
		                        end if;
			                     end;
			                     pragma Assert (HC.Reasm_Len <= HC.Reasm_Need);
		                        pragma Assert
		                          (if HC.Reasm_Hdr_Pending
		                           then HC.Reasm_Need = 4
		                                and then HC.Reasm_Buf'Length =
		                                  Max_HS_Msg);
	                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

                     --  Header-pending sentinel: once 4 bytes are
                     --  present, decode the actual HS_Total and
                     --  upgrade Reasm_Need.
		                     if HC.Reasm_Hdr_Pending
		                       and then HC.Reasm_Len >= 4
		                       and then HC.Reasm_Buf /= null
		                     then
		                        pragma Assert (S.State = Wait_Client_Hello);
			                        pragma Assert (S.Role = Role_Server);
			                        pragma Assert (Server_Configured (HC));
		                        pragma Assert (HC.Reasm_Need = 4);
			                        pragma Assert
			                          (HC.Reasm_Buf'Length = 131072);
			                        pragma Assert (HC.Reasm_Len = HC.Reasm_Need);
					                        Decode_Pending_Reassembly_Header;
				                        if S.State /= Wait_Client_Hello then
		            return;
			                        end if;
		                     end if;
		                     pragma Assert (S.State = Wait_Client_Hello);
		                     pragma Assert (HC.Reasm_Buf /= null);
		                     pragma Assert (HC.Reasm_Buf'First = 0);
		                     pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
		                     pragma Assert (HC.Reasm_Buf'Length <= N32'Last);
		                     pragma Assert
		                       (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));

		                     if HC.Reasm_Len < HC.Reasm_Need then
	                        --  Still need more fragments
		                        Result := OK;
		                        More_Input_Needed := True;
		                        pragma Assert (S.State = Wait_Client_Hello);
			                        pragma Assert (Server_Configured (HC));
			                        pragma Assert (Reasm_Building (HC));
			                        pragma Assert (S.Role = Role_Server);
				                        pragma Assert
				                          (S.State = Wait_Client_Hello);
					                        return;
				                     end if;
			                     pragma Assert (HC.Reasm_Len >= HC.Reasm_Need);
			                     pragma Assert (S.Role = Role_Server);
			                     pragma Assert (Server_Configured (HC));
			                     pragma Assert (Reasm_Building (HC));
				                     pragma Assert (HC.Reasm_Buf /= null);
			                     pragma Assert (HC.Reasm_Buf'First = 0);
			                     pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
			                     pragma Assert (HC.Reasm_Buf'Length <= N32'Last);
			                     pragma Assert
			                       (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
				                  end Append_Reassembly_Fragment;

			                  procedure Parse_Completed_Reassembly
			                  with Pre => S.State = Wait_Client_Hello
				                              and then S.Role = Role_Server
					                              and then Server_Configured (HC)
				                              and then Reasm_Building (HC)
					                              and then SPARKTLSCrypto.P384.Field.Initialized
				                              and then SPARKTLSCrypto.P384.ECDSA.Initialized
						                              and then HC.Reasm_Buf /= null
			                              and then HC.Reasm_Buf'First = 0
			                              and then HC.Reasm_Buf'Last < N32'Last
			                              and then HC.Reasm_Buf'Length <= Max_HS_Msg
				                              and then HC.Reasm_Len >= HC.Reasm_Need
			                              and then HC.Legacy_Session_ID_Len
			                                in 0 .. 32
			                              and then HC.Reasm_Len <=
			                                N32 (HC.Reasm_Buf'Length),
				                       Post => Wait_Client_Hello_Post (S, HC);

		                  procedure Parse_Completed_Reassembly
		                  is
		                     Parse_OK : Boolean;
		                  begin
	                     --  Full message reassembled — parse it.
		                     --  This message will be appended to the transcript;
		                     --  reject anything larger than the transcript
		                     --  buffer before slicing and parsing it.
		                     if HC.Reasm_Len = 0
		                       or HC.Reasm_Len > Transcript_Capacity
		                     then
		                        Free_Reasm;
		                        Send_Alert_And_Error (S, Decode_Error, Result);
			                           pragma Assert (S.Role = Role_Server);
			                           pragma Assert (Wait_Client_Hello_Post (S, HC));
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
				                           pragma Assert (Server_Configured (HC));
				                           pragma Assert
				                             (HC.Legacy_Session_ID_Len in 0 .. 32);
				                           Append_Transcript (HC, Full_Msg);
				                           pragma Assert (HC.Transcript_Len > 0);
				                        end if;
				                     end;
			                     Free_Reasm;
		                     pragma Assert (Reasm_Building (HC));

				                  if not Parse_OK then
			                        Dispatch_CH_Parse_Error_Alert (S, Result);
				                        pragma Assert (Wait_Client_Hello_Post (S, HC));
			                        return;
		                     end if;

		                     pragma Assert (Server_Configured (HC));
		                     pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
		                     pragma Assert (Reasm_Building (HC));
			                     pragma Assert (HC.Transcript_Len > 0);
		                     pragma Assert
		                       (if HC.Version = TLS_1_3
		                        then S.Negotiated_Suite in
		                               Suite_AES_128_GCM_SHA256
		                             | Suite_AES_256_GCM_SHA384
		                             | Suite_CHACHA20_POLY1305_SHA256);
		                     Complete_Client_Hello (S, HC, Result);
		                     pragma Assert (Wait_Client_Hello_Post (S, HC));
			                  end Parse_Completed_Reassembly;
			                  begin
			                     pragma Assert
			                       (if HC.Reasm_Hdr_Pending then
			                          HC.Reasm_Need = 4
			                          and then HC.Reasm_Len <= 4
			                          and then HC.Reasm_Buf /= null
			                          and then HC.Reasm_Buf'Length =
			                            Max_HS_Msg);
			                     Append_Reassembly_Fragment;
			                     if S.State /= Wait_Client_Hello
			                       or else More_Input_Needed
		                     then
		                        pragma Assert
		                          (if S.State = Wait_Client_Hello
		                           then Server_Configured (HC));
		                        pragma Assert
		                          (if S.State = Wait_Client_Hello
		                           then Reasm_Building (HC));
		                        pragma Assert (Wait_Client_Hello_Post (S, HC));
		                        return;
			                     end if;

				                     pragma Assert (S.State = Wait_Client_Hello);
				                     pragma Assert (S.Role = Role_Server);
				                     pragma Assert (not More_Input_Needed);
			                     pragma Assert (Server_Configured (HC));
			                     pragma Assert (Reasm_Building (HC));
				                     pragma Assert (HC.Reasm_Buf /= null);
			                     pragma Assert (HC.Reasm_Buf'First = 0);
			                     pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
			                     pragma Assert (HC.Reasm_Buf'Length <= N32'Last);
			                     pragma Assert (HC.Reasm_Len >= HC.Reasm_Need);
			                     pragma Assert
			                       (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
			                     Parse_Completed_Reassembly;
			                     pragma Assert (Wait_Client_Hello_Post (S, HC));
			                  end Continue_Reassembly;

		                  procedure Process_Fresh_Handshake_Record
		                  with Pre => S.State = Wait_Client_Hello
		                              and then S.Role = Role_Server
			                              and then Server_Configured (HC)
			                        and then Reasm_Building (HC)
			                              and then HC.Legacy_Session_ID_Len in 0 .. 32
		                              and then Server_State_Keys_Ready (S, HC)
		                              and then Handshake_Record_Fragment_Ready
		                                (Rec)
			                              and then Rec.Record_Len <=
			                                Available (S.Input)
			                              and then S.Input.Read_Pos <=
			                                IO_Buffer_Capacity - Rec.Record_Len
			                              and then HC.Reasm_Need = 0
		                              and then Frag_Start <=
		                                S.Input.Write_Pos - 1
		                              and then Frag_Len <=
		                                S.Input.Write_Pos - Frag_Start
		                              and then Frag_Len < Transcript_Capacity,
		                       Post => Result in Action
		                               and then Wait_Client_Hello_Post (S, HC);

		                  procedure Parse_Single_Record_Client_Hello
		                  with Pre => S.State = Wait_Client_Hello
		                              and then S.Role = Role_Server
		                        and then Server_Configured (HC)
		                        and then Reasm_Building (HC)
		                        and then HC.Legacy_Session_ID_Len in 0 .. 32
		                              and then Server_State_Keys_Ready (S, HC)
		                              and then Handshake_Record_Fragment_Ready
		                                (Rec)
			                              and then Rec.Record_Len <=
			                                Available (S.Input)
			                              and then S.Input.Read_Pos <=
			                                IO_Buffer_Capacity - Rec.Record_Len
			                              and then HC.Reasm_Need = 0
		                              and then Frag_Len >= 4
		                              and then Frag_Start <=
		                                S.Input.Write_Pos - 1
		                              and then Frag_Len <=
		                                S.Input.Write_Pos - Frag_Start
		                              and then Frag_Len < Transcript_Capacity,
						                       Post => Wait_Client_Hello_Post (S, HC);

		                  procedure Parse_Single_Record_Client_Hello
		                  is
		                     Parse_OK : Boolean;
		                  begin
		                     --  Single-record message: parse directly. Copy
		                     --  instead of renaming to avoid aliasing between
		                     --  the fragment parameter and the in-out Session.
		                     declare
		                        Frag : constant Byte_Seq :=
		                           S.Input.Data (Frag_Start ..
		                                         Frag_Start + Frag_Len - 1);
		                     begin
		                        Handshake.Server_Msgs.Parse_Client_Hello
		                          (S, HC, Frag, Parse_OK);

			                        if not Parse_OK then
			                           pragma Assert (S.State = Wait_Client_Hello);
			                           Dispatch_CH_Parse_Error_Alert (S, Result);
			                           pragma Assert (S.State = Error_State);
				                           S.Input.Read_Pos :=
			                              S.Input.Read_Pos + Rec.Record_Len;
			                           pragma Assert (S.State = Error_State);
			                           pragma Assert (Wait_Client_Hello_Post (S, HC));
		                           return;
			                        end if;
			                        pragma Assert (Server_Configured (HC));
			                        pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);

				                        pragma Assert
				                          (Frag_Len < Transcript_Capacity);
			                        pragma Assert
			                          (Frag'Last - Frag'First = Frag_Len - 1);
				                        Append_Transcript (HC, Frag);
				                        pragma Assert (HC.Transcript_Len > 0);
			                     end;
			                     S.Input.Read_Pos :=
			                        S.Input.Read_Pos + Rec.Record_Len;
			                     Free_Byte_Seq (HC.Reasm_Buf);
			                     HC.Reasm_Len := 0;
			                     HC.Reasm_Need := 0;
			                     HC.Reasm_Hdr_Pending := False;

					                     pragma Assert (Server_Configured (HC));
						                     pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
							                     pragma Assert (HC.Transcript_Len > 0);
						                     pragma Assert (Reasm_Building (HC));
						                     pragma Assert (Reasm_Buffer_Shaped (HC));
						                     Complete_Client_Hello (S, HC, Result);
				                     pragma Assert (Wait_Client_Hello_Post (S, HC));
				                  end Parse_Single_Record_Client_Hello;

		                  procedure Start_Header_Pending_Reassembly
		                  with Pre => S.State = Wait_Client_Hello
		                              and then Server_Configured (HC)
		                              and then Reasm_Building (HC)
		                              and then HC.Reasm_Need = 0
			                              and then Frag_Len in 1 .. 3
			                              and then Rec.Record_Len <=
			                                Available (S.Input)
			                              and then S.Input.Read_Pos <=
			                                IO_Buffer_Capacity - Rec.Record_Len
			                              and then Frag_Start <=
		                                S.Input.Write_Pos - 1
		                              and then Frag_Len <=
		                                S.Input.Write_Pos - Frag_Start,
			                       Post => Wait_Client_Hello_Post (S, HC);

		                  procedure Start_Header_Pending_Reassembly
		                  is
		                  begin
		                     Free_Byte_Seq (HC.Reasm_Buf);
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
				                     pragma Assert (S.State = Wait_Client_Hello);
				                     pragma Assert (Server_Configured (HC));
				                     pragma Assert (Reasm_Building (HC));
				                     pragma Assert (Wait_Client_Hello_Post (S, HC));
		                  end Start_Header_Pending_Reassembly;

		                  procedure Start_Known_Length_Reassembly
		                    (HS_Total : N32)
		                  with Pre => S.State = Wait_Client_Hello
		                              and then Server_Configured (HC)
		                              and then Reasm_Building (HC)
		                              and then HC.Reasm_Need = 0
		                              and then Frag_Len >= 4
		                              and then HS_Total in 4 .. Max_HS_Msg
			                              and then HS_Total > Frag_Len
			                              and then Rec.Record_Len <=
			                                Available (S.Input)
			                              and then S.Input.Read_Pos <=
			                                IO_Buffer_Capacity - Rec.Record_Len
			                              and then Frag_Start <=
		                                S.Input.Write_Pos - 1
		                              and then Frag_Len <=
		                                S.Input.Write_Pos - Frag_Start,
			                       Post => Wait_Client_Hello_Post (S, HC);

		                  procedure Start_Known_Length_Reassembly
		                    (HS_Total : N32)
		                  is
		                  begin
			                     Free_Byte_Seq (HC.Reasm_Buf);
			                     HC.Reasm_Buf := new Byte_Seq'
			                        (0 .. HS_Total - 1 => 0);
			                     HC.Reasm_Need := HS_Total;
			                     HC.Reasm_Len := Frag_Len;
		                        HC.Reasm_Hdr_Pending := False;
			                     HC.Reasm_Buf (0 .. Frag_Len - 1) :=
		                        S.Input.Data (Frag_Start ..
		                                      Frag_Start + Frag_Len - 1);
		                     S.Input.Read_Pos :=
		                        S.Input.Read_Pos + Rec.Record_Len;
			                     Result := OK;
			                     pragma Assert (S.State = Wait_Client_Hello);
			                     pragma Assert (Server_Configured (HC));
			                     pragma Assert (HC.Reasm_Buf /= null);
			                     pragma Assert (HC.Reasm_Buf'First = 0);
			                     pragma Assert (HC.Reasm_Buf'Length = HS_Total);
			                     pragma Assert (HC.Reasm_Need = HS_Total);
			                     pragma Assert (HC.Reasm_Len = Frag_Len);
			                     pragma Assert (HC.Reasm_Need in 4 .. Max_HS_Msg);
			                     pragma Assert (HC.Reasm_Len <= HC.Reasm_Need);
			                     pragma Assert
			                       (HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
			                     pragma Assert
			                       (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
			                     pragma Assert (Reasm_Building (HC));
			                     pragma Assert (Wait_Client_Hello_Post (S, HC));
		                  end Start_Known_Length_Reassembly;

		                  procedure Process_Fresh_Handshake_Record
		                  is
		                  begin
		                     --  Fresh handshake record. Check if the message
		                     --  spans multiple records by reading the 3-byte
		                     --  handshake length.
	                     pragma Assert (Reasm_Building (HC));
			                     pragma Assert (HC.Reasm_Need = 0);
			                     if Frag_Len < 4 then
		                        --  RFC 8446 Section 5.1: handshake messages MAY
		                        --  span records. The first fragment is shorter
		                        --  than the 4-byte HS header itself, so start
		                        --  reassembly with a header-pending sentinel.
			                        if Frag_Len = 0 then
			                           S.Input.Read_Pos :=
			                              S.Input.Read_Pos + Rec.Record_Len;
		                           Send_Alert_And_Error
		                             (S, Decode_Error, Result);
		                           pragma Assert (S.State = Error_State);
			                           pragma Assert (Wait_Client_Hello_Post (S, HC));
			                           return;
			                        end if;

			                        pragma Assert (Frag_Len in 1 .. 3);
			                        Start_Header_Pending_Reassembly;
			                        pragma Assert (Wait_Client_Hello_Post (S, HC));
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
		                           pragma Assert (S.State = Error_State);
                           pragma Assert (Wait_Client_Hello_Post (S, HC));
		                           return;
		                        end if;

			                        if HS_Total > Frag_Len then
			                           pragma Assert
			                             (HS_Total in 4 .. Max_HS_Msg);
			                           Start_Known_Length_Reassembly
			                             (HS_Total);
			                           pragma Assert (Wait_Client_Hello_Post (S, HC));
			                           return;
			                        end if;
		                     end;

			                     pragma Assert (Frag_Len >= 4);
			                     Parse_Single_Record_Client_Hello;
			                     pragma Assert (Wait_Client_Hello_Post (S, HC));
				                  end Process_Fresh_Handshake_Record;
		               begin
			                  Result := Error_Alert;
			                  --  Check if we're in the middle of reassembly
			                  if HC.Reasm_Need > 0 then
			                     if HC.Reasm_Buf = null then
			                        Send_Alert_And_Error
			                          (S, Decode_Error, Result);
			                        pragma Assert (Wait_Client_Hello_Post (S, HC));
			                        return;
			                     end if;
		                     Continue_Reassembly;
			                     pragma Assert (Wait_Client_Hello_Post (S, HC));
			                     return;

			                  end if;

			                  pragma Assert (HC.Reasm_Need = 0);
			                  pragma Assert (Frag_Len < Transcript_Capacity);
		                  Process_Fresh_Handshake_Record;
		                  pragma Assert (Wait_Client_Hello_Post (S, HC));
				               end Process_Handshake_Record;
			               begin
			                  Result := Error_Alert;
			                  Process_Handshake_Record;
				            end;
				            end;
			            pragma Assert (Result in Action);
			            pragma Assert
			              (if S.State in Wait_Client_Hello
			                         | Wait_Client_Hello_Retry
			                         | Server_Hello_Sent
			                         | Wait_Client_Finished
			               then Server_Configured (HC));
				            pragma Assert
				              (if S.State = Wait_Client_Hello
				               then Reasm_Building (HC));
			            pragma Assert
			              (if S.State = Wait_Client_Hello
			                  and then HC.Reasm_Need > 0
			               then HC.Reasm_Len < HC.Reasm_Need);
		            pragma Assert (Wait_Client_Hello_Post (S, HC));
	            return;
	   end Handle_Wait_Client_Hello;


	   procedure Validate_Client_Hello_Retry
	     (S     : in out Session;
	      HC    : in out Handshake_Context;
	      Msg   : in     Byte_Seq;
	      Valid :    out Boolean)
	   is
	      Parse_OK : Boolean;
	      CH1_Hash : constant Unsigned_32 := HC.CH_Ext_Hash;
	   begin
	      Valid := False;

	      --  Reset for CH2 parsing. Seen_Ext_Count + Tags also reset:
	      --  duplicate-extension checks are intra-ClientHello, not CH1 vs CH2.
	      HC.Client_Saw_Key_Share := False;
	      HC.Client_Has_X25519 := False;
	      HC.Client_Has_P256 := False;
	      HC.Client_Has_P384 := False;
	      HC.Client_Saw_Supported_Groups := False;
	      HC.Client_Supports_X25519 := False;
	      HC.Client_Supports_P256 := False;
	      HC.Client_Supports_P384 := False;
	      HC.CH_Ext_Hash := 0;
	      HC.CH_Ext_Count := 0;
	      HC.Seen_Ext_Count := 0;
	      HC.Seen_Ext_Tags := (others => 0);
	      pragma Assert (HC.HRR_Sent);
	      pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);

	      Handshake.Server_Msgs.Parse_Client_Hello (S, HC, Msg, Parse_OK);

	      if not Parse_OK then
	         return;
	      end if;

	      pragma Assert (S.State = Wait_Client_Hello_Retry);
	      if HC.Version /= TLS_1_3 then
	         return;
	      end if;

	      --  RFC 8446 §4.1.2: CH2 extensions must be in the same order
	      --  as CH1. Cookie is excluded from the hash in both messages.
	      if HC.CH_Ext_Hash /= CH1_Hash then
	         return;
	      end if;

	      pragma Assert (HC.Version = TLS_1_3);
	      pragma Assert
	        (S.Negotiated_Suite in
	           Suite_AES_128_GCM_SHA256
	         | Suite_AES_256_GCM_SHA384
	         | Suite_CHACHA20_POLY1305_SHA256);
	      Valid := True;
	   end Validate_Client_Hello_Retry;



	   procedure Complete_Client_Hello_Retry
	     (S                      : in out Session;
	      HC                     : in out Handshake_Context;
	      Msg                    : in     Byte_Seq;
	      Consume_Current_Record : in     Boolean;
	      Record_Len             : in     N32;
	      Ready_To_Build         :    out Boolean;
	      Result                 :    out Action)
	   is
	      Valid_CH2 : Boolean;

      procedure Consume_Record
      with Pre  =>
        Server_Active (S)
        and then Nonce_Space_Available (S.Server_App)
        and then
          (if Consume_Current_Record
           then S.Input.Read_Pos <= N32'Last - Record_Len
             and then S.Input.Read_Pos + Record_Len <= S.Input.Write_Pos),
      Post =>
        S.State = S.State'Old
        and then S.Role = S.Role'Old
        and then S.Negotiated_Suite = S.Negotiated_Suite'Old
	        and then S.Server_App.Counter = S.Server_App.Counter'Old
	        and then S.Server_App.Suite = S.Server_App.Suite'Old
	        and then Server_Active (S)
	        and then Nonce_Space_Available (S.Server_App)
	        and then
	          (if Consume_Current_Record
	           then S.Input.Read_Pos = S.Input.Read_Pos'Old + Record_Len
	             and then S.Input.Write_Pos = S.Input.Write_Pos'Old
	           else S.Input.Read_Pos = S.Input.Read_Pos'Old
	             and then S.Input.Write_Pos = S.Input.Write_Pos'Old)
	   is
	      begin
	         if Consume_Current_Record then
	            pragma Assert
	              (S.Input.Read_Pos + Record_Len <= S.Input.Write_Pos);
	            S.Input.Read_Pos := S.Input.Read_Pos + Record_Len;
	         end if;
	      end Consume_Record;

      procedure Free_CH2_Reasm
      with Pre  => Server_Configured (HC)
                   and then Nonce_Space_Available (HC.Server_HS),
           Post => HC.Reasm_Buf = null
                   and then Reasm_Building (HC)
                   and then HC.Version = HC.Version'Old
                   and then HC.HRR_Sent = HC.HRR_Sent'Old
	                   and then HC.Legacy_Session_ID_Len =
	                     HC.Legacy_Session_ID_Len'Old
	                   and then HC.Transcript_Len =
	                     HC.Transcript_Len'Old
	                   and then HC.Server_HS.Counter =
	                     HC.Server_HS.Counter'Old
	                   and then HC.Server_HS.Suite =
	                     HC.Server_HS.Suite'Old
	                   and then Server_Configured (HC)
	                   and then Nonce_Space_Available (HC.Server_HS)
	   is
	      begin
	         Free_Byte_Seq (HC.Reasm_Buf);
	         HC.Reasm_Len := 0;
	         HC.Reasm_Need := 0;
	         HC.Reasm_Hdr_Pending := False;
	      end Free_CH2_Reasm;
	   begin
                     Ready_To_Build := False;
	                     if Msg'Length = 0
	                       or else N32 (Msg'Length) > Transcript_Capacity
                     then
                        Consume_Record;
                        Free_CH2_Reasm;
                        Send_Alert_And_Error (S, Decode_Error, Result);
                        return;
                     end if;

	                     Validate_Client_Hello_Retry (S, HC, Msg, Valid_CH2);
	                     if not Valid_CH2 then
	                        --  After HRR, CH2 parse/version/order failures are
	                        --  illegal_parameter (RFC 8446 §4.1.4).
	                        Consume_Record;
	                        Free_CH2_Reasm;
	                        Send_Alert_And_Error
	                          (S, Illegal_Parameter, Result);
                        return;
	                     end if;
	                     pragma Assert (S.State = Wait_Client_Hello_Retry);
	                     pragma Assert (HC.Version = TLS_1_3);

	                     --  Append CH2 to transcript
	                     pragma Assert (Msg'First <= Msg'Last);
	                     Append_Transcript (HC, Msg);
	                     pragma Assert (HC.Transcript_Len > 0);
	                     Consume_Record;
                     Free_CH2_Reasm;
                     if HC.Cfg.Local = null
                       or else not HC.Cfg.Local.Has_Identity
                       or else HC.Cfg.Random = null
                       or else HC.Cfg.Local.NaCl_Cert_Len >
                         N32 (Max_Cert_DER)
                       or else HC.Cfg.Local.Int_Count > Max_Pool_Size
                       or else
                         (for some I in 0 .. Max_Pool_Size - 1 =>
                            HC.Cfg.Local.Ints (I).DER_Len >
                              X509.N32 (Max_Cert_DER))
                       or else
                         (HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                          and then HC.Cfg.Local.RSA_Mod_Len
                            not in 64 .. 512)
                     then
                        Send_Alert_And_Error
                          (S, Handshake_Failure, Result);
			            pragma Assert
		              (if S.State = Wait_Client_Hello_Retry
		               then Reasm_Building (HC));
	                        return;
                     end if;
                     pragma Assert (S.State = Wait_Client_Hello_Retry);
                     pragma Assert (Server_Configured (HC));
                     pragma Assert
                       (Handshake.Server_Msgs.Local_Config_Valid
                          (HC.Cfg.Local));
                     pragma Assert
                       (HC.Cfg.Local.NaCl_Cert_Len <=
                        N32 (Max_Cert_DER));
                     pragma Assert
                       (HC.Cfg.Local.Int_Count <= Max_Pool_Size);
                     pragma Assert
                       (for all I in 0 .. Max_Pool_Size - 1 =>
                          HC.Cfg.Local.Ints (I).DER_Len <=
                            X509.N32 (Max_Cert_DER));
                     pragma Assert
                       (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
                        then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512);
                     pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
                     pragma Assert (Nonce_Space_Available (HC.Server_HS));
                     pragma Assert (Nonce_Space_Available (S.Server_App));
                     pragma Assert (Reasm_Building (HC));
                     pragma Assert
                       (S.Negotiated_Suite in
                          Suite_AES_128_GCM_SHA256
                        | Suite_AES_256_GCM_SHA384
                        | Suite_CHACHA20_POLY1305_SHA256);
                     pragma Assert (HC.HRR_Sent);

	                     Result := OK;
	                     Ready_To_Build := True;
	   end Complete_Client_Hello_Retry;


	   procedure Build_Server_Flight_After_Client_Hello_Retry
	     (S      : in out Session;
	      HC     : in out Handshake_Context;
	      Result :    out Action)
	   is
	   begin
	      Build_Server_Flight (S, HC, Result);
	      pragma Assert (S.State in Server_Hello_Sent | Error_State);
	   end Build_Server_Flight_After_Client_Hello_Retry;


	   procedure Handle_Client_Hello_Retry
	     (S      : in out Session;
	      HC     : in out Handshake_Context;
	      Result :    out Action)
	   is
	   begin
            --  After HRR, wait for the client's second ClientHello.
            --  Same parsing as Wait_Client_Hello but we expect the
            --  client to include key_share for our requested group.
		            if Input_Available (S) = 0 then
	               Result := Need_Input;
	               pragma Assert (S.State = Wait_Client_Hello_Retry);
	               pragma Assert (Reasm_Building (HC));
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
				                  pragma Assert
			                    (if S.State not in Error_State | Closed
			                     then Reasm_Building (HC));
			                  pragma Assert
			                    (if S.State = Wait_Client_Hello_Retry
			                        and then HC.Reasm_Need = 0
			                     then Reasm_Building (HC));
			                  return;
		               end if;

               if Rec.Bad_Version then
	                  --  RFC 8446 §5.1: legacy_record_version must lie
	                  --  in {3,1}..{3,4}. Out-of-band → protocol_version.
	                  Send_Alert_And_Error (S, Protocol_Version, Result);
				                  pragma Assert
			                    (if S.State not in Error_State | Closed
			                     then Reasm_Building (HC));
				                  pragma Assert
				                    (if S.State = Wait_Client_Hello_Retry
				                        and then HC.Reasm_Need = 0
				                     then Reasm_Building (HC));
			                  return;
		               end if;

               if not Rec.OK then
                  if Rec.Record_Len > 0 then
	                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	                     Send_Alert_And_Error (S, Unexpected_Message, Result);
				                     pragma Assert
			                       (if S.State not in Error_State | Closed
			                        then Reasm_Building (HC));
				                     pragma Assert
				                       (if S.State = Wait_Client_Hello_Retry
				                           and then HC.Reasm_Need = 0
				                        then Reasm_Building (HC));
			                  else
		                     Result := Need_Input;
		                     pragma Assert (S.State = Wait_Client_Hello_Retry);
		                     pragma Assert (Reasm_Building (HC));
			                     pragma Assert
			                       (if HC.Reasm_Need = 0
			                        then Reasm_Building (HC));
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
	                        pragma Assert (Reasm_Building (HC));
	                     else
                        --  RFC 5246 §7.1 / RFC 8446 §5: CCS payload MUST
                        --  be the single byte 0x01 (BoGo
                        --  BadChangeCipherSpec-*).
	                        Send_Alert_And_Error
	                          (S, Unexpected_Message, Result);
	                     end if;
				                     pragma Assert
			                       (if S.State not in Error_State | Closed
			                        then Reasm_Building (HC));
				                     pragma Assert
				                       (if S.State = Wait_Client_Hello_Retry
				                           and then HC.Reasm_Need = 0
				                        then Reasm_Building (HC));
			               end;
	                  return;
	               end if;

	               if Rec.Content /= Records.Content_Handshake then
		                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
		                  Send_Alert_And_Error (S, Unexpected_Message, Result);
						                  pragma Assert
					                    (if S.State not in Error_State | Closed
					                     then Reasm_Building (HC));
						                  pragma Assert
						                    (if S.State = Wait_Client_Hello_Retry
						                        and then HC.Reasm_Need = 0
						                     then Reasm_Building (HC));
				                  return;
		               end if;

               --  Parse second ClientHello. CH2 is allowed to span
               --  multiple records just like CH1, including the
               --  pathological one-byte-record split used by BoGo.
               declare
                  Frag_Start : constant N32 :=
                     S.Input.Read_Pos + Rec.Fragment_Pos;
                  Frag_Len   : constant N32 := Rec.Fragment_Len;
	                  Rec_Consumed : Boolean := False;

                  procedure Consume_Record is
                  begin
                     if not Rec_Consumed then
                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        Rec_Consumed := True;
                     end if;
                  end Consume_Record;

                  procedure Free_CH2_Reasm is
                  begin
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0;
                     HC.Reasm_Need := 0;
                     HC.Reasm_Hdr_Pending := False;
                  end Free_CH2_Reasm;


               begin
                  if HC.Reasm_Need > 0 then
	                        if HC.Reasm_Buf = null
	                          or else HC.Reasm_Len >= HC.Reasm_Need
	                     then
	                        Consume_Record;
		                        Send_Alert_And_Error (S, Decode_Error, Result);
		                        pragma Assert
		                          (if S.State not in Error_State | Closed
		                           then Reasm_Building (HC));
			                        pragma Assert
			                          (if S.State = Wait_Client_Hello_Retry
			                              and then HC.Reasm_Need = 0
			                           then Reasm_Building (HC));
		                        return;
		                     end if;

                     declare
                        Remaining : constant N32 :=
                           HC.Reasm_Need - HC.Reasm_Len;
                        Take      : constant N32 :=
                           N32'Min (Frag_Len, Remaining);
                     begin
                        if Take > 0
                          and then HC.Reasm_Len + Take <=
                                     N32 (HC.Reasm_Buf'Length)
                        then
                           HC.Reasm_Buf
                             (HC.Reasm_Len ..
                              HC.Reasm_Len + Take - 1) :=
                              S.Input.Data
                                (Frag_Start .. Frag_Start + Take - 1);
                           HC.Reasm_Len := HC.Reasm_Len + Take;
                        end if;
                     end;
                     Consume_Record;

                     if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
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
		                              Free_CH2_Reasm;
		                              Send_Alert_And_Error (S, Decode_Error, Result);
		                              pragma Assert
		                                (if S.State not in Error_State | Closed
		                                 then Reasm_Building (HC));
			                              pragma Assert
			                                (if S.State = Wait_Client_Hello_Retry
			                                    and then HC.Reasm_Need = 0
			                                 then Reasm_Building (HC));
		                              return;
		                           end if;
                           HC.Reasm_Need := HS_Total;
                        end;
                     end if;

                     if HC.Reasm_Len < HC.Reasm_Need then
                        Result := OK;
                        pragma Assert (Reasm_Building (HC));
                        return;
                     end if;

	                     declare
	                        Full_Len : constant N32 := HC.Reasm_Need;
	                        Full_Msg : constant Byte_Seq :=
	                           HC.Reasm_Buf (0 .. Full_Len - 1);
	                        Ready_To_Build : Boolean;
	                     begin
	                        Complete_Client_Hello_Retry
	                          (S, HC, Full_Msg, False, 0,
	                           Ready_To_Build, Result);
		                        if Ready_To_Build then
		                           Build_Server_Flight_After_Client_Hello_Retry
		                             (S, HC, Result);
		                        end if;
	                     end;
                  elsif Frag_Len = 0 then
                     Consume_Record;
                     Send_Alert_And_Error (S, Decode_Error, Result);
	                  elsif Frag_Len < 4 then
	                     pragma Assert (HC.Reasm_Need = 0);
	                     Free_Byte_Seq (HC.Reasm_Buf);
	                     HC.Reasm_Buf := new Byte_Seq'
	                       (0 .. Max_HS_Msg - 1 => 0);
                     HC.Reasm_Need := 4;
                     HC.Reasm_Hdr_Pending := True;
                     HC.Reasm_Len := Frag_Len;
                     HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                        S.Input.Data (Frag_Start ..
                                      Frag_Start + Frag_Len - 1);
                     Consume_Record;
	                     Result := OK;
	                     pragma Assert (Reasm_Building (HC));
	                     pragma Assert (HC.Reasm_Buf /= null);
	                  else
                     declare
                        HS_Msg_Len : constant N32 :=
                           N32 (S.Input.Data (Frag_Start + 1)) * 65536 +
                           N32 (S.Input.Data (Frag_Start + 2)) * 256 +
                           N32 (S.Input.Data (Frag_Start + 3));
                        HS_Total   : constant N32 := HS_Msg_Len + 4;
                     begin
	                        if HS_Total > Max_HS_Msg then
	                           Consume_Record;
	                           Send_Alert_And_Error (S, Decode_Error, Result);
		                        elsif HS_Total > Frag_Len then
		                           pragma Assert (HC.Reasm_Need = 0);
		                           Free_Byte_Seq (HC.Reasm_Buf);
		                           HC.Reasm_Buf := new Byte_Seq'
	                             (0 .. HS_Total - 1 => 0);
                           HC.Reasm_Need := HS_Total;
                           HC.Reasm_Hdr_Pending := False;
                           HC.Reasm_Len := Frag_Len;
                           HC.Reasm_Buf (0 .. Frag_Len - 1) :=
                              S.Input.Data (Frag_Start ..
                                            Frag_Start + Frag_Len - 1);
                           Consume_Record;
	                           Result := OK;
	                           pragma Assert (Reasm_Building (HC));
	                           pragma Assert (HC.Reasm_Buf /= null);
		                        else
		                           declare
		                              Frag : Byte_Seq (0 .. Frag_Len - 1);
	                              Ready_To_Build : Boolean;
	                           begin
	                              Frag :=
	                                S.Input.Data
	                                  (Frag_Start ..
	                                   Frag_Start + Frag_Len - 1);
	                              Complete_Client_Hello_Retry
	                                (S, HC, Frag, True, Rec.Record_Len,
	                                 Ready_To_Build, Result);
	                              if Ready_To_Build then
	                                 Build_Server_Flight_After_Client_Hello_Retry
	                                   (S, HC, Result);
	                              end if;
		                           end;
	                        end if;
		                     end;
			                  end if;
			               end;
			            end;
			            pragma Assert
				              (if S.State = Wait_Client_Hello_Retry
				                  and then HC.Reasm_Need = 0
				               then Reasm_Building (HC));
				   end Handle_Client_Hello_Retry;

   --  Dispatch handshake states to the appropriate handler
   procedure Advance_Handshake
	     (S      : in out Session;
	      HC     : in out Handshake_Context;
	      Result :    out Action)
	   is
	      Old_State : constant Connection_State := S.State;
	   begin
	      case S.State is
	         when Wait_Client_Hello =>
	            pragma Assert (Old_State = Wait_Client_Hello);
	            Handle_Wait_Client_Hello (S, HC, Result);
			            pragma Assert
			              (if S.State = Wait_Client_Hello
			               then Reasm_Building (HC));

	         when Server_Hello_Sent =>
	            pragma Assert (Old_State = Server_Hello_Sent);
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
		            pragma Assert
		              (if S.State = Wait_Client_Hello
		               then Reasm_Building (HC));


	         when Wait_Client_Hello_Retry =>
	            pragma Assert (Old_State = Wait_Client_Hello_Retry);
	            Handle_Client_Hello_Retry (S, HC, Result);
	            pragma Assert
	              (if S.State not in Error_State | Closed
	               then Reasm_Building (HC));

	         when Wait_Client_Certificate
	            | Wait_Client_Cert_Verify =>
	            pragma Assert
	              (Old_State in Wait_Client_Certificate
	                            | Wait_Client_Cert_Verify);
	            if HC.Version = TLS_1_2 then
	               if S.State = Wait_Client_Certificate then
	                  SPARKTLS.Server.TLS12.Process_Client_Certificate_12
	                    (S, HC, Result);
	               elsif not HC.CKE_Received_12 then
	                  SPARKTLS.Server.TLS12.Process_Client_Key_Exchange_12
	                    (S, HC, Result);
	               else
	                  SPARKTLS.Server.TLS12.Process_Client_CertVerify_12
	                    (S, HC, Result);
	               end if;
	            else
	               Process_Client_Auth (S, HC, Result);
	            end if;

		         when Wait_Client_Finished =>
	            pragma Assert (Old_State = Wait_Client_Finished);
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
				                        pragma Assert
				                          (if S.State = Wait_Client_Hello
				                           then Reasm_Building (HC));
	      end case;
	      case Old_State is
	         when Wait_Client_Hello
	            | Server_Hello_Sent
	            | Wait_Client_Hello_Retry
	            | Wait_Client_Certificate
	            | Wait_Client_Cert_Verify
	            | Wait_Client_Finished =>
	            null;
	         when others =>
	            pragma Assert (S.State = Error_State);
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
      --  The hash algorithm is selected by the negotiated cipher suite.
      if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384 then
         declare
            CH1_Hash  : SPARKNaCl.Hashing.SHA384.Digest;
            Synthetic : Byte_Seq (0 .. 51) := (others => 0);
         begin
            SPARKNaCl.Hashing.SHA384.Hash
              (CH1_Hash, HC.Transcript (0 .. HC.Transcript_Len - 1));

            Synthetic (0) := 254;  --  message_hash type
            Synthetic (1) := 0;
            Synthetic (2) := 0;
            Synthetic (3) := 48;   --  SHA-384 hash length
            Synthetic (4 .. 51) := Byte_Seq (CH1_Hash);

            HC.Transcript (0 .. 51) := Synthetic;
            HC.Transcript_Len := 52;
         end;
      else
         declare
            CH1_Hash  : Digest;
            Synthetic : Byte_Seq (0 .. 35) := (others => 0);
         begin
            Hash (CH1_Hash, HC.Transcript (0 .. HC.Transcript_Len - 1));

            Synthetic (0) := 254;  --  message_hash type
            Synthetic (1) := 0;
            Synthetic (2) := 0;
            Synthetic (3) := 32;   --  SHA-256 hash length
            Synthetic (4 .. 35) := Byte_Seq (CH1_Hash);

            HC.Transcript (0 .. 35) := Synthetic;
            HC.Transcript_Len := 36;
         end;
      end if;

      --  Append HRR to transcript
      Append_Transcript (HC, HRR_Buf (0 .. Msg_Len - 1));
      HC.HRR_Selected_Group := Group;

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
         HC.Sent_HRR_CCS := True;
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
                and then HC.Cfg.Store_Session /= null
                    and then HC.Cfg.Lookup_Session /= null
                and then HC.Transcript_Len <= Transcript_Capacity
                and then HC.PSK_Binder_Len <= Max_HS_Msg
                and then Server_Configured (HC)
                and then HC.Cfg.Local.NaCl_Cert_Len
                  <= N32 (Max_Cert_DER)
                and then
                  (for all I in 0 .. Max_Pool_Size - 1 =>
                     HC.Cfg.Local.Ints (I).DER_Len
                       <= X509.N32 (Max_Cert_DER))
		                and then
		                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
		                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
		                and then HC.Legacy_Session_ID_Len in 0 .. 32
		                and then Reasm_Building (HC)
		                and then Reasm_Buffer_Shaped (HC),
		        Post => (if not Rejected
		                 then S.State = S.State'Old
		                      and S.Role = S.Role'Old
			                      and Server_Configured (HC)
			                      and Reasm_Building (HC)
			                      and Reasm_Buffer_Shaped (HC)
			                      and HC.Transcript_Len = HC.Transcript_Len'Old
		                      and HC.HRR_Sent = HC.HRR_Sent'Old
	                      and HC.Legacy_Session_ID_Len in 0 .. 32
	                      and HC.Cfg.Local.NaCl_Cert_Len
	                        <= N32 (Max_Cert_DER)
	                      and (for all I in 0 .. Max_Pool_Size - 1 =>
	                             HC.Cfg.Local.Ints (I).DER_Len
	                               <= X509.N32 (Max_Cert_DER))
	                      and
	                        (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
	                         then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
	                      and S.Negotiated_Suite = S.Negotiated_Suite'Old)
			                 and then (if Rejected then S.State = Error_State)
			                 and then Reasm_Building (HC)
			                 and then Reasm_Buffer_Shaped (HC);

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
      HC.Cfg.Lookup_Session
        (
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
   function Local_Sig_Compatible
     (Scheme : Unsigned_16;
      Cert   : Signing_Algorithm) return Boolean is
   begin
      case Cert is
         when Sign_Ed25519 =>
            return Scheme = 16#0807#;
         when Sign_ECDSA_P256 =>
            return Scheme = 16#0403#;
         when Sign_ECDSA_P384 =>
            return Scheme = 16#0503#;
         when Sign_RSA_PSS =>
            return Scheme in 16#0804# | 16#0805# | 16#0806#;
         when Sign_None =>
            return False;
      end case;
   end Local_Sig_Compatible;

   procedure Negotiate_Sig_Algo
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Algo_OK  :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Server_Configured (HC)
                and then HC.Cfg.Local.NaCl_Cert_Len
                  <= N32 (Max_Cert_DER)
                and then
                  (for all I in 0 .. Max_Pool_Size - 1 =>
                     HC.Cfg.Local.Ints (I).DER_Len
                       <= X509.N32 (Max_Cert_DER))
		                and then
		                  (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
		                   then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
		                and then HC.Legacy_Session_ID_Len in 0 .. 32
		                and then Reasm_Building (HC)
		                and then Reasm_Buffer_Shaped (HC),
	        Post => (if Algo_OK
		                 then S.State = S.State'Old
		                      and S.Role = S.Role'Old
			                      and S.Negotiated_Suite = S.Negotiated_Suite'Old
			                      and Server_Configured (HC)
			                      and Reasm_Building (HC)
			                      and Reasm_Buffer_Shaped (HC)
			                      and HC.Transcript_Len = HC.Transcript_Len'Old
	                      and HC.HRR_Sent = HC.HRR_Sent'Old
	                      and HC.Legacy_Session_ID_Len in 0 .. 32
	                      and HC.Cfg.Local.NaCl_Cert_Len
	                        <= N32 (Max_Cert_DER)
	                      and (for all I in 0 .. Max_Pool_Size - 1 =>
	                             HC.Cfg.Local.Ints (I).DER_Len
	                               <= X509.N32 (Max_Cert_DER))
	                      and
	                        (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
	                         then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512)
	                      and HC.Negotiated_Sig_Algo /= 0
	                      and Handshake.Sig_Algo_Compatible_With_Cert
	                        (HC.Negotiated_Sig_Algo,
	                         HC.Cfg.Local.Sign_Algo))
			                 and then (if not Algo_OK then S.State = Error_State)
			                 and then Reasm_Building (HC)
			                 and then Reasm_Buffer_Shaped (HC);

   procedure Negotiate_Sig_Algo
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Algo_OK  :    out Boolean;
      Result   :    out Action)
   is
   begin
      Result := OK;
      Algo_OK := False;
      if HC.Cfg.Sign_Sig_Algo_Count > 0 then
         for J in Sig_Algo_Index loop
            pragma Loop_Invariant (S.State = S.State'Loop_Entry);
            pragma Loop_Invariant (S.Role = S.Role'Loop_Entry);
            pragma Loop_Invariant
              (S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            pragma Loop_Invariant (Server_Configured (HC));
            pragma Loop_Invariant (Reasm_Building (HC));
            pragma Loop_Invariant
              (HC.Transcript_Len = HC.Transcript_Len'Loop_Entry);
            pragma Loop_Invariant (HC.HRR_Sent = HC.HRR_Sent'Loop_Entry);
            pragma Loop_Invariant (HC.Legacy_Session_ID_Len in 0 .. 32);
            pragma Loop_Invariant
              (HC.Cfg.Local.NaCl_Cert_Len <= N32 (Max_Cert_DER));
            pragma Loop_Invariant
              (for all I in 0 .. Max_Pool_Size - 1 =>
                 HC.Cfg.Local.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER));
            pragma Loop_Invariant
              (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
               then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512);
            pragma Loop_Invariant
              (if Algo_OK then
                 HC.Negotiated_Sig_Algo /= 0
                 and then Handshake.Sig_Algo_Compatible_With_Cert
                            (HC.Negotiated_Sig_Algo,
                             HC.Cfg.Local.Sign_Algo));
            exit when J >= HC.Cfg.Sign_Sig_Algo_Count;
            if Local_Sig_Compatible
                 (HC.Cfg.Sign_Sig_Algos (J), HC.Cfg.Local.Sign_Algo)
              and then Sig_Scheme_In_List
                         (HC.Cfg.Sign_Sig_Algos (J),
                          HC.Peer_Sig_Algos,
                          HC.Peer_Sig_Algo_Count)
            then
               HC.Negotiated_Sig_Algo := HC.Cfg.Sign_Sig_Algos (J);
               Algo_OK := True;
               exit;
            end if;
         end loop;
      else
         for I in 0 .. HC.Peer_Sig_Algo_Count - 1 loop
            pragma Loop_Invariant (S.State = S.State'Loop_Entry);
            pragma Loop_Invariant (S.Role = S.Role'Loop_Entry);
            pragma Loop_Invariant
              (S.Negotiated_Suite = S.Negotiated_Suite'Loop_Entry);
            pragma Loop_Invariant (Server_Configured (HC));
            pragma Loop_Invariant (Reasm_Building (HC));
            pragma Loop_Invariant
              (HC.Transcript_Len = HC.Transcript_Len'Loop_Entry);
            pragma Loop_Invariant (HC.HRR_Sent = HC.HRR_Sent'Loop_Entry);
            pragma Loop_Invariant (HC.Legacy_Session_ID_Len in 0 .. 32);
            pragma Loop_Invariant
              (HC.Cfg.Local.NaCl_Cert_Len <= N32 (Max_Cert_DER));
            pragma Loop_Invariant
              (for all K in 0 .. Max_Pool_Size - 1 =>
                 HC.Cfg.Local.Ints (K).DER_Len <= X509.N32 (Max_Cert_DER));
            pragma Loop_Invariant
              (if HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS
               then HC.Cfg.Local.RSA_Mod_Len in 64 .. 512);
            pragma Loop_Invariant
              (if Algo_OK then
                 HC.Negotiated_Sig_Algo /= 0
                 and then Handshake.Sig_Algo_Compatible_With_Cert
                            (HC.Negotiated_Sig_Algo,
                             HC.Cfg.Local.Sign_Algo));
            if Local_Sig_Compatible
                 (HC.Peer_Sig_Algos (I), HC.Cfg.Local.Sign_Algo)
            then
               HC.Negotiated_Sig_Algo := HC.Peer_Sig_Algos (I);
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
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Scratch   : in out IO_Buffer;
      Saved_Ctr : in     Unsigned_64;
      Result    :    out Action;
      Emitted   :    out Boolean)
   is
      Enc_Out : N32;
   begin
      Append_Transcript (HC, Plaintext);
      Records.Build_Encrypted_Record
        (Plaintext  => Plaintext,
         Inner_Type => 16#16#,
         Keys       => HC.Server_HS,
         Output     => Scratch,
         Bytes_Out  => Enc_Out);

      if Enc_Out = 0 then
         HC.Server_HS.Counter := Saved_Ctr;
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
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      Scratch   : in out IO_Buffer;
      Saved_Ctr : in     Unsigned_64;
      Result    :    out Action;
      Emitted   :    out Boolean)
   is
      Enc_Out : N32;
   begin
      Append_Transcript (HC, Plaintext);

      if Plaintext'Length <= Max_Fragment then
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext,
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
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
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
            S.Last_Error := Insufficient_Buffer;
            Set_State (S, Error_State);
            Result := Error_Alert;
            Emitted := False;
            return;
         end if;

         pragma Assert (HC.Server_HS.Counter <= Unsigned_64'Last - 1);
         pragma Assert (Nonce_Space_Available (HC.Server_HS));
         Records.Build_Encrypted_Record
           (Plaintext  => Plaintext (N32 (Max_Fragment) .. Plaintext'Last),
            Inner_Type => 16#16#,
            Keys       => HC.Server_HS,
            Output     => Scratch,
            Bytes_Out  => Enc_Out);

         if Enc_Out = 0 then
            HC.Server_HS.Counter := Saved_Ctr;
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
      Flight_Suite    : constant Unsigned_16 := S.Negotiated_Suite;
      Flight_Hash_Len : N32 := 32;
      --  Track whether we've started writing encrypted records (so we
      --  know whether a counter rollback is needed on commit failure).
      Encryption_Started : Boolean := False;
   begin
      --  PSK resumption: verify binder, install if valid, fatal-alert
      --  on mismatch. Sets HC.Using_PSK on success.
      if HC.PSK_Offered and then HC.Cfg.Store_Session /= null
                    and then HC.Cfg.Lookup_Session /= null then
         declare
            Rejected : Boolean;
         begin
            Verify_PSK_Binder (S, HC, Rejected, Result);
	            if Rejected then
		            return;
	            end if;
         end;
      end if;

      --  RFC 8446 §4.2.3: pick a sig_algorithm compatible with our
      --  local cert. Skipped on PSK resumption (no signature in flight).
      if not HC.Using_PSK then
         declare
            Got_It : Boolean;
         begin
            Negotiate_Sig_Algo (S, HC, Got_It, Result);
	            if not Got_It then
				            return;
	            end if;
         end;
      end if;

      --  Check if HelloRetryRequest is needed.
      --
      --  RFC 8446 §4.1.4: choose the first mutually supported group
      --  in server preference order. If the client did not send a
      --  key_share for that selected group, send HRR requesting it.
      if not HC.HRR_Sent then
         declare
            Need_HRR            : Boolean := False;
            HRR_Group           : Unsigned_16 := 0;
            Preferred_Has_Share : Boolean := False;
         begin
            if not HC.Client_Saw_Key_Share then
               Send_Alert_And_Error (S, Missing_Extension, Result);
               return;
            end if;

            --  Pick the server-preferred mutually supported group.
            if HC.Client_Supports_X25519 then
               HRR_Group := 16#001D#;
               Preferred_Has_Share := HC.Client_Has_X25519;
            elsif HC.Client_Supports_P256 then
               HRR_Group := 16#0017#;
               Preferred_Has_Share := HC.Client_Has_P256;
            elsif HC.Client_Supports_P384 then
               HRR_Group := 16#0018#;
               Preferred_Has_Share := HC.Client_Has_P384;
            end if;

            if HRR_Group /= 0 and then not Preferred_Has_Share then
               Need_HRR := True;
            end if;

            if Need_HRR then
	               Build_Hello_Retry_Request
	                 (S, HC, HRR_Group, SH_Buf, SH_Len, Rec_Out);
		               if SH_Len = 0 then
		                  if S.State not in Idle | Closed | Closing | Error_State then
		                     Send_Alert_And_Error (S, Internal_Error, Result);
			                  else
			                     Result := Error_Alert;
			                  end if;
		            return;
		               end if;
		               pragma Assert (S.State = Wait_Client_Hello);
		               Set_State (S, Wait_Client_Hello_Retry);
		               HC.HRR_Sent := True;
               --  RFC 8446 §4.1.4: at-most-one-HRR invariant. After
               --  this assignment, the outer `if not HC.HRR_Sent`
               --  guard prevents any further HRR from being built
	               --  in this connection.
	               pragma Assert (HRR_Sent_At_Most_Once_RFC_8446_4_1_4 (HC));
		               pragma Assert (Reasm_Building (HC));
		               Result := Has_Output;
		               return;
            end if;
         end;
      end if;

      if HC.Cfg.Require_ALPN
        and then not Handshake.Server_Msgs.Has_ALPN_Match (HC)
      then
         Send_Alert_And_Error (S, No_Application_Protocol, Result);
         return;
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
      Flight_Hash_Len := HC.Hash_Len;
      pragma Assert
        (if Flight_Suite = Suite_AES_256_GCM_SHA384
         then Flight_Hash_Len = 48
         else Flight_Hash_Len = 32);
      --  Save the AEAD counter snapshot now: every Build_Encrypted_Record
      --  call below advances HC.Server_HS.Counter unconditionally
      --  (Post: Keys.Counter = Keys.Counter'Old + 1). If the final
      --  commit fails we restore this so the next record's nonce stays
      --  in sync with whatever the peer last saw.
      Saved_Ctr := HC.Server_HS.Counter;
      pragma Assert (Saved_Ctr = 0);
      pragma Assert (Nonce_Space_Available (HC.Server_HS));

      --  Send CCS for middlebox compatibility unless HRR already sent it.
      if not HC.Sent_HRR_CCS then
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
         EE_Buf : Byte_Seq (0 .. 271);
         EE_Len : N32;
         Emitted : Boolean;
      begin
         Handshake.Server_Msgs.Build_Encrypted_Extensions (HC, S, EE_Buf, EE_Len);
         pragma Assert (EE_Len in 6 .. N32 (EE_Buf'Length));
         pragma Assert (EE_Len <= Max_Fragment);
         pragma Assert (HC.Server_HS.Counter = 0);
         pragma Assert (Nonce_Space_Available (HC.Server_HS));
	         pragma Assert (S.State not in Idle | Closing | Closed | Error_State);
         pragma Assert (Server_Active (S));
         Encryption_Started := True;
         Append_And_Encrypt_Server_HS
           (S         => S,
            HC        => HC,
            Plaintext => EE_Buf (0 .. EE_Len - 1),
            Scratch   => Scratch,
            Saved_Ctr => Saved_Ctr,
            Result    => Result,
            Emitted   => Emitted);
	         if not Emitted then
		         return;
		         end if;
	         pragma Assert (HC.Server_HS.Counter = 1);
	         pragma Assert (Nonce_Space_Available (HC.Server_HS));
	         pragma Assert (Reasm_Building (HC));
	      end;

      --  Skip Certificate/CertificateVerify for PSK resumption
      if not HC.Using_PSK then

      --  Build CertificateRequest if mTLS is configured
      if HC.Cfg.Request_Client_Cert then
         declare
            CR_Buf  : Byte_Seq (0 .. 31);
            CR_Len  : N32;
            Emitted : Boolean;
         begin
            Handshake.Server_Msgs.Build_Certificate_Request (CR_Buf, CR_Len);
            if CR_Len > 0 then
               pragma Assert (CR_Len <= Max_Fragment);
               pragma Assert (Nonce_Space_Available (HC.Server_HS));
               Append_And_Encrypt_Server_HS
                 (S         => S,
                  HC        => HC,
                  Plaintext => CR_Buf (0 .. CR_Len - 1),
                  Scratch   => Scratch,
                  Saved_Ctr => Saved_Ctr,
                  Result    => Result,
                  Emitted   => Emitted);
	               if not Emitted then
		         return;
	               end if;
            end if;
	            pragma Assert (HC.Server_HS.Counter in 1 .. 2);
	            pragma Assert (Nonce_Space_Available (HC.Server_HS));
	            pragma Assert (Reasm_Building (HC));
	         end;
	      end if;

      --  Build Certificate chain (leaf + intermediates, encrypted)
	      declare
	         --  Max: leaf + 8 intermediates, each up to 8 KB + 5 bytes overhead
	         Cert_Buf : Byte_Seq (0 .. 9 * (Max_Cert_DER_Len + 5) + 10);
	         Cert_Len : N32;
	         Emitted  : Boolean;
	      begin
	         if HC.Cfg.Local = null
	           or else HC.Cfg.Local.NaCl_Cert_Len > N32 (Max_Cert_DER)
	           or else HC.Cfg.Local.Int_Count > Max_Pool_Size
	           or else
	             (for some I in 0 .. Max_Pool_Size - 1 =>
	                HC.Cfg.Local.Ints (I).DER_Len > X509.N32 (Max_Cert_DER))
	         then
	            HC.Server_HS.Counter := Saved_Ctr;
		            S.Last_Error := Internal_Error;
		            Set_State (S, Error_State);
		            Result := Error_Alert;
		         return;
	         end if;
	         Handshake.Certs.Build_Certificate_Chain
	           (Id     => HC.Cfg.Local.all,
	            Result => Cert_Buf,
            Len    => Cert_Len);

         if Cert_Len = 0
           or else Cert_Len >= Transcript_Capacity
           or else Cert_Len > 2 * Max_Fragment
         then
            HC.Server_HS.Counter := Saved_Ctr;
	            S.Last_Error := Internal_Error;
	            Set_State (S, Error_State);
	            Result := Error_Alert;
		         return;
         end if;

         pragma Assert (Cert_Len < Transcript_Capacity);
         pragma Assert (Cert_Len <= 2 * Max_Fragment);
         pragma Assert (HC.Server_HS.Counter <= Unsigned_64'Last - 2);
         Append_And_Encrypt_Server_HS_Fragmented
           (S         => S,
            HC        => HC,
            Plaintext => Cert_Buf (0 .. Cert_Len - 1),
            Scratch   => Scratch,
            Saved_Ctr => Saved_Ctr,
            Result    => Result,
            Emitted   => Emitted);
		         if not Emitted then
		            return;
		         end if;
	         if not Nonce_Space_Available (HC.Server_HS) then
	            HC.Server_HS.Counter := Saved_Ctr;
		            S.Last_Error := Internal_Error;
		            Set_State (S, Error_State);
		            Result := Error_Alert;
		                  return;
		         end if;
		         pragma Assert (Reasm_Building (HC));
		      end;

      --  Build CertificateVerify (encrypted)
      declare
         H_Len   : constant N32 := Flight_Hash_Len;
         CV_Hash : Byte_Seq (0 .. H_Len - 1);
         CV_Buf  : Byte_Seq (0 .. 523);
         CV_Len  : N32;
         Emitted : Boolean;
      begin
         case Flight_Suite is
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

	         if HC.Negotiated_Sig_Algo in 16#0804# | 16#0805# | 16#0806#
	           and then (HC.Cfg.Random = null
	                     or else HC.Cfg.Local.RSA_Mod_Len not in 64 .. 512)
	         then
	            HC.Server_HS.Counter := Saved_Ctr;
	            S.Last_Error := Internal_Error;
	            Set_State (S, Error_State);
	            Result := Error_Alert;
			            return;
	         end if;
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

         pragma Assert (CV_Len <= Max_Fragment);
         pragma Assert (Nonce_Space_Available (HC.Server_HS));
         Append_And_Encrypt_Server_HS
           (S         => S,
            HC        => HC,
            Plaintext => CV_Buf (0 .. CV_Len - 1),
            Scratch   => Scratch,
            Saved_Ctr => Saved_Ctr,
            Result    => Result,
            Emitted   => Emitted);
		         if not Emitted then
		            return;
		         end if;
	         if not Nonce_Space_Available (HC.Server_HS) then
	            HC.Server_HS.Counter := Saved_Ctr;
		            S.Last_Error := Internal_Error;
		            Set_State (S, Error_State);
		            Result := Error_Alert;
			            return;
		         end if;
		         pragma Assert (Reasm_Building (HC));
		      end;

			      end if;  --  not Using_PSK (skip cert/cert_verify for resumption)

			      pragma Assert (Server_Configured (HC));
			      pragma Assert (Reasm_Building (HC));

		      --  Build Finished (encrypted)
	      declare
         Emitted : Boolean;
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

	                  pragma Assert (Nonce_Space_Available (HC.Server_HS));
	                  pragma Assert (Reasm_Building (HC));
	                  Append_And_Encrypt_Server_HS
                    (S         => S,
                     HC        => HC,
                     Plaintext => Big_Finished,
                     Scratch   => Scratch,
                     Saved_Ctr => Saved_Ctr,
	                     Result    => Result,
	                     Emitted   => Emitted);
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
                  pragma Assert (Fin_Len <= Max_Fragment);
                  pragma Assert (Nonce_Space_Available (HC.Server_HS));
                  Append_And_Encrypt_Server_HS
                    (S         => S,
                     HC        => HC,
                     Plaintext => Fin_Buf (0 .. Fin_Len - 1),
                     Scratch   => Scratch,
                     Saved_Ctr => Saved_Ctr,
	                     Result    => Result,
	                     Emitted   => Emitted);
	               end;
         end case;

	         if not Emitted then
				            return;
	         end if;
         pragma Assert
           (S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                  | Suite_AES_256_GCM_SHA384
                                  | Suite_CHACHA20_POLY1305_SHA256);
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
	      pragma Assert (Reasm_Building (HC));

			      Set_State (S, Server_Hello_Sent);
			      pragma Assert (Reasm_Building (HC));
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
            if HC.Selected_Group = 16#0018# then
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
         declare
            Hello_Hash : Digest := Transcript_Hash_256 (HC);
            Early      : Digest;
            HS_Secret  : Digest;
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret
              (Early, Bytes_32 (HC.PSK_Value (0 .. 31)));
            if HC.Selected_Group = 16#0018# then
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
               Exporter       : OKM384_Seq (0 .. 47);
            begin
               Key_Schedule.Derive_Master_Secret_384
                 (Master, Key_Schedule.Digest_384 (HC.Handshake_Secret));

               Key_Schedule.Derive_App_Traffic_Secrets_384
                 (Client_App_Sec, Server_App_Sec, Master, TS_Hash);
               Key_Schedule.Derive_Exporter_Master_Secret_384
                 (Exporter, Master, TS_Hash);

               HC.Master_Secret := Bytes_48 (Master);
               S.Exporter_Secret := Bytes_48 (Exporter);
               S.Exporter_Secret_Len := 48;
               S.Exporter_Client_Random := HC.Client_Random;
               S.Exporter_Server_Random := HC.Server_Random;

               Set_Traffic_Keys (S.Client_App,
                                 Bytes_48 (Byte_Seq (Client_App_Sec)),
                                 S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App,
                                 Bytes_48 (Byte_Seq (Server_App_Sec)),
                                 S.Negotiated_Suite);

               --  RFC 8446 4.6.3: retain the secrets themselves, not just
               --  the derived key/IV, so KeyUpdate can ratchet forward.
               S.Client_App_Secret :=
                  Bytes_48 (Byte_Seq (Client_App_Sec));
               S.Server_App_Secret :=
                  Bytes_48 (Byte_Seq (Server_App_Sec));
               S.App_Secret_Len := 48;
            end;

         when others =>
            declare
               TS_Hash        : constant Digest := Transcript_Hash_256 (HC);
               Master         : Digest;
               Client_App_Sec : OKM_Seq (0 .. 31);
               Server_App_Sec : OKM_Seq (0 .. 31);
               Exporter       : OKM_Seq (0 .. 31);
               CS48           : Bytes_48 := (others => 0);
               SS48           : Bytes_48 := (others => 0);
            begin
               Key_Schedule.Derive_Master_Secret
                 (Master, Digest (HC.Handshake_Secret (0 .. 31)));

               Key_Schedule.Derive_App_Traffic_Secrets
                 (Client_App_Sec, Server_App_Sec,
                  Master, TS_Hash);
               Key_Schedule.Derive_Exporter_Master_Secret
                 (Exporter, Master, TS_Hash);

               HC.Master_Secret := (others => 0);
               HC.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));
               S.Exporter_Secret := (others => 0);
               S.Exporter_Secret (0 .. 31) := Bytes_32 (Byte_Seq (Exporter));
               S.Exporter_Secret_Len := 32;
               S.Exporter_Client_Random := HC.Client_Random;
               S.Exporter_Server_Random := HC.Server_Random;

               CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
               SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
               Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);

               --  RFC 8446 4.6.3: retain the secrets for the KeyUpdate
               --  ratchet.
               S.Client_App_Secret := CS48;
               S.Server_App_Secret := SS48;
               S.App_Secret_Len    := 32;
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
                and then Data'Last >= 3
                and then Data'Last < N32'Last - 4
                and then Data'Last < Transcript_Capacity
	                and then S.State = Wait_Client_Certificate
	                  and then Nonce_Space_Available (S.Server_App)
		                  and then Server_Configured (HC)
		                  and then HC.Transcript_Len > 0
		                  and then Reasm_Building (HC)
		                  and then Reasm_Buffer_Shaped (HC)
				                and then HC.Reasm_Len <= HC.Reasm_Need,
			        Post => (if S.State not in Error_State | Closed
				                          then Server_Configured (HC)
			                               and then Reasm_Building (HC));

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
	      pragma Assert (Reasm_Building (HC));
	      if not Parse_OK then
         Send_Encrypted_Alert (S, Parse_Err, Result);
         return;
      end if;

      if not HC.Peer_Cert_Valid then
         if HC.Peer_Cert_DER_Len > 0 then
            Send_Encrypted_Alert (S, Decode_Error, Result);
            return;
         end if;
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
                and then Data'Length > 0
                and then Data'Last < N32'Last - 4
                and then Data'Last < Transcript_Capacity
                and then S.State = Wait_Client_Cert_Verify
                and then Server_Configured (HC)
                and then Nonce_Space_Available (S.Server_App)
                and then HC.Hash_Len in 32 | 48
                and then
                  (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                   then HC.Hash_Len = 48
                   else HC.Hash_Len = 32)
	                and then HC.Transcript_Len > 0
	                and then HC.Transcript_Len <= Transcript_Capacity
	                and then Reasm_Building (HC)
	                and then HC.Peer_Cert_Valid
	                and then HC.Peer_Cert_DER_Len > 0
	                and then HC.Peer_Cert_DER_Len <= Max_Cert_DER_Len
	                and then
	                  X509.N32 (HC.Peer_Cert_DER_Len) - 1 < X509.N32'Last
	                and then X509.Spans_Valid
	                  (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1)
	                and then SPARKTLSCrypto.P384.Field.Initialized
	                and then SPARKTLSCrypto.P384.ECDSA.Initialized
	                and then Free_Space (S.Output) >=
	                           Records.Record_Header_Size + 3 + Records.Tag_Size,
		        Post => (if S.State not in Error_State | Closed
		                          then Server_Configured (HC)
	                               and then Reasm_Building (HC));

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
      pragma Assert
        (X509.Spans_Valid
           (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1));
      Result := OK;
      case S.Negotiated_Suite is
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

         if Msg_Len >= 8 and then Data'Length >= 8 then
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

               if HC.Cfg.Verify_Sig_Algo_Count > 0
                 and then not Sig_Scheme_In_List
                                (Sig_Scheme,
                                 HC.Cfg.Verify_Sig_Algos,
                                 HC.Cfg.Verify_Sig_Algo_Count)
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
                     Sig := Data (Sig_Start ..
                                  Sig_Start + Sig_Len - 1);
                     Verified := Cert_Verify.Verify_Signature
                       (Data       => Content,
                        Sig        => Sig,
                        Cert       => HC.Peer_Cert,
                        Sig_Scheme => Sig_Scheme);
                  end;
               else
                  Send_Encrypted_Alert (S, Decode_Error, Result);
                  return;
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

      if HC.Peer_Cert_Valid then
         declare
            Cert_DER_Len_Const : constant N32 := HC.Peer_Cert_DER_Len;
            Leaf_Last : constant X509.N32 :=
               X509.N32 (Cert_DER_Len_Const) - 1;
            Cert_X : X509.Byte_Seq
               (0 .. Leaf_Last) :=
                 (others => 0);
            VR : Validation_Result;
         begin
            pragma Assert (Cert_DER_Len_Const = HC.Peer_Cert_DER_Len);
            pragma Assert
              (Leaf_Last = X509.N32 (HC.Peer_Cert_DER_Len) - 1);
            for I in N32 range 0 .. HC.Peer_Cert_DER_Len - 1 loop
               pragma Loop_Invariant
                 (Cert_DER_Len_Const = HC.Peer_Cert_DER_Len);
               pragma Loop_Invariant
                 (HC.Peer_Cert = HC.Peer_Cert'Loop_Entry);
               pragma Loop_Invariant
                 (HC.Peer_Cert_DER_Len =
                    HC.Peer_Cert_DER_Len'Loop_Entry);
               pragma Loop_Invariant
                 (Leaf_Last =
                    X509.N32 (HC.Peer_Cert_DER_Len) - 1);
               pragma Loop_Invariant (Leaf_Last < X509.N32'Last);
               pragma Loop_Invariant
                 (X509.Spans_Valid
                    (HC.Peer_Cert'Loop_Entry,
                     X509.N32 (HC.Peer_Cert_DER_Len'Loop_Entry) - 1));
               Cert_X (X509.N32 (I)) :=
                  X509.Byte (HC.Peer_Cert_DER (I));
            end loop;
            pragma Assert (Leaf_Last < X509.N32'Last);
            pragma Assert
              (X509.N32 (HC.Peer_Cert_DER_Len) - 1 < X509.N32'Last);

            VR := Validate_Leaf_Policy
              (Leaf     => HC.Peer_Cert,
               Leaf_DER =>
                  Cert_X
                    (0 .. X509.N32 (HC.Peer_Cert_DER_Len) - 1),
               Hostname => "",
               Purpose  => Purpose_Client,
               Mode     => HC.Cfg.Verify_Mode);
            if VR /= Valid then
               Send_Encrypted_Alert (S, Bad_Certificate, Result);
               pragma Assert (S.Last_Error /= Unexpected_Message);
               pragma Assert (Output_Pending (S) > 0);
               pragma Assert
                 (Cert_Validation_Alerted_RFC_5246_7_4_2
                    (S.State, Output_Pending (S), S.Last_Error));
               return;
            end if;

            --  Skip_Verify is the explicit "require any client
            --  certificate" mode: enforce leaf policy and proof of
            --  possession, but do not require a trusted issuer chain.
            if not HC.Cfg.Skip_Verify then
               if HC.Cfg.Trust = null or else HC.Cfg.Get_Time = null then
                  Send_Encrypted_Alert (S, Bad_Certificate, Result);
                  pragma Assert (S.Last_Error /= Unexpected_Message);
                  pragma Assert (Output_Pending (S) > 0);
                  pragma Assert
                    (Cert_Validation_Alerted_RFC_5246_7_4_2
                       (S.State, Output_Pending (S), S.Last_Error));
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
                  Send_Encrypted_Alert (S, Bad_Certificate, Result);
                  pragma Assert (S.Last_Error /= Unexpected_Message);
                  pragma Assert (Output_Pending (S) > 0);
                  pragma Assert
                    (Cert_Validation_Alerted_RFC_5246_7_4_2
                       (S.State, Output_Pending (S), S.Last_Error));
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
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Building (HC));
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
            pragma Assert (Reasm_Building (HC));
         end if;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Rec.Fragment_Len = 1 and then not HC.CCS_Received then
               HC.CCS_Received := True;
               Result := OK;
               pragma Assert (Reasm_Building (HC));
            else
               declare
                  Ignored_A : N32;
               begin
                  Records.Build_Alert_Record
                    (2, 10, S.Server_App, S.Output, Ignored_A);
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
            pragma Assert (Rec.Fragment_Len <=
                             Records.Max_Fragment + Max_Record_Overhead);
            pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
            pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
            pragma Assert (Rec.Fragment_Len =
                             Rec.Record_Len - Rec.Fragment_Pos);
            pragma Assert (Rec.Record_Len <= Available (S.Input));

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
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, Ignored_A);
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
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, Ignored_A);
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
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, Ignored_A);
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
                  Msg_Type : Byte;
                  Msg_Len  : N32;
                  Parse_OK : Boolean;
                  Plain_Len_Const : constant N32 := Plain_Len;
                  Data     : constant Byte_Seq := Plaintext (0 .. Plain_Len_Const - 1);
               begin
                  Handshake.Parse_Handshake_Header
                    (Data, Msg_Type, Msg_Len, Parse_OK);

	                  if not Parse_OK then
	                     --  Unknown handshake type is a state-machine error
	                     --  (unexpected_message); malformed shape for a known
	                     --  handshake type is decode_error.
	                     declare
	                        Raw_Type : constant Byte :=
	                          (if Plain_Len_Const >= 1 then Data (0) else 0);
	                        Is_Known : constant Boolean :=
	                          Raw_Type in 16#01# | 16#02# | 16#04# |
	                                      16#08# | 16#0B# | 16#0C# |
	                                      16#0D# | 16#0E# | 16#0F# |
	                                      16#10# | 16#14#;
	                     begin
	                        Send_Encrypted_Alert
	                          (S,
	                           (if Is_Known then Decode_Error
	                            else Unexpected_Message),
	                           Result);
	                     end;
	                     return;
	                  end if;

	                  if Plain_Len_Const < 4 then
	                     Send_Encrypted_Alert (S, Decode_Error, Result);
	                     return;
	                  end if;

	                  pragma Assert (Reasm_Building (HC));

	                  case S.State is
	                     when Wait_Client_Certificate =>
	                        if Msg_Type /= Handshake.HT_Certificate then
	                           Send_Encrypted_Alert
	                             (S, Unexpected_Message, Result);
	                           return;
	                        end if;
	                        pragma Assert (Reasm_Buffer_Shaped (HC));
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
                  pragma Assert
                    (if S.State not in Error_State | Closed
                     then Server_Configured (HC)
                          and then Reasm_Building (HC));
               end;
            end;

         when others =>
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            pragma Assert (Reasm_Building (HC));
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
                           Ignored_A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 51, S.Server_App, S.Output, Ignored_A);
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
                           Ignored_A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 10, S.Server_App, S.Output, Ignored_A);
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
                              Ignored_A : N32;
                           begin
                              Records.Build_Alert_Record
                                (2, 51, S.Server_App, S.Output, Ignored_A);
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
                        Ticket_Random : Byte_Seq (0 .. 5);
                        Nonce         : Byte_Seq (0 .. 1);
                        Age_Add       : Unsigned_32;
                        TID           : Ticket_ID := (others => 0);
                        Enc_Out       : N32;
                     begin
                        HC.Cfg.Random.all (Ticket_Random);
                        Nonce := Ticket_Random (0 .. 1);
                        Age_Add :=
                          Unsigned_32 (Ticket_Random (2)) * 2**24
                          + Unsigned_32 (Ticket_Random (3)) * 2**16
                          + Unsigned_32 (Ticket_Random (4)) * 2**8
                          + Unsigned_32 (Ticket_Random (5));

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
                                 if HC.Cfg.Store_Session /= null
                    and then HC.Cfg.Lookup_Session /= null then
                                    pragma Warnings
                                      (Off, "value conversion implemented by copy");
                                    HC.Cfg.Store_Session
                                      (                                       Bytes_48 (PSK_Out), 48,
                                       S.Negotiated_Suite, Age_Add, TID);
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
                                 if HC.Cfg.Store_Session /= null
                    and then HC.Cfg.Lookup_Session /= null then
                                    declare
                                       PSK_48 : Bytes_48 := (others => 0);
                                    begin
                                       for I in N32 range 0 .. 31 loop
                                          PSK_48 (I) := PSK_Out (I);
                                       end loop;
                                       HC.Cfg.Store_Session
                                         (                                          PSK_48, 32,
                                          S.Negotiated_Suite, Age_Add, TID);
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
                        if HC.Cfg.Store_Session /= null
                    and then HC.Cfg.Lookup_Session /= null
                          and then HC.Has_PSK_DHE_KE
                        then
                           declare
                              --  NST format: type(1) + len(3) + lifetime(4) +
                              --  age_add(4) + nonce_len(1) + nonce(2) +
                              --  ticket_len(2) + ticket(16) + ext_len(2) +
                              --  GREASE extension(4) + optional
                              --  ticket_flags(7) = 39 or 46.
                              --  We never emit the early_data extension —
                              --  0-RTT is intentionally out of scope (see
                              --  Cfg.Resume_Ticket comment in sparktls.ads).
                              Include_Flags : constant Boolean :=
                                 HC.Cfg.TLS13_Resumption_Across_Names;
                              NST_Total : constant N32 :=
                                 (if Include_Flags then 46 else 39);
                              NST_Body_Len : constant N32 :=
                                 NST_Total - 4;
                              NST_Ext_Len : constant N32 :=
                                 (if Include_Flags then 11 else 4);
                              NST : Byte_Seq (0 .. 45) := (others => 0);
                           begin
                              --  Handshake type: NewSessionTicket (0x04)
                              NST (0) := 16#04#;
                              --  Length: 35 or 42 bytes
                              NST (1) := 0; NST (2) := 0;
                              NST (3) := Byte (NST_Body_Len);
                              --  ticket_lifetime: 3600 seconds (1 hour)
                              NST (4) := 0; NST (5) := 0;
                              NST (6) := 16#0E#; NST (7) := 16#10#;
                              --  ticket_age_add
                              NST (8) := Byte (Shift_Right (Age_Add, 24));
                              NST (9) := Byte
                                (Shift_Right (Age_Add, 16) and 16#FF#);
                              NST (10) := Byte
                                (Shift_Right (Age_Add, 8) and 16#FF#);
                              NST (11) := Byte (Age_Add and 16#FF#);
                              --  ticket_nonce_length: 2
                              NST (12) := 2;
                              --  ticket_nonce
                              NST (13) := Nonce (0);
                              NST (14) := Nonce (1);
                              --  ticket_length: 16
                              NST (15) := 0; NST (16) := 16;
                              --  ticket (the cache ID)
                              NST (17 .. 32) := TID;
                              --  extensions_length: 4 or 11
                              NST (33) := 0; NST (34) := Byte (NST_Ext_Len);
                              --  GREASE extension 0x0a0a, empty body.
                              NST (35) := 16#0A#; NST (36) := 16#0A#;
                              NST (37) := 0; NST (38) := 0;
                              if Include_Flags then
                                 --  ticket_flags extension (0x003E), body
                                 --  opaque flags<1..255>. Bit 8
                                 --  resumption_across_names is encoded as
                                 --  two minimally-encoded flag bytes: 00 01.
                                 NST (39) := 0; NST (40) := 16#3E#;
                                 NST (41) := 0; NST (42) := 3;
                                 NST (43) := 2;
                                 NST (44) := 0;
                                 NST (45) := 1;
                              end if;

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
                                   (Plaintext  => NST (0 .. NST_Total - 1),
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
      procedure Dispatch_Finished_Message
        (Data   : in     Byte_Seq;
         Len    : in     N32;
         Result :    out Action)
      with Pre => S.State = Wait_Client_Finished
                  and then S.Role = Role_Server
	                  and then Nonce_Space_Available (S.Server_App)
		                  and then Server_Configured (HC)
		                  and then Reasm_Building (HC)
			                  and then Reasm_Buffer_Shaped (HC)
			                  and then HC.Transcript_Len > 0
	                  and then Data'First = 0
                  and then Len > 0
                  and then Data'Last < N32'Last
                  and then Len - 1 <= Data'Last,
           Post => (if S.State not in Error_State | Closed
			                             then Server_Configured (HC)
			                                  and then Reasm_Building (HC)
			                                  and then Reasm_Buffer_Shaped (HC))
      is
         Msg_Type : Byte;
         Msg_Len  : N32;
         Parse_OK : Boolean;
      begin
         Handshake.Parse_Handshake_Header
           (Data (0 .. Len - 1), Msg_Type, Msg_Len, Parse_OK);

         if not Parse_OK then
            --  Distinguish unknown-type (BoGo WrongMessageType injects
            --  type+42) from malformed shape. Unknown type →
            --  unexpected_message; otherwise decode_error.
            declare
               Raw_Type : constant Byte :=
                 (if Len >= 1 then Data (0) else 0);
               Is_Known : constant Boolean :=
                 Raw_Type in 16#01# | 16#02# | 16#04# |
                             16#08# | 16#0B# | 16#0C# |
                             16#0D# | 16#0E# | 16#0F# |
                             16#10# | 16#14#;
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record
                 (2, (if Is_Known then 50 else 10),
                  S.Server_App, S.Output, Ignored_A);
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
            declare
               Ignored_A : N32;
            begin
               Records.Build_Alert_Record
                 (2, 10, S.Server_App, S.Output, Ignored_A);
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

         Verify_Client_Finished (S, HC, Data, Len, Msg_Len, Result);
      end Dispatch_Finished_Message;
   begin
      Result := OK;
      pragma Assert (Rec.Fragment_Len >= 1);
      pragma Assert (Rec.Fragment_Len <=
                       Records.Max_Fragment + Max_Record_Overhead);
      pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
      pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
      pragma Assert (Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos);
      pragma Assert (Rec.Record_Len <= Available (S.Input));
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
						                     pragma Assert
						                       (if S.State = Wait_Client_Hello
						                        then Reasm_Building (HC));
	                  return;
               end if;

               --  RFC 8446 §5.4: TLSInnerPlaintext MUST NOT exceed
               --  2^14 + 1 octets. Check before decrypting.
               if Frag_Len - Records.Tag_Size >
                  Records.Max_Fragment + 1
               then
	                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
	                  Send_Encrypted_Alert (S, Record_Overflow, Result);
		            pragma Assert
		              (if S.State = Wait_Client_Hello
		               then Reasm_Building (HC));
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
	                     pragma Assert (Reasm_Building (HC));
	                     return;
                  end if;
                  --  MAC failure or empty inner plaintext.
                  --  Send alert with app keys (client switched to app
                  --  keys after receiving our Finished).
                  --  RFC 8446 §5.2: bad_record_mac (20)
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 20, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Bad_Record_MAC;
                  Set_State (S, Error_State);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
	                  else
	                     Result := Error_Alert;
	                  end if;
		            pragma Assert
		              (if S.State = Wait_Client_Hello
		               then Reasm_Building (HC));
	                  return;
               end if;

               if Inner_Type = 16#15# and then Plain_Len >= 2 then
                  --  Peer sent alert
                  S.Last_Error := Error_Code'Val
                    (Natural'Min (Natural (Plaintext (1)),
                                  Error_Code'Pos (Error_Code'Last)));
	                  Set_State (S, Error_State);
	                  Result := Error_Alert;
	                  pragma Assert
	                    (if S.State not in Error_State | Closed
	                     then Reasm_Building (HC));
	                  return;
               elsif Inner_Type /= 16#16# then
                  --  Unexpected inner type during handshake
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 10, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  if Output_Pending (S) > 0 then
                     Result := Has_Output;
	                  else
	                     Result := Error_Alert;
	                  end if;
	                  pragma Assert
	                    (if S.State not in Error_State | Closed
	                     then Reasm_Building (HC));
	                  return;
               end if;

               --  Parse handshake header
	               if Plain_Len = 0 then
	                  Send_Encrypted_Alert (S, Decode_Error, Result);
	                  pragma Assert
	                    (if S.State not in Error_State | Closed
	                     then Reasm_Building (HC));
	                  return;
               end if;

               if HC.Reasm_Need > 0 and then HC.Reasm_Buf /= null then
                  declare
                     Pos : N32 := 0;
                  begin
                     if HC.Reasm_Len < HC.Reasm_Need then
                        declare
                           Need : constant N32 :=
                             HC.Reasm_Need - HC.Reasm_Len;
                           Take : constant N32 := N32'Min (Plain_Len, Need);
                        begin
                           if Take > 0
                             and then HC.Reasm_Len + Take <=
                                      N32 (HC.Reasm_Buf'Length)
                           then
                              HC.Reasm_Buf
                                (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                                  Plaintext (0 .. Take - 1);
                              HC.Reasm_Len := HC.Reasm_Len + Take;
                              Pos := Take;
                           end if;
                        end;
                     end if;

                     if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
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
                              Send_Encrypted_Alert (S, Decode_Error, Result);
	                              return;
	                           end if;
	                           HC.Reasm_Need := HS_Total;
	                           pragma Assert (HC.Reasm_Need > 0);
	                        end;
	                     end if;
	                     pragma Assert (HC.Reasm_Need > 0);

	                     if HC.Reasm_Len < HC.Reasm_Need and then Pos < Plain_Len
	                     then
                        declare
                           Need : constant N32 :=
                             HC.Reasm_Need - HC.Reasm_Len;
                           Take : constant N32 :=
                             N32'Min (Plain_Len - Pos, Need);
                        begin
                           if Take > 0
                             and then HC.Reasm_Len + Take <=
                                      N32 (HC.Reasm_Buf'Length)
                           then
                              HC.Reasm_Buf
                                (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                                  Plaintext (Pos .. Pos + Take - 1);
                              HC.Reasm_Len := HC.Reasm_Len + Take;
                              Pos := Pos + Take;
                           end if;
                        end;
                     end if;

	                     if HC.Reasm_Len < HC.Reasm_Need then
	                        Result := OK;
	                        pragma Assert (Reasm_Building (HC));
	                        --  Proof decomposition for the assert below.
	                        --  Reasm_Len has just grown by Take, and the
	                        --  prover cannot re-establish Reasm_Buffer_Shaped
	                        --  in one step here. Each conjunct below is
	                        --  discharged on its own and then used as a
	                        --  lemma. All five are PROVED, so they are
	                        --  verified stepping stones, not assumptions.
	                        pragma Assert (HC.Reasm_Buf /= null);
	                        pragma Assert
	                          (if HC.Reasm_Buf /= null then
	                             HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
	                        pragma Assert
	                          (if HC.Reasm_Buf /= null then
	                             HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
	                        pragma Assert
	                          (if HC.Reasm_Need = 0 then HC.Reasm_Len = 0
	                           else HC.Reasm_Need >= 4);
	                        pragma Assert
	                          (if HC.Reasm_Hdr_Pending then
	                             HC.Reasm_Need = 4
	                             and then HC.Reasm_Len <= 4);
	                        pragma Assert (Reasm_Buffer_Shaped (HC));
	                        return;
	                     end if;

                     pragma Assert (HC.Reasm_Need > 0);
                     declare
                        Full_Len : constant N32 := HC.Reasm_Need;
                        Full     : constant Byte_Seq :=
                          HC.Reasm_Buf (0 .. Full_Len - 1);
                     begin
                        Free_Byte_Seq (HC.Reasm_Buf);
                        HC.Reasm_Len := 0;
                        HC.Reasm_Need := 0;
                        HC.Reasm_Hdr_Pending := False;
                        pragma Assert (Full_Len > 0);
                        pragma Assert (Full'First = 0);
                        pragma Assert (Full'Last < N32'Last);
                        pragma Assert (Full_Len - 1 <= Full'Last);
                        pragma Assert (Reasm_Building (HC));
                        Dispatch_Finished_Message
                          (Full, Full_Len, Result);
                     end;
                     return;
                  end;
               end if;

               if Plain_Len < 4 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
                  HC.Reasm_Need := 4;
                  HC.Reasm_Hdr_Pending := True;
                  HC.Reasm_Len := Plain_Len;
	                  HC.Reasm_Buf (0 .. Plain_Len - 1) :=
	                    Plaintext (0 .. Plain_Len - 1);
	                  Result := OK;
	                  pragma Assert (Reasm_Building (HC));
	                  pragma Assert (Reasm_Buffer_Shaped (HC));
	                  return;
	               end if;

               declare
                  HS_Total : constant N32 :=
                    N32 (Plaintext (1)) * 65536
                    + N32 (Plaintext (2)) * 256
                    + N32 (Plaintext (3)) + 4;
               begin
                  if HS_Total > Max_HS_Msg then
                     Send_Encrypted_Alert (S, Decode_Error, Result);
                     return;
                  elsif HS_Total > Plain_Len then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Buf := new Byte_Seq'(0 .. HS_Total - 1 => 0);
                     HC.Reasm_Need := HS_Total;
                     HC.Reasm_Hdr_Pending := False;
                     HC.Reasm_Len := Plain_Len;
	                     HC.Reasm_Buf (0 .. Plain_Len - 1) :=
	                       Plaintext (0 .. Plain_Len - 1);
	                     Result := OK;
	                     pragma Assert (Reasm_Building (HC));
	                     pragma Assert (Reasm_Buffer_Shaped (HC));
	                     return;
	                  end if;
               end;

               pragma Assert (Plain_Len > 0);
               pragma Assert (Plaintext'First = 0);
               pragma Assert (Plaintext'Last < N32'Last);
               pragma Assert (Plain_Len - 1 <= Plaintext'Last);
	               Dispatch_Finished_Message (Plaintext, Plain_Len, Result);
	               pragma Assert
	                 (if S.State not in Error_State | Closed
	                  then Reasm_Building (HC));
		               pragma Assert
		                 (if S.State not in Error_State | Closed
		                  then Reasm_Buffer_Shaped (HC));
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
                  Ignored_A : N32;
               begin
                  Records.Build_Alert_Record
                    (2, 10, S.Server_App, S.Output, Ignored_A);
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
	            pragma Assert
	              (if S.State not in Error_State | Closed
	               then Reasm_Building (HC));
	      end case;
	   end Process_Client_Finished;

   --  Process records in Connected state
   ----------------------------------------------------------------------
   --  Post-handshake handshake messages (RFC 8446 §4.6)
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
   with Post => S.Post_HS_Len = 0 and then S.Post_HS_Need = 0;

   procedure Reset_Post_HS_Reasm (S : in out Session) is
   begin
      S.Post_HS_Len  := 0;
      S.Post_HS_Need := 0;
   end Reset_Post_HS_Reasm;

   --  RFC 8446 §4.6.3. The peer's KeyUpdate rotates its WRITE key, which
   --  for a server is S.Client_App (our read direction). A request_update
   --  obliges us to rotate S.Server_App and say so before our next
   --  Application Data record.
   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   with Pre  => S.State in Connected | Closing
                and then Msg'First = 0
                and then Nonce_Space_Available (S.Server_App)
                and then S.App_Secret_Len in 32 | 48
                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                            | Suite_AES_256_GCM_SHA384
                                            | Suite_CHACHA20_POLY1305_SHA256,
        Post => (if Result = OK
                 then S.State in Connected | Closing
                   and then Nonce_Space_Available (S.Server_App));

   procedure Process_Key_Update_Message
     (S      : in out Session;
      Msg    : in     Byte_Seq;
      Result :    out Action)
   is
      Request : Boolean;
      Valid   : Boolean;
   begin
      Key_Update.Parse_Key_Update (Msg, Request, Valid);

      if not Valid then
         --  RFC 8446 §4.6.3: malformed body, or request_update outside
         --  {0,1}, MUST be illegal_parameter.
         Send_Encrypted_Alert (S, Illegal_Parameter, Result);
         return;
      end if;

      --  Cap the rate: each rekey costs a KDF and the RFC sets no bound
      --  (BoGo TooManyKeyUpdates).
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
   with Pre  => S.State in Connected | Closing
                and then Nonce_Space_Available (S.Server_App)
                and then S.Post_HS_Need in 4 .. Max_Record_Plaintext
                and then S.Post_HS_Len = S.Post_HS_Need,
        Post => S.Post_HS_Len = 0 and then S.Post_HS_Need = 0;

   procedure Dispatch_Post_HS_Message
     (S      : in out Session;
      Result :    out Action)
   is
      Msg_Len : constant N32 := S.Post_HS_Need;
      Msg     : constant Byte_Seq (0 .. Msg_Len - 1) :=
        S.Post_HS_Buf (0 .. Msg_Len - 1);
   begin
      if Msg (0) = Key_Update.HS_Key_Update then
         if S.App_Secret_Len in 32 | 48
           and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256
         then
            Process_Key_Update_Message (S, Msg, Result);
         else
            --  TLS 1.3 only; a TLS 1.2 session has no retained secret.
            Send_Encrypted_Alert (S, Unexpected_Message, Result);
         end if;
      else
         --  RFC 8446 §4.6: a server legitimately receives few
         --  post-handshake messages. NewSessionTicket is server-to-client,
         --  and post-handshake client auth is not supported here, so
         --  anything else is unexpected rather than ignorable.
         Send_Encrypted_Alert (S, Unexpected_Message, Result);
      end if;
      Reset_Post_HS_Reasm (S);
   end Dispatch_Post_HS_Message;

   procedure Process_Post_HS_Handshake_Bytes
     (S         : in out Session;
      Plaintext : in     Byte_Seq;
      Plain_Len : in     N32;
      Result    :    out Action)
   with Pre => S.State in Connected | Closing
               and then Nonce_Space_Available (S.Server_App)
               and then Plaintext'First = 0
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
         pragma Loop_Invariant (S.State in Connected | Closing);
         pragma Loop_Invariant (Nonce_Space_Available (S.Server_App));
         pragma Loop_Invariant (S.Post_HS_Len <= Max_Record_Plaintext);
         pragma Loop_Invariant (S.Post_HS_Need <= Max_Record_Plaintext);
         pragma Loop_Invariant
           (if S.Post_HS_Need = 0
            then S.Post_HS_Len = 0
            else S.Post_HS_Need >= 4
              and then S.Post_HS_Len <= S.Post_HS_Need);

         --  Start of a new message: take the 4-byte header first.
         if S.Post_HS_Need = 0 then
            S.Post_HS_Len  := 0;
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
               --  Header complete: read the 24-bit body length.
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
                     Send_Encrypted_Alert (S, Decode_Error, Result);
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

      pragma Assert (Rec.Fragment_Len >= 1);
      pragma Assert (Rec.Fragment_Len <=
                       Records.Max_Fragment + Max_Record_Overhead);
      pragma Assert (Rec.Fragment_Pos = Records.Record_Header_Size);
      pragma Assert (Rec.Record_Len >= Rec.Fragment_Pos);
      pragma Assert (Rec.Fragment_Len = Rec.Record_Len - Rec.Fragment_Pos);
      pragma Assert (Rec.Record_Len <= Available (S.Input));

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

         --  RFC 8446 §5.4: TLSInnerPlaintext MUST NOT exceed
         --  2^14 + 1 octets. Check before decrypting.
         if Frag_Len - Records.Tag_Size >
            Records.Max_Fragment + 1
         then
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
            --  MAC failure or empty inner plaintext (RFC 8446 §5.2/§5.4)
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
               if S.State = Closing and then Plain_Len > 0 then
                  Send_Encrypted_Alert (S, Unexpected_Message, Result);
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
                  --  Empty plaintext record — count + cap (BoGo
                  --  SendEmptyRecords / TOO_MANY_EMPTY_FRAGMENTS).
                  S.Empty_Records_Recvd :=
                     S.Empty_Records_Recvd + 1;
                  if S.Empty_Records_Recvd > 32 then
                     declare
                        Ignored_A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, 10, S.Server_App, S.Output, Ignored_A);
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
               --  RFC 8446 §4.6 post-handshake handshake message. Until
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
                  Process_Post_HS_Handshake_Bytes
                    (S, Plaintext, Plain_Len, Result);
               else
                  Result := OK;
               end if;

            when 16#15# =>
               --  Alert. RFC 8446 §6 / RFC 5246 §7.2: 2-byte payload
               --  `level | description`. Validate level, distinguish
               --  close_notify, tolerate user_canceled (with cap),
               --  reject every other warning with decode_error, and
               --  reject bogus levels with illegal_parameter.
               if Plain_Len < 2 then
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 50, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Decode_Error;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0
                             then Has_Output else Error_Alert);
               elsif Plaintext (0) /= 1 and Plaintext (0) /= 2 then
                  --  Bogus level (BoGo SendBogusAlertType: 0x42).
                  declare
                     Ignored_A : N32;
                  begin
                     Records.Build_Alert_Record
                       (2, 47, S.Server_App, S.Output, Ignored_A);
                  end;
                  S.Last_Error := Illegal_Parameter;
                  Set_State (S, Error_State);
                  Result := (if Output_Pending (S) > 0
                             then Has_Output else Error_Alert);
               elsif Plaintext (1) = 0 then
                  --  close_notify — reply in kind (warning level 1).
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
                           Ignored_A : N32;
                        begin
                           Records.Build_Alert_Record
                             (2, 50, S.Server_App, S.Output, Ignored_A);
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
                        Ignored_A : N32;
                     begin
                        Records.Build_Alert_Record
                          (2, 50, S.Server_App, S.Output, Ignored_A);
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

   procedure Close_Notify (S : in out Session) is
      Ignored_Alert_Out : N32;
   begin
      if S.Negotiated_Version = TLS_1_2 then
         Records.TLS12.Build_Alert_Record_12
           (Level       => 1,
            Desc        => 0,
            Keys        => S.Server_App,
            Implicit_IV => S.Server_IV_12,
            Seq_Num     => S.Server_Seq_12,
            Output      => S.Output,
            Bytes_Out   => Ignored_Alert_Out);
      else
         Records.Build_Alert_Record
           (Level     => 1,
            Desc      => 0,
            Keys      => S.Server_App,
            Output    => S.Output,
            Bytes_Out => Ignored_Alert_Out);
      end if;
      --  RFC 8446 §6.1: at most one close_notify per peer; if we
      --  already transitioned to Closing on a prior invocation, the
      --  state-machine transition is a no-op.
      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Server;
