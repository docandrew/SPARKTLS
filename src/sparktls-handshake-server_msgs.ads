with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;
with SPARKTLS.Records.TLS12;
with SPARKTLSCrypto.P384.Field;
with X509;

--  TLS 1.3 Server Handshake Messages
--
--  Parse ClientHello, build ServerHello, EncryptedExtensions,
--  and CertificateRequest.
package SPARKTLS.Handshake.Server_Msgs with
   SPARK_Mode => On
is
   --  Maximum ServerHello size
   Max_Server_Hello : constant := 256;

   --  Defined as membership in the predicated subtype rather than by
   --  restating its conjuncts. Config.Local now has subtype
   --  Valid_Identity_Access, so Local_Config_Valid (HC.Cfg.Local) unfolds to
   --  a membership test that holds by construction. Written as a second
   --  literal conjunction it did not: the prover had to match two
   --  independent copies of the same predicate and could not.
   function Local_Config_Valid (Local : Identity_Access) return Boolean is
     (Local in Valid_Identity_Access)
   with Ghost;

   function Local_Config_Frame
     (Old_Local : Identity_Access;
      New_Local : Identity_Access) return Boolean is
     ((Old_Local = null or else Old_Local /= null)
      and then Local_Config_Valid (New_Local))
   with Ghost;

   --  Parse a ClientHello from raw handshake message bytes.
   --  Extracts: client_random, legacy_session_id, cipher suites offered,
   --  key share (client public key).
   --  Selects the best cipher suite we support.
   --
   --  Pre bounds Data'Length by Max_HS_Msg (the wire-message limit
   --  enforced by the record-layer reassembler). Without this bound
   --  the body-length conversion and bit-length multiplications inside
   --  could overflow N32.
   procedure Parse_Client_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
	      OK   :    out Boolean)
							      with Pre => Data'Length > 0
								                 and then Data'Last <= N32 (Max_HS_Msg) - 1
							                         and then Reasm_Building (HC)
							                         and then HC.Legacy_Session_ID_Len in 0 .. 32,
                    Post => (if HC.Cfg.Local'Old /= null
                              then HC.Cfg.Local /= null
                                   and then
                                     (if HC.Cfg.Local'Old.Has_Identity
                                      then HC.Cfg.Local.Has_Identity))
                            and then
                              (if HC.Cfg.Random'Old /= null
                               then HC.Cfg.Random /= null)
	                            and then S.State = S.State'Old
	                            and then S.Role = S.Role'Old
	                            and then S.Input.Read_Pos =
	                              S.Input.Read_Pos'Old
	                            and then S.Input.Write_Pos =
	                              S.Input.Write_Pos'Old
			                            and then S.Server_App.Counter =
			                              S.Server_App.Counter'Old
			                            and then HC.Server_HS.Counter =
			                              HC.Server_HS.Counter'Old
				                            and then S.Server_App.Suite =
				                              S.Server_App.Suite'Old
											                            and then HC.HRR_Sent = HC.HRR_Sent'Old
				                            and then Reasm_Building (HC)
				                            and then
	                              (if OK and then HC.Version = TLS_1_3
	                               then S.Negotiated_Suite in
	                                 Suite_AES_128_GCM_SHA256
	                               | Suite_AES_256_GCM_SHA384
	                               | Suite_CHACHA20_POLY1305_SHA256)
			                            and then HC.Legacy_Session_ID_Len in 0 .. 32;

   --  Build a ServerHello handshake message.
   --  Includes key_share and supported_versions extensions.
   --  Returns the complete handshake message ready for record wrapping.
   procedure Build_Server_Hello
     (S      : in     Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
                and then HC.Cfg.Random /= null
		                and then HC.Legacy_Session_ID_Len in 0 .. 32
		                and then Reasm_Building (HC)
		                and then Reasm_Buffer_Shaped (HC)
		                and then S.Negotiated_Suite in Suite_AES_128_GCM_SHA256
	                                               | Suite_AES_256_GCM_SHA384
	                                               | Suite_CHACHA20_POLY1305_SHA256
                and then SPARKTLSCrypto.P384.Field.Initialized,
           Post => Len <= N32 (Result'Length)
                   and then (if Len > 0 then Len >= 4)
                   and then HC.Cfg.Random /= null
                   and then
                     (if Local_Config_Valid (HC.Cfg.Local'Old)
                      then Local_Config_Valid (HC.Cfg.Local))
	                   and then (if HC.Cfg.Local'Old /= null
	                             then HC.Cfg.Local /= null)
		                   and then (if HC.Cfg.Local'Old /= null
		                                 and then HC.Cfg.Local'Old.Has_Identity
		                             then HC.Cfg.Local /= null
		                                  and then HC.Cfg.Local.Has_Identity)
				                   and then Reasm_Building (HC)
                           and then Reasm_Buffer_Shaped (HC);

   function Has_ALPN_Match (HC : Handshake_Context) return Boolean;

   --  RFC 8446 Section 4.3.1: Build EncryptedExtensions.
   --  Sent immediately after ServerHello (encrypted with HS keys).
   --  May include ALPN extension if client offered and server matches.
   --
   --  Body writes S.Negotiated_ALPN on a successful match but never
   --  touches S.State; the frame post lets callers preserve their
   --  S.State knowledge through the call so the surrounding flight
   --  builder can keep proving its Set_State / Send_Alert_And_Error
   --  preconditions.
   procedure Build_Encrypted_Extensions
     (HC     : in     Handshake_Context;
      S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and then Result'Last in 271 .. N32'Last - 1,
   --  Header(4) + ext_list_len(2) + SNI ack(4)
   --  + ALPN ext(7 + Max_Hostname_Len=255) = 272
        Post => S.State = S.State'Old
                and then S.Role = S.Role'Old
                and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                and then (if S.Role'Old = Role_Server
                          and then S.State'Old not in
                            Idle | Closing | Closed | Error_State
                          then S.Role = Role_Server
                               and then S.State not in
                                 Idle | Closing | Closed | Error_State)
                and then Len in 6 .. N32 (Result'Length);

   --  Build a CertificateRequest handshake message (server -> client).
   --  Minimal: empty certificate_request_context, signature_algorithms
   --  extension listing Ed25519, ECDSA-P256-SHA256, ECDSA-P384-SHA384.
   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0
               and Result'Last in 31 .. 16#FFFF#,
        Post => Len <= N32 (Result'Length);

end SPARKTLS.Handshake.Server_Msgs;
