with SPARKNaCl; use SPARKNaCl;
with SPARKTLS.Handshake.TLS12; use SPARKTLS.Handshake.TLS12;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;

--  TLS 1.2 Client State Machine (RFC 5246)
--
--  Owns the entire TLS 1.2 handshake after ServerHello is parsed.
--  Called from Client.Advance when HC.Version = TLS_1_2.
--
--  Internal state tracking uses HC fields:
--    HC.CKE_Received_12  — client flight (CKE+CCS+Finished) sent
--    HC.CCS_Received     — server CCS received
--
--  Handshake flow:
--    1. Parse server flight: Certificate, ServerKeyExchange, ServerHelloDone
--    2. Compute ECDHE shared secret + derive keys
--    3. Send client flight: ClientKeyExchange, CCS, Finished
--    4. Receive server CCS
--    5. Decrypt + verify server Finished
--    6. Transition to Connected
--  Private child: this unit is internal to SPARKTLS and is deliberately
--  not part of the public API. Being a private child also lets its
--  contracts name Session components directly (a private child's visible
--  part sees the parent's private part), which a public child's visible
--  part may not do once Session becomes a private type.
private package SPARKTLS.Client.TLS12 with
   SPARK_Mode => On
is
   --  Step the TLS 1.2 handshake state machine.
   --  Called repeatedly from Client.Advance until Connected or Error.
   --
   --  Internally tracks progress via HC flags:
   --    !CKE_Received_12           → processing server flight
   --    CKE_Received_12, !CCS_Received → waiting for server CCS
   --    CKE_Received_12, CCS_Received  → waiting for server Finished
   procedure Advance_Handshake_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => (S.State not in Idle | Closing | Closed | Error_State)
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
               and then Reasm_Buffer_Shaped (HC)
		               and then
		                 (if not HC.CKE_Received_12 then
		                    Reasm_Building (HC)
	                    and then
	                      (if HC.Reasm_Buf /= null
	                           and then HC.Reasm_Need > 0
	                       then HC.Reasm_Buf'First = 0
	                            and then HC.Reasm_Buf'Length <= Max_HS_Msg
	                            and then HC.Reasm_Need <=
	                              N32 (HC.Reasm_Buf'Length)
	                            and then HC.Reasm_Len <=
	                              N32 (HC.Reasm_Buf'Length)
	                            and then
	                              (if HC.Reasm_Hdr_Pending
	                               then HC.Reasm_Need = 4
	                                    and then HC.Reasm_Len <= 4
	                                    and then HC.Reasm_Buf'Length =
	                                      Max_HS_Msg))
	                    and then HC.Cfg.Random /= null
                    and then HC.Selected_Group in
                      Group_X25519 | Group_Secp256r1 | Group_Secp384r1
	                    and then Valid_ECDHE_Group (HC.Selected_Group)
	                    and then HC.Transcript_Len > 0
	                    and then HC.Transcript_Len <= Transcript_Capacity
	                    and then S.Negotiated_Suite in
	                      Suite_ECDHE_RSA_AES128_GCM_SHA256
	                    | Suite_ECDHE_RSA_AES256_GCM_SHA384
		                    | Suite_ECDHE_RSA_CHACHA20_SHA256
		                    | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
		                    | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
		                    | Suite_ECDHE_ECDSA_CHACHA20_SHA256
		                    and then SPARKTLSCrypto.P384.Field.Initialized
		                    and then SPARKTLSCrypto.P384.ECDSA.Initialized
		                    and then
		                      SPARKTLS.Records.TLS12.Nonce_Space_Available_12
		                        (HC.Client_Seq_12)
		                    and then
		                      (if HC.Cfg.Local /= null
		                           and then HC.Cfg.Local.Has_Identity
		                       then SPARKTLS.Handshake.Server_Msgs
			                              .Local_Config_Valid (HC.Cfg.Local)))
	               and then
	                 (if HC.CKE_Received_12
	                  then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                         (HC.Client_Seq_12))
		               and then
		                 (if HC.CKE_Received_12 and then not HC.CCS_Received then
	                    HC.Cfg.Random /= null
                    and then HC.Selected_Group in
                      Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                    and then Valid_ECDHE_Group (HC.Selected_Group)
                    and then HC.Transcript_Len > 0
                    and then HC.Transcript_Len <= Transcript_Capacity
                    and then S.Negotiated_Suite in
                      Suite_ECDHE_RSA_AES128_GCM_SHA256
                    | Suite_ECDHE_RSA_AES256_GCM_SHA384
                    | Suite_ECDHE_RSA_CHACHA20_SHA256
                    | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                    | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
	                    | Suite_ECDHE_ECDSA_CHACHA20_SHA256
	                    and then SPARKTLSCrypto.P384.Field.Initialized
	                    and then SPARKTLSCrypto.P384.ECDSA.Initialized
                        and then
                          (if HC.Reasm_Buf /= null
                               and then HC.Reasm_Need > 0
                           then Reasm_Buffer_Shaped (HC))
                        and then
                          (if HC.Cfg.Local /= null
                               and then HC.Cfg.Local.Has_Identity
                           then SPARKTLS.Handshake.Server_Msgs
                                  .Local_Config_Valid (HC.Cfg.Local)))
	               and then (if HC.CKE_Received_12 and then HC.CCS_Received
	                         then Reasm_Building (HC)
	                              and then
	                                (HC.Reasm_Buf = null
	                                 or else
	                                   (HC.Reasm_Buf'First = 0
	                                    and then HC.Reasm_Buf'Length <=
	                                      Max_HS_Msg
		                                    and then HC.Reasm_Len <=
		                                      N32 (HC.Reasm_Buf'Length)
		                                    and then HC.Reasm_Need <=
		                                      N32 (HC.Reasm_Buf'Length)
		                                    and then HC.Reasm_Need >= 4
		                                    and then
		                                      (if HC.Reasm_Hdr_Pending
	                                       then HC.Reasm_Need = 4
	                                            and then HC.Reasm_Len <= 4
	                                            and then HC.Reasm_Buf'Length =
	                                              Max_HS_Msg)))
	                              and then S.State in Wait_Server_Finished
                                                  | Client_Finished_Sent
                              and then HC.Transcript_Len > 0
                              and then SPARKTLS.Records.TLS12
                                .Nonce_Space_Available_12
                                  (HC.Client_Seq_12)
                              and then SPARKTLS.Records.TLS12
                                .Nonce_Space_Available_12
                                  (HC.Server_Seq_12));

   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   procedure Process_Connected_12
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State in Connected | Closing
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
	               and then Empty_Records_Bounded_RFC_8446_5_2 (S)
	               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                 (S.Client_Seq_12)
	               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                 (S.Server_Seq_12);

end SPARKTLS.Client.TLS12;
