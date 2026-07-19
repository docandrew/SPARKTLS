with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Records.TLS12;
with X509;

--  TLS 1.2 Server State Machine (RFC 5246)
--
--  Server handshake flow (ECDHE, server-authenticated):
--
--    Wait_Client_Hello_12
--      → Parse ClientHello (no supported_versions with 0x0304)
--      → Build ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
--      → Server_Hello_Done_Sent_12
--
--    Server_Hello_Done_Sent_12
--      → Drain output, then Wait_Client_KE_12
--
--    Wait_Client_KE_12
--      → Parse ClientKeyExchange (client's ECDHE pubkey)
--      → Compute shared secret, derive master secret, expand keys
--      → Wait_Client_CCS_12
--
--    Wait_Client_CCS_12
--      → Receive ChangeCipherSpec record
--      → Activate client's write keys (decrypt subsequent records)
--      → Wait_Client_Finished_12
--
--    Wait_Client_Finished_12
--      → Receive encrypted Finished, verify verify_data
--      → Send server ChangeCipherSpec + server Finished
--      → Connected
--
--  Key differences from TLS 1.3:
--    - CCS triggers key activation (not implicit after ServerHello)
--    - ServerKeyExchange carries the ECDHE pubkey (not key_share extension)
--    - Separate ClientKeyExchange message (not in ClientHello)
--    - Finished is 12 bytes (not 32/48)
--    - No EncryptedExtensions message
--    - No CertificateVerify from server for ECDHE (signature is in SKE)
package SPARKTLS.Server.TLS12 with
   SPARK_Mode => On
is
   --  Build the TLS 1.2 server flight:
   --  ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
   --
   --  All sent as plaintext records (no encryption yet).
   --  After this, state transitions to Server_Hello_Done_Sent_12.
   procedure Build_Server_Flight_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre  => HC.Version = TLS_1_2
	                and then HC.Cfg.Local /= null
	                and then HC.Cfg.Local.Has_Identity
	                and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                           (HC.Cfg.Local)
	                and then HC.Cfg.Random /= null
                --  Server-side state on entry. Client_Hello_Sent (the
                --  client's own post-CH state) is intentionally NOT
                --  permitted here -- the only valid transition out of
                --  Client_Hello_Sent is Wait_Server_Hello, which would
                --  conflict with the final Set_State (Server_Hello_Sent).
                and then S.State = Wait_Client_Hello
	                and then S.Role = Role_Server
	                and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
	                           (HC.Server_Seq_12)
	                and then Reasm_Building (HC)
	                and then SPARKTLSCrypto.P384.Field.Initialized
	                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => S.State in Server_Hello_Sent | Wait_Client_Finished
                            | Error_State
                and then
                  (if S.State in Server_Hello_Sent | Wait_Client_Finished
                   then S.Role = Role_Server
                        and then HC.Version = TLS_1_2
                        and then HC.Cfg.Local /= null
	                        and then HC.Cfg.Local.Has_Identity
	                        and then
	                          SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                            (HC.Cfg.Local)
	                        and then HC.Cfg.Random /= null
	                        and then Reasm_Building (HC));

   --  Process the client's KeyExchange message.
   --  Extracts the client's ECDHE public key, computes shared secret,
   --  derives master secret and expands into per-connection keys.
   --
   --  Called from server.adb's Wait_Client_Finished dispatch when
   --  the TLS 1.2 ClientKeyExchange / ChangeCipherSpec haven't yet
   --  arrived.
   procedure Process_Client_Key_Exchange_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State in Wait_Client_Cert_Verify
                                 | Wait_Client_Finished
	               and then HC.Cfg.Local /= null
	               and then HC.Cfg.Local.Has_Identity
	               and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                          (HC.Cfg.Local)
	               and then HC.Cfg.Random /= null
	               and then Reasm_Building (HC)
	               and then SPARKTLS.Handshake.TLS12.Valid_ECDHE_Group
	                 (HC.Selected_Group)
               and then SPARKTLSCrypto.P384.Field.Initialized
               and then SPARKTLSCrypto.P384.ECDSA.Initialized
               --  Required by Derive_Keys_12 called at the end:
               and then HC.Transcript_Len <= Transcript_Capacity
               and then S.Negotiated_Suite in
                          Suite_ECDHE_RSA_AES128_GCM_SHA256
                        | Suite_ECDHE_RSA_AES256_GCM_SHA384
                        | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                        | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                        | Suite_ECDHE_RSA_CHACHA20_SHA256
                        | Suite_ECDHE_ECDSA_CHACHA20_SHA256,
	        Post => S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
	                           | Connected | Closing | Error_State
		               and then HC.Cfg.Local /= null
			        and then HC.Cfg.Local.Has_Identity
			        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
			                   (HC.Cfg.Local)
			        and then HC.Cfg.Random /= null;
   --  RFC 5246 §7.4.7 single-CKE invariant is enforced as a
   --  pragma Assert at the end of the body (in the .adb), since
   --  the body's preexisting medium-severity unproven calls block
   --  level-1 discharge of a procedure-level Post here. The Assert
   --  pins the property at the success exit; the runtime guard at
   --  the top of the body enforces it on the wire.

   --  Process the optional TLS 1.2 client Certificate message after the
   --  server has sent CertificateRequest. A non-empty, parseable leaf moves
   --  the handshake to Wait_Client_Cert_Verify so the client proves private
   --  key possession before Finished.
   procedure Process_Client_Certificate_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Certificate
               and then Reasm_Building (HC)
               and then HC.Cfg.Local /= null
               and then HC.Cfg.Local.Has_Identity
               and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                          (HC.Cfg.Local)
               and then HC.Cfg.Random /= null,
        Post => S.State in Wait_Client_Certificate
                          | Wait_Client_Cert_Verify
                          | Wait_Client_Finished
                          | Error_State
                and then
                  (if S.State /= Error_State
                   then Reasm_Building (HC)
                        and then HC.Cfg.Local /= null
                        and then HC.Cfg.Local.Has_Identity
                        and then
                          SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                            (HC.Cfg.Local)
                        and then HC.Cfg.Random /= null)
                and then
                  (if S.State = Wait_Client_Cert_Verify
                   then HC.Peer_Cert_Valid
                        and then HC.Peer_Cert_DER_Len
                                  in 1 .. Max_Cert_DER_Len
                        and then X509.Spans_Valid
                          (HC.Peer_Cert,
                           X509.N32 (HC.Peer_Cert_DER_Len) - 1));

   --  Process TLS 1.2 CertificateVerify from a client-authenticated peer.
   procedure Process_Client_CertVerify_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Cert_Verify
               and then Reasm_Building (HC)
               and then HC.Transcript_Len in 1 .. Transcript_Capacity
               and then HC.Peer_Cert_Valid
               and then HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
               and then X509.Spans_Valid
                 (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1)
               and then SPARKTLSCrypto.P384.Field.Initialized
               and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => S.State in Wait_Client_Cert_Verify | Wait_Client_Finished
                          | Error_State
                and then
                  (if S.State /= Error_State then Reasm_Building (HC));

   --  Legacy CCS entry point. The active TLS 1.2 server path validates
   --  the client's ChangeCipherSpec inline while processing the
   --  ClientKeyExchange/Finished sequence. Reaching this hook means
   --  dispatch has already gone off the expected path.
   procedure Process_Client_CCS_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Finished;

   --  Process the client's encrypted Finished message.
   --  Verifies the 12-byte verify_data against expected value.
   --  On success: sends server CCS + server Finished, transitions to Connected.
   --
   --  RFC 5246 §7.1: ChangeCipherSpec MUST precede Finished. The
   --  CCS_Precedes_Finished_RFC_5246_7_1 Pre captures this — both
   --  CKE and CCS MUST already be received before we attempt to
   --  decrypt and verify the Finished record.
   procedure Process_Client_Finished_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Finished
	        and then HC.Cfg.Local /= null
	        and then HC.Cfg.Local.Has_Identity
	        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                   (HC.Cfg.Local)
	        and then HC.Cfg.Random /= null
               and then Reasm_Building (HC)
               and then CCS_Precedes_Finished_RFC_5246_7_1 (HC)
               --  Required by Send_Encrypted_Alert_12 in error paths
               --  (RFC 5246 §7.2.1 post-CCS encrypted alerts).
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                          (HC.Client_Seq_12)
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                          (HC.Server_Seq_12)
               and then Free_Space (S.Output) >= 7,
	        Post => S.State in Wait_Client_Finished | Connected | Closing
	                           | Error_State
		        and then HC.Cfg.Local /= null
		        and then HC.Cfg.Local.Has_Identity
		        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
		                   (HC.Cfg.Local)
		        and then HC.Cfg.Random /= null;

   --  Derive TLS 1.2 key material from the pre-master secret.
   --  Computes master_secret, then expands into:
   --    client_write_key, server_write_key (16 or 32 bytes)
   --    client_write_IV, server_write_IV (4 bytes each, GCM implicit nonce)
   --  Sets up Traffic_Keys for both directions.
   procedure Derive_Keys_12
     (S  : in out Session;
      HC : in out Handshake_Context)
      with Pre =>
        HC.Version = TLS_1_2
        and then HC.Cfg.Local /= null
        and then HC.Cfg.Local.Has_Identity
        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                   (HC.Cfg.Local)
        and then HC.Cfg.Random /= null
        and then Reasm_Building (HC)
        --  Transcript bound: hashing slices Transcript (0 .. Len - 1)
        and then HC.Transcript_Len > 0
        and then HC.Transcript_Len <= Transcript_Capacity
        and then
          (if HC.TLS12_EMS_Transcript_Len > 0
           then HC.TLS12_EMS_Transcript_Len <= Transcript_Capacity)
     --  Negotiated_Suite must be one of the six TLS 1.2 ECDHE suites
     --  we recognize, so the local mapping matches Internal_Suite_For.
     and then S.Negotiated_Suite in
                Suite_ECDHE_RSA_AES128_GCM_SHA256
              | Suite_ECDHE_RSA_AES256_GCM_SHA384
              | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
              | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
              | Suite_ECDHE_RSA_CHACHA20_SHA256
              | Suite_ECDHE_ECDSA_CHACHA20_SHA256,
        --  RFC 7627 §4: master_secret PRF binding. After Derive_Keys_12
        --  returns, HC.MS_Derivation matches HC.Use_EMS via the
        --  EMS_PRF_Binding_RFC_7627_4 predicate. This is the v9→v12
        --  invariant whose absence caused the TLS-Anvil regression.
	           Post => HC.Version = TLS_1_2
	                   and then HC.Cfg.Local /= null
	                   and then HC.Cfg.Local.Has_Identity
	                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
	                              (HC.Cfg.Local)
	                   and then HC.Cfg.Random /= null
                   and then Reasm_Building (HC)
                   and then S.State = S.State'Old
                   and then S.Role = S.Role'Old
                   and then S.Negotiated_Suite = S.Negotiated_Suite'Old
                   and then HC.Client_Seq_12 = 0
                   and then HC.Server_Seq_12 = 0
                   and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                              (HC.Client_Seq_12)
                   and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                              (HC.Server_Seq_12)
                   and then EMS_PRF_Binding_RFC_7627_4 (HC)
                   and then HC.MS_Derivation /= Not_Derived;

   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   --  Dispatches on inner content type (0x17=app data, 0x15=alert).
   procedure Process_Connected_12
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State = Connected
               and then Empty_Records_Bounded_RFC_8446_5_2 (S)
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                 (S.Client_Seq_12)
               and then SPARKTLS.Records.TLS12.Nonce_Space_Available_12
                 (S.Server_Seq_12);

end SPARKTLS.Server.TLS12;
