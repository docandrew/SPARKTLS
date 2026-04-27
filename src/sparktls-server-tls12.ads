with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;

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
                and then HC.Cfg.Random /= null
                and then S.State in Wait_Client_Hello | Client_Hello_Sent
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized;

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
               and then S.State = Wait_Client_Finished
               and then HC.Cfg.Local /= null
               and then HC.Cfg.Local.Has_Identity
               and then SPARKTLSCrypto.P384.Field.Initialized
               and then SPARKTLSCrypto.P384.ECDSA.Initialized;

   --  Process ChangeCipherSpec from client.
   --  Activates the client's write keys for decrypting subsequent records.
   --  RFC 5246 §7.1: CCS is a single byte (0x01) in its own record.
   procedure Process_Client_CCS_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Finished;

   --  Process the client's encrypted Finished message.
   --  Verifies the 12-byte verify_data against expected value.
   --  On success: sends server CCS + server Finished, transitions to Connected.
   procedure Process_Client_Finished_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre => HC.Version = TLS_1_2
               and then S.State = Wait_Client_Finished;

   --  Derive TLS 1.2 key material from the pre-master secret.
   --  Computes master_secret, then expands into:
   --    client_write_key, server_write_key (16 or 32 bytes)
   --    client_write_IV, server_write_IV (4 bytes each, GCM implicit nonce)
   --  Sets up Traffic_Keys for both directions.
   procedure Derive_Keys_12
     (S  : in out Session;
      HC : in out Handshake_Context)
   with Pre => HC.Version = TLS_1_2;

   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   --  Dispatches on inner content type (0x17=app data, 0x15=alert).
   procedure Process_Connected_12
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State = Connected;

end SPARKTLS.Server.TLS12;
