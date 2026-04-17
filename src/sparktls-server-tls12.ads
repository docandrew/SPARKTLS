with SPARKNaCl; use SPARKNaCl;

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
   SPARK_Mode => Off  --  uses HC_Ptr access type
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
                and HC.Cfg.Local /= null
                and HC.Cfg.Local.Has_Identity
                and HC.Cfg.Random /= null;

   --  Process the client's KeyExchange message.
   --  Extracts the client's ECDHE public key, computes shared secret,
   --  derives master secret and expands into per-connection keys.
   procedure Process_Client_Key_Exchange_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   --  Process ChangeCipherSpec from client.
   --  Activates the client's write keys for decrypting subsequent records.
   --  RFC 5246 §7.1: CCS is a single byte (0x01) in its own record.
   procedure Process_Client_CCS_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   --  Process the client's encrypted Finished message.
   --  Verifies the 12-byte verify_data against expected value.
   --  On success: sends server CCS + server Finished, transitions to Connected.
   procedure Process_Client_Finished_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action);

   --  Derive TLS 1.2 key material from the pre-master secret.
   --  Computes master_secret, then expands into:
   --    client_write_key, server_write_key (16 or 32 bytes)
   --    client_write_IV, server_write_IV (4 bytes each, GCM implicit nonce)
   --  Sets up Traffic_Keys for both directions.
   procedure Derive_Keys_12
     (S  : in out Session;
      HC : in out Handshake_Context);

end SPARKTLS.Server.TLS12;
