with SPARKTLS.HS_Pool;
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
--      â Parse ClientHello (no supported_versions with 0x0304)
--      â Build ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
--      â Server_Hello_Done_Sent_12
--
--    Server_Hello_Done_Sent_12
--      â Drain output, then Wait_Client_KE_12
--
--    Wait_Client_KE_12
--      â Parse ClientKeyExchange (client's ECDHE pubkey)
--      â Compute shared secret, derive master secret, expand keys
--      â Wait_Client_CCS_12
--
--    Wait_Client_CCS_12
--      â Receive ChangeCipherSpec record
--      â Activate client's write keys (decrypt subsequent records)
--      â Wait_Client_Finished_12
--
--    Wait_Client_Finished_12
--      â Receive encrypted Finished, verify verify_data
--      â Send server ChangeCipherSpec + server Finished
--      â Connected
--
--  Key differences from TLS 1.3:
--    - CCS triggers key activation (not implicit after ServerHello)
--    - ServerKeyExchange carries the ECDHE pubkey (not key_share extension)
--    - Separate ClientKeyExchange message (not in ClientHello)
--    - Finished is 12 bytes (not 32/48)
--    - No EncryptedExtensions message
--    - No CertificateVerify from server for ECDHE (signature is in SKE)
--  Private child: this unit is internal to SPARKTLS and is deliberately
--  not part of the public API. Being a private child also lets its
--  contracts name Session components directly (a private child's visible
--  part sees the parent's private part), which a public child's visible
--  part may not do once Session becomes a private type.

private package SPARKTLS.Server.TLS12
  with SPARK_Mode => On
is
   --  Step the TLS 1.2 handshake after ClientHello negotiation.
   procedure Advance_Handshake_12
     (S      : in out Server_Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Result : out Action)
   with Pre => S.Version = TLS_1_2;

   --  Build the TLS 1.2 server flight:
   --  ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
   --
   --  All sent as plaintext records (no encryption yet).
   --  After this, state transitions to Server_Hello_Sent while the
   --  output flight is drained.
   procedure Build_Server_Flight_12
     (S : in out Server_Session; Cfg : in Ready_Config; Result : out Action)
   with
     Pre =>
       S.Version
       = TLS_1_2
         --  Server-side state on entry. Client_Hello_Sent (the
         --  client's own post-CH state) is intentionally NOT
         --  permitted here -- the only valid transition out of
         --  Client_Hello_Sent is Wait_Server_Hello, which would
         --  conflict with the final Set_State (Server_Hello_Sent).
       and then S.State = Wait_Client_Hello
       and then S.Role = Role_Server;


   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   --  Dispatches on inner content type (0x17=app data, 0x15=alert).
   procedure Process_Connected_12 (S : in out Session; Result : out Action)
   with Pre => S.State in Connected | Closing and then Empty_Records_Bounded_RFC_8446_5_2 (S);

end SPARKTLS.Server.TLS12;
