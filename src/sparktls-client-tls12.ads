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
      HC     : in out Engaged_Context;
      Result :    out Action);

   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   procedure Process_Connected_12
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State in Connected | Closing
               and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
                       and then Empty_Records_Bounded_RFC_8446_5_2 (S);

end SPARKTLS.Client.TLS12;
