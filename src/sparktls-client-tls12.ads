with SPARKNaCl; use SPARKNaCl;

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
package SPARKTLS.Client.TLS12 with
   SPARK_Mode => Off  --  uses HC_Ptr access type
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
      Result :    out Action);

   --  Process records in Connected state for TLS 1.2.
   --  Decrypts incoming records using TLS 1.2 GCM (explicit nonce).
   procedure Process_Connected_12
     (S      : in out Session;
      Result :    out Action);

end SPARKTLS.Client.TLS12;
