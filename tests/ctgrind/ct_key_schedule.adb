--  Constant-time check for the TLS 1.3 key schedule.
--
--  Exercises the chain that turns ECDHE shared secret + (optional)
--  PSK into the actual traffic keys: Early Secret → Handshake
--  Secret → traffic secrets → traffic Key/IV. Each step is HKDF-
--  Expand-Label, which boils down to HMAC-SHA-256 chains. Marking
--  the shared secret as undefined and running the chain catches any
--  branch on key-derived state.
--
--  This path runs on every TLS handshake — a CT bug here would let
--  a network attacker observe handshake timings to leak ECDHE
--  shared secret bits.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.HKDF;
with SPARKTLS.Key_Schedule;
with Ctgrind;

procedure Ct_Key_Schedule is
   --  Public hash of the handshake transcript.
   Hello_Hash : SPARKTLSCrypto.Hashing.SHA256.Digest :=
     (others => 16#A5#);

   --  ECDHE shared secret (32 bytes for X25519 / P-256).
   Shared : Byte_Seq (0 .. 31) := (others => 16#42#);

   --  PSK input keying material (also secret in the resumption
   --  path; for first-time handshakes it's 0s).
   IKM    : Byte_Seq (0 .. 31) := (others => 16#00#);

   Early    : SPARKTLSCrypto.Hashing.SHA256.Digest;
   HS       : SPARKTLSCrypto.Hashing.SHA256.Digest;
   Client_S : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 31);
   Server_S : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 31);
   Key      : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 31);
   IV       : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 11);
begin
   Ctgrind.Make_Undefined
     (Shared'Address, Interfaces.C.size_t (Shared'Length));
   Ctgrind.Make_Undefined
     (IKM'Address, Interfaces.C.size_t (IKM'Length));

   SPARKTLS.Key_Schedule.Derive_Early_Secret (Early, IKM);
   --  Early itself is now secret-derived; let memcheck propagate.
   SPARKTLS.Key_Schedule.Derive_Handshake_Secret (HS, Shared, Early);
   SPARKTLS.Key_Schedule.Derive_HS_Traffic_Secrets
     (Client_S, Server_S, HS, Hello_Hash);
   SPARKTLS.Key_Schedule.Derive_Traffic_Key_IV
     (Key, IV, Byte_Seq (Client_S));

   --  Output keys are still secret-tainted — re-mark as defined to
   --  read them safely (they will go to the AEAD, which has its own
   --  CT harness).
   Ctgrind.Make_Defined
     (Key'Address, Interfaces.C.size_t (Key'Length));
   Ctgrind.Make_Defined
     (IV'Address, Interfaces.C.size_t (IV'Length));
   Ctgrind.Use_Output (Key'Address, Interfaces.C.size_t (Key'Length));
   Ctgrind.Use_Output (IV'Address, Interfaces.C.size_t (IV'Length));

   Put_Line ("ct_key_schedule: TLS 1.3 SHA-256 key derivation chain"
             & " completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Key_Schedule;
