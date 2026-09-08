--  Test-only white-box access to SPARKTLS.Session internals.
--
--  Session is a private type: consumers reach its state through the query
--  functions in SPARKTLS and cannot read or assign components. That is the
--  point -- it stops the handshake state machine being corrupted from
--  outside the library.
--
--  A few unit tests legitimately need to go behind that curtain: they inject
--  known key material to check a KDF against RFC vectors, or reset a session
--  between scenarios. Being a child of SPARKTLS, this package's body has
--  visibility of the parent's private part, so it can offer those operations
--  without SPARKTLS itself exposing setters to real callers.
--
--  IMPORTANT: this unit lives under tests/, NOT src/. It is deliberately
--  absent from the library's Source_Dirs, so it is never compiled into or
--  shipped with libsparktls -- only the test projects add tests/support to
--  their source path. Do not move it into src/, and do not add it to
--  sparktls.gpr: that would hand consumers a supported way to scribble on
--  session state.
--
--  SPARK_Mode is Off: these operations exist to violate the invariants the
--  rest of the library maintains, so there is nothing here worth proving.

package SPARKTLS.Test_Support with
   SPARK_Mode => Off
is

   --  Return a session to its default-initialised state. Replaces the
   --  "S := (others => <>)" aggregate assignment tests used before Session
   --  became private.
   procedure Reset (S : out Session);

   --  Force handshake outcomes without running a handshake, so a test can
   --  drive code paths that are only reachable from a completed session.
   procedure Set_Negotiated_Version (S : in out Session; V : TLS_Version);
   procedure Set_State (S : in out Session; V : Connection_State);
   procedure Set_Negotiated_Suite (S : in out Session; V : Unsigned_16);
   procedure Set_Negotiated_Suite_12 (S : in out Session; V : Unsigned_16);

   --  Install known exporter inputs (RFC 8446 s7.5 / RFC 5705 vectors).
   procedure Set_Exporter_State
     (S             : in out Session;
      Secret        : Bytes_48;
      Len           : N32;
      Client_Random : Bytes_32;
      Server_Random : Bytes_32);

   function Exporter_Secret        (S : Session) return Bytes_48;
   function Exporter_Secret_Len    (S : Session) return N32;
   function Exporter_Client_Random (S : Session) return Bytes_32;
   function Exporter_Server_Random (S : Session) return Bytes_32;

   --  True iff a handshake context is still attached and it recorded a
   --  PSK offer. Collapses the "S.HC_Ptr /= null and then S.HC_Ptr.PSK.Offered"
   --  test-side dereference.
   function PSK_Offered (S : Session) return Boolean;

   --  True iff a handshake context is still attached. Kept separate from
   --  PSK_Offered so a test can assert "context present AND no PSK offered",
   --  which "not PSK_Offered" alone would not express -- that is also true
   --  when the context has already been freed.
   function Has_Handshake_Context (S : Session) return Boolean;

   --  TLS 1.2 record sequence counters. SPARKTLS exposes these as Ghost
   --  functions so contracts can name them; ghost entities cannot be called
   --  from ordinary code, which the BoGo shim needs for its debug output.

   --  TLS 1.3 application traffic counters. A KeyUpdate resets the
   --  rotated direction to zero, so these make rekeying observable from
   --  a test without exposing key material.
   function Client_App_Counter (S : Session) return Unsigned_64;
   function Server_App_Counter (S : Session) return Unsigned_64;
   function Key_Update_Pending (S : Session) return Boolean;
   function Key_Updates_Recvd (S : Session) return Natural;

   --  Test-only: force a traffic counter. The RFC 8446 §5.5 rekey
   --  threshold is ~8.4 million records, so the proactive-rotation path is
   --  otherwise unreachable in a test. Setting the counter directly lets a
   --  test park it just below the threshold and observe the rotation.
   procedure Set_Client_App_Counter (S : in out Session; V : Unsigned_64);
   procedure Set_Server_App_Counter (S : in out Session; V : Unsigned_64);

   --  RFC 7627: did this TLS 1.2 session negotiate Extended Master
   --  Secret? Session mirrors HC.Use_EMS before the handshake context is
   --  freed, so this stays readable post-handshake.
   --
   --  Exposed here rather than in SPARKTLS because consumers have no need
   --  for it: BoGo's -expect-extended-master-secret asks the shim to
   --  confirm the library's own view agrees with what went on the wire.
   --  Correctness of the derivation is already established by the
   --  handshake completing at all -- a mismatched PRF label would produce
   --  a different master_secret and fail Finished verification.
   --
   --  Reports TRUE for any TLS 1.3 session. TLS 1.3 has no EMS
   --  extension, but its key schedule binds the full handshake
   --  transcript, so the property EMS exists to provide holds
   --  inherently. BoringSSL reports the same via
   --  SSL_get_extms_support, and ems_tests.go passes
   --  -expect-extended-master-secret on EVERY TLS 1.3 case, including
   --  the NoExtendedMasterSecret- ones ("In TLS 1.3, the extension is
   --  irrelevant and always reports as enabled").
   function Extended_Master_Secret_Used (S : Session) return Boolean;

end SPARKTLS.Test_Support;
