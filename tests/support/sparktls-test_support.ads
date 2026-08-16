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
   --  PSK offer. Collapses the "S.HC_Ptr /= null and then S.HC_Ptr.PSK_Offered"
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
   function Client_Seq_12 (S : Session) return Unsigned_64;
   function Server_Seq_12 (S : Session) return Unsigned_64;

end SPARKTLS.Test_Support;
