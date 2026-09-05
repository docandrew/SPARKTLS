with SPARKNaCl;  use SPARKNaCl;

--  Server-side handshake negotiation shared by TLS 1.2 and TLS 1.3.
--  Version-specific message builders live in Handshake.TLS12 and
--  Handshake.TLS13.

package SPARKTLS.Handshake.Server_Msgs
  with SPARK_Mode => On
is
   --  Needed because Session is now a private type: contracts that used to
   --  say S.State'Old now say State (S)'Old, and Ada only permits 'Old on a
   --  function call in a potentially-unevaluated context (inside an "if" in
   --  a postcondition) when this pragma is present. The accessors are
   --  precondition-free expression functions over one component each, so
   --  evaluating them unconditionally is harmless. Same pragma RecordFlux
   --  emits in its own generated specs.
   pragma Unevaluated_Use_Of_Old (Allow);
   --  Defined as membership in the predicated subtype rather than by
   --  restating its conjuncts. Config.Local now has subtype
   --  Valid_Identity_Access, so Local_Config_Valid (HC.Cfg.Local) unfolds to
   --  a membership test that holds by construction. Written as a second
   --  literal conjunction it did not: the prover had to match two
   --  independent copies of the same predicate and could not.
   function Local_Config_Valid (Local : Identity_Access) return Boolean
   is (Local in Valid_Identity_Access)
   with Ghost;

   --  Parse a ClientHello from raw handshake message bytes.
   --  Extracts: client_random, legacy_session_id, cipher suites offered,
   --  key share (client public key).
   --  Selects the best cipher suite we support.
   --
   --  Pre bounds Data'Length by Max_HS_Msg (the wire-message limit
   --  enforced by the record-layer reassembler). Without this bound
   --  the body-length conversion and bit-length multiplications inside
   --  could overflow N32.
   procedure Parse_Client_Hello
     (Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context;
      Data          : in Byte_Seq;
      Version       : out TLS_Version;
      OK            : out Boolean)
   with
     Pre => Data'Length > 0 and then Data'Last <= N32 (Max_HS_Msg) - 1,
     --  No identity clause here: the callers (server.adb after SNI selection,
     --  server-tls13 after HRR) re-validate S.HC.Cfg.Local at runtime before
     --  building anything, so nothing consumed it; and this unit never writes
     --  HC.Cfg, the fact was merely lost across four call boundaries.
     Post => (if OK then Version in TLS_1_2 | TLS_1_3);

   function Has_ALPN_Match (HC : Handshake_Context) return Boolean;

   --  Exported for the TLS 1.2 ServerHello builder (was a byte-identical
   --  _12 clone in Handshake.TLS12; deleted 2026-08-27).
   function Select_ALPN (HC : Handshake_Context) return Hostname_Buf;

end SPARKTLS.Handshake.Server_Msgs;
