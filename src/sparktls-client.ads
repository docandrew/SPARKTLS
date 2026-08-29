with SPARKTLS.Records.TLS12;

package SPARKTLS.Client
  with SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  Client-side TLS 1.3 session management
   --
   --  Usage (blocking):
   --
   --    S   : SPARKTLS.Session;
   --    Cfg : SPARKTLS.Config := (Random => My_RNG'Access, ...);
   --    Res : SPARKTLS.Action;
   --    Buf : Byte_Seq (0 .. 16383);
   --    N   : N32;
   --
   --    SPARKTLS.Client.Init (S, Cfg);
   --
   --    loop
   --       SPARKTLS.Client.Advance (S, Res);
   --       case Res is
   --          when Has_Output =>
   --             SPARKTLS.Drain_Ciphertext (S, Buf, N);
   --             Socket_Write (Buf (0 .. N - 1));
   --          when Need_Input =>
   --             N := Socket_Read (Buf);
   --             SPARKTLS.Feed_Ciphertext (S, Buf (0 .. N - 1), N);
   --          when Handshake_Done =>
   --             exit;  -- ready for application data
   --          when Plaintext_Ready =>
   --             SPARKTLS.Read_Plaintext (S, Buf, N);
   --             -- process Buf (0 .. N - 1)
   --          when Error_Alert =>
   --             -- handle Last_Error (S)
   --             exit;
   --          when others =>
   --             null;
   --       end case;
   --    end loop;
   --
   --  Usage (async / event-driven):
   --
   --    On socket readable:
   --       N := Socket_Read (Buf);
   --       SPARKTLS.Feed_Ciphertext (S, Buf (0 .. N - 1), N);
   --       loop
   --          SPARKTLS.Client.Advance (S, Res);
   --          exit when Res = Need_Input;
   --          -- handle Has_Output, Plaintext_Ready, etc.
   --       end loop;
   --
   --    On socket writable (if Has_Output was returned):
   --       SPARKTLS.Drain_Ciphertext (S, Buf, N);
   --       Socket_Write (Buf (0 .. N - 1));
   ----------------------------------------------------------------------------

   --  Quick setup: configure and initialize a client session in one call.
   --  Sets Mode_WebPKI and Purpose_Server.
   --  After Configure, the caller should drain and send the ClientHello.
   procedure Configure
     (S                    : out Client_Session;
      Hostname             : String;
      Trust                : Trust_Store_Access;
      Random               : Random_Bytes_Fn;
      Clock                : Get_Time_Fn;
      Local                : Valid_Identity_Access := null;
      Mode                 : Validation_Mode := Mode_WebPKI;
      ALPN                 : String := "";
      Versions             : Version_Policy := Allow_Both;
      Resume               : Session_Ticket := (others => <>);
      Skip_Verify          : Boolean := False;
      Skip_Hostname_Verify : Boolean := False)
      --  Mirrors Init's postcondition: Configure is a thin wrapper that
      --  builds a Config and calls Init, so it can promise no more than Init
      --  does. Init fails closed to Error_State.
   with Pre => Random /= null and Clock /= null;
   --  Skip_Verify: skip full X.509 chain validation against Trust
   --  (development / self-signed certs). Without Skip_Verify, a trust
   --  store and clock must be configured before the handshake can
   --  start, except for valid TLS 1.3 ticket resumption. Hostname
   --  binding (Â§6.4) is NOT affected by this flag â set
   --  Skip_Hostname_Verify to opt out of hostname binding as well.
   --
   --  Skip_Hostname_Verify: skip RFC 6125 Â§6.4 SAN/CN matching even
   --  when Hostname is non-empty. The usual opt-out is to pass
   --  Hostname => ""; this flag is for callers that need SNI on the
   --  wire (Hostname-derived) but explicitly don't want the cert
   --  bound to it (rare; e.g. trust-on-first-use schemes).
   --  ALPN (RFC 7301): the protocol name to offer in the
   --  application_layer_protocol_negotiation extension. Empty
   --  string means no ALPN extension is sent. Single protocol
   --  only â for multi-protocol advertisement use Init with a
   --  manually-built Config.

   --  Initialize a client session with full control over Config.
   --  After Init, the caller should drain and send the ClientHello.
   procedure Init
     (S   : out Client_Session;
      Cfg : in Config)
   with Pre => Cfg.Random /= null;

   --  Step the client handshake / record processing state machine.
   --
   --  Processes available input, advances state, and may produce
   --  output. The returned Action tells the caller what to do:
   --
   --    Need_Input     => read from transport, Feed_Ciphertext, Advance
   --    Has_Output     => Drain_Ciphertext, send, Advance
   --    Plaintext_Ready => call Read_Plaintext
   --    Handshake_Done => connection is ready for app data
   --    Error_Alert    => check Last_Error (S)
   --  RFC 8446 Â§4.1: Step the client handshake / record processing
   --  state machine.
   procedure Advance (S : in out Session; Result : out Action)
   with Pre => State (S) /= Idle and Role (S) = Role_Client;

   --  RFC 8446 Â§6.1: Send a close_notify alert.
   procedure Close_Notify
     (S : in out Session)
      --  Deliberately callable on an already-closed session: Advance reports
      --  both a half-duplex close and a completed close with Shutdown, and the
      --  application cannot distinguish them. On a finished session this is a
      --  no-op (the body returns before touching the scrubbed keys).
   with
     Pre =>
       Role (S)
       = Role_Client
         --  EXECUTABLE nonce-space fact (the #2302 doctrine: a Pre
         --  the caller cannot check is unenforceable). Covers the
         --  arithmetic backstop on both versions and the 2**23 cap
         --  on TLS 1.2, version-gated inside -- the old ghost _12
         --  conjunct would wrongly reject a TLS 1.3 session sitting
         --  at the cap awaiting rotation, now that the counter is
         --  the shared channel counter.
       and not Write_Limit_Reached (S),
     Post =>
       (if State (S)'Old in Connected | Closing
        then State (S) = Closing)             --  RFC 8446 6.1
       and
       --  Plain "and"/"or", never the short-circuit forms. The right
       --  operand of "and then"/"or else" is potentially unevaluated,
       --  and Ada RM 6.1.1(27) bars a function call as the prefix of
       --  'Old in such a position. S'Old is not the escape hatch:
       --  Session is a deep type, so it introduces aliasing and SPARK
       --  RM 3.10(13) rejects it -- which aborted proof round 26.
                                                                   (State (S)'Old in
                                                                      Connected
                                                                      | Closing
                                                                    or State (S) = State (S)'Old);

   --  True if a peer certificate has been received and parsed.
   function Has_Peer_Certificate (S : Session) return Boolean;

   ----------------------------------------------------------------------------
   --  Session resumption (RFC 8446 Â§4.6.1 / Â§2.2)
   --
   --  Workflow:
   --    1. Connect normally. After Handshake_Done (or after any
   --       Advance call), check Has_Session_Ticket; if True,
   --       persist Get_Session_Ticket's return value.
   --    2. On the next connection, place the saved ticket in
   --       Cfg.Resume_Ticket BEFORE Init / Configure. Init copies
   --       it into the session before building CH, which then
   --       carries the pre_shared_key extension.
   --
   --  The Cfg-driven path is required because Init constructs and
   --  queues CH atomically â there is no post-Init injection point
   --  for the ticket.
   ----------------------------------------------------------------------------

   --  True iff a usable resumption PSK has been derived from a
   --  NewSessionTicket. Servers may send NSTs at any point after
   --  Handshake_Done; callers should re-check (and resnapshot)
   --  whenever they return to their event loop.
   function Has_Session_Ticket (S : Session) return Boolean;

   --  True iff the current connection's handshake completed
   --  using the PSK supplied via Cfg.Resume_Ticket (server
   --  accepted resumption). Cleared on every Init/Configure.
   --  Stable across the freeing of the handshake context â the
   --  flag is mirrored from HC into S at handshake completion.
   function Was_Resumed (S : Session) return Boolean;

   --  Note: 0-RTT (RFC 8446 Â§2.3 / Â§4.2.10) is intentionally
   --  not exposed. There is no Write_Early_Data / Was_0RTT_Accepted
   --  API on this stack â the replay + lack-of-forward-secrecy
   --  trade-off is incompatible with the project's threat model.
   --  Resumption (Was_Resumed above) is 1-RTT and fully supported.

   --  Snapshot the current resumption ticket. Returns the empty
   --  ticket (Valid=False) if none. The returned record is
   --  self-contained and can be persisted to disk / passed to
   --  another process; placing it in a future Cfg.Resume_Ticket
   --  enables PSK resumption.
   --
   --  RFC 8446 Â§4.6.1: tickets MUST NOT be reused; the caller is
   --  responsible for using each persisted ticket at most once.
   function Get_Session_Ticket (S : Session) return Session_Ticket;

   --  RFC 5077 Â§3.3 TLS 1.2 session ticket extraction. Mirror of the
   --  TLS 1.3 PSK pair above. The TLS 1.2 server populates this
   --  field via NewSessionTicket; callers persist it across
   --  connections and inject into the next Config.TLS12_Resume_Ticket
   --  to attempt abbreviated resumption.
   function Has_TLS12_Ticket (S : Session) return Boolean;

   function Get_TLS12_Ticket (S : Session) return Session_Ticket_12;

private

   --  Completions of the query functions declared above. A public child's
   --  private part may name the parent's private components, so these keep
   --  their original bodies verbatim once Session becomes a private type.
   --  GNATprove reads expression-function completions here, so the prover
   --  sees exactly what it saw before this relocation.

   function Has_Peer_Certificate (S : Session) return Boolean
   is (S.Peer_Cert_Valid);

   function Has_Session_Ticket (S : Session) return Boolean
   is (S.Ticket.Valid);

   function Was_Resumed (S : Session) return Boolean
   is (S.Resumed_From_PSK);

   function Get_Session_Ticket (S : Session) return Session_Ticket
   is (S.Ticket);

   function Has_TLS12_Ticket (S : Session) return Boolean
   is (S.TLS12_New_Ticket.Valid);

   function Get_TLS12_Ticket (S : Session) return Session_Ticket_12
   is (S.TLS12_New_Ticket);

end SPARKTLS.Client;
