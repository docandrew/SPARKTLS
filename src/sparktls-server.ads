with SPARKTLS.Records.TLS12;

package SPARKTLS.Server
  with SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  Server-side TLS 1.3 session management
   --
   --  Usage follows the same pattern as SPARKTLS.Client, but the
   --  server begins by waiting for a ClientHello rather than
   --  sending one.
   --
   --  Usage (blocking):
   --
   --    S   : SPARKTLS.Session;
   --    Cfg : SPARKTLS.Config := (Random => My_RNG'Access, ...);
   --    Res : SPARKTLS.Action;
   --    Buf : Byte_Seq (0 .. 16383);
   --    N   : N32;
   --
   --    SPARKTLS.Server.Init
   --      (S        => S,
   --       Cfg      => Cfg,
   --       Cert_DER => My_Cert_Bytes,
   --       Key      => My_Ed25519_Private_Key);
   --
   --    loop
   --       SPARKTLS.Server.Advance (S, Res);
   --       case Res is
   --          when Has_Output  => drain + send
   --          when Need_Input  => read + feed
   --          when Handshake_Done => exit;
   --          when Plaintext_Ready => read app data
   --          when Error_Alert => handle error
   --          when others => null;
   --       end case;
   --    end loop;
   ----------------------------------------------------------------------------

   --  Quick setup: configure and initialize a server session in one call.
   --  Sets Mode_WebPKI.
   --  Optionally provide a Trust store and Request_Client_Cert for mTLS.
   procedure Configure
     (S                     : out Server_Session;
      Local                 : Valid_Identity_Access;
      Random                : Random_Bytes_Fn;
      Trust                 : Trust_Store_Access := null;
      Request_Client_Cert   : Boolean := False;
      Require_Client_Cert   : Boolean := False;
      Store_Session         : Store_Session_Fn := null;
      Lookup_Session        : Lookup_Session_Fn := null;
      ALPN                  : String := "";
      Versions              : Version_Policy := Allow_Both;
      Get_Active_TEK        : Get_Active_TEK_Fn := null;
      Get_TEK_By_Id         : Get_TEK_By_Id_Fn := null;
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;
      Get_Time              : Get_Time_Fn := null;
      Select_Identity       : SNI_Cert_Selector := null)
      --  Mirrors Server.Init's requirements, which Configure must satisfy on
      --  the caller's behalf. Client.Configure has always carried the equivalent
      --  check; the server's absence of one was invisible while this body was
      --  SPARK_Mode => Off, and let a null Random reach Init.
   with Pre => Random /= null and then Local /= null and then Local.Has_Identity;
   --  Select_Identity: optional SNI-based identity selector
   --  (RFC 6066 Â§3 / RFC 8446 Â§4.4.2.4). When non-null and the client
   --  sent a non-empty server_name extension, the callback receives
   --  the hostname and returns the matching Identity_Access. A
   --  non-null result overrides `Local` for this session. A null
   --  result causes fallback to `Local` (permissive default; openssl-
   --  compatible behaviour rather than `unrecognized_name` alert).
   --  Get_Time: optional UTC wall-clock callback. Required when
   --  Request_Client_Cert is True, because mTLS chain validation
   --  checks certificate notBefore / notAfter. Also required for
   --  TLS 1.2 session-ticket expiry enforcement (without it the
   --  Decrypt_Ticket path skips the age window check).
   --  Note: 0-RTT (RFC 8446 Â§2.3 / Â§4.2.10) is intentionally not
   --  supported on either side. NST omits the early_data extension,
   --  EE never echoes it, and any client that speculatively sends
   --  0-RTT records has them silently dropped (the bounded skip in
   --  Process_Client_Finished). Resumption (1-RTT PSK) is fully
   --  supported and is forward-secret + replay-safe via the
   --  required psk_dhe_ke mode.
   --  ALPN (RFC 7301): the protocol name we'll select when a
   --  client offers it in the application_layer_protocol_negotiation
   --  extension. Empty string means we don't echo ALPN even if
   --  the client offered something. Single-protocol only â for
   --  multi-protocol selection use Init with a built Config.
   --  SPARK_Mode Off: Ticket_Store_Access is access-all (shared mutable
   --  cache). SPARK's ownership model treats it as a move, but the pointer
   --  is intentionally shared between caller and Config.

   --  Initialize a server session with full control over Config.
   --  Cfg.Local must point to an Identity with a certificate and key.
   procedure Init
     (S   : out Server_Session;
      Cfg : in Config)
   with
     Pre => Cfg.Random /= null and then Cfg.Local /= null and then Cfg.Local.Has_Identity
     --  The formal is the CONSTRAINED subtype (#39, 2026-08-24):
     --  inside the body S.Role = Role_Server by view, so the
     --  aggregate's discriminant check is static, and the old
     --  'Constrained Pre + Role Post are subsumed by the profile.
   ;

   --  RFC 8446 Â§4.1: Step the server handshake / record processing
   --  state machine.
   --
   --  Result semantics (RFC 8446 Â§4, Â§5, Â§6):
   --    OK           â progress made, state may or may not change
   --    Need_Input   â caller must feed more ciphertext
   --    Has_Output   â caller must drain and send ciphertext
   --    Handshake_Done â handshake complete, state = Connected
   --    Plaintext_Ready â decrypted app data available
   --    Shutdown     â clean close complete, state = Closed
   --    Error_Alert  â fatal error, alert was sent, state = Closed
   procedure Advance
     (S      : in out Server_Session;
      Result : out Action)
      --  Role (S) = Role_Server was deleted from this Pre 2026-08-20: the
      --  Server_Session subtype constrains the discriminant, so it is now
      --  UNSTATEABLE rather than merely required.
   with Pre => State (S) /= Idle;

   --  RFC 8446 Â§6.1: Send a close_notify alert.
   --  Transitions to Closing state.
   procedure Close_Notify
     (S : in out Session)
      --  Deliberately callable on an already-closed session: Advance reports
      --  both a half-duplex close and a completed close with Shutdown, and the
      --  application cannot distinguish them. On a finished session this is a
      --  no-op (the body returns before touching the scrubbed keys).
   with
     Pre =>
       Role (S)
       = Role_Server
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

   --  True if a client certificate was received (mutual TLS).
   --
   --  Declared here, completed in the private part below: once Session is a
   --  private type, an expression function in a public child's VISIBLE part
   --  may not name Session components. The private part of a public child
   --  does have that visibility, and GNATprove still reads the completion,
   --  so this is a relocation with no change in meaning for the prover.
   function Has_Peer_Certificate (S : Session) return Boolean;

   ----------------------------------------------------------------------------
   --  RFC 5077 TLS 1.2 ticket encryption key (TEK) rotation
   --
   --  ROTATION LIVES IN SPARKTLS.Session_Cache, NOT HERE. This package
   --  once declared Rotate_TLS12_Ticket_Key; it moved during the
   --  callback refactor and the orphaned body was deleted 2026-08-19.
   --  Use:
   --      Session_Cache.Rotate_TEK (New_Key_ID, New_TEK, Now_Secs)
   --      Session_Cache.Active_Key_Age (Now_Secs)
   --
   --  Semantics (unchanged): the new key takes the active slot and older
   --  keys shift down, staying valid for INCOMING ticket decryption so
   --  clients holding tickets from prior keys still resume during the
   --  grace window; the oldest slot drops out. New tickets ENCRYPT under
   --  the active key only.
   --
   --  ROTATION IS AUTOMATIC BY DEFAULT, not caller-driven. Once the app
   --  calls Session_Cache.Initialize (Random, Clock, Rotation_Interval)
   --  the cache rotates lazily every Rotation_Interval seconds (24 h
   --  default): Get_Active_TEK checks the active key's age on each ticket
   --  issuance and rotates in place, generating fresh material from the
   --  app-supplied CSPRNG. No timer task; an idle server does no work.
   --  Rotate_TEK / Active_Key_Age are the manual escape hatch, used with
   --  Rotation_Interval => 0 for HSM- or orchestrator-supplied keys.
   --
   --  Atomicity: rotation writes the shared key array. In our
   --  state-machine model the caller drives Advance one handshake at a
   --  time per Server, so the write is naturally atomic with respect to
   --  in-flight handshakes. Multi-threaded callers sharing one Cfg MUST
   --  serialize Advance calls.
   --
   --  Now_Secs is wall-clock Unix seconds recorded as Created_At for the
   --  new key, typically Tickets_12.To_Unix_Seconds (Cfg.Get_Time.all).


private

   --  Completions of the query functions declared above. A public child's
   --  private part may name the parent's private components, so these keep
   --  their original bodies verbatim once Session becomes a private type.

   function Has_Peer_Certificate (S : Session) return Boolean
   is (S.Peer_Cert_Valid);

   --  A server config that can actually run a handshake: identity present
   --  and a randomness source wired. This is the gate Init applies before
   --  the ONLY write of HC.Cfg, plus the mTLS coherence rule.
   function Server_Config_Can_Start (Cfg : Config) return Boolean
   is (Cfg.Local /= null
       and then Cfg.Local.Has_Identity
       and then Cfg.Random /= null
       and then (not Cfg.Request_Client_Cert
                 or else Cfg.Skip_Verify
                 or else (Cfg.Trust /= null and then Cfg.Get_Time /= null)));

   --  The configured-server fact as a TYPE, so the handler chain receives
   --  it by construction instead of re-deriving it per call.
   --
   --  Why a view subtype and not a predicate on HC.Cfg itself: a
   --  default-initialized Handshake_Context has Cfg.Local = null, so the
   --  component cannot carry the predicate (same reason Session has none --
   --  see the NO-Dynamic_Predicate note in sparktls.ads). HC.Cfg stays
   --  plain Config; Advance establishes membership ONCE with a fail-closed
   --  runtime test (three null checks -- semantically unreachable, since
   --  Server_Config_Can_Start gates the only write), and everything below
   --  takes `Cfg : Ready_Config` and reads config through the formal.
   --
   --  Deliberately ONLY the Server_Configured trio, not all of
   --  Server_Config_Can_Start: every use site pays the predicate in VC
   --  context, and the mTLS coherence conjunct is consumed by exactly one
   --  path today (runtime-guarded there anyway). Strengthen with a second
   --  subtype if that path ever wants it proved instead.
   subtype Ready_Config is Config
   with
     Dynamic_Predicate =>
       Ready_Config.Local /= null
       and then Ready_Config.Local.Has_Identity
       and then Ready_Config.Random /= null;

end SPARKTLS.Server;
