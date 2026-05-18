package SPARKTLS.Server with
   SPARK_Mode => On
is
   --================================================================
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
   --================================================================

   --  Quick setup: configure and initialize a server session in one call.
   --  Sets Mode_WebPKI and the default cipher suite.
   --  Optionally provide a Trust store and Request_Client_Cert for mTLS.
   procedure Configure
     (S                     : out Session;
      Local                 : Identity_Access;
      Random                : Random_Bytes_Fn;
      Trust                 : Trust_Store_Access := null;
      Request_Client_Cert   : Boolean := False;
      Require_Client_Cert   : Boolean := False;
      Tickets               : Ticket_Store_Access := null;
      ALPN                  : String := "";
      Versions              : Version_Policy := Allow_Both;
      TLS12_Ticket_Keys     : TLS12_Ticket_Keys_Access := null;
      TLS12_Ticket_Lifetime : Unsigned_32 := 3600;
      Get_Time              : Get_Time_Fn := null;
      Select_Identity       : SNI_Cert_Selector := null)
   with SPARK_Mode => Off;
   --  Select_Identity: optional SNI-based identity selector
   --  (RFC 6066 §3 / RFC 8446 §4.4.2.4). When non-null and the client
   --  sent a non-empty server_name extension, the callback receives
   --  the hostname and returns the matching Identity_Access. A
   --  non-null result overrides `Local` for this session. A null
   --  result causes fallback to `Local` (permissive default; openssl-
   --  compatible behaviour rather than `unrecognized_name` alert).
   --  Get_Time: optional UTC wall-clock callback. Required for
   --  TLS 1.2 session-ticket expiry enforcement (without it the
   --  Decrypt_Ticket path skips the age window check). Also used
   --  by X.509 chain validation for notBefore / notAfter.
   --  Note: 0-RTT (RFC 8446 §2.3 / §4.2.10) is intentionally not
   --  supported on either side. NST omits the early_data extension,
   --  EE never echoes it, and any client that speculatively sends
   --  0-RTT records has them silently dropped (the bounded skip in
   --  Process_Client_Finished). Resumption (1-RTT PSK) is fully
   --  supported and is forward-secret + replay-safe via the
   --  required psk_dhe_ke mode.
   --  ALPN (RFC 7301): the protocol name we'll select when a
   --  client offers it in the application_layer_protocol_negotiation
   --  extension. Empty string means we don't echo ALPN even if
   --  the client offered something. Single-protocol only — for
   --  multi-protocol selection use Init with a built Config.
   --  SPARK_Mode Off: Ticket_Store_Access is access-all (shared mutable
   --  cache). SPARK's ownership model treats it as a move, but the pointer
   --  is intentionally shared between caller and Config.

   --  Initialize a server session with full control over Config.
   --  Cfg.Local must point to an Identity with a certificate and key.
   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   with Pre  => Cfg.Random /= null and
                Cfg.Local /= null and
                Cfg.Local.Has_Identity,
        Post => S.State = Wait_Client_Hello and
                S.Role = Role_Server;

   --  RFC 8446 §4.1: Step the server handshake / record processing
   --  state machine. State transitions follow the valid transition graph.
   --
   --  Result semantics (RFC 8446 §4, §5, §6):
   --    OK           → progress made, state may or may not change
   --    Need_Input   → caller must feed more ciphertext
   --    Has_Output   → caller must drain and send ciphertext
   --    Handshake_Done → handshake complete, state = Connected
   --    Plaintext_Ready → decrypted app data available
   --    Shutdown     → clean close complete, state = Closed
   --    Error_Alert  → fatal error, alert was sent, state = Closed
   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with Pre  => S.State /= Idle and S.Role = Role_Server,
        Post => (S.State = S.State'Old
                 or else Valid_Transition (S.State'Old, S.State))
                and (if Result = Handshake_Done then
                       S.State = Connected)
                and (if Result = Shutdown then
                       S.State = Closed)
                and (if Result = Error_Alert then
                       S.State = Closed);

   --  RFC 8446 §7.5: Encrypt and queue application data.
   --  Only valid in the application key phase (Connected state).
   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   with Pre  => S.State = Connected and
                S.Role = Role_Server and
                In_App_Key_Phase (S.State) and     --  RFC 8446 §7.5
                Plaintext'First = 0 and
                Plaintext'Length > 0,
        Post => Bytes_Written <= N32 (Plaintext'Length) and
                S.State = Connected;               --  doesn't change state

   --  RFC 8446 §6.1: Send a close_notify alert.
   --  Transitions to Closing state.
   procedure Close_Notify (S : in out Session)
   with Pre  => (S.State = Connected or S.State = Closing) and
                S.Role = Role_Server,
        Post => S.State = Closing;                 --  RFC 8446 §6.1

   --  True if a client certificate was received (mutual TLS).
   function Has_Peer_Certificate (S : Session) return Boolean is
      (S.Peer_Cert_Valid);

end SPARKTLS.Server;
