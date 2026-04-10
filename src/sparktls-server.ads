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
     (S                   : out Session;
      Local               : Identity_Access;
      Random              : Random_Bytes_Fn;
      Trust               : Trust_Store_Access := null;
      Request_Client_Cert : Boolean := False)
   with Pre  => Random /= null and
                Local /= null and
                Local.Has_Identity,
        Post => S.State = Wait_Client_Hello and
                S.Role = Role_Server;

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

   --  Step the server handshake / record processing state machine.
   --  Same semantics as SPARKTLS.Client.Advance.
   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State /= Idle and S.Role = Role_Server;

   --  Encrypt and queue application data for sending.
   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   with Pre  => S.State = Connected and
                S.Role = Role_Server and
                Plaintext'First = 0 and
                Plaintext'Length > 0,
        Post => Bytes_Written <= N32 (Plaintext'Length);

   --  Send a close_notify alert to initiate clean shutdown.
   procedure Close_Notify (S : in out Session)
   with Pre => (S.State = Connected or S.State = Closing) and
               S.Role = Role_Server;

   --  True if a client certificate was received (mutual TLS).
   function Has_Peer_Certificate (S : Session) return Boolean is
      (S.Peer_Cert_Valid);

end SPARKTLS.Server;
