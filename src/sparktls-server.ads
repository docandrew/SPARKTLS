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
   --          when App_Data_Ready => read app data
   --          when Error_Alert => handle error
   --          when others => null;
   --       end case;
   --    end loop;
   --================================================================

   --  Initialize a server session.
   --
   --  The server starts in Wait_Client_Hello, expecting the caller
   --  to feed ClientHello bytes into the input buffer.
   --
   --  Cert_DER: raw DER-encoded server certificate.
   --  Key: Ed25519 64-byte signing key (secret + public halves).
   procedure Init
     (S        :    out Session;
      Cfg      : in     Config;
      Cert_DER : in     Byte_Seq;
      Key      : in     Bytes_64)
   with Pre  => Cfg.Random /= null and
                Cert_DER'First = 0 and
                Cert_DER'Length > 0 and
                N32 (Cert_DER'Length) <= Max_Cert_DER_Len,
        Post => S.State = Wait_Client_Hello and
                not S.Is_Client;

   --  Step the server handshake / record processing state machine.
   --  Same semantics as SPARKTLS.Client.Advance.
   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State /= Idle and not S.Is_Client;

   --  Encrypt and queue application data for sending.
   procedure Write_App_Data
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   with Pre  => S.State = Connected and
                not S.Is_Client and
                Plaintext'First = 0 and
                Plaintext'Length > 0,
        Post => Bytes_Written <= N32 (Plaintext'Length);

   --  Send a close_notify alert to initiate clean shutdown.
   procedure Close_Notify (S : in out Session)
   with Pre => (S.State = Connected or S.State = Closing) and
               not S.Is_Client;

   --  True if a client certificate was received (mutual TLS).
   function Has_Peer_Certificate (S : Session) return Boolean is
      (S.Peer_Cert_Valid);

end SPARKTLS.Server;
