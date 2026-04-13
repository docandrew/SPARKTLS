package SPARKTLS.Client with
   SPARK_Mode => On
is
   --================================================================
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
   --             -- handle S.Last_Error
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
   --================================================================

   --  Quick setup: configure and initialize a client session in one call.
   --  Sets Mode_WebPKI, Purpose_Server, and the default cipher suite.
   --  After Configure, the caller should drain and send the ClientHello.
   procedure Configure
     (S        : out Session;
      Hostname : String;
      Trust    : Trust_Store_Access;
      Random   : Random_Bytes_Fn;
      Clock    : Get_Time_Fn;
      Local    : Identity_Access := null)
   with Pre  => Random /= null and Clock /= null,
        Post => S.State = Client_Hello_Sent and
                S.Role = Role_Client and
                Output_Pending (S) > 0;

   --  Initialize a client session with full control over Config.
   --  After Init, the caller should drain and send the ClientHello.
   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   with Pre  => Cfg.Random /= null,
        Post => S.State = Client_Hello_Sent and
                S.Role = Role_Client and
                Output_Pending (S) > 0;

   --  Step the client handshake / record processing state machine.
   --
   --  Processes available input, advances state, and may produce
   --  output. The returned Action tells the caller what to do:
   --
   --    Need_Input     => read from transport, Feed_Ciphertext, Advance
   --    Has_Output     => Drain_Ciphertext, send, Advance
   --    Plaintext_Ready => call Read_Plaintext
   --    Handshake_Done => connection is ready for app data
   --    Error_Alert    => check S.Last_Error
   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   with Pre => S.State /= Idle and S.Role = Role_Client;

   --  Encrypt and queue application data for sending.
   --
   --  Returns the number of plaintext bytes accepted. May be less
   --  than Plaintext'Length if the output buffer is nearly full;
   --  drain and retry in that case.
   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   with Pre  => S.State = Connected and
                S.Role = Role_Client and
                Plaintext'First = 0 and
                Plaintext'Length > 0,
        Post => Bytes_Written <= N32 (Plaintext'Length);

   --  Send a close_notify alert to initiate clean shutdown.
   --
   --  After calling, drain the output buffer and continue calling
   --  Advance until Shutdown is returned.
   procedure Close_Notify (S : in out Session)
   with Pre => (S.State = Connected or S.State = Closing) and
               S.Role = Role_Client;

   --  True if a peer certificate has been received and parsed.
   function Has_Peer_Certificate (S : Session) return Boolean is
      (S.Peer_Cert_Valid);

end SPARKTLS.Client;
