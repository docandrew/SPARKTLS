--  Simple blocking TLS 1.3 server for protocol compliance testing.
--  Handles one connection at a time, sequentially. No epoll, no async.
--  Perfect for tlsfuzzer and protocol testing tools.
--
--  Usage: tls_blocking_server <cert.pem> <key.pem>

with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;
with X509;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Software_Signer;
with SPARKTLS.Tickets;
with Entropy_Random;

with GNAT.Sockets;               use GNAT.Sockets;
with SPARKTLS.Ticket_Keys;

procedure TLS_Blocking_Server is

   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Roots   : aliased SPARKTLS.Trust_Store;
   MTLS    : Boolean := False;
   MTLS_Require : Boolean := False;
   --  --external-sign: the TLS side holds a public-only identity and every
   --  handshake signature goes through Software_Signer,
   --  standing in for a YubiKey, TPM, HSM or separate signing process.
   External_Sign : Boolean := False;

   --  TLS 1.2 ticket encryption keys (RFC 5077). One TEK generated
   --  at startup with a fixed Key_ID; rotates only on restart.

   --  UTC wall-clock callback used by ticket expiry + cert validation.
   --  Production code would centralise this (e.g. monotonic + UTC
   --  delta from NTP); for the example, Ada.Calendar.Clock is fine
   --  on a host with a reasonable system time.
   function Now_UTC return X509.Date_Time is
      use Ada.Calendar;
      T  : constant Time := Clock;
      Y  : Year_Number;
      M  : Month_Number;
      D  : Day_Number;
      Hr : Ada.Calendar.Formatting.Hour_Number;
      Mn : Ada.Calendar.Formatting.Minute_Number;
      Sc : Ada.Calendar.Formatting.Second_Number;
      SS : Ada.Calendar.Formatting.Second_Duration;
   begin
      --  Ada.Calendar.Split works in package Calendar's implementation-
      --  defined (local) time zone, RM 9.6. X.509 notBefore/notAfter are
      --  UTC, so a local split shifts every validity comparison by the
      --  host's UTC offset -- which is why this is NOT plain Split
      --  despite the name. Formatting.Split with Time_Zone => 0 is UTC.
      Ada.Calendar.Formatting.Split
        (T, Y, M, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y,
              Month  => M,
              Day    => D,
              Hour   => Hr,
              Minute => Mn,
              Second => Sc);
   end Now_UTC;

   Server_Sock : Socket_Type;
   --  Port: env var SPARKTLS_PORT overrides the 8443 default. Lets
   --  the integration runner rotate ports per test so a TIME_WAIT
   --  from the previous test doesn't force a sleep before the next.
   function Get_Port return Port_Type is
   begin
      if Ada.Environment_Variables.Exists ("SPARKTLS_PORT") then
         return Port_Type'Value
           (Ada.Environment_Variables.Value ("SPARKTLS_PORT"));
      end if;
      return 8443;
   end Get_Port;
   Port : constant Port_Type := Get_Port;

   --  Optional TEK rotation interval override (seconds). Defaults
   --  to 24h; tests / dev set SPARKTLS_TEK_ROTATE_SECS=N for a
   --  shorter interval so rotation can be observed in real time.
   function Get_TEK_Rotate_Secs return Unsigned_32 is
   begin
      if Ada.Environment_Variables.Exists ("SPARKTLS_TEK_ROTATE_SECS") then
         return Unsigned_32'Value
           (Ada.Environment_Variables.Value ("SPARKTLS_TEK_ROTATE_SECS"));
      end if;
      return 24 * 3600;
   end Get_TEK_Rotate_Secs;
   TEK_Rotate_Secs : constant Unsigned_32 := Get_TEK_Rotate_Secs;

   Trace   : constant Boolean := Ada.Environment_Variables.Exists ("SPARKTLS_TRACE");
   Conn_No : Natural := 0;

   procedure Handle_Connection (Client_Sock : Socket_Type) is
      S         : SPARKTLS.Server_Session;
      Res       : SPARKTLS.Action;
      Read_Dead : Boolean := False;
      Write_Dead : Boolean := False;

      Net_In  : Byte_Seq (0 .. 16383);
      Net_Out : Byte_Seq (0 .. 16383);

      procedure Send_Output is
         N : N32;
         Last : Stream_Element_Offset;
      begin
         loop
            Drain_Ciphertext (S, Net_Out, N);
            exit when N = 0;
            declare
               SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
            begin
               for I in SE'Range loop
                  SE (I) := Stream_Element (Net_Out (N32 (I - 1)));
               end loop;
               GNAT.Sockets.Send_Socket (Client_Sock, SE, Last);
            end;
         end loop;
      exception
         when Socket_Error =>
            Write_Dead := True;
      end Send_Output;

      procedure Read_Input is
         SE   : Stream_Element_Array (1 .. 16384);
         Last : Stream_Element_Offset;
         Fed  : N32;
      begin
         GNAT.Sockets.Receive_Socket (Client_Sock, SE, Last);
         if Last >= SE'First then
            null;
            for I in SE'First .. Last loop
               Net_In (N32 (I - 1)) := Byte (SE (I));
            end loop;
            Feed_Ciphertext (S, Net_In (0 .. N32 (Last) - 1), Fed);
         else
            Read_Dead := True;
         end if;
      exception
         when others => Read_Dead := True;
      end Read_Input;

      --  Application data held back until a newline arrives (see the
      --  Plaintext_Ready arm below).
      Echo_Buf : Byte_Seq (0 .. 65535);
      Echo_Len : N32 := 0;

      --  How much of Echo_Buf to answer now. Everything, unless the buffer
      --  looks like the start of an HTTP request ("GET ", "POST ", ...)
      --  that has not reached its blank line yet: tlsfuzzer's KeyUpdate
      --  scripts split "GET / HTTP/1.0" around a KeyUpdate and expect the
      --  server's KeyUpdate before any application data, which is what an
      --  HTTP server answering complete requests would do. Anything else
      --  (an integration client sending "hello" with no newline) is echoed
      --  as soon as the input is drained.
      function Echo_Cut return N32 is
         function Starts (P : String) return Boolean is
           (Echo_Len >= P'Length
            and then (for all I in P'Range =>
                        Echo_Buf (N32 (I - P'First)) = Character'Pos (P (I))));
         --  Fewer bytes than the method token itself, all matching it so
         --  far ("G", "GE", "GET"): hold, it may still become a request
         --  (tlsfuzzer chacha20 "1/n-1 record splitting" sends the first
         --  byte alone).
         function Prefix_Of (P : String) return Boolean is
           (Echo_Len < P'Length
            and then (for all I in 0 .. Echo_Len - 1 =>
                        Echo_Buf (I) = Character'Pos (P (P'First + Integer (I)))));
      begin
         if Echo_Len > 0
           and then (Prefix_Of ("GET ") or else Prefix_Of ("POST ")
                     or else Prefix_Of ("HEAD ") or else Prefix_Of ("PUT "))
         then
            return 0;
         end if;
         if Starts ("GET ") or else Starts ("POST ") or else Starts ("HEAD ")
           or else Starts ("PUT ")
         then
            for I in 1 .. Echo_Len - 1 loop
               if Echo_Buf (I) = 10
                 and then (Echo_Buf (I - 1) = 10
                           or else (I >= 3 and then Echo_Buf (I - 1) = 13
                                    and then Echo_Buf (I - 2) = 10))
               then
                  return I + 1;   --  through the blank line
               end if;
            end loop;
            return 0;             --  request still incomplete: hold
         end if;
         return Echo_Len;
      end Echo_Cut;

      --  Echo the first Cut bytes of Echo_Buf and keep the rest.
      procedure Flush_Echo (Cut : N32) is
         Written : N32;
      begin
         if Cut = 0 then
            return;
         end if;
         SPARKTLS.Write_Plaintext (S, Echo_Buf (0 .. Cut - 1), Written);
         Send_Output;
         if Cut < Echo_Len then
            Echo_Buf (0 .. Echo_Len - Cut - 1) := Echo_Buf (Cut .. Echo_Len - 1);
         end if;
         Echo_Len := Echo_Len - Cut;
      end Flush_Echo;

   begin
      --  Receive timeout. 30 s suits an interactive example, but it is
      --  far too long for a conformance harness: this server handles one
      --  connection at a time, and tlsfuzzer deliberately stalls or
      --  abandons connections. A stalled peer therefore blocks the accept
      --  loop for the full timeout and takes the NEXT several tests down
      --  with it, which showed up as run-to-run flakiness (keyupdate
      --  scoring 58-61/62 across identical runs with different failures
      --  each time). SPARKTLS_RECV_TIMEOUT lets the harness ask for a
      --  short timeout without changing the example's default behaviour.
      Set_Socket_Option
        (Client_Sock, Socket_Level,
         (Name    => Receive_Timeout,
          Timeout =>
            (if Ada.Environment_Variables.Exists ("SPARKTLS_RECV_TIMEOUT")
             then Duration'Value
                    (Ada.Environment_Variables.Value
                       ("SPARKTLS_RECV_TIMEOUT"))
             else 30.0)));
      --  A peer that stops reading (zero window) must not pin the task.
      Set_Socket_Option
        (Client_Sock, Socket_Level, (Name => Send_Timeout, Timeout => 10.0));
      Set_Socket_Option
        (Client_Sock, IP_Protocol_For_TCP_Level,
         (Name => No_Delay, Enabled => True));

      S := Server.Configure
        ((Local               => Id'Unchecked_Access,
          Random              => Entropy_Random.Random'Access,
          Trust               => (if MTLS then Roots'Unchecked_Access
                                  else null),
          Request_Client_Cert => MTLS,
          Require_Client_Cert => MTLS_Require,
          Sign                => (if External_Sign
                                  then Software_Signer.Sign'Access else null),
          Get_Active_TEK      =>
            SPARKTLS.Ticket_Keys.Get_Active_TEK'Access,
          Get_TEK_By_Id       =>
            SPARKTLS.Ticket_Keys.Get_TEK_By_Id'Access,
          Get_Time            => Now_UTC'Unrestricted_Access,
          others              => <>));

      --  Handshake + data loop
      loop
         Server.Advance (S, Res);

         case Res is
            when Has_Output =>
               Send_Output;
               if Write_Dead then
                  exit;
               end if;

            when Need_Input =>
               if Read_Dead then exit; end if;
               --  Input drained: every record the peer sent so far has been
               --  processed (KeyUpdate replies and tickets are queued), so
               --  now answer the complete lines received. An event-driven
               --  server behaves the same way: it reads everything the
               --  socket holds before the application gets to write.
               Flush_Echo (Echo_Cut);
               Read_Input;
               if Read_Dead then
                  --  Peer closed: send whatever unterminated tail is held.
                  Flush_Echo (Echo_Len);
                  exit;
               end if;

            when Handshake_Done =>
               null;  --  Handshake complete, continue processing

            when Plaintext_Ready =>
               --  Read decrypted data and queue it for the echo. It is
               --  answered once the input is drained (Need_Input above, see
               --  Echo_Cut for the one case that is held back longer); the
               --  tail is flushed when the peer closes.
               declare
                  App   : Byte_Seq (0 .. 16383);
                  App_N : N32;
               begin
                  Read_Plaintext (S, App, App_N);
                  if App_N > 0 and then Echo_Len <= Echo_Buf'Last - App_N then
                     Echo_Buf (Echo_Len .. Echo_Len + App_N - 1) := App (0 .. App_N - 1);
                     Echo_Len := Echo_Len + App_N;
                  end if;
               end;

            when Error_Alert =>
               --  Alert already sent (drained via Has_Output).
               --  Graceful TCP shutdown: close write side, then
               --  wait for the peer to read our alert and close.
               begin
                  Shutdown_Socket (Client_Sock, Shut_Write);
               exception
                  when others => null;
               end;
               --  Read until peer closes or timeout
               declare
                  Dummy : Stream_Element_Array (1 .. 1024);
                  Last  : Stream_Element_Offset;
               begin
                  loop
                     Receive_Socket (Client_Sock, Dummy, Last);
                     exit when Last < Dummy'First;
                  end loop;
               exception
                  when others => null;
               end;
               exit;

            when Shutdown =>
               Server.Close_Notify (S);
               Send_Output;
               begin
                  Shutdown_Socket (Client_Sock, Shut_Write);
               exception
                  when others => null;
               end;
               exit;

            when others =>
               null;
         end case;
      end loop;

      --  Whatever ended the connection, give the handshake slot back
      --  (see SPARKTLS.Drop): a peer that disconnects after our
      --  ServerHello otherwise pins it for the life of the process.
      SPARKTLS.Drop (S);

   exception
      when Socket_Error =>
         SPARKTLS.Drop (S);
      when E : others =>
         SPARKTLS.Drop (S);
         Put_Line ("  Connection error: " &
                   Ada.Exceptions.Exception_Message (E));
   end Handle_Connection;

   task type Worker with Storage_Size => 8 * 1024 * 1024 is
      entry Start (Sock : Socket_Type; No : Natural);
   end Worker;
   type Worker_Access is access Worker;

   --  Bound on connections in flight. Beyond it new connections are
   --  refused at accept: a task per connection with no ceiling lets a
   --  slow-trickling peer population grow memory without limit.
   Max_Workers : constant := 64;
   protected Workers is
      procedure Try_Acquire (Got : out Boolean);
      procedure Release;
   private
      Count : Natural := 0;
   end Workers;
   protected body Workers is
      procedure Try_Acquire (Got : out Boolean) is
      begin
         Got := Count < Max_Workers;
         if Got then
            Count := Count + 1;
         end if;
      end Try_Acquire;
      procedure Release is
      begin
         if Count > 0 then
            Count := Count - 1;
         end if;
      end Release;
   end Workers;

   task body Worker is
      Client_Sock : Socket_Type;
      Conn        : Natural;
   begin
      accept Start (Sock : Socket_Type; No : Natural) do
         Client_Sock := Sock;
         Conn        := No;
      end Start;
      if Trace then
         Put_Line ("conn" & Conn'Image & " accept");
      end if;
      Handle_Connection (Client_Sock);
      begin
         Shutdown_Socket (Client_Sock, Shut_Read_Write);
      exception
         when others => null;
      end;
      Close_Socket (Client_Sock);
      Workers.Release;
      if Trace then
         Put_Line ("conn" & Conn'Image & " done");
      end if;
   exception
      when E : others =>
         Workers.Release;
         Put_Line ("Error: " & Ada.Exceptions.Exception_Message (E));
   end Worker;

begin
   Entropy_Random.Init;

   --  Ticket storage lives in the application, not in SPARKTLS. One call
   --  seeds the first TLS 1.2 ticket key and turns on rotation (24h by
   --  default); rotation is lazy, checked on the ticket path, so there is
   --  no timer task to manage.
   SPARKTLS.Ticket_Keys.Initialize
     (Random            => Entropy_Random.Random'Access,
      Clock             => Now_UTC'Unrestricted_Access,
      Rotation_Interval => Get_TEK_Rotate_Secs);

   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_blocking_server <cert.pem> <key.pem>" &
                " [--mtls <ca.pem>] [--staple <ocsp.der>] [--external-sign]" &
                " [--external-sign-corrupt|--external-sign-refuse]");
      return;
   end if;

   Credentials.Load_Identity
     (Id,
      Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2),
      Id_OK);
   if not Id_OK then
      Put_Line ("Failed to load identity");
      return;
   end if;

   --  --external-sign (any position): hand the private key to the signer
   --  and reload the identity from the certificate alone, so the TLS side
   --  provably holds no key material.
   for I in 3 .. Ada.Command_Line.Argument_Count loop
      if Ada.Command_Line.Argument (I) = "--external-sign" then
         External_Sign := True;
      elsif Ada.Command_Line.Argument (I) = "--external-sign-corrupt" then
         Software_Signer.Corrupt_Output := True;   --  test: wrong signature
      elsif Ada.Command_Line.Argument (I) = "--external-sign-refuse" then
         Software_Signer.Refuse := True;           --  test: signer fails
      end if;
   end loop;
   if External_Sign then
      declare
         S_OK, P_OK : Boolean;
      begin
         Software_Signer.Init
           (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), S_OK);
         Credentials.Load_Identity_Public (Id, Ada.Command_Line.Argument (1), P_OK);
         if not (S_OK and P_OK) then
            Put_Line ("Failed to set up the external signer");
            return;
         end if;
         Put_Line ("External signer: enabled (" & Id.Sign_Algo'Image
                   & ", TLS side holds no private key)");
      end;
   end if;

   --  Optional --staple <ocsp.der>: RFC 6066 stapled OCSP response, sent
   --  to clients that ask (TLS 1.3 CertificateEntry extension, TLS 1.2
   --  CertificateStatus). Any argument position after the key.
   for I in 3 .. Ada.Command_Line.Argument_Count - 1 loop
      if Ada.Command_Line.Argument (I) = "--staple" then
         declare
            St_OK : Boolean;
         begin
            Credentials.Load_Staple (Id, Ada.Command_Line.Argument (I + 1), St_OK);
            if St_OK then
               Put_Line ("OCSP staple: loaded (" & Id.OCSP_Staple_Len'Image & " bytes)");
            else
               Put_Line ("Warning: failed to load OCSP staple "
                         & Ada.Command_Line.Argument (I + 1));
            end if;
         end;
      end if;
   end loop;

   --  --mtls <ca.pem> / --mtls-require <ca.pem>, any position after the key
   for I in 3 .. Ada.Command_Line.Argument_Count - 1 loop
      if Ada.Command_Line.Argument (I) = "--mtls"
        or else Ada.Command_Line.Argument (I) = "--mtls-require"
      then
         declare
            Roots_OK : Boolean;
         begin
            Credentials.Load_Trust_Store
              (Roots, Ada.Command_Line.Argument (I + 1), Roots_OK);
            if Roots_OK then
               MTLS := True;
               MTLS_Require :=
                 Ada.Command_Line.Argument (I) = "--mtls-require";
               Put_Line ("mTLS enabled (trust: " &
                         Ada.Command_Line.Argument (I + 1)
                         & (if MTLS_Require then ", REQUIRED)" else ")"));
            else
               Put_Line ("Warning: failed to load trust store, mTLS disabled");
            end if;
         end;
      end if;
   end loop;

   Put_Line ("=== SPARKTLS Blocking Server ===");
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   Initialize;
   Create_Socket (Server_Sock);
   Set_Socket_Option (Server_Sock, Socket_Level,
                      (Name => Reuse_Address, Enabled => True));
   Bind_Socket (Server_Sock,
                (Family => Family_Inet,
                 Addr   => Any_Inet_Addr,
                 Port   => Port));
   Listen_Socket (Server_Sock, 128);

   Put_Line ("Ready.");

   --  Accept connections forever, one task per connection. Each
   --  connection is still handled by the blocking loop in
   --  Handle_Connection; the tasks only let several run at once. That
   --  matters for conformance scanners: TLS-Scanner (TLS-Anvil's feature
   --  scan) probes from three threads with a one-second timeout, and a
   --  server that answers one connection at a time misses every probe
   --  queued behind a peer that is still waiting (2026-09-14: every
   --  TLS-Anvil test came back "disabled" for this reason). Shared state is
   --  task-safe: the identity and trust store are read-only after start-up,
   --  Entropy_Random has no state, and SPARKTLS.Ticket_Keys is a protected
   --  object. Terminated Worker objects are not reclaimed; this is a test
   --  server.
   loop
      declare
         Client_Sock : Socket_Type;
         Client_Addr : Sock_Addr_Type;
         W           : Worker_Access;
      begin
         Accept_Socket (Server_Sock, Client_Sock, Client_Addr);
         --  SPARKTLS_TRACE=1: one line per connection, so a harness log
         --  shows which connection a stall belongs to.
         Conn_No := Conn_No + 1;
         declare
            Got : Boolean;
         begin
            Workers.Try_Acquire (Got);
            if Got then
               W := new Worker;
               W.Start (Client_Sock, Conn_No);
            else
               if Trace then
                  Put_Line ("conn" & Conn_No'Image & " refused (Max_Workers)");
               end if;
               Close_Socket (Client_Sock);
            end if;
         end;
      exception
         when E : others =>
            Put_Line ("Error: " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
end TLS_Blocking_Server;
