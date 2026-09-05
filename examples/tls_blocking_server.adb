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
with SPARKTLS.Tickets_12;
with Entropy_Random;

with GNAT.Sockets;               use GNAT.Sockets;
with SPARKTLS.Session_Cache;

procedure TLS_Blocking_Server is

   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Roots   : aliased SPARKTLS.Trust_Store;
   MTLS    : Boolean := False;
   MTLS_Require : Boolean := False;

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
          Store_Session       =>
            SPARKTLS.Session_Cache.Store_Session'Access,
          Lookup_Session      =>
            SPARKTLS.Session_Cache.Lookup_Session'Access,
          Get_Active_TEK      =>
            SPARKTLS.Session_Cache.Get_Active_TEK'Access,
          Get_TEK_By_Id       =>
            SPARKTLS.Session_Cache.Get_TEK_By_Id'Access,
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
               Read_Input;
               if Read_Dead then exit; end if;

            when Handshake_Done =>
               null;  --  Handshake complete, continue processing

            when Plaintext_Ready =>
               --  Read decrypted data, echo it back verbatim
               declare
                  App   : Byte_Seq (0 .. 16383);
                  App_N : N32;
               begin
                  Read_Plaintext (S, App, App_N);
                  if App_N > 0 then
                     declare
                        Written : N32;
                     begin
                        SPARKTLS.Write_Plaintext
                          (S, App (0 .. App_N - 1), Written);
                        Send_Output;
                     end;
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

   exception
      when Socket_Error =>
         null;
      when E : others =>
         Put_Line ("  Connection error: " &
                   Ada.Exceptions.Exception_Message (E));
   end Handle_Connection;

begin
   Entropy_Random.Init;

   --  Ticket storage lives in the application, not in SPARKTLS. One call
   --  seeds the first TLS 1.2 ticket key and turns on rotation (24h by
   --  default); rotation is lazy, checked on the ticket path, so there is
   --  no timer task to manage.
   SPARKTLS.Session_Cache.Initialize
     (Random            => Entropy_Random.Random'Access,
      Clock             => Now_UTC'Unrestricted_Access,
      Rotation_Interval => Get_TEK_Rotate_Secs);

   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("Usage: tls_blocking_server <cert.pem> <key.pem>" &
                " [--mtls <ca.pem>]");
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

   --  Check for --mtls / --mtls-require flag
   if Ada.Command_Line.Argument_Count >= 4
      and then (Ada.Command_Line.Argument (3) = "--mtls"
                or else Ada.Command_Line.Argument (3) = "--mtls-require")
   then
      declare
         Roots_OK : Boolean;
      begin
         Credentials.Load_Trust_Store
           (Roots, Ada.Command_Line.Argument (4), Roots_OK);
         if Roots_OK then
            MTLS := True;
            MTLS_Require :=
              Ada.Command_Line.Argument (3) = "--mtls-require";
            Put_Line ("mTLS enabled (trust: " &
                      Ada.Command_Line.Argument (4)
                      & (if MTLS_Require then ", REQUIRED)" else ")"));
         else
            Put_Line ("Warning: failed to load trust store, mTLS disabled");
         end if;
      end;
   end if;

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

   --  Accept connections forever
   loop
      declare
         Client_Sock : Socket_Type;
         Client_Addr : Sock_Addr_Type;
      begin
         Accept_Socket (Server_Sock, Client_Sock, Client_Addr);
         Handle_Connection (Client_Sock);
         begin
            Shutdown_Socket (Client_Sock, Shut_Read_Write);
         exception
            when others => null;
         end;
         Close_Socket (Client_Sock);
      exception
         when E : others =>
            Put_Line ("Error: " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
end TLS_Blocking_Server;
