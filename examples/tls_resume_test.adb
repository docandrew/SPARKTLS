--  tls_resume_test - exercise TLS 1.3 PSK resumption end-to-end
--  against a real TLS server.
--
--  Usage:
--    tls_resume_test [-host HOST] [-port PORT] [-0rtt]
--
--  Default: 127.0.0.1:8443. The companion server (e.g. openssl
--  s_server -tls1_3 -num_tickets 1) must be running.
--
--  Performs TWO sequential connections in one process:
--    1. Fresh handshake. Drains post-handshake messages so any
--       NewSessionTicket arrives + is parsed. Snapshots the
--       resulting Session_Ticket via Get_Session_Ticket. Closes.
--    2. New connection with Cfg.Resume_Ticket set to the snapshot.
--       Optionally Cfg.Allow_0RTT for 0-RTT mode. After handshake,
--       reports whether the server selected our PSK (resumption
--       succeeded) by inspecting HC.Using_PSK before HC is freed,
--       or — once the handshake context is gone — by re-querying
--       a session-level flag we record at handshake-completion.
--
--  Exit code: 0 if both connections complete and the second one
--  resumed; non-zero otherwise.

with Ada.Command_Line;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Exceptions;
with Ada.Streams;          use Ada.Streams;
with Ada.Text_IO;          use Ada.Text_IO;
with Interfaces;           use Interfaces;

with SPARKNaCl;            use SPARKNaCl;

with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Client;
with Entropy_Random;
with X509;

with GNAT.Sockets;         use GNAT.Sockets;

procedure TLS_Resume_Test is

   --  Defaults
   Host : String (1 .. 256) := (others => ' ');
   Host_Len : Natural := 0;
   Port : Port_Type := 8443;
   Want_0RTT : Boolean := False;

   --  Carried across the two connections.
   Saved_Ticket : Session_Ticket;

   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      Hr  : Ada.Calendar.Formatting.Hour_Number;
      Mn  : Ada.Calendar.Formatting.Minute_Number;
      Sc  : Ada.Calendar.Formatting.Second_Number;
      SS  : Ada.Calendar.Formatting.Second_Duration;
   begin
      --  Ada.Calendar.Split works in package Calendar's implementation-
      --  defined (local) time zone, RM 9.6. X.509 notBefore/notAfter are
      --  UTC, so a local split shifts every validity comparison by the
      --  host's UTC offset. Formatting.Split with Time_Zone => 0 is the
      --  UTC one.
      Ada.Calendar.Formatting.Split
        (Now, Y, Mo, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Hr, Minute => Mn, Second => Sc);
   end Current_Time;

   --  Run one TLS handshake against the configured peer.  When
   --  Resume is True we pass Saved_Ticket back via Cfg.Resume_Ticket
   --  (and optionally Cfg.Allow_0RTT). On success, refresh
   --  Saved_Ticket from S so subsequent calls can resume.
   --
   --  Returns:
   --    OK     - handshake succeeded
   --    Was_PSK - True iff S.HC_Ptr.Using_PSK at the time the
   --              second flight is sent, i.e. the server selected
   --              our PSK. False on the first (fresh) connection.
   procedure Run_One_Connection
     (Resume   : in     Boolean;
      With_0RTT : in    Boolean;
      OK       :    out Boolean;
      Was_PSK  :    out Boolean)
   is
      S        : Client_Session;
      Cfg      : Config;
      Res      : Action;
      Sock     : Socket_Type;
      Channel  : Stream_Access;
      Net_Buf  : Byte_Seq (0 .. 16383);
      N        : N32;
      Iter     : Natural := 0;
   begin
      OK := False;
      Was_PSK := False;

      Cfg.Random := Entropy_Random.Random'Access;
      Cfg.Versions := TLS_1_3_Only;
      --  Integration test runs against an OpenSSL self-signed test cert.
      Cfg.Skip_Verify := True;
      declare
         H : constant String := Host (1 .. Host_Len);
      begin
         Cfg.Server_Name.Data (1 .. H'Length) := H;
         Cfg.Server_Name.Len := H'Length;
      end;
      if Resume and then Saved_Ticket.Valid then
         Cfg.Resume_Ticket := Saved_Ticket;
         --  With_0RTT historically enabled 0-RTT mode; the
         --  feature was removed (replay + lack of forward
         --  secrecy is out of scope). Flag retained on the CLI
         --  so existing invocations don't break, but it's a no-op.
         pragma Unreferenced (With_0RTT);
      end if;

      --  Connect TCP.
      Initialize;
      Create_Socket (Socket => Sock);
      Set_Socket_Option
        (Socket => Sock,
         Level  => Socket_Level,
         Option => (Name => Receive_Timeout, Timeout => 3.0));
      Connect_Socket
        (Socket => Sock,
         Server => (Family => Family_Inet,
                    Addr   => Inet_Addr ("127.0.0.1"),
                    Port   => Port));
      Channel := Stream (Sock);

      S := SPARKTLS.Client.Configure (Cfg);

      --  Handshake loop.
      Handshake_Loop : loop
         Iter := Iter + 1;
         exit Handshake_Loop when Iter > 200;  --  safety

         SPARKTLS.Client.Advance (S, Res);
         case Res is
            when Has_Output =>
               SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
               if N > 0 then
                  Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
               end if;

            when Need_Input =>
               --  Read one record header + body from the socket.
               begin
                  Byte_Seq'Read (Channel, Net_Buf (0 .. 4));
                  declare
                     Rec_Len : constant N32 :=
                        N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
                  begin
                     if Rec_Len > 0 and then Rec_Len <= 16640 then
                        Byte_Seq'Read (Channel,
                          Net_Buf (5 .. 4 + Rec_Len));
                        N := 5 + Rec_Len;
                        SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);
                     end if;
                  end;
               exception
                  when others =>
                     Put_Line ("  socket read failed");
                     exit Handshake_Loop;
               end;

            when Handshake_Done =>
               OK := True;
               --  HC was already freed by Advance when state hit
               --  Connected; use the Session-level mirror.
               Was_PSK := SPARKTLS.Client.Was_Resumed (S);
               exit Handshake_Loop;

            when Plaintext_Ready =>
               SPARKTLS.Read_Plaintext (S, Net_Buf, N);

            when Error_Alert =>
               Put_Line ("  handshake error: " & SPARKTLS.Describe (SPARKTLS.Last_Error (S)));
               --  Drain any pending alert before closing.
               SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
               if N > 0 then
                  begin
                     Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
                  exception when others => null;
                  end;
               end if;
               exit Handshake_Loop;

            when Shutdown =>
               Put_Line ("  shutdown before handshake_done");
               exit Handshake_Loop;

            when SPARKTLS.OK =>
               null;
         end case;
      end loop Handshake_Loop;

      --  Drain any post-handshake records (NewSessionTicket).
      --  Receive_Timeout above will eventually fire; treat as EOF.
      if OK then
         declare
            Drain_Iter : Natural := 0;
         begin
            Post_HS : loop
               Drain_Iter := Drain_Iter + 1;
               exit Post_HS when Drain_Iter > 20;
               begin
                  Byte_Seq'Read (Channel, Net_Buf (0 .. 4));
                  declare
                     Rec_Len : constant N32 :=
                        N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
                  begin
                     if Rec_Len > 0 and then Rec_Len <= 16640 then
                        Byte_Seq'Read (Channel,
                          Net_Buf (5 .. 4 + Rec_Len));
                        N := 5 + Rec_Len;
                        SPARKTLS.Feed_Ciphertext
                          (S, Net_Buf (0 .. N - 1), N);
                        SPARKTLS.Client.Advance (S, Res);
                        if Res = Plaintext_Ready then
                           SPARKTLS.Read_Plaintext (S, Net_Buf, N);
                        end if;
                     end if;
                  end;
               exception
                  when others =>
                     exit Post_HS;
               end;
            end loop Post_HS;
         end;

         --  Capture the ticket if the server sent one.
         if SPARKTLS.Client.Has_Session_Ticket (S) then
            Saved_Ticket := SPARKTLS.Client.Get_Session_Ticket (S);
            Put_Line ("  captured ticket (len="
                      & Saved_Ticket.Ticket_Len'Image
                      & " psk_len=" & Saved_Ticket.PSK_Len'Image
                      & ")");
         else
            Put_Line ("  no session ticket received");
         end if;
      end if;

      --  Cleanly close socket. Don't bother with close_notify on
      --  the first connection — server will tear down on FIN too.
      begin
         Close_Socket (Sock);
      exception when others => null;
      end;
   end Run_One_Connection;

begin
   Entropy_Random.Init;

   --  Default host
   declare
      H : constant String := "localhost";
   begin
      Host (1 .. H'Length) := H;
      Host_Len := H'Length;
   end;

   --  Parse args
   declare
      I : Natural := 1;
   begin
      while I <= Ada.Command_Line.Argument_Count loop
         declare
            A : constant String := Ada.Command_Line.Argument (I);
         begin
            if A = "-host" and then I < Ada.Command_Line.Argument_Count then
               declare
                  V : constant String := Ada.Command_Line.Argument (I + 1);
               begin
                  Host (1 .. V'Length) := V;
                  Host (V'Length + 1 .. Host'Last) := (others => ' ');
                  Host_Len := V'Length;
               end;
               I := I + 2;
            elsif A = "-port" and then I < Ada.Command_Line.Argument_Count then
               Port := Port_Type'Value
                         (Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            elsif A = "-0rtt" then
               Want_0RTT := True;
               I := I + 1;
            else
               I := I + 1;
            end if;
         end;
      end loop;
   end;

   Put_Line ("=== tls_resume_test ===");
   Put_Line ("Host: " & Host (1 .. Host_Len) & ":" & Port'Image);
   Put_Line ("0-RTT: " & Want_0RTT'Image);

   --  Connection 1: fresh handshake, capture ticket.
   Put_Line ("Connection 1 (fresh handshake)...");
   declare
      Conn1_OK, Conn1_PSK : Boolean;
   begin
      Run_One_Connection
        (Resume    => False,
         With_0RTT => False,
         OK        => Conn1_OK,
         Was_PSK   => Conn1_PSK);
      if not Conn1_OK then
         Put_Line ("FAIL: connection 1 did not complete handshake");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      if Conn1_PSK then
         Put_Line ("FAIL: connection 1 unexpectedly resumed");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
   end;

   if not Saved_Ticket.Valid then
      Put_Line ("FAIL: no session ticket from connection 1");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   --  Connection 2: resume.
   Put_Line ("Connection 2 (resumption)...");
   declare
      Conn2_OK, Conn2_PSK : Boolean;
   begin
      Run_One_Connection
        (Resume    => True,
         With_0RTT => Want_0RTT,
         OK        => Conn2_OK,
         Was_PSK   => Conn2_PSK);
      if not Conn2_OK then
         Put_Line ("FAIL: connection 2 did not complete handshake");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      if not Conn2_PSK then
         Put_Line ("FAIL: connection 2 did NOT resume (server fell back)");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      Put_Line ("PASS: resumption succeeded");
   end;

exception
   when E : others =>
      Put_Line ("FATAL: " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end TLS_Resume_Test;
