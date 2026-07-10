--  mTLS test client — a minimal SPARKTLS client that supports
--  the flags the integration tests need to drive a full
--  client-side handshake against openssl s_server, including
--  mutual auth (client cert + key) and a post-handshake app-data
--  round-trip.
--
--  Why this exists: the original tls_test_client only does TLS
--  1.3 with no mTLS. Bugs in client_application_traffic_secret_0
--  derivation went unnoticed because no integration test sent
--  ANY app data after a mTLS handshake — Finished decrypted fine
--  even with the wrong app keys, and the bug only appeared on
--  the next encrypted record (e.g. close_notify).
--
--  Usage:
--    mtls_test_client --port 18443 [--host HOSTNAME]
--                     [--cert-file FILE --key-file FILE]
--                     [--trust-cert FILE]
--                     [--message STR]
--                     [--expect-echo]
--                     [--expect-fail]
--
--  Exit 0 on success, 1 on failure. Prints status to stdout,
--  errors to stderr. The `--expect-fail` flag inverts the exit
--  code (used for tests where the handshake SHOULD be rejected).

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Ada.Calendar;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Credentials;
with Entropy_Random;
with X509;

with GNAT.Sockets;               use GNAT.Sockets;

procedure MTLS_Test_Client is

   Exit_Success : constant := 0;
   Exit_Failure : constant := 1;

   subtype Path_Buf is String (1 .. 1024);
   Empty_Path : constant Path_Buf := (others => Character'Val (0));

   Cfg_Port      : Natural := 0;
   Cfg_Host      : String (1 .. 256) := (others => Character'Val (0));
   Cfg_Host_Len  : Natural := 0;
   Cfg_Cert      : Path_Buf := Empty_Path;
   Cfg_Key       : Path_Buf := Empty_Path;
   Cfg_Trust     : Path_Buf := Empty_Path;
   Cfg_Message   : String (1 .. 4096) := (others => Character'Val (0));
   Cfg_Msg_Len   : Natural := 5;
   Cfg_Expect_Echo : Boolean := False;
   Cfg_Expect_Fail : Boolean := False;
   Cfg_ALPN      : String (1 .. 255) := (others => Character'Val (0));
   Cfg_ALPN_Len  : Natural := 0;
   Cfg_Expect_ALPN : String (1 .. 255) := (others => Character'Val (0));
   Cfg_Expect_ALPN_Len : Natural := 0;
   Cfg_Skip_Verify          : Boolean := False;
   Cfg_Skip_Hostname_Verify : Boolean := False;

   procedure Err (M : String) is
   begin
      Put_Line (Standard_Error, "mtls_test_client: " & M);
   end Err;

   function Trim (S : String) return String is
      Last : Natural := S'First - 1;
   begin
      for I in S'Range loop
         exit when S (I) = Character'Val (0);
         Last := I;
      end loop;
      return S (S'First .. Last);
   end Trim;

   procedure Set_Path (Dst : in out Path_Buf; Src : String) is
   begin
      Dst := Empty_Path;
      Dst (1 .. Src'Length) := Src;
   end Set_Path;

   procedure Parse_Args is
      I : Natural := 1;
      use Ada.Command_Line;

      function Next_Arg return String is
      begin
         I := I + 1;
         if I > Argument_Count then
            Err ("missing value after " & Argument (I - 1));
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            raise Program_Error;
         end if;
         return Argument (I);
      end Next_Arg;
   begin
      --  Default message: "hello"
      Cfg_Message (1 .. 5) := "hello";
      Cfg_Msg_Len := 5;
      Cfg_Host (1 .. 9) := "localhost";
      Cfg_Host_Len := 9;

      while I <= Argument_Count loop
         declare
            A : constant String := Argument (I);
         begin
            if A = "--port" then
               Cfg_Port := Natural'Value (Next_Arg);
            elsif A = "--host" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg_Host := (others => Character'Val (0));
                  Cfg_Host (1 .. V'Length) := V;
                  Cfg_Host_Len := V'Length;
               end;
            elsif A = "--cert-file" then
               Set_Path (Cfg_Cert, Next_Arg);
            elsif A = "--key-file" then
               Set_Path (Cfg_Key, Next_Arg);
            elsif A = "--trust-cert" then
               Set_Path (Cfg_Trust, Next_Arg);
            elsif A = "--message" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg_Message := (others => Character'Val (0));
                  Cfg_Message (1 .. V'Length) := V;
                  Cfg_Msg_Len := V'Length;
               end;
            elsif A = "--expect-echo" then
               Cfg_Expect_Echo := True;
            elsif A = "--expect-fail" then
               Cfg_Expect_Fail := True;
            elsif A = "--skip-verify" then
               Cfg_Skip_Verify := True;
            elsif A = "--skip-hostname-verify" then
               Cfg_Skip_Hostname_Verify := True;
            elsif A = "--alpn" then
               declare
                  V : constant String := Next_Arg;
               begin
                  if V'Length > 0 and V'Length <= 255 then
                     Cfg_ALPN (1 .. V'Length) := V;
                     Cfg_ALPN_Len := V'Length;
                  end if;
               end;
            elsif A = "--expect-alpn" then
               declare
                  V : constant String := Next_Arg;
               begin
                  if V'Length > 0 and V'Length <= 255 then
                     Cfg_Expect_ALPN (1 .. V'Length) := V;
                     Cfg_Expect_ALPN_Len := V'Length;
                  end if;
               end;
            else
               Err ("unknown arg: " & A);
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Failure));
               raise Program_Error;
            end if;
         end;
         I := I + 1;
      end loop;
   end Parse_Args;

   --  Clock callback for cert validation. Use a fixed in-band date
   --  so test certs (which expire) still validate.
   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      S   : Day_Duration;
   begin
      Split (Now, Y, Mo, D, S);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Natural (S) / 3600,
              Minute => (Natural (S) mod 3600) / 60,
              Second => Natural (S) mod 60);
   end Current_Time;

   S       : SPARKTLS.Session;
   Res     : SPARKTLS.Action;
   Sock    : Socket_Type;

   Net_Out : Byte_Seq (0 .. 16383);
   Net_In  : Byte_Seq (0 .. 16383);
   App_Buf : Byte_Seq (0 .. 4095);

   Id      : aliased SPARKTLS.Identity;
   Id_OK   : Boolean;
   Roots   : aliased SPARKTLS.Trust_Store;
   Roots_OK : Boolean;
   Have_Local : Boolean := False;
   Have_Trust : Boolean := False;

   App_Sent : Boolean := False;
   App_Received : Boolean := False;
   Run_Failed : Boolean := False;

   procedure Send_Pending is
      N : N32;
      Last : Stream_Element_Offset;
   begin
      loop
         Drain_Ciphertext (S, Net_Out, N);
         exit when N = 0;
         declare
            SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
         begin
            for K in 0 .. N - 1 loop
               SE (Stream_Element_Offset (K + 1)) :=
                  Stream_Element (Net_Out (K));
            end loop;
            GNAT.Sockets.Send_Socket (Sock, SE, Last);
         end;
      end loop;
   end Send_Pending;

   procedure Recv_Once (Done : out Boolean) is
      SE : Stream_Element_Array (1 .. 16384);
      Last : Stream_Element_Offset;
      Fed : N32;
   begin
      Done := False;
      begin
         GNAT.Sockets.Receive_Socket (Sock, SE, Last);
      exception
         when others =>
            Done := True;
            return;
      end;
      if Last < SE'First then
         Done := True;
         return;
      end if;
      declare
         Avail : constant N32 := N32 (Last - SE'First + 1);
      begin
         for K in 0 .. Avail - 1 loop
            Net_In (K) := Byte (SE (SE'First + Stream_Element_Offset (K)));
         end loop;
         Feed_Ciphertext (S, Net_In (0 .. Avail - 1), Fed);
      end;
   end Recv_Once;

begin
   Entropy_Random.Init;
   Parse_Args;

   if Cfg_Port = 0 then
      Err ("--port required");
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Failure));
      return;
   end if;

   --  Connect TCP
   Initialize;
   Create_Socket (Sock);
   Set_Socket_Option (Sock, Socket_Level,
      (Name => Receive_Timeout, Timeout => 5.0));
   begin
      Connect_Socket
        (Sock,
         (Family => Family_Inet,
          Addr   => Inet_Addr ("127.0.0.1"),
          Port   => Port_Type (Cfg_Port)));
   exception
      when E : others =>
         Err ("connect failed: "
              & Ada.Exceptions.Exception_Message (E));
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Failure));
         return;
   end;

   --  Load credentials
   declare
      Cert : constant String := Trim (Cfg_Cert);
      Key  : constant String := Trim (Cfg_Key);
      Trust : constant String := Trim (Cfg_Trust);
   begin
      if Trust /= "" then
         SPARKTLS.Credentials.Load_Trust_Store (Roots, Trust, Roots_OK);
         if not Roots_OK then
            Err ("load trust failed: " & Trust);
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            return;
         end if;
         Have_Trust := True;
      end if;
      if Cert /= "" and Key /= "" then
         SPARKTLS.Credentials.Load_Identity (Id, Cert, Key, Id_OK);
         if not Id_OK then
            Err ("load identity failed: " & Cert);
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            return;
         end if;
         Have_Local := True;
      end if;
   end;

   --  Mode_RFC5280: structural cert validation only, no WebPKI
   --  CT/SCT/etc. enforcement. Test certs are self-signed; the
   --  WebPKI mode would reject them as untrusted.
   SPARKTLS.Client.Configure
     (S                    => S,
      Hostname             => Cfg_Host (1 .. Cfg_Host_Len),
      Trust                =>
         (if Have_Trust then Roots'Unchecked_Access else null),
      Random               => Entropy_Random.Random'Access,
      Clock                => Current_Time'Unrestricted_Access,
      Local                =>
         (if Have_Local then Id'Unchecked_Access else null),
      Mode                 => SPARKTLS.Mode_RFC5280,
      ALPN                 => Cfg_ALPN (1 .. Cfg_ALPN_Len),
      Skip_Verify          => Cfg_Skip_Verify,
      Skip_Hostname_Verify => Cfg_Skip_Hostname_Verify);

   --  Drive handshake to completion, then exchange app data, then close.
   Loop1 :
   loop
      SPARKTLS.Client.Advance (S, Res);
      case Res is
         when Has_Output =>
            Send_Pending;
         when Need_Input =>
            declare
               Done : Boolean;
            begin
               Recv_Once (Done);
               if Done then
                  if not App_Sent then
                     Err ("peer closed during handshake");
                     Run_Failed := True;
                  end if;
                  exit Loop1;
               end if;
            end;
         when OK =>
            null;
         when Handshake_Done =>
            --  --expect-alpn check: after handshake, verify the
            --  negotiated ALPN matches what we asked for.
            if Cfg_Expect_ALPN_Len > 0 then
               declare
                  Got : constant String := SPARKTLS.Get_ALPN (S);
                  Want : constant String :=
                     Cfg_Expect_ALPN (1 .. Cfg_Expect_ALPN_Len);
               begin
                  if Got /= Want then
                     Err ("ALPN mismatch: got='" & Got
                          & "' want='" & Want & "'");
                     Run_Failed := True;
                     exit Loop1;
                  end if;
               end;
            end if;
            --  Send the test message immediately, then wait for echo
            --  (or just close cleanly if --expect-echo not set).
            declare
               Msg : constant Byte_Seq (0 .. N32 (Cfg_Msg_Len) - 1) :=
                  (others => 0);
               Buf : Byte_Seq (0 .. N32 (Cfg_Msg_Len) - 1);
               Written : N32;
            begin
               for I in 0 .. Cfg_Msg_Len - 1 loop
                  Buf (N32 (I)) := Byte (Character'Pos (
                     Cfg_Message (Cfg_Message'First + I)));
               end loop;
               pragma Unreferenced (Msg);
               SPARKTLS.Write_Plaintext (S, Buf, Written);
               Send_Pending;
               App_Sent := True;
            end;
         when Plaintext_Ready =>
            declare
               N : N32;
            begin
               Read_Plaintext (S, App_Buf, N);
               if N > 0 then
                  App_Received := True;
                  if Cfg_Expect_Echo then
                     --  Print first byte of received data for sanity.
                     Put_Line ("ECHO_RECEIVED bytes=" & N32'Image (N));
                  end if;
                  --  Initiate clean shutdown.
                  SPARKTLS.Client.Close_Notify (S);
                  Send_Pending;
               end if;
            end;
         when Error_Alert =>
            Send_Pending;
            Err ("handshake error: state=" & S.State'Image
                 & " err=" & S.Last_Error'Image);
            Run_Failed := True;
            exit Loop1;
         when Shutdown =>
            exit Loop1;
      end case;
   end loop Loop1;

   --  Determine final outcome
   declare
      Success : constant Boolean := not Run_Failed
         and then App_Sent
         and then (not Cfg_Expect_Echo or else App_Received);
      Want_Failure : constant Boolean := Cfg_Expect_Fail;
      Final_OK : constant Boolean :=
         (if Want_Failure then not Success else Success);
   begin
      if Final_OK then
         Put_Line ("OK");
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Success));
      else
         Err ("FAIL: success=" & Success'Image
              & " expect_fail=" & Want_Failure'Image
              & " app_sent=" & App_Sent'Image
              & " app_received=" & App_Received'Image);
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Failure));
      end if;
   end;

exception
   when Program_Error =>
      null;
   when E : others =>
      Err (Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Failure));
end MTLS_Test_Client;
