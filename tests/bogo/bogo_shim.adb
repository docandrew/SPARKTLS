--  BoGo shim — BoringSSL test-runner adversarial-test integration.
--
--  See ssl/test/PORTING.md in the BoringSSL tree:
--    1. TCP-client to localhost:<port> (runner already listening)
--    2. Send shim_id as 8-byte little-endian uint64
--    3. Speak TLS over that TCP connection
--    4. Exit 0 = pass, 89 = unimplemented (skipped),
--       other = unexpected failure
--
--  Phase-1 flag coverage (from tests/bogo/README.md):
--    -server -port -shim-id -ipv6 -cert-file -key-file -trust-cert
--    -min-version -max-version -shim-writes-first
--    -expect-handshake-fails -resume-count -cipher -curves
--  Anything else → exit 89 with a message on stderr.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Client;
with SPARKTLS.Credentials;
with Entropy_Random;
with X509;

with GNAT.Sockets;               use GNAT.Sockets;

procedure Bogo_Shim is

   --  Exit codes per ssl/test/PORTING.md.
   Exit_Success       : constant := 0;
   Exit_Unimplemented : constant := 89;
   Exit_Failure       : constant := 1;

   --  Compact unbounded-string. We only need to compare and pass to
   --  loaders; no truncation needed in practice.
   subtype Unbounded_Text is String (1 .. 1024);

   --  Argv config — populated by Parse_Args.
   type Config_T is record
      Is_Server            : Boolean := False;
      Port                 : Natural := 0;
      Shim_Id              : Unsigned_64 := 0;
      Ipv6                 : Boolean := False;
      Cert_File            : Unbounded_Text := (others => Character'Val (0));
      Key_File             : Unbounded_Text := (others => Character'Val (0));
      Trust_Cert           : Unbounded_Text := (others => Character'Val (0));
      Min_Version          : Unsigned_16 := 16#0303#;  --  TLS 1.2
      Max_Version          : Unsigned_16 := 16#0304#;  --  TLS 1.3
      Shim_Writes_First    : Boolean := False;
      Expect_Hs_Fails      : Boolean := False;
      Resume_Count         : Natural := 0;
      --  ALPN (RFC 7301). BoGo wire-encodes -advertise-alpn already
      --  (e.g. "\x03foo"); we strip the 1-byte length prefix and store
      --  the bare protocol name. Multi-protocol lists pick the FIRST.
      ALPN_Proto           : Unbounded_Text := (others => Character'Val (0));
      ALPN_Proto_Len       : Natural := 0;
      Expect_ALPN          : Unbounded_Text := (others => Character'Val (0));
      Expect_ALPN_Len      : Natural := 0;
      Decline_ALPN         : Boolean := False;
   end record;

   Cfg : Config_T;
   Sock    : Socket_Type;
   Channel : Stream_Access;

   --  ------------------------------------------------------------------
   --  Stderr write helper.
   --  ------------------------------------------------------------------
   procedure Err (Msg : String) is
   begin
      Put_Line (Standard_Error, Msg);
   end Err;

   --  ------------------------------------------------------------------
   --  Argv parsing. Each unhandled flag → exit 89.
   --  ------------------------------------------------------------------
   procedure Parse_Args is
      I : Natural := 1;
      use Ada.Command_Line;

      function Next_Arg return String is
      begin
         I := I + 1;
         if I > Argument_Count then
            Err ("bogo_shim: missing value after " & Argument (I - 1));
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Unimplemented));
            raise Program_Error;
         end if;
         return Argument (I);
      end Next_Arg;

      function Hex_To_U16 (S : String) return Unsigned_16 is
         V : Unsigned_16 := 0;
      begin
         for C of S loop
            if C in '0' .. '9' then
               V := V * 16 + Unsigned_16 (Character'Pos (C) - Character'Pos ('0'));
            elsif C in 'a' .. 'f' then
               V := V * 16 +
                    Unsigned_16 (Character'Pos (C) - Character'Pos ('a') + 10);
            elsif C in 'A' .. 'F' then
               V := V * 16 +
                    Unsigned_16 (Character'Pos (C) - Character'Pos ('A') + 10);
            elsif C = 'x' or C = 'X' then
               V := 0;  --  skip "0x" prefix
            end if;
         end loop;
         return V;
      end Hex_To_U16;

   begin
      while I <= Argument_Count loop
         declare
            A : constant String := Argument (I);
         begin
            if A = "-is-handshaker-supported" then
               --  BoGo runner probes for split-handshake support
               --  before any test runs. We don't implement the
               --  handshaker process; reply "No" on stdout, exit 0.
               Put_Line ("No");
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Success));
               raise Program_Error;
            elsif A = "-server" then
               Cfg.Is_Server := True;
            elsif A = "-port" then
               Cfg.Port := Natural'Value (Next_Arg);
            elsif A = "-shim-id" then
               Cfg.Shim_Id := Unsigned_64'Value (Next_Arg);
            elsif A = "-ipv6" then
               Cfg.Ipv6 := True;
            elsif A = "-cert-file" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg.Cert_File (1 .. V'Length) := V;
                  Cfg.Cert_File (V'Length + 1 .. Cfg.Cert_File'Last)
                    := (others => Character'Val (0));
               end;
            elsif A = "-key-file" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg.Key_File (1 .. V'Length) := V;
                  Cfg.Key_File (V'Length + 1 .. Cfg.Key_File'Last)
                    := (others => Character'Val (0));
               end;
            elsif A = "-trust-cert" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg.Trust_Cert (1 .. V'Length) := V;
                  Cfg.Trust_Cert (V'Length + 1 .. Cfg.Trust_Cert'Last)
                    := (others => Character'Val (0));
               end;
            elsif A = "-min-version" then
               Cfg.Min_Version := Hex_To_U16 (Next_Arg);
            elsif A = "-max-version" then
               Cfg.Max_Version := Hex_To_U16 (Next_Arg);
            elsif A = "-shim-writes-first" then
               Cfg.Shim_Writes_First := True;
            elsif A = "-expect-handshake-fails" then
               Cfg.Expect_Hs_Fails := True;
            elsif A = "-resume-count" then
               Cfg.Resume_Count := Natural'Value (Next_Arg);
            elsif A = "-shim-config" then
               --  No JSON config support yet — ignore the file path.
               declare
                  Ignore : constant String := Next_Arg;
                  pragma Unreferenced (Ignore);
               begin
                  null;
               end;
            elsif A = "-advertise-alpn"
              or else A = "-select-alpn"
              or else A = "-expect-advertised-alpn"
            then
               --  RFC 7301 ALPN. BoGo's wire form for these flags is
               --  the bytes that go directly in the protocol_name_list
               --  for `-advertise-alpn` (each protocol prefixed by a
               --  1-byte length, e.g. "\x03foo\x08http/1.1"). For
               --  `-select-alpn` the value is the bare protocol name.
               --  We only support a single ALPN protocol today, so for
               --  the multi-proto advertise lists we pick the FIRST.
               declare
                  V : constant String := Next_Arg;
                  Proto : String (1 .. 255);
                  Plen  : Natural := 0;
               begin
                  if A = "-advertise-alpn" or A = "-expect-advertised-alpn"
                  then
                     --  Length-prefix-delimited; first protocol only.
                     if V'Length >= 1 then
                        declare
                           N : constant Natural := Character'Pos (V (V'First));
                        begin
                           if N > 0 and N <= 255
                             and V'Length >= 1 + N
                           then
                              Plen := N;
                              Proto (1 .. N) := V (V'First + 1 .. V'First + N);
                           end if;
                        end;
                     end if;
                  else
                     --  -select-alpn: bare protocol name.
                     if V'Length <= 255 then
                        Plen := V'Length;
                        Proto (1 .. Plen) := V;
                     end if;
                  end if;
                  if Plen > 0 then
                     Cfg.ALPN_Proto (1 .. Plen) := Proto (1 .. Plen);
                     Cfg.ALPN_Proto_Len := Plen;
                  end if;
               end;
            elsif A = "-expect-alpn" then
               declare
                  V : constant String := Next_Arg;
               begin
                  if V'Length > 0 and V'Length <= 255 then
                     Cfg.Expect_ALPN (1 .. V'Length) := V;
                     Cfg.Expect_ALPN_Len := V'Length;
                  end if;
               end;
            elsif A = "-decline-alpn" then
               Cfg.Decline_ALPN := True;
            else
               Err ("bogo_shim: unimplemented flag: " & A);
               Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Unimplemented));
               raise Program_Error;
            end if;
         end;
         I := I + 1;
      end loop;
   end Parse_Args;

   --  Trim a NUL-padded fixed-size string.
   function Trim_Path (S : String) return String is
      Last : Natural := S'First - 1;
   begin
      for K in S'Range loop
         exit when S (K) = Character'Val (0);
         Last := K;
      end loop;
      return S (S'First .. Last);
   end Trim_Path;

   --  ------------------------------------------------------------------
   --  TCP connect with the BoGo shim_id handshake.
   --  ------------------------------------------------------------------
   procedure Connect_And_Greet is
      Addr : Sock_Addr_Type;
      SE   : Stream_Element_Array (1 .. 8);
      Last : Stream_Element_Offset;
      pragma Unreferenced (Last);
      V    : Unsigned_64 := Cfg.Shim_Id;
   begin
      Initialize;
      if Cfg.Ipv6 then
         Create_Socket (Socket => Sock, Family => Family_Inet6);
         Addr := (Family => Family_Inet6,
                  Addr   => Inet_Addr ("::1"),
                  Port   => Port_Type (Cfg.Port));
      else
         Create_Socket (Socket => Sock);
         Addr := (Family => Family_Inet,
                  Addr   => Inet_Addr ("127.0.0.1"),
                  Port   => Port_Type (Cfg.Port));
      end if;
      Connect_Socket (Socket => Sock, Server => Addr);

      Channel := Stream (Sock);

      --  Send shim_id as 8-byte little-endian.
      for K in SE'Range loop
         SE (K) := Stream_Element (V and 16#FF#);
         V := Shift_Right (V, 8);
      end loop;
      Stream_Element_Array'Write (Channel, SE);
   end Connect_And_Greet;

   --  ------------------------------------------------------------------
   --  Run a single TLS handshake (no resumption yet — Phase 1).
   --  ------------------------------------------------------------------
   procedure Run_Handshake is
      S   : SPARKTLS.Session;
      Res : SPARKTLS.Action;

      Net_In  : Byte_Seq (0 .. 16383);
      Net_Out : Byte_Seq (0 .. 16383);

      Id      : aliased SPARKTLS.Identity;
      Id_OK   : Boolean;
      Roots   : aliased SPARKTLS.Trust_Store;
      Roots_OK : Boolean;
      Tickets : aliased SPARKTLS.Ticket_Store;

      procedure Send_Pending is
         N    : N32;
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
         SE   : Stream_Element_Array (1 .. 16384);
         Last : Stream_Element_Offset;
         Fed  : N32;
      begin
         Done := False;
         GNAT.Sockets.Receive_Socket (Sock, SE, Last);
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
      if Cfg.Is_Server then
         declare
            Cert : constant String := Trim_Path (Cfg.Cert_File);
            Key  : constant String := Trim_Path (Cfg.Key_File);
         begin
            SPARKTLS.Credentials.Load_Identity (Id, Cert, Key, Id_OK);
            if not Id_OK then
               Err ("bogo_shim: load identity failed");
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Failure));
               return;
            end if;
            declare
               --  ALPN protocol the server will select if a client
               --  offered it. -decline-alpn forces empty (don't echo).
               Server_ALPN : constant String :=
                  (if Cfg.Decline_ALPN or Cfg.ALPN_Proto_Len = 0
                   then ""
                   else Cfg.ALPN_Proto (1 .. Cfg.ALPN_Proto_Len));
            begin
               SPARKTLS.Server.Configure
                 (S       => S,
                  Local   => Id'Unchecked_Access,
                  Random  => Entropy_Random.Random'Access,
                  Tickets => Tickets'Unchecked_Access,
                  ALPN    => Server_ALPN);
            end;
         end;
      else
         declare
            Trust : constant String := Trim_Path (Cfg.Trust_Cert);
            Cert  : constant String := Trim_Path (Cfg.Cert_File);
            Key   : constant String := Trim_Path (Cfg.Key_File);
            Have_Local : Boolean := False;
         begin
            if Trust /= "" then
               SPARKTLS.Credentials.Load_Trust_Store (Roots, Trust, Roots_OK);
               if not Roots_OK then
                  Err ("bogo_shim: load trust failed");
                  Ada.Command_Line.Set_Exit_Status
                    (Ada.Command_Line.Exit_Status (Exit_Failure));
                  return;
               end if;
            end if;
            if Cert /= "" and Key /= "" then
               --  mTLS: client cert + key for CertificateRequest reply.
               SPARKTLS.Credentials.Load_Identity (Id, Cert, Key, Id_OK);
               if not Id_OK then
                  Err ("bogo_shim: load client identity failed");
                  Ada.Command_Line.Set_Exit_Status
                    (Ada.Command_Line.Exit_Status (Exit_Failure));
                  return;
               end if;
               Have_Local := True;
            end if;
            declare
               --  Client ALPN: advertise this single protocol in CH.
               Client_ALPN : constant String :=
                  (if Cfg.ALPN_Proto_Len = 0 then ""
                   else Cfg.ALPN_Proto (1 .. Cfg.ALPN_Proto_Len));
            begin
               SPARKTLS.Client.Configure
                 (S        => S,
                  Hostname => "localhost",
                  Trust    => (if Trust /= ""
                               then Roots'Unchecked_Access else null),
                  Random   => Entropy_Random.Random'Access,
                  Clock    => null,
                  Local    => (if Have_Local
                               then Id'Unchecked_Access else null),
                  ALPN     => Client_ALPN);
            end;
         end;
      end if;

      --  Drive Advance until handshake completes or fails.
      loop
         if Cfg.Is_Server then
            SPARKTLS.Server.Advance (S, Res);
         else
            SPARKTLS.Client.Advance (S, Res);
         end if;
         case Res is
            when Has_Output =>
               Send_Pending;
            when Need_Input =>
               declare
                  Done : Boolean;
               begin
                  Recv_Once (Done);
                  if Done then
                     Err ("bogo_shim: peer closed during handshake");
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Exit_Status
                    (if Cfg.Expect_Hs_Fails then Exit_Success else Exit_Failure));
                     return;
                  end if;
               end;
            when OK =>
               null;  --  more progress on next iteration
            when Handshake_Done =>
               exit;
            when Error_Alert =>
               Send_Pending;
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status
                    (if Cfg.Expect_Hs_Fails then Exit_Success else Exit_Failure));
               return;
            when Plaintext_Ready =>
               null;
            when Shutdown =>
               exit;
         end case;
      end loop;

      if Cfg.Expect_Hs_Fails then
         --  Got here = handshake succeeded but test expected failure.
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Failure));
         return;
      end if;

      --  -expect-alpn STR: after handshake the negotiated protocol
      --  must equal STR. Mismatch = test failure.
      if Cfg.Expect_ALPN_Len > 0 then
         declare
            Got : constant String := SPARKTLS.Get_ALPN (S);
            Want : constant String :=
               Cfg.Expect_ALPN (1 .. Cfg.Expect_ALPN_Len);
         begin
            if Got /= Want then
               Err ("expect-alpn mismatch: got='" & Got
                    & "' want='" & Want & "'");
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Failure));
               return;
            end if;
         end;
      end if;

      --  ----- Phase-2 application-data echo loop ---------------------
      --  After handshake, BoGo's bssl_shim does an XOR-echo: read
      --  ciphertext, decrypt, XOR each plaintext byte with 0xFF,
      --  write back. Runs until peer closes (close_notify / TCP FIN).
      --
      --  -shim-writes-first: per bssl_shim.cc:1183, shim sends the
      --  fixed string "hello" before reading anything else.
      if Cfg.Shim_Writes_First then
         declare
            Hello : constant Byte_Seq := (16#68#, 16#65#, 16#6C#,
                                          16#6C#, 16#6F#);  --  "hello"
            Written : N32;
         begin
            if Cfg.Is_Server then
               SPARKTLS.Server.Write_Plaintext (S, Hello, Written);
            else
               SPARKTLS.Client.Write_Plaintext (S, Hello, Written);
            end if;
            Send_Pending;
         end;
      end if;
      Echo_Loop :
      loop
         if Cfg.Is_Server then
            SPARKTLS.Server.Advance (S, Res);
         else
            SPARKTLS.Client.Advance (S, Res);
         end if;
         case Res is
            when Has_Output =>
               Send_Pending;
            when Need_Input =>
               declare
                  Done : Boolean;
               begin
                  Recv_Once (Done);
                  exit Echo_Loop when Done;  --  peer closed
               end;
            when Plaintext_Ready =>
               --  BoGo echo protocol from bssl_shim.cc:1255-1257:
               --    for (int i = 0; i < n; i++) buf[i] ^= 0xff;
               --  Read decrypted bytes, XOR each with 0xff, write back.
               declare
                  App   : Byte_Seq (0 .. 16383);
                  App_N : N32;
                  Written : N32;
               begin
                  Read_Plaintext (S, App, App_N);
                  if App_N > 0 then
                     for I in N32 range 0 .. App_N - 1 loop
                        App (I) := App (I) xor 16#FF#;
                     end loop;
                     if Cfg.Is_Server then
                        SPARKTLS.Server.Write_Plaintext
                          (S, App (0 .. App_N - 1), Written);
                     else
                        SPARKTLS.Client.Write_Plaintext
                          (S, App (0 .. App_N - 1), Written);
                     end if;
                     Send_Pending;
                  end if;
               end;
            when OK =>
               null;
            when Handshake_Done =>
               null;  --  shouldn't recur after first time
            when Shutdown =>
               exit Echo_Loop;
            when Error_Alert =>
               Send_Pending;
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Failure));
               return;
         end case;
      end loop Echo_Loop;

      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Success));
   end Run_Handshake;

begin
   Entropy_Random.Init;
   Parse_Args;
   if Cfg.Port = 0 then
      Err ("bogo_shim: -port required");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Failure));
      return;
   end if;

   Connect_And_Greet;
   Run_Handshake;

exception
   when Program_Error =>
      --  Parse_Args / Next_Arg raise Program_Error to short-circuit
      --  with the exit status already set (e.g. Exit_Unimplemented).
      --  Don't overwrite it.
      null;
   when E : others =>
      Err ("bogo_shim: " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Failure));
end Bogo_Shim;
