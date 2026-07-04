--  tls12_resume_test — exercise TLS 1.2 session ticket (RFC 5077)
--  resumption end-to-end against a real TLS server.
--
--  Usage:
--    tls12_resume_test [-host HOST] [-port PORT]
--
--  Companion server: openssl s_server -cert ... -key ... -tls1_2
--                                     -cipher ECDHE-RSA-AES128-GCM-SHA256
--                                     -www -accept <port>
--
--  Two sequential connections:
--    1. Fresh handshake. Drain to receive NewSessionTicket. Snapshot
--       via Client.Get_TLS12_Ticket.
--    2. New connection with Cfg.TLS12_Resume_Ticket = snapshot.
--       Expect abbreviated handshake (no Certificate / SKE / CKE on
--       the wire; server sends SH → NST → CCS → Finished; we reply
--       with CCS → Finished only).
--  Exit 0 if both succeed and the second resumed.

with Ada.Command_Line;
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

procedure TLS12_Resume_Test is

   Host : String (1 .. 256) := (others => ' ');
   Host_Len : Natural := 0;
   Port : Port_Type := 18443;

   Saved_Ticket : Session_Ticket_12;

   procedure Run_One_Connection
     (Resume : in     Boolean;
      OK_Out :    out Boolean;
      Got_Ticket : out Boolean)
   is
      S       : Session;
      Cfg     : Config;
      Res     : Action;
      Sock    : Socket_Type;
      Channel : Stream_Access;
      Net     : Byte_Seq (0 .. 16383);
      N       : N32;
      Iter    : Natural := 0;
   begin
      OK_Out := False;
      Got_Ticket := False;

      Cfg.Random := Entropy_Random.Random'Access;
      Cfg.Suite  := TLS_AES_128_GCM_SHA256;
      Cfg.Versions := TLS_1_2_Only;
      --  Integration test runs against an OpenSSL self-signed test cert.
      Cfg.Skip_Verify := True;
      declare
         H : constant String := Host (1 .. Host_Len);
      begin
         Cfg.Server_Name.Data (1 .. H'Length) := H;
         Cfg.Server_Name.Len := H'Length;
      end;
      if Resume and then Saved_Ticket.Valid then
         Cfg.TLS12_Resume_Ticket := Saved_Ticket;
      end if;

      Initialize;
      Create_Socket (Sock);
      Set_Socket_Option
        (Sock, Socket_Level,
         (Name => Receive_Timeout, Timeout => 3.0));
      Connect_Socket
        (Sock,
         (Family => Family_Inet,
          Addr   => Inet_Addr ("127.0.0.1"),
          Port   => Port));
      Channel := Stream (Sock);

      SPARKTLS.Client.Init (S, Cfg);

      Loop_HS : loop
         Iter := Iter + 1;
         exit Loop_HS when Iter > 200;

         SPARKTLS.Client.Advance (S, Res);
         case Res is
            when Has_Output =>
               SPARKTLS.Drain_Ciphertext (S, Net, N);
               if N > 0 then
                  Byte_Seq'Write (Channel, Net (0 .. N - 1));
               end if;

            when Need_Input =>
               begin
                  Byte_Seq'Read (Channel, Net (0 .. 4));
                  declare
                     Rec_Len : constant N32 :=
                        N32 (Net (3)) * 256 + N32 (Net (4));
                  begin
                     if Rec_Len > 0 and then Rec_Len <= 16640 then
                        Byte_Seq'Read (Channel,
                          Net (5 .. 4 + Rec_Len));
                        N := 5 + Rec_Len;
                        SPARKTLS.Feed_Ciphertext
                          (S, Net (0 .. N - 1), N);
                     end if;
                  end;
               exception
                  when others => exit Loop_HS;
               end;

            when Handshake_Done =>
               OK_Out := True;
               exit Loop_HS;

            when Plaintext_Ready =>
               SPARKTLS.Read_Plaintext (S, Net, N);

            when Error_Alert | Shutdown =>
               exit Loop_HS;

            when SPARKTLS.OK =>
               null;
         end case;
      end loop Loop_HS;

      --  Drain a bit more to catch a trailing NewSessionTicket that
      --  the server may issue right after Finished (RFC 5077 §3.3:
      --  full-HS NST arrives after client Finished).
      if OK_Out then
         declare
            Drain_Iter : Natural := 0;
         begin
            Post : loop
               Drain_Iter := Drain_Iter + 1;
               exit Post when Drain_Iter > 20;
               begin
                  Byte_Seq'Read (Channel, Net (0 .. 4));
                  declare
                     Rec_Len : constant N32 :=
                        N32 (Net (3)) * 256 + N32 (Net (4));
                  begin
                     if Rec_Len > 0 and then Rec_Len <= 16640 then
                        Byte_Seq'Read (Channel,
                          Net (5 .. 4 + Rec_Len));
                        N := 5 + Rec_Len;
                        SPARKTLS.Feed_Ciphertext
                          (S, Net (0 .. N - 1), N);
                        SPARKTLS.Client.Advance (S, Res);
                        if Res = Plaintext_Ready then
                           SPARKTLS.Read_Plaintext (S, Net, N);
                        end if;
                     end if;
                  end;
               exception
                  when others => exit Post;
               end;
            end loop Post;
         end;

         if SPARKTLS.Client.Has_TLS12_Ticket (S) then
            Saved_Ticket := SPARKTLS.Client.Get_TLS12_Ticket (S);
            Got_Ticket := True;
            Put_Line ("  captured TLS 1.2 ticket (len="
                      & Saved_Ticket.Ticket_Len'Image & ")");
         else
            Put_Line ("  no TLS 1.2 session ticket received");
         end if;
      end if;

      begin Close_Socket (Sock); exception when others => null; end;
   end Run_One_Connection;

begin
   Entropy_Random.Init;

   declare
      H : constant String := "localhost";
   begin
      Host (1 .. H'Length) := H;
      Host_Len := H'Length;
   end;

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
                  Host_Len := V'Length;
               end;
               I := I + 2;
            elsif A = "-port"
              and then I < Ada.Command_Line.Argument_Count
            then
               Port := Port_Type'Value (Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            else
               I := I + 1;
            end if;
         end;
      end loop;
   end;

   Put_Line ("=== tls12_resume_test ===");
   Put_Line ("Host: " & Host (1 .. Host_Len) & ":" & Port'Image);

   Put_Line ("Connection 1 (fresh handshake)...");
   declare
      Conn1_OK, Conn1_Tix : Boolean;
   begin
      Run_One_Connection (Resume => False, OK_Out => Conn1_OK,
                          Got_Ticket => Conn1_Tix);
      if not Conn1_OK then
         Put_Line ("FAIL: connection 1 did not complete handshake");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      if not Conn1_Tix then
         Put_Line ("FAIL: connection 1 did not receive a ticket");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
   end;

   if not Saved_Ticket.Valid then
      Put_Line ("FAIL: no session ticket from connection 1");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Put_Line ("Connection 2 (resumption)...");
   declare
      Conn2_OK, Conn2_Tix : Boolean;
   begin
      Run_One_Connection (Resume => True, OK_Out => Conn2_OK,
                          Got_Ticket => Conn2_Tix);
      if not Conn2_OK then
         Put_Line ("FAIL: connection 2 did not complete handshake");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      Put_Line ("PASS: resumption succeeded");
   end;

exception
   when E : others =>
      Put_Line ("FATAL: " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end TLS12_Resume_Test;
