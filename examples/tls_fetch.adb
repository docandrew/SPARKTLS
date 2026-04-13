--  tls_fetch - a toy curl/wget built on SPARKTLS
--
--  Usage:
--    tls_fetch https://example.com
--    tls_fetch https://example.com/path
--    tls_fetch https://example.com:8443/path
--
--  Performs a TLS 1.3 handshake, sends an HTTP/1.1 GET request,
--  and prints the response to stdout.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Numerics.Discrete_Random;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.System_Roots;

with X509;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Fetch is

   --  Clock callback for certificate validation
   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      S   : Day_Duration;
      Hr  : Natural;
      Mn  : Natural;
      Sc  : Natural;
   begin
      Split (Now, Y, Mo, D, S);
      Hr := Natural (S) / 3600;
      Mn := (Natural (S) mod 3600) / 60;
      Sc := Natural (S) mod 60;
      return (Year   => Y,
              Month  => Mo,
              Day    => D,
              Hour   => Hr,
              Minute => Mn,
              Second => Sc);
   end Current_Time;

   --  Simple PRNG (NOT CSPRNG - demo only)
   package Random_Byte is new
      Ada.Numerics.Discrete_Random (SPARKNaCl.Byte);

   Gen : Random_Byte.Generator;

   procedure My_Random (Output : out Byte_Seq) is
   begin
      for I in Output'Range loop
         Output (I) := Random_Byte.Random (Gen);
      end loop;
   end My_Random;

   --  Simple URL parser for https://host[:port][/path]
   procedure Parse_URL
     (URL      : in     String;
      Host     :    out String;
      Host_Len :    out Natural;
      Port     :    out GNAT.Sockets.Port_Type;
      Path     :    out String;
      Path_Len :    out Natural;
      OK       :    out Boolean)
   is
      Pos : Natural;
      Host_Start : Natural;
      Host_End   : Natural;
   begin
      Host     := (others => ' ');
      Host_Len := 0;
      Port     := 443;
      Path     := (others => ' ');
      Path_Len := 0;
      OK       := False;

      --  Must start with "https://"
      if URL'Length < 9 then
         return;
      end if;

      if URL (URL'First .. URL'First + 7) /= "https://" then
         Put_Line ("Error: only https:// URLs are supported");
         return;
      end if;

      Host_Start := URL'First + 8;

      --  Find end of host (: or / or end of string)
      Host_End := Host_Start;
      while Host_End <= URL'Last and then
            URL (Host_End) /= ':' and then
            URL (Host_End) /= '/'
      loop
         Host_End := Host_End + 1;
      end loop;
      Host_End := Host_End - 1;

      Host_Len := Host_End - Host_Start + 1;
      if Host_Len = 0 or Host_Len > Host'Length then
         Put_Line ("Error: invalid hostname");
         return;
      end if;
      Host (Host'First .. Host'First + Host_Len - 1) :=
         URL (Host_Start .. Host_End);

      Pos := Host_End + 1;

      --  Optional port
      if Pos <= URL'Last and then URL (Pos) = ':' then
         Pos := Pos + 1;
         declare
            Port_Start : constant Natural := Pos;
            Port_Val   : Natural := 0;
         begin
            while Pos <= URL'Last and then URL (Pos) in '0' .. '9' loop
               Port_Val := Port_Val * 10 +
                  Character'Pos (URL (Pos)) - Character'Pos ('0');
               Pos := Pos + 1;
            end loop;
            if Pos = Port_Start or Port_Val > 65535 then
               Put_Line ("Error: invalid port");
               return;
            end if;
            Port := GNAT.Sockets.Port_Type (Port_Val);
         end;
      end if;

      --  Path (everything from / onwards, or "/" if none)
      if Pos <= URL'Last and then URL (Pos) = '/' then
         Path_Len := URL'Last - Pos + 1;
         if Path_Len > Path'Length then
            Path_Len := Path'Length;
         end if;
         Path (Path'First .. Path'First + Path_Len - 1) :=
            URL (Pos .. Pos + Path_Len - 1);
      else
         Path (Path'First) := '/';
         Path_Len := 1;
      end if;

      OK := True;
   end Parse_URL;

   --  Convert a String to Byte_Seq
   function To_Bytes (S : String) return Byte_Seq is
      Result : Byte_Seq (0 .. N32 (S'Length) - 1);
   begin
      for I in S'Range loop
         Result (N32 (I - S'First)) := Byte (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   --  Read one TLS record from the socket and feed it to the session
   procedure Read_Record
     (Channel : Stream_Access;
      S       : in out Session;
      Net_Buf : in out Byte_Seq;
      Done    :    out Boolean)
   is
      N : N32;
   begin
      Done := False;
      Byte_Seq'Read (Channel, Net_Buf (0 .. 4));
      declare
         Rec_Len : constant N32 :=
            N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
      begin
         if Rec_Len > 0 and Rec_Len <= 16640 then
            Byte_Seq'Read (Channel, Net_Buf (5 .. 4 + Rec_Len));
            N := 5 + Rec_Len;
            SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);
         else
            Done := True;
         end if;
      end;
   exception
      when others =>
         Done := True;
   end Read_Record;

   --  Session and config
   S   : SPARKTLS.Session;
   Res : SPARKTLS.Action;

   --  Network I/O buffer
   Net_Buf : Byte_Seq (0 .. 16383);
   N       : N32;

   --  URL components
   Host     : String (1 .. 255) := (others => ' ');
   Host_Len : Natural;
   Port     : GNAT.Sockets.Port_Type;
   Path     : String (1 .. 4096) := (others => ' ');
   Path_Len : Natural;
   URL_OK   : Boolean;

   --  Socket
   Sock    : GNAT.Sockets.Socket_Type;
   Channel : Stream_Access;
   Addr    : GNAT.Sockets.Sock_Addr_Type;

   --  Trust store (loaded from OS)
   Roots      : aliased SPARKTLS.Trust_Store;
   Root_Count : Natural := 0;
   Roots_OK   : Boolean := False;

   --  Output control
   Verbose      : Boolean := False;
   Headers_Only : Boolean := False;
   Insecure     : Boolean := False;
   URL_Arg      : Natural := 0;

begin
   Random_Byte.Reset (Gen);

   --  Parse arguments
   for I in 1 .. Ada.Command_Line.Argument_Count loop
      declare
         Arg : constant String := Ada.Command_Line.Argument (I);
      begin
         if Arg = "-v" or Arg = "--verbose" then
            Verbose := True;
         elsif Arg = "-I" or Arg = "--head" then
            Headers_Only := True;
         elsif Arg = "-k" or Arg = "--insecure" then
            Insecure := True;
         elsif Arg (Arg'First) /= '-' then
            URL_Arg := I;
         end if;
      end;
   end loop;

   if URL_Arg = 0 then
      Put_Line ("Usage: tls_fetch [-v] [-I] [-k] <https://host[:port][/path]>");
      Put_Line ("  -v, --verbose   Show handshake details");
      Put_Line ("  -I, --head      Show response headers only");
      Put_Line ("  -k, --insecure  Skip certificate verification");
      return;
   end if;

   Parse_URL (Ada.Command_Line.Argument (URL_Arg),
              Host, Host_Len, Port, Path, Path_Len, URL_OK);

   if not URL_OK then
      return;
   end if;

   declare
      Hostname : constant String := Host (1 .. Host_Len);
      Pathstr  : constant String := Path (1 .. Path_Len);
   begin
      if Verbose then
         Put_Line ("* Host: " & Hostname);
         Put_Line ("* Port:" & Port'Image);
         Put_Line ("* Path: " & Pathstr);
      end if;

      null;  --  TLS configured below after TCP connect

      --  DNS resolve
      if Verbose then
         Put_Line ("* Resolving " & Hostname & "...");
      end if;

      GNAT.Sockets.Initialize;

      declare
         Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
            GNAT.Sockets.Get_Host_By_Name (Hostname);
      begin
         Addr := (Family => GNAT.Sockets.Family_Inet,
                  Addr   => GNAT.Sockets.Addresses (Host_Entry, 1),
                  Port   => Port);
      end;

      if Verbose then
         Put_Line ("* Connecting to " &
            GNAT.Sockets.Image (Addr) & "...");
      end if;

      --  TCP connect
      GNAT.Sockets.Create_Socket (Socket => Sock);
      GNAT.Sockets.Set_Socket_Option
        (Socket => Sock,
         Level  => GNAT.Sockets.Socket_Level,
         Option => (Name    => GNAT.Sockets.Receive_Timeout,
                    Timeout => 10.0));
      GNAT.Sockets.Connect_Socket (Socket => Sock, Server => Addr);

      Channel := GNAT.Sockets.Stream (Sock);

      if Verbose then
         Put_Line ("* Connected.");
      end if;

      --  Load system roots (unless -k)
      if not Insecure then
         SPARKTLS.System_Roots.Load (Roots, Root_Count, Roots_OK);
         if Verbose then
            Put_Line ("* Loaded" & Root_Count'Image & " root CAs");
         end if;
      end if;

      --  TLS handshake
      SPARKTLS.Client.Configure
        (S        => S,
         Hostname => Hostname,
         Trust    => (if Insecure or not Roots_OK
                      then null
                      else Roots'Unchecked_Access),
         Random   => My_Random'Unrestricted_Access,
         Clock    => Current_Time'Unrestricted_Access);

      Handshake : loop
         SPARKTLS.Client.Advance (S, Res);

         case Res is
            when SPARKTLS.Has_Output =>
               SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
               if N > 0 then
                  Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
               end if;

            when SPARKTLS.Need_Input =>
               declare
                  Done : Boolean;
               begin
                  Read_Record (Channel, S, Net_Buf, Done);
                  if Done then
                     Put_Line ("Error: connection closed during handshake");
                     GNAT.Sockets.Close_Socket (Sock);
                     return;
                  end if;
               end;

            when SPARKTLS.Handshake_Done =>
               if Verbose then
                  Put ("* TLS 1.3 handshake complete (");
                  case S.Negotiated_Suite is
                     when SPARKTLS.Suite_AES_128_GCM_SHA256 =>
                        Put ("TLS_AES_128_GCM_SHA256");
                     when SPARKTLS.Suite_CHACHA20_POLY1305_SHA256 =>
                        Put ("TLS_CHACHA20_POLY1305_SHA256");
                     when SPARKTLS.Suite_AES_256_GCM_SHA384 =>
                        Put ("TLS_AES_256_GCM_SHA384");
                     when others =>
                        Put ("0x" & S.Negotiated_Suite'Image);
                  end case;
                  Put_Line (")");
               end if;
               exit Handshake;

            when SPARKTLS.Plaintext_Ready =>
               --  Discard early data during handshake
               SPARKTLS.Read_Plaintext (S, Net_Buf, N);

            when SPARKTLS.Error_Alert =>
               Put_Line ("TLS error: " & S.Last_Error'Image);
               GNAT.Sockets.Close_Socket (Sock);
               return;

            when SPARKTLS.Shutdown =>
               Put_Line ("Error: server closed connection during handshake");
               GNAT.Sockets.Close_Socket (Sock);
               return;

            when SPARKTLS.OK =>
               null;
         end case;
      end loop Handshake;

      --  Drain any post-handshake messages (NewSessionTicket etc.)
      --  Use a short timeout so we don't block forever
      if S.State = SPARKTLS.Connected then
         GNAT.Sockets.Set_Socket_Option
           (Socket => Sock,
            Level  => GNAT.Sockets.Socket_Level,
            Option => (Name    => GNAT.Sockets.Receive_Timeout,
                       Timeout => 1.0));

         Post_HS : loop
            declare
               Done : Boolean;
            begin
               Read_Record (Channel, S, Net_Buf, Done);
               exit Post_HS when Done;
               SPARKTLS.Client.Advance (S, Res);
               if Res = SPARKTLS.Plaintext_Ready then
                  SPARKTLS.Read_Plaintext (S, Net_Buf, N);
               end if;
            end;
         end loop Post_HS;

         --  Restore longer timeout for response
         GNAT.Sockets.Set_Socket_Option
           (Socket => Sock,
            Level  => GNAT.Sockets.Socket_Level,
            Option => (Name    => GNAT.Sockets.Receive_Timeout,
                       Timeout => 10.0));
      end if;

      --  Build and send HTTP/1.1 GET request
      if S.State = SPARKTLS.Connected then
         declare
            Request : constant String :=
               "GET " & Pathstr & " HTTP/1.1" & ASCII.CR & ASCII.LF &
               "Host: " & Hostname & ASCII.CR & ASCII.LF &
               "User-Agent: tls_fetch/0.1 (SPARKTLS)" & ASCII.CR & ASCII.LF &
               "Accept: */*" & ASCII.CR & ASCII.LF &
               "Connection: close" & ASCII.CR & ASCII.LF &
               ASCII.CR & ASCII.LF;
            Req_Bytes : constant Byte_Seq := To_Bytes (Request);
            Written   : N32;
         begin
            if Verbose then
               Put_Line ("* Sending HTTP request...");
               declare
                  Lines : constant String := Request;
               begin
                  for I in Lines'Range loop
                     if Lines (I) /= ASCII.CR then
                        if Lines (I) = ASCII.LF then
                           New_Line (Standard_Error);
                        else
                           Put (Standard_Error, Lines (I));
                        end if;
                     end if;
                  end loop;
               end;
            end if;

            SPARKTLS.Client.Write_Plaintext (S, Req_Bytes, Written);
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
            end if;
         end;

         --  Receive and print the HTTP response
         declare
            App_Buf      : Byte_Seq (0 .. 16383);
            App_N        : N32;
            In_Headers   : Boolean := True;
            Done         : Boolean := False;
         begin
            Receive_Loop : loop
               exit Receive_Loop when Done;

               --  Read a TLS record
               Read_Record (Channel, S, Net_Buf, Done);
               exit Receive_Loop when Done;

               --  Process it
               Process_Loop : loop
                  SPARKTLS.Client.Advance (S, Res);

                  case Res is
                     when SPARKTLS.Plaintext_Ready =>
                        SPARKTLS.Read_Plaintext (S, App_Buf, App_N);
                        if App_N > 0 then
                           --  Print response bytes
                           for I in N32 range 0 .. App_N - 1 loop
                              declare
                                 C : constant Character :=
                                    Character'Val (App_Buf (I));
                              begin
                                 --  Track header/body boundary
                                 if In_Headers then
                                    Put (C);
                                    --  Detect end of headers (blank line)
                                    if I + 3 <= App_N - 1 and then
                                       App_Buf (I) = 16#0D# and then
                                       App_Buf (I + 1) = 16#0A# and then
                                       App_Buf (I + 2) = 16#0D# and then
                                       App_Buf (I + 3) = 16#0A#
                                    then
                                       In_Headers := False;
                                       --  Print the remaining CRLF
                                       Put (Character'Val (App_Buf (I + 1)));
                                       Put (Character'Val (App_Buf (I + 2)));
                                       Put (Character'Val (App_Buf (I + 3)));

                                       if not Headers_Only then
                                          --  Print rest of this chunk as body
                                          for J in N32 range I + 4 .. App_N - 1 loop
                                             Put (Character'Val (App_Buf (J)));
                                          end loop;
                                       end if;
                                       exit;
                                    end if;
                                 elsif not Headers_Only then
                                    Put (C);
                                 end if;
                              end;
                           end loop;
                        end if;

                     when SPARKTLS.Has_Output =>
                        SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
                        if N > 0 then
                           Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
                        end if;

                     when SPARKTLS.Shutdown =>
                        Done := True;
                        exit Process_Loop;

                     when SPARKTLS.Error_Alert =>
                        if S.Last_Error /= SPARKTLS.No_Error then
                           Put_Line (Standard_Error,
                              "TLS error: " & S.Last_Error'Image);
                        end if;
                        Done := True;
                        exit Process_Loop;

                     when SPARKTLS.Need_Input =>
                        exit Process_Loop;

                     when others =>
                        exit Process_Loop;
                  end case;
               end loop Process_Loop;
            end loop Receive_Loop;
         end;

         --  Clean shutdown
         if S.State = SPARKTLS.Connected then
            SPARKTLS.Client.Close_Notify (S);
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               begin
                  Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
               exception
                  when others => null;
               end;
            end if;
         end if;
      end if;

      GNAT.Sockets.Close_Socket (Sock);
   end;

exception
   when E : others =>
      Put_Line (Standard_Error,
         "Fatal: " & Ada.Exceptions.Exception_Message (E));
      begin
         GNAT.Sockets.Close_Socket (Sock);
      exception
         when others => null;
      end;
end TLS_Fetch;
