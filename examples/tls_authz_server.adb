--  Reference implementation: client-certificate authorization through the
--  application verification hook (Config.Verify_Peer) on the server side.
--
--  The proven core validates the client's chain to the configured CA and
--  enforces clientAuth EKU. Only when that has passed does the hook run,
--  and it decides WHICH authenticated clients may connect: the leaf's
--  subject CN or a SAN dNSName must be on the --allow list. Everything
--  else is vetoed with bad_certificate. No --allow entry means nobody is
--  authorized (fail closed). Each decision is logged, which is also where
--  a deployment would put its out-of-band revocation check.
--
--  Usage: tls_authz_server <cert.pem> <key.pem> <client-ca.pem>
--                          [--allow NAME]...
--  Port: SPARKTLS_PORT (default 8443). Echoes application data.

with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Characters.Handling;
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
with Entropy_Random;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Authz_Server is

   Id       : aliased SPARKTLS.Identity;
   Id_OK    : Boolean;
   Roots    : aliased SPARKTLS.Trust_Store;
   Roots_OK : Boolean;

   Max_Allowed : constant := 16;
   subtype Name_Buf is String (1 .. 256);
   type Name_List is array (1 .. Max_Allowed) of Name_Buf;
   type Len_List  is array (1 .. Max_Allowed) of Natural;
   Allowed     : Name_List := (others => (others => ' '));
   Allowed_Len : Len_List := (others => 0);
   Allowed_Count : Natural := 0;

   --  UTC wall clock for certificate validity (see tls_blocking_server).
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
      Ada.Calendar.Formatting.Split
        (T, Y, M, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y,
              Month  => M,
              Day    => D,
              Hour   => Hr,
              Minute => Mn,
              Second => Sc);
   end Now_UTC;

   function Get_Port return Port_Type is
   begin
      if Ada.Environment_Variables.Exists ("SPARKTLS_PORT") then
         return Port_Type'Value
           (Ada.Environment_Variables.Value ("SPARKTLS_PORT"));
      end if;
      return 8443;
   end Get_Port;
   Port : constant Port_Type := Get_Port;

   function Span_Text (DER : X509.Byte_Seq; Sp : X509.Span) return String is
      use type X509.N32;
   begin
      if not Sp.Present or else Sp.Last < Sp.First or else Sp.Last > DER'Last
      then
         return "";
      end if;
      declare
         R : String (1 .. Natural (Sp.Last - Sp.First + 1));
      begin
         for I in Sp.First .. Sp.Last loop
            R (Natural (I - Sp.First) + 1) := Character'Val (DER (I));
         end loop;
         return R;
      end;
   end Span_Text;

   function Is_Allowed (Name : String) return Boolean is
      Lower : constant String := Ada.Characters.Handling.To_Lower (Name);
   begin
      for I in 1 .. Allowed_Count loop
         if Allowed (I) (1 .. Allowed_Len (I)) = Lower then
            return True;
         end if;
      end loop;
      return False;
   end Is_Allowed;

   ---------------------------------------------------------------------------
   --  The authorization hook. The core has already validated the chain to
   --  the client CA and checked clientAuth EKU; this decides who may enter.
   ---------------------------------------------------------------------------

   function Authorize_Client
     (Leaf_DER  : X509.Byte_Seq;
      Leaf      : X509.Certificate;
      Ints       : SPARKTLS.Cert_Pool;
      Int_Count  : Natural;
      Anchor_DER : X509.Byte_Seq;
      Anchor     : X509.Certificate;
      Hostname   : String;
      Purpose    : SPARKTLS.Validation_Purpose) return Boolean
   is
      pragma Unreferenced (Ints, Anchor_DER, Anchor, Hostname, Purpose);
      CN : constant String :=
        (if X509.Has_Subject_CN (Leaf)
         then Span_Text (Leaf_DER, X509.Subject_CN (Leaf))
         else "");
      Granted : Boolean := Is_Allowed (CN);
   begin
      if not Granted then
         for I in 1 .. X509.SAN_Count (Leaf) loop
            if Is_Allowed (Span_Text (Leaf_DER, X509.SAN_DNS (Leaf, I))) then
               Granted := True;
            end if;
         end loop;
      end if;
      Put_Line ("AUTHZ " & (if Granted then "accept" else "deny")
                & " subject CN='" & CN & "' intermediates="
                & Int_Count'Image);
      return Granted;
   end Authorize_Client;

   ---------------------------------------------------------------------------

   Server_Sock : Socket_Type;

   procedure Handle_Connection (Client_Sock : Socket_Type) is
      S          : SPARKTLS.Server_Session;
      Res        : SPARKTLS.Action;
      Read_Dead  : Boolean := False;
      Write_Dead : Boolean := False;

      Net_In  : Byte_Seq (0 .. 16383);
      Net_Out : Byte_Seq (0 .. 16383);

      procedure Send_Output is
         N    : N32;
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
      Set_Socket_Option
        (Client_Sock, Socket_Level,
         (Name => Receive_Timeout, Timeout => 10.0));
      Set_Socket_Option
        (Client_Sock, IP_Protocol_For_TCP_Level,
         (Name => No_Delay, Enabled => True));

      --  Request AND require a client certificate; the core validates it
      --  against Roots (the client CA) and the hook then authorizes it.
      --  Skip_Verify stays False: the hook only narrows a verified chain.
      S := Server.Configure
        ((Local               => Id'Unchecked_Access,
          Random              => Entropy_Random.Random'Access,
          Trust               => Roots'Unchecked_Access,
          Request_Client_Cert => True,
          Require_Client_Cert => True,
          Verify_Peer         => Authorize_Client'Unrestricted_Access,
          Get_Time            => Now_UTC'Unrestricted_Access,
          others              => <>));

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
               null;

            when Plaintext_Ready =>
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
               begin
                  Shutdown_Socket (Client_Sock, Shut_Write);
               exception
                  when others => null;
               end;
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

   if Ada.Command_Line.Argument_Count < 3 then
      Put_Line ("Usage: tls_authz_server <cert.pem> <key.pem> <client-ca.pem>"
                & " [--allow NAME]...");
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

   Credentials.Load_Trust_Store
     (Roots, Ada.Command_Line.Argument (3), Roots_OK);
   if not Roots_OK then
      Put_Line ("Failed to load client CA: " & Ada.Command_Line.Argument (3));
      return;
   end if;

   declare
      I : Natural := 4;
   begin
      while I <= Ada.Command_Line.Argument_Count loop
         if Ada.Command_Line.Argument (I) = "--allow"
           and then I < Ada.Command_Line.Argument_Count
           and then Allowed_Count < Max_Allowed
         then
            declare
               V : constant String := Ada.Characters.Handling.To_Lower
                 (Ada.Command_Line.Argument (I + 1));
            begin
               if V'Length in 1 .. Name_Buf'Length then
                  Allowed_Count := Allowed_Count + 1;
                  Allowed (Allowed_Count) (1 .. V'Length) := V;
                  Allowed_Len (Allowed_Count) := V'Length;
               end if;
            end;
            I := I + 2;
         else
            Put_Line ("Ignoring unknown argument: "
                      & Ada.Command_Line.Argument (I));
            I := I + 1;
         end if;
      end loop;
   end;

   Put_Line ("=== SPARKTLS Authz Server ===");
   Put_Line ("Client CA: " & Ada.Command_Line.Argument (3));
   if Allowed_Count = 0 then
      Put_Line ("No --allow entries: every authenticated client is denied.");
   else
      for I in 1 .. Allowed_Count loop
         Put_Line ("Allow: " & Allowed (I) (1 .. Allowed_Len (I)));
      end loop;
   end if;
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
end TLS_Authz_Server;
