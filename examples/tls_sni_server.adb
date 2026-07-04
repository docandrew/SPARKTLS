--  Demonstrates SNI-based certificate selection (RFC 6066 §3 /
--  RFC 8446 §4.4.2.4): one TLS listener serving multiple
--  identities, picking the right cert based on the SNI hostname.
--
--  Usage:
--    tls_sni_server <default.crt> <default.key> <alt.crt> <alt.key>
--
--  Picks `alt.{crt,key}` for any SNI hostname containing "alt";
--  otherwise serves `default.{crt,key}`. Real deployments would use
--  a hostname → cert map (e.g., hash table or trie); this simple
--  substring check is just for exercising the API.

with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_SNI_Server is

   Id_Default : aliased SPARKTLS.Identity;
   Id_Alt     : aliased SPARKTLS.Identity;
   Id_Default_OK, Id_Alt_OK : Boolean;

   --  SNI selector: returns Id_Alt for any hostname containing "alt",
   --  Id_Default otherwise. Caller's responsibility is just to call
   --  the function with the bytes the client sent — we case-fold to
   --  lowercase before substring matching to be RFC 1035-friendly.
   function Pick_Identity (Server_Name : in String)
      return SPARKTLS.Selected_Identity_Access
   is
      Lower : String (Server_Name'Range);
   begin
      for I in Server_Name'Range loop
         declare
            C : constant Character := Server_Name (I);
         begin
            if C in 'A' .. 'Z' then
               Lower (I) := Character'Val
                              (Character'Pos (C) - Character'Pos ('A')
                               + Character'Pos ('a'));
            else
               Lower (I) := C;
            end if;
         end;
      end loop;

      for I in Lower'First .. Lower'Last - 2 loop
         if Lower (I .. I + 2) = "alt" then
            return Id_Alt'Unchecked_Access;
         end if;
      end loop;

      return Id_Default'Unchecked_Access;
   end Pick_Identity;

   Server_Sock : Socket_Type;

   procedure Handle_Connection (Client_Sock : Socket_Type) is
      S         : SPARKTLS.Session;
      Res       : SPARKTLS.Action;
      Read_Dead : Boolean := False;

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

      Server.Configure
        (S               => S,
         Local           => Id_Default'Unchecked_Access,
         Random          => Entropy_Random.Random'Access,
         Select_Identity => Pick_Identity'Unrestricted_Access);

      loop
         Server.Advance (S, Res);
         case Res is
            when Has_Output => Send_Output;
            when Need_Input =>
               if Read_Dead then exit; end if;
               Read_Input;
               if Read_Dead then exit; end if;
            when Handshake_Done => null;
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
                        Server.Write_Plaintext
                          (S, App (0 .. App_N - 1), Written);
                        Send_Output;
                     end;
                  end if;
               end;
            when Error_Alert =>
               begin Shutdown_Socket (Client_Sock, Shut_Write);
               exception when others => null;
               end;
               exit;
            when Shutdown =>
               Server.Close_Notify (S);
               Send_Output;
               exit;
            when others => null;
         end case;
      end loop;
   exception
      when E : others =>
         Put_Line ("  Connection error: "
                   & Ada.Exceptions.Exception_Message (E));
   end Handle_Connection;

   function Get_Port return Port_Type is
   begin
      if Ada.Environment_Variables.Exists ("SPARKTLS_PORT") then
         return Port_Type'Value
           (Ada.Environment_Variables.Value ("SPARKTLS_PORT"));
      end if;
      return 8443;
   end Get_Port;
   Port : constant Port_Type := Get_Port;
begin
   Entropy_Random.Init;

   if Ada.Command_Line.Argument_Count < 4 then
      Put_Line ("Usage: tls_sni_server "
                & "<default.crt> <default.key> <alt.crt> <alt.key>");
      return;
   end if;

   Credentials.Load_Identity
     (Id_Default,
      Ada.Command_Line.Argument (1),
      Ada.Command_Line.Argument (2),
      Id_Default_OK);
   if not Id_Default_OK then
      Put_Line ("Failed to load default identity");
      return;
   end if;

   Credentials.Load_Identity
     (Id_Alt,
      Ada.Command_Line.Argument (3),
      Ada.Command_Line.Argument (4),
      Id_Alt_OK);
   if not Id_Alt_OK then
      Put_Line ("Failed to load alt identity");
      return;
   end if;

   Put_Line ("=== SPARKTLS SNI Server ===");
   Put_Line ("Listening on 0.0.0.0:" & Port'Image);

   Initialize;
   Create_Socket (Server_Sock);
   Set_Socket_Option (Server_Sock, Socket_Level,
                      (Name => Reuse_Address, Enabled => True));
   Bind_Socket (Server_Sock,
                (Family => Family_Inet,
                 Addr   => Any_Inet_Addr,
                 Port   => Port));
   Listen_Socket (Server_Sock, 5);

   Put_Line ("Ready.");

   loop
      declare
         Client_Sock : Socket_Type;
         Client_Addr : Sock_Addr_Type;
      begin
         Accept_Socket (Server_Sock, Client_Sock, Client_Addr);
         Handle_Connection (Client_Sock);
         begin Shutdown_Socket (Client_Sock, Shut_Read_Write);
         exception when others => null;
         end;
         Close_Socket (Client_Sock);
      exception
         when E : others =>
            Put_Line ("Error: "
                      & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

exception
   when E : others =>
      Put_Line ("Fatal: " & Ada.Exceptions.Exception_Message (E));
end TLS_SNI_Server;
