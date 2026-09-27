--  Enter_Error_State zeroes a failed session's secrets at the moment it
--  fails, not when the application later drains the fatal alert and calls
--  Advance again. A connected session is fed a record that fails
--  authentication: the encrypted bad_record_mac alert must be queued, and
--  by then the traffic keys, the prepared write key and the exporter secret
--  must already be zero.
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with Test_Pool;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Server;
with SPARKTLS.Test_Support;
procedure Test_Error_State_Scrub is
   package TS renames SPARKTLS.Test_Support;
   Total : Natural := 0;
   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then raise Program_Error with What; end if;
      Total := Total + 1;
   end Check;

   procedure Exercise (Role : TLS_Role; Suite : Supported_Suite) is
      S       : Session (Role);
      --  application_data record, 32 bytes that no key authenticates
      Forged  : constant Byte_Seq (0 .. 36) :=
        (0 => 16#17#, 1 => 16#03#, 2 => 16#03#, 3 => 16#00#, 4 => 16#20#,
         others => 16#A5#);
      Fed     : N32;
      Result  : Action;
      Scratch : Byte_Seq (0 .. 4095);
      N       : N32;
   begin
      TS.Reset (S);
      TS.Install_Test_Traffic (S, Suite);
      TS.Set_Exporter_State (S, (others => 53), 32, (others => 59), (others => 61));
      Check (TS.Client_Keys (S).Key /= Bytes_32'(others => 0), "setup: no keys installed");

      Feed_Ciphertext (S, Forged, Fed);
      Check (Fed = Forged'Length, "forged record not accepted");
      if Role = Role_Client then
         SPARKTLS.Client.Advance (S, Test_Pool.Handshakes, Result);
      else
         SPARKTLS.Server.Advance (S, Test_Pool.Handshakes, Result);
      end if;

      Check (Result = Has_Output, "no alert reported");
      Check (State (S) = Error_State, "session did not fail");
      Check (Last_Error (S) = Bad_Record_MAC, "wrong error");
      Check (Output_Pending (S) > 0, "alert not queued before the scrub");
      Check (TS.Client_Keys (S).Key = Bytes_32'(others => 0)
             and TS.Client_Keys (S).IV = Bytes_12'(others => 0),
             "client traffic key kept while the alert is pending");
      Check (TS.Server_Keys (S).Key = Bytes_32'(others => 0)
             and TS.Server_Keys (S).IV = Bytes_12'(others => 0),
             "server traffic key kept while the alert is pending");
      Check (TS.Write_Cache_Erased (S), "prepared write key kept");
      Check (TS.Exporter_Secret (S) = SPARKTLS.Bytes_48'(others => 0), "exporter secret kept");

      Drain_Ciphertext (S, Scratch, N);
      Check (N > 0, "alert not drained");
      if Role = Role_Client then
         SPARKTLS.Client.Advance (S, Test_Pool.Handshakes, Result);
      else
         SPARKTLS.Server.Advance (S, Test_Pool.Handshakes, Result);
      end if;
      --  The server moves on to Closed; the client stays in Error_State.
      Check (Result = Error_Alert and State (S) in Error_State | Closed,
             "failed session did not settle");
   end Exercise;
begin
   for Role in TLS_Role loop
      Exercise (Role, Suite_AES_128_GCM_SHA256);
      Exercise (Role, Suite_AES_256_GCM_SHA384);
      Exercise (Role, Suite_ChaCha20_Poly1305_SHA256);
   end loop;
   Put_Line ("PASS: secrets zeroed on entering Error_State:" & Total'Image);
end Test_Error_State_Scrub;
