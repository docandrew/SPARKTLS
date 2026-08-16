with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;

with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Server;
with Det_Random_Lib;
with X509;

procedure Test_Validation_Config is

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   Roots : aliased Trust_Store;
   Id    : aliased Identity := (Has_Identity => True, others => <>);

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   function Fixed_Now return X509.Date_Time is
     ((Year => 2026, Month => 7, Day => 4,
       Hour => 0, Minute => 0, Second => 0));

   procedure Test_Client_Quick_Null_Trust_Fails_Closed is
      S : Session;
   begin
      SPARKTLS.Client.Configure
        (S        => S,
         Hostname => "example.com",
         Trust    => null,
         Random   => Det_Random_Lib.Det_Random'Access,
         Clock    => Fixed_Now'Unrestricted_Access);

      Check ("client Configure: null Trust fails closed",
             State (S) = Error_State);
   end Test_Client_Quick_Null_Trust_Fails_Closed;

   procedure Test_Client_Init_Null_Time_Fails_Closed is
      S   : Session;
      Cfg : Config;
   begin
      Cfg.Random := Det_Random_Lib.Det_Random'Access;
      Cfg.Trust := Roots'Unchecked_Access;
      Cfg.Get_Time := null;
      Cfg.Skip_Verify := False;

      SPARKTLS.Client.Init (S, Cfg);

      Check ("client Init: null Get_Time with verification fails closed",
             State (S) = Error_State);
   end Test_Client_Init_Null_Time_Fails_Closed;

   procedure Test_Client_Explicit_Skip_Verify_Allowed is
      S   : Session;
      Cfg : Config;
   begin
      Cfg.Random := Det_Random_Lib.Det_Random'Access;
      Cfg.Trust := null;
      Cfg.Get_Time := null;
      Cfg.Skip_Verify := True;

      SPARKTLS.Client.Init (S, Cfg);

      Check ("client Init: explicit Skip_Verify allows no Trust/Get_Time",
             State (S) = Client_Hello_Sent);
   end Test_Client_Explicit_Skip_Verify_Allowed;

   procedure Test_Server_MTLS_Null_Trust_Fails_Closed is
      S : Session;
   begin
      SPARKTLS.Server.Configure
        (S                   => S,
         Local               => Id'Unchecked_Access,
         Random              => Det_Random_Lib.Det_Random'Access,
         Trust               => null,
         Request_Client_Cert => True,
         Require_Client_Cert => True,
         Get_Time            => Fixed_Now'Unrestricted_Access);

      Check ("server Configure: mTLS with null Trust fails closed",
             State (S) = Error_State);
   end Test_Server_MTLS_Null_Trust_Fails_Closed;

   procedure Test_Server_MTLS_Null_Time_Fails_Closed is
      S : Session;
   begin
      SPARKTLS.Server.Configure
        (S                   => S,
         Local               => Id'Unchecked_Access,
         Random              => Det_Random_Lib.Det_Random'Access,
         Trust               => Roots'Unchecked_Access,
         Request_Client_Cert => True,
         Require_Client_Cert => True,
         Get_Time            => null);

      Check ("server Configure: mTLS with null Get_Time fails closed",
             State (S) = Error_State);
   end Test_Server_MTLS_Null_Time_Fails_Closed;

   procedure Test_Server_No_MTLS_Allows_Null_Trust_Time is
      S : Session;
   begin
      SPARKTLS.Server.Configure
        (S                   => S,
         Local               => Id'Unchecked_Access,
         Random              => Det_Random_Lib.Det_Random'Access,
         Trust               => null,
         Request_Client_Cert => False,
         Require_Client_Cert => False,
         Get_Time            => null);

      Check ("server Configure: no mTLS allows null Trust/Get_Time",
             State (S) = Wait_Client_Hello);
   end Test_Server_No_MTLS_Allows_Null_Trust_Time;

begin
   Put_Line ("--- SPARKTLS validation configuration ---");

   Test_Client_Quick_Null_Trust_Fails_Closed;
   Test_Client_Init_Null_Time_Fails_Closed;
   Test_Client_Explicit_Skip_Verify_Allowed;
   Test_Server_MTLS_Null_Trust_Fails_Closed;
   Test_Server_MTLS_Null_Time_Fails_Closed;
   Test_Server_No_MTLS_Allows_Null_Trust_Time;

   Put_Line
     ("=== validation_config:" & Pass'Image & " passed, "
      & Fail'Image & " failed ===");

   if Fail /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Validation_Config;
