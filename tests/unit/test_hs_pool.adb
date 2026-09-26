--  SPARKTLS.Handshake_Pool: the application-sized pool of handshake slots.
--  A session takes a slot at Configure and gives it back when its handshake
--  ends or it is dropped; a full pool refuses the next session; a session
--  is only ever served from the pool it was configured with.
with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;

with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Server;
with Test_HS_Pool_Pools;   use Test_HS_Pool_Pools;
with Det_Random_Lib;

procedure Test_HS_Pool is

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   Id : aliased Identity := (Has_Identity => True, others => <>);

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

   function Start (Pool : in out Handshake_Pool) return Session is
     (SPARKTLS.Server.Configure ((Local => Id'Unchecked_Access, others => <>), Pool));

   S1, S2, S3, S4 : Server_Session;
   Res            : Action;
begin
   Put_Line ("--- SPARKTLS.Handshake_Pool ---");
   Det_Random_Lib.Reset;

   Check ("pool sizes as declared", Small.Size = 2 and Other.Size = 1);

   S1 := Start (Small);
   S2 := Start (Small);
   Check ("two sessions fill a two-slot pool",
          State (S1) = Wait_Client_Hello and State (S2) = Wait_Client_Hello);

   S3 := Start (Small);
   Check ("a full pool refuses the next session with No_Free_Sessions",
          State (S3) = Error_State and Last_Error (S3) = No_Free_Sessions);

   Drop (S1, Small);
   Check ("Drop closes the session", State (S1) = Closed);

   S4 := Start (Small);
   Check ("Drop gave the slot back: it serves the next session",
          State (S4) = Wait_Client_Hello);

   --  S2 holds slot 2, which a one-slot pool does not have.
   SPARKTLS.Server.Advance (S2, Other, Res);
   Check ("Advance refuses a slot outside the pool it is given",
          Res = Error_Alert and State (S2) = Error_State
          and Last_Error (S2) = Internal_Error);

   Drop (S2, Small);
   Drop (S4, Small);
   S1 := Start (Small);
   S2 := Start (Small);
   Check ("after Drop, the whole pool is free again",
          State (S1) = Wait_Client_Hello and State (S2) = Wait_Client_Hello);
   Drop (S1, Small);
   Drop (S2, Small);

   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HS_Pool;
