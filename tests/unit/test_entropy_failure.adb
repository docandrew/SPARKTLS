--  A generator that returns nothing must be caught at the first draw:
--  the operation fails with Entropy_Failure and nothing derived from the
--  draw is used. The generator is SPARKTLS.RBG; it hands back nothing
--  once it has latched off (its entropy source failed) or before Init.
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Handshake.TLS13;
with SPARKTLS.RBG;
with SPARKTLS.RBG.Testing;
with SPARKTLS.Ticket_Keys;
with SPARKTLS.Test_Support;
with Det_Random_Lib;

procedure Test_Entropy_Failure is
   use type SPARKTLS.RBG.RBG_Status;
   Arena : aliased SPARKTLS.Arena_Bytes := (others => 0);

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

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

   --  An entropy source that has failed persistently.
   procedure Dead_Source (Output : out Byte_Seq; OK : out Boolean) is
   begin
      Output := (others => 0);
      OK := False;
   end Dead_Source;

   procedure Kill_Generator is
      OK : Boolean;
   begin
      SPARKTLS.RBG.Shutdown;
      SPARKTLS.RBG.Testing.Init_From (Dead_Source'Unrestricted_Access, OK);
      Check ("setup: generator latched (Init with a dead source fails)",
             not OK and then SPARKTLS.RBG.Status = SPARKTLS.RBG.Error);
   end Kill_Generator;

   procedure Test_Draw is
      Buf : Byte_Seq (0 .. 31);
      OK  : Boolean;
   begin
      SPARKTLS.RBG.Shutdown;
      Draw (Buf, OK);
      Check ("Draw: uninstantiated generator -> OK = False", not OK);
      Kill_Generator;
      Draw (Buf, OK);
      Check ("Draw: dead generator -> OK = False", not OK);
      Check ("Draw: dead generator -> output is all zero", (for all I in Buf'Range => Buf (I) = 0));
      Det_Random_Lib.Reset;
      Draw (Buf, OK);
      Check ("Draw: live generator -> OK = True", OK);
   end Test_Draw;

   procedure Build_SH (Live : Boolean; Len : out N32; Err : out Error_Code; SR_Zero : out Boolean) is
      S      : Server_Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. SPARKTLS.Handshake.TLS13.Max_Server_Hello - 1) := (others => 0);
   begin
      if Live then Det_Random_Lib.Reset; else Kill_Generator; end if;
      SPARKTLS.Test_Support.Reset (S);
      HC := (others => <>);
      HC.Client_Has_X25519 := True;
      HC.KE.Peer_PK        := (others => 16#01#);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (Suite_AES_128_GCM_SHA256, HC, Arena, Result, Len);
      Err := HC.Ext_Parse_Err;
      SR_Zero := (for all I in HC.Server_Random'Range => HC.Server_Random (I) = 0);
   end Build_SH;

   procedure Test_Server_Hello is
      Len : N32; Err : Error_Code; SR_Zero : Boolean;
   begin
      Build_SH (False, Len, Err, SR_Zero);
      Check ("ServerHello: dead generator -> no message", Len = 0);
      Check ("ServerHello: dead generator -> Entropy_Failure recorded", Err = Entropy_Failure);
      Check ("ServerHello: dead generator -> no server random kept", SR_Zero);
      Build_SH (True, Len, Err, SR_Zero);
      Check ("ServerHello: live generator -> message built", Len > 4);
   end Test_Server_Hello;

   procedure Test_Ticket_Keys is
      Key_ID : Byte_Seq (0 .. 3);
      TEK    : Byte_Seq (0 .. 31);
      Found  : Boolean;
   begin
      Kill_Generator;
      SPARKTLS.Ticket_Keys.Initialize (Clock => null, Rotation_Interval => 0);
      SPARKTLS.Ticket_Keys.Get_Active_TEK (Key_ID, TEK, Found);
      Check ("Ticket keys: dead generator -> no sealing key installed", not Found);
   end Test_Ticket_Keys;

   procedure Test_Alert_Mapping is
   begin
      Check ("Entropy_Failure -> alert 80 (internal_error)",
             Expected_Alert_Desc (Entropy_Failure) = 80);
   end Test_Alert_Mapping;

begin
   Put_Line ("--- entropy failure: dead generator fails closed ---");
   Test_Draw;
   Test_Server_Hello;
   Test_Ticket_Keys;
   Test_Alert_Mapping;
   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image
             & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Entropy_Failure;
