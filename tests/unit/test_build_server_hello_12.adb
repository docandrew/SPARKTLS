--  Build_Server_Hello_12: the server_name acknowledgement (RFC 6066 3)
--  is emitted iff Config.Ack_Server_Name and the client sent SNI.
--
--  Task 146 background: the emission guard used to test only Peer_SNI,
--  while the size accounting also tested Ack_Server_Name. The output was
--  still correct (the ack is four zero bytes over a zeroed buffer, and the
--  length excluded it), so this is a regression test for the visible
--  behaviour, not for the old dead store.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Handshake.TLS12;
with Det_Random_Lib;

procedure Test_Build_Server_Hello_12 is
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

   --  A minimal valid identity: Identity_Valid only asks for a non-empty
   --  certificate when Has_Identity and sane pool/RSA bounds.
   Id : aliased Identity;

   --  Build one TLS 1.2 ServerHello with the client having sent SNI and
   --  report whether the extensions block carries a server_name entry.
   procedure Run_Case
     (Ack     : in Boolean;
      Len     : out N32;
      Has_Ack : out Boolean)
   is
      HC     : Handshake_Context := (others => <>);
      ALPN   : Hostname_Buf;
      Result : Byte_Seq (0 .. 511) := (others => 0);
   begin
      HC.Cfg.Random          := Det_Random_Lib.Det_Random'Access;
      HC.Cfg.Local           := Id'Unchecked_Access;
      HC.Cfg.Ack_Server_Name := Ack;
      HC.Peer_SNI.Len        := 9;
      HC.Peer_SNI.Data (1 .. 9) := "localhost";

      SPARKTLS.Handshake.TLS12.Build_Server_Hello_12
        (Negotiated => Suite_ECDHE_RSA_AES128_GCM_SHA256,
         ALPN       => ALPN,
         HC         => HC,
         Result     => Result,
         Len        => Len);

      --  Walk the message: HS header (4), version (2), random (32),
      --  sid_len (1) + sid, suite (2), compression (1), ext_len (2), then
      --  (tag, len, body) entries. Report whether tag 0x0000 is present.
      Has_Ack := False;
      if Len >= 43 then
         declare
            Sid_Len : constant N32 := N32 (Result (38));
            Ext_Off : constant N32 := 4 + 2 + 32 + 1 + Sid_Len + 2 + 1;
         begin
            if Ext_Off + 2 <= Len then
               declare
                  Ext_Len : constant N32 :=
                    N32 (Result (Ext_Off)) * 256 + N32 (Result (Ext_Off + 1));
                  P       : N32 := Ext_Off + 2;
                  Ext_End : constant N32 := Ext_Off + 2 + Ext_Len;
               begin
                  Check ("extensions block ends exactly at the returned length",
                         Ext_End = Len);
                  while P + 4 <= Ext_End loop
                     declare
                        Tag  : constant N32 := N32 (Result (P)) * 256 + N32 (Result (P + 1));
                        ELen : constant N32 := N32 (Result (P + 2)) * 256 + N32 (Result (P + 3));
                     begin
                        if Tag = 0 and then ELen = 0 then
                           Has_Ack := True;
                        end if;
                        P := P + 4 + ELen;
                     end;
                  end loop;
               end;
            end if;
         end;
      end if;
   end Run_Case;

   Len     : N32;
   Has_Ack : Boolean;
begin
   Id.Has_Identity  := True;
   Id.NaCl_Cert_Len := 1;
   Id.Sign_Algo     := Sign_Ed25519;

   Put_Line ("Build_Server_Hello_12: server_name ack iff configured");

   Run_Case (Ack => False, Len => Len, Has_Ack => Has_Ack);
   Check ("Ack_Server_Name = False: a ServerHello of plausible length",
          Len in 42 .. 512);
   Check ("Ack_Server_Name = False: no server_name ack in the message",
          not Has_Ack);

   Run_Case (Ack => True, Len => Len, Has_Ack => Has_Ack);
   Check ("Ack_Server_Name = True: server_name ack present in the message",
          Has_Ack);

   Put_Line ("Total:" & Total'Image & "  Pass:" & Pass'Image & "  Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Build_Server_Hello_12;
