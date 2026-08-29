--  Unit test for client-side TLS 1.3 PSK resumption wiring.
--
--  Verifies that:
--    1. A Session_Ticket placed in Cfg.Resume_Ticket flows through
--       Init into the session ticket (see Client.Get_Session_Ticket).
--    2. The resulting ClientHello contains the pre_shared_key
--       extension (tag 0x0029) and a psk_key_exchange_modes
--       extension (tag 0x002D).
--    3. The handshake context records that PSK was offered
--       (HC.PSK.Offered = True), which is the gate Tag_Is_Offered
--       uses to permit a server pre_shared_key echo.
--
--  Does NOT exercise the full PSK round-trip — that's an integration
--  concern (run against OpenSSL s_server / BoringSSL). This test
--  catches regressions in the local wiring without needing a network.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Tickets_12;
with Det_Random_Lib;
with X509;
with SPARKTLS.Test_Support;

procedure Test_PSK_Resume is

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

   Now_Second : Natural := 0;

   --  Fixed clock for the test (no cert validation needed at CH time).
   function Fixed_Now return X509.Date_Time is
     ((Year => 2026, Month => 5, Day => 15,
       Hour => 0, Minute => 0, Second => Now_Second));

   --  Build a synthetic Session_Ticket. The PSK bytes are arbitrary;
   --  the test only checks that the ticket flows through to the
   --  wire and that the binder + PSK-ext block is emitted.
   function Make_Ticket return Session_Ticket is
      T : Session_Ticket;
   begin
      T.Ticket_Len := 32;
      for I in N32 range 0 .. 31 loop
         T.Ticket (I) := Byte (I);  --  arbitrary ticket bytes
      end loop;
      T.Lifetime := 7200;
      T.Age_Add  := 16#DEADBEEF#;
      T.Received_At := SPARKTLS.Tickets_12.To_Unix_Seconds
        ((Year => 2026, Month => 5, Day => 15,
          Hour => 0, Minute => 0, Second => 0));
      T.PSK_Len  := 32;
      for I in N32 range 0 .. 31 loop
         T.PSK (I) := Byte (16#A0# + (Natural (I) mod 16));
      end loop;
      T.Suite := Wire_Suite_AES_128_GCM_SHA256;
      declare
         H : constant String := "localhost";
      begin
         T.Server_Name.Data (1 .. H'Length) := H;
         T.Server_Name.Len := H'Length;
      end;
      T.Valid := True;
      return T;
   end Make_Ticket;

   --  Search the CH bytes for an extension with the given tag.
   --  Returns position of the first byte of `extension_data` if
   --  found, or -1 if not.  CH layout:
   --    type(1=0x01) + len(3) + version(2) + random(32) + sid_len(1)
   --    + sid(0..32) + suites_len(2) + suites(N) + comp_len(1)
   --    + comp(N) + ext_len(2) + extensions(M)
   --  Returns Not_Found (= 0; valid positions are always >= 4) when
   --  the tag isn't present.  N32 is non-negative so we can't use -1.
   Not_Found : constant N32 := 0;

   function Find_Ext (CH : Byte_Seq; Tag : Unsigned_16) return N32 is
      P : N32 := CH'First + 4;  --  past handshake header
      Sid_Len, Suites_Len, Comp_Len, Ext_Total : N32;
   begin
      if N32 (CH'Length) < 39 then
         return Not_Found;
      end if;
      P := P + 2 + 32;            --  past version + random
      Sid_Len := N32 (CH (P));
      P := P + 1 + Sid_Len;       --  past sid
      Suites_Len := N32 (CH (P)) * 256 + N32 (CH (P + 1));
      P := P + 2 + Suites_Len;
      Comp_Len := N32 (CH (P));
      P := P + 1 + Comp_Len;
      Ext_Total := N32 (CH (P)) * 256 + N32 (CH (P + 1));
      P := P + 2;
      declare
         Ext_End : constant N32 := P + Ext_Total;
      begin
         while P + 4 <= Ext_End loop
            declare
               T_U : constant Unsigned_16 :=
                  Unsigned_16 (CH (P)) * 256 + Unsigned_16 (CH (P + 1));
               D_Len : constant N32 :=
                  N32 (CH (P + 2)) * 256 + N32 (CH (P + 3));
            begin
               if T_U = Tag then
                  return P + 4;
               end if;
               P := P + 4 + D_Len;
            end;
         end loop;
      end;
      return Not_Found;
   end Find_Ext;

   S   : Session;
   Cfg : Config;

begin
   Put_Line ("=== TLS 1.3 PSK resumption client-side wiring ===");

   --  Set up a minimal client Config with a resumption ticket.
   Cfg.Random := Det_Random_Lib.Det_Random'Access;
   declare
      H : constant String := "localhost";
   begin
      Cfg.Server_Name.Data (1 .. H'Length) := H;
      Cfg.Server_Name.Len := H'Length;
   end;
   Cfg.Resume_Ticket := Make_Ticket;
   Cfg.Get_Time := Fixed_Now'Unrestricted_Access;
   Now_Second := 10;

   --  Init builds CH and queues it in S.Output.
   SPARKTLS.Client.Init (S, Cfg);

   Check ("Init sets Client_Hello_Sent state",
          State (S) = Client_Hello_Sent);
   Check ("Output_Pending > 0 after Init",
          Output_Pending (S) > 0);
   Check ("Cfg.Resume_Ticket flows into the session ticket",
          SPARKTLS.Client.Get_Session_Ticket (S).Valid
          and then SPARKTLS.Client.Get_Session_Ticket (S).PSK_Len = 32);

   --  Drain the CH and inspect.
   declare
      Net_Buf : Byte_Seq (0 .. 16383);
      N       : N32;
   begin
      Drain_Ciphertext (S, Net_Buf, N);
      Check ("CH drained (N > 0)", N > 0);

      --  Skip 5-byte record header to get to the handshake message.
      --  Net_Buf (0)=0x16 (handshake), Net_Buf (1..2)=record version,
      --  Net_Buf (3..4)=record length.
      if N > 5 then
         declare
            CH : Byte_Seq (0 .. N - 6) := Net_Buf (5 .. N - 1);
            PSK_Pos : constant N32 := Find_Ext (CH, 16#0029#);
            PSK_KEM_Pos : constant N32 := Find_Ext (CH, 16#002D#);
         begin
            Check ("ClientHello contains pre_shared_key (0x0029)",
                   PSK_Pos /= Not_Found);
            Check ("ClientHello contains psk_key_exchange_modes (0x002D)",
                   PSK_KEM_Pos /= Not_Found);
            --  pre_shared_key body: identities (2-byte len) +
            --  identities + binders (2-byte len) + binders.
            if PSK_Pos /= Not_Found then
               --  First identity: ticket_len(2) + ticket + age(4).
               --  Identities outer length (2 bytes) + ticket_len(2)
               --  should be at PSK_Pos+2..PSK_Pos+3.
               declare
                  Ticket_Len_Field : constant N32 :=
                     N32 (CH (PSK_Pos + 2)) * 256 +
                     N32 (CH (PSK_Pos + 3));
               begin
                  Check ("PSK identity carries 32-byte ticket",
                         Ticket_Len_Field = 32);
               end;

               if PSK_Pos + 39 <= N32 (CH'Last) then
                  declare
                     Age : constant Unsigned_32 :=
                       Unsigned_32 (CH (PSK_Pos + 36)) * 2**24
                       + Unsigned_32 (CH (PSK_Pos + 37)) * 2**16
                       + Unsigned_32 (CH (PSK_Pos + 38)) * 2**8
                       + Unsigned_32 (CH (PSK_Pos + 39));
                  begin
                     Check ("PSK identity age includes elapsed ticket age",
                            Age = 16#DEADE5FF#);
                  end;
               else
                  Check ("PSK identity age field present", False);
               end if;
            end if;
         end;
      end if;
   end;

   --  Verify HC.PSK.Offered flag is set (so the matrix lets server
   --  echo pre_shared_key).
   Check ("HC.PSK.Offered = True after Init with valid ticket",
          SPARKTLS.Test_Support.PSK_Offered (S));

   declare
      S_Mismatch   : Session;
      Cfg_Mismatch : Config := Cfg;
      H            : constant String := "example.com";
      Net          : Byte_Seq (0 .. 16383);
      Drained      : N32;
      Has_PSK      : Boolean := False;
   begin
      Cfg_Mismatch.Server_Name :=
        (Len => 0, Data => (others => ' '));
      Cfg_Mismatch.Server_Name.Data (1 .. H'Length) := H;
      Cfg_Mismatch.Server_Name.Len := H'Length;
      Cfg_Mismatch.Skip_Verify := True;

      SPARKTLS.Client.Init (S_Mismatch, Cfg_Mismatch);
      Drain_Ciphertext (S_Mismatch, Net, Drained);
      if Drained > 5 then
         Has_PSK := Find_Ext (Net (5 .. Drained - 1), 16#0029#) /= Not_Found;
      end if;
      Check ("mismatched ticket hostname is not offered",
             not SPARKTLS.Client.Get_Session_Ticket (S_Mismatch).Valid
             and then SPARKTLS.Test_Support.Has_Handshake_Context (S_Mismatch)
             and then not SPARKTLS.Test_Support.PSK_Offered (S_Mismatch)
             and then not Has_PSK);
   end;

   --  0-RTT is intentionally not supported (see Cfg.Resume_Ticket
   --  comment in sparktls.ads). The CH must NEVER carry the
   --  early_data extension (0x002A), even when resuming.
   declare
      S2      : Session;
      Cfg2    : constant Config := Cfg;
      Net     : Byte_Seq (0 .. 16383);
      Drained : N32;
      No_ED   : Boolean := True;
   begin
      SPARKTLS.Client.Init (S2, Cfg2);
      Drain_Ciphertext (S2, Net, Drained);
      if Drained > 5 then
         No_ED := Find_Ext (Net (5 .. Drained - 1), 16#002A#) = Not_Found;
      end if;
      Check ("CH does not contain early_data ext (0x002A)", No_ED);
   end;

   Put_Line ("");
   Put_Line ("=== Total:" & Total'Image &
             " Pass:" & Pass'Image &
             " Fail:" & Fail'Image & " ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_PSK_Resume;
