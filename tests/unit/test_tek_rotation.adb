--  Unit test for the TLS 1.2 TEK rotation primitive
--  (SPARKTLS.Server.Rotate_TLS12_Ticket_Key). Verifies:
--    1. Active index advances by 1 (mod TLS12_Max_Keys).
--    2. New key lands in the new active slot with the supplied
--       Key_ID, TEK, and Created_At.
--    3. Previously-active slot retains Valid=True (grace window).
--    4. After TLS12_Max_Keys rotations, the original key is fully
--       overwritten and no longer present.
--    5. Round-trip via Tickets_12: a ticket issued under key A
--       still decrypts after rotation to key B (grace window
--       semantics).

with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;         use Interfaces;
with SPARKNaCl;          use SPARKNaCl;
with SPARKTLS;           use SPARKTLS;
with SPARKTLS.Server;
with SPARKTLS.Tickets_12;

procedure Test_TEK_Rotation is

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

   Keys : TLS12_Ticket_Key_Array;
   Active : Natural := 0;

begin
   Put_Line ("=== Test_TEK_Rotation ===");

   --  Seed: slot 0 with Key_ID = 01 02 03 04, TEK all 0xAA,
   --  Created_At = 1000.
   Keys (0) :=
     (Key_ID     => (16#01#, 16#02#, 16#03#, 16#04#),
      TEK        => (others => 16#AA#),
      Valid      => True,
      Created_At => 1000);
   for I in 1 .. TLS12_Max_Keys - 1 loop
      Keys (I) := (Key_ID => (others => 0), TEK => (others => 0),
                   Valid => False, Created_At => 0);
   end loop;

   --  Rotate in a new key at Now=2000.
   declare
      New_ID  : constant Byte_Seq (0 .. 3)  := (16#11#, 16#22#, 16#33#, 16#44#);
      New_TEK : constant Byte_Seq (0 .. 31) := (others => 16#BB#);
   begin
      SPARKTLS.Server.Rotate_TLS12_Ticket_Key
        (Keys       => Keys,
         Active_Idx => Active,
         New_Key_ID => New_ID,
         New_TEK    => New_TEK,
         Now_Secs   => 2000);
   end;

   Check ("rotation 1: Active moved to slot 1",
          Active = 1);
   Check ("rotation 1: new key Key_ID lands in slot 1",
          Keys (1).Key_ID = Byte_Seq'(16#11#, 16#22#, 16#33#, 16#44#));
   Check ("rotation 1: new key TEK lands in slot 1",
          Keys (1).TEK = Byte_Seq'(0 .. 31 => 16#BB#));
   Check ("rotation 1: new key Created_At = 2000",
          Keys (1).Created_At = 2000);
   Check ("rotation 1: new key Valid",
          Keys (1).Valid);

   Check ("rotation 1: prior slot 0 still has its Key_ID (grace)",
          Keys (0).Key_ID = Byte_Seq'(16#01#, 16#02#, 16#03#, 16#04#));
   Check ("rotation 1: prior slot 0 still Valid (grace decrypt)",
          Keys (0).Valid);
   Check ("rotation 1: prior slot 0 Created_At unchanged",
          Keys (0).Created_At = 1000);

   --  Rotate again: new key goes to slot 2.
   declare
      New_ID  : constant Byte_Seq (0 .. 3)  := (16#A1#, 16#A2#, 16#A3#, 16#A4#);
      New_TEK : constant Byte_Seq (0 .. 31) := (others => 16#CC#);
   begin
      SPARKTLS.Server.Rotate_TLS12_Ticket_Key
        (Keys       => Keys,
         Active_Idx => Active,
         New_Key_ID => New_ID,
         New_TEK    => New_TEK,
         Now_Secs   => 3000);
   end;
   Check ("rotation 2: Active moved to slot 2",
          Active = 2);
   Check ("rotation 2: slot 0 (original) still present",
          Keys (0).Key_ID = Byte_Seq'(16#01#, 16#02#, 16#03#, 16#04#));

   --  Rotate twice more — after 4 total rotations the original
   --  key in slot 0 should be overwritten.
   for I in 1 .. 2 loop
      declare
         New_ID  : constant Byte_Seq (0 .. 3)  :=
           (Byte (I), Byte (I), Byte (I), Byte (I));
         New_TEK : constant Byte_Seq (0 .. 31) := (others => Byte (I));
      begin
         SPARKTLS.Server.Rotate_TLS12_Ticket_Key
           (Keys       => Keys,
            Active_Idx => Active,
            New_Key_ID => New_ID,
            New_TEK    => New_TEK,
            Now_Secs   => Unsigned_64 (4000 + I * 1000));
      end;
   end loop;

   Check ("rotation 4: original Key_ID (01 02 03 04) is overwritten",
          Keys (0).Key_ID /= Byte_Seq'(16#01#, 16#02#, 16#03#, 16#04#));

   --  Round-trip: encrypt a ticket under the current active key,
   --  rotate, verify the ticket still decrypts via grace window.
   declare
      package T renames SPARKTLS.Tickets_12;

      Plain_In : T.Ticket_Plain :=
        (Master_Secret => (others => 16#42#),
         Suite         => 16#C02F#,
         Created_At    => 100,
         SID_Len       => 0,
         SID           => (others => 0));

      Ticket   : Byte_Seq (0 .. 255) := (others => 0);
      Tk_Len   : N32;

      Plain_Out : T.Ticket_Plain;
      Status    : Boolean;

      Nonce    : constant T.Bytes_12 := (others => 16#33#);
      Cur_ID   : T.Bytes_4;
      Cur_TEK  : T.Bytes_32;
   begin
      --  Capture current active key
      for I in N32 range 0 .. 3 loop
         Cur_ID (I) := Keys (Active).Key_ID (I);
      end loop;
      for I in N32 range 0 .. 31 loop
         Cur_TEK (I) := Keys (Active).TEK (I);
      end loop;

      T.Encrypt_Ticket
        (Plain      => Plain_In,
         Key_ID     => Cur_ID,
         TEK        => Cur_TEK,
         Nonce      => Nonce,
         Ticket     => Ticket,
         Ticket_Len => Tk_Len);
      Check ("round-trip: encrypt produced bytes",
             Tk_Len > 0);

      --  Rotate one more time → the encrypting key is no longer
      --  active but still present in the array.
      declare
         New_ID  : constant Byte_Seq (0 .. 3)  := (16#FE#, 16#FE#, 16#FE#, 16#FE#);
         New_TEK : constant Byte_Seq (0 .. 31) := (others => 16#FE#);
      begin
         SPARKTLS.Server.Rotate_TLS12_Ticket_Key
           (Keys       => Keys,
            Active_Idx => Active,
            New_Key_ID => New_ID,
            New_TEK    => New_TEK,
            Now_Secs   => 9999);
      end;

      T.Decrypt_Ticket
        (Ticket  => Ticket (0 .. Tk_Len - 1),
         Keys    => Keys,
         Now     => 200,        --  within Max_Age window
         Max_Age => 3600,
         Plain   => Plain_Out,
         Status  => Status);

      Check ("round-trip: ticket from prior key still decrypts (grace)",
             Status);
      Check ("round-trip: master_secret round-trips intact",
             Status and then Plain_Out.Master_Secret = Plain_In.Master_Secret);
   end;

   Put_Line ("=== Summary: " & Pass'Image & " /" & Total'Image
             & " pass," & Fail'Image & " fail ===");

   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TEK_Rotation;
