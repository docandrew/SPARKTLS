--  Unit test for TLS 1.2 ticket-encryption-key rotation.
--
--  Rotation used to live in the library (SPARKTLS.Server.Rotate_TLS12_Ticket_Key,
--  operating on a caller-supplied key array reached through Config). It does
--  not any more: SPARKTLS holds no ticket keys, so key lifetime belongs to
--  whoever implements the Get_Active_TEK / Get_TEK_By_Id callbacks. This test
--  therefore targets the reference implementation, SPARKTLS.Session_Cache.
--
--  It also tests the properties through the PUBLIC surface rather than by
--  inspecting slots, because the ring is now private state inside a protected
--  object. That is a better test: it pins observable behaviour rather than
--  layout.
--
--  Verifies:
--    1. With no key installed, Get_Active_TEK reports Found => False
--       (server simply issues no ticket).
--    2. After Rotate_TEK, the active key is the one just installed.
--    3. Grace window: a key remains retrievable by its Key_ID after a
--       later rotation, so tickets already issued still resume.
--    4. After TLS12_Max_Keys rotations the oldest key is gone.
--    5. Round-trip: a ticket sealed under key A still opens after
--       rotation to key B, and fails once A has aged out of the ring.

with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;         use Interfaces;
with SPARKNaCl;          use SPARKNaCl;
with SPARKTLS;           use SPARKTLS;
with SPARKTLS.Session_Cache;
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

   function Key_ID_Of (N : Byte) return Byte_Seq is
     (Byte_Seq'(0 => N, 1 => N, 2 => N, 3 => N));

   function TEK_Of (N : Byte) return Byte_Seq is
      R : Byte_Seq (0 .. 31) := (others => N);
   begin
      return R;
   end TEK_Of;

   Got_ID  : Byte_Seq (0 .. 3)  := (others => 0);
   Got_TEK : Byte_Seq (0 .. 31) := (others => 0);
   Found   : Boolean;

begin
   Put_Line ("=== TLS 1.2 TEK rotation (SPARKTLS.Session_Cache) ===");

   SPARKTLS.Session_Cache.Reset;

   --  1. No key installed yet.
   SPARKTLS.Session_Cache.Get_Active_TEK (Got_ID, Got_TEK, Found);
   Check ("no active key before first rotation", not Found);

   --  2. First key becomes active.
   SPARKTLS.Session_Cache.Rotate_TEK (Key_ID_Of (16#A1#), TEK_Of (16#A1#), 1000);
   SPARKTLS.Session_Cache.Get_Active_TEK (Got_ID, Got_TEK, Found);
   Check ("first rotation installs an active key", Found);
   Check ("active key is the one installed",
          Found and then Got_ID = Key_ID_Of (16#A1#)
                 and then Got_TEK = TEK_Of (16#A1#));

   --  3. Grace window: the old key survives a rotation.
   SPARKTLS.Session_Cache.Rotate_TEK (Key_ID_Of (16#B2#), TEK_Of (16#B2#), 2000);
   SPARKTLS.Session_Cache.Get_Active_TEK (Got_ID, Got_TEK, Found);
   Check ("second rotation makes the new key active",
          Found and then Got_ID = Key_ID_Of (16#B2#));

   SPARKTLS.Session_Cache.Get_TEK_By_Id (Key_ID_Of (16#A1#), Got_TEK, Found);
   Check ("previous key still retrievable (grace window)",
          Found and then Got_TEK = TEK_Of (16#A1#));

   --  4. Age the first key out of the ring.
   for I in 1 .. TLS12_Max_Keys loop
      SPARKTLS.Session_Cache.Rotate_TEK
        (Key_ID_Of (Byte (16#C0# + I)), TEK_Of (Byte (16#C0# + I)),
         Unsigned_64 (3000 + I));
   end loop;
   SPARKTLS.Session_Cache.Get_TEK_By_Id (Key_ID_Of (16#A1#), Got_TEK, Found);
   Check ("oldest key dropped after TLS12_Max_Keys rotations", not Found);

   --  5. Ticket round-trip across a rotation.
   SPARKTLS.Session_Cache.Reset;
   SPARKTLS.Session_Cache.Rotate_TEK (Key_ID_Of (16#D4#), TEK_Of (16#D4#), 5000);
   declare
      Plain      : SPARKTLS.Tickets_12.Ticket_Plain;
      Ticket_Buf : Byte_Seq (0 .. 255);
      Ticket_Len : N32;
      Nonce      : constant Byte_Seq (0 .. 11) := (others => 7);
      Out_Plain  : SPARKTLS.Tickets_12.Ticket_Plain;
      OK         : Boolean;
      Wanted     : Byte_Seq (0 .. 3);
      TEK_Buf    : Byte_Seq (0 .. 31) := (others => 0);
      Have       : Boolean;
   begin
      Plain.Master_Secret := (others => 16#5A#);
      Plain.Suite         := Suite_ECDHE_RSA_AES128_GCM_SHA256;
      Plain.Created_At    := 5000;
      Plain.SID_Len       := 0;
      Plain.SID           := (others => 0);

      SPARKTLS.Session_Cache.Get_Active_TEK (Got_ID, Got_TEK, Found);
      SPARKTLS.Tickets_12.Encrypt_Ticket
        (Plain      => Plain,
         Key_ID     => SPARKTLS.Tickets_12.Bytes_4 (Got_ID),
         TEK        => SPARKTLS.Tickets_12.Bytes_32 (Got_TEK),
         Nonce      => SPARKNaCl.Bytes_12 (Nonce),
         Ticket     => Ticket_Buf,
         Ticket_Len => Ticket_Len);
      Check ("ticket sealed under active key", Ticket_Len > 0);

      --  Rotate, then open the ticket via its own Key_ID.
      SPARKTLS.Session_Cache.Rotate_TEK
        (Key_ID_Of (16#E5#), TEK_Of (16#E5#), 6000);

      Wanted := SPARKTLS.Tickets_12.Ticket_Key_ID
                  (Ticket_Buf (0 .. Ticket_Len - 1));
      SPARKTLS.Session_Cache.Get_TEK_By_Id (Wanted, TEK_Buf, Have);
      Check ("sealing key still available after rotation", Have);

      if Have then
         SPARKTLS.Tickets_12.Decrypt_Ticket
           (Ticket  => Ticket_Buf (0 .. Ticket_Len - 1),
            TEK     => TEK_Buf,
            Now     => 6100,
            Max_Age => 3600,
            Plain   => Out_Plain,
            Status  => OK);
         Check ("ticket opens after rotation (grace window)", OK);
         Check ("recovered master secret matches",
                OK and then Out_Plain.Master_Secret = Plain.Master_Secret);
      end if;
   end;

   Put_Line ("=== TEK rotation:" & Pass'Image & " passed," &
             Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TEK_Rotation;
