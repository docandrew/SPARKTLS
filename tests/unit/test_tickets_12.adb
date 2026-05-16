--  Unit test for SPARKTLS.Tickets_12 encrypt/decrypt round-trip.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Tickets_12;

procedure Test_Tickets_12 is

   package T renames SPARKTLS.Tickets_12;

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

   TEK_A : constant T.Bytes_32 :=
     (16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#, 16#88#,
      16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#, 16#00#,
      others => 16#42#);
   TEK_B : constant T.Bytes_32 :=
     (16#5A#, 16#5A#, 16#5A#, 16#5A#, others => 16#A5#);
   Key_ID_A : constant T.Bytes_4 := (16#01#, 16#02#, 16#03#, 16#04#);
   Key_ID_B : constant T.Bytes_4 := (16#F0#, 16#F1#, 16#F2#, 16#F3#);
   Nonce    : constant T.Bytes_12 := (others => 16#7E#);

   function Make_Plain return T.Ticket_Plain is
      P : T.Ticket_Plain;
   begin
      for I in N32 range 0 .. 47 loop
         P.Master_Secret (I) := Byte (16#80# + (Natural (I) mod 32));
      end loop;
      P.Suite := 16#C02F#;
      P.Created_At := 1_700_000_000;
      P.SID_Len := 16;
      for I in N32 range 0 .. 15 loop
         P.SID (I) := Byte (16#C0# + Natural (I));
      end loop;
      return P;
   end Make_Plain;

   function Make_Keys return TLS12_Ticket_Key_Array is
      K : TLS12_Ticket_Key_Array;
   begin
      K (0) := (Key_ID => Byte_Seq (Key_ID_A),
                TEK    => Byte_Seq (TEK_A),
                Valid  => True);
      K (1) := (Key_ID => Byte_Seq (Key_ID_B),
                TEK    => Byte_Seq (TEK_B),
                Valid  => True);
      K (2) := (Key_ID => (others => 0), TEK => (others => 0),
                Valid  => False);
      K (3) := (Key_ID => (others => 0), TEK => (others => 0),
                Valid  => False);
      return K;
   end Make_Keys;

begin
   Put_Line ("=== SPARKTLS.Tickets_12 round-trip ===");

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Key_ID_A, TEK_A, Nonce, Ticket, Len);
      Check ("Encrypt: Len > 0", Len > 0);
      Check ("Encrypt: Len = 32 + 59 + 16",
             Len = 32 + 59 + 16);
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_700_000_100, 3600, P_Out, OK);
      Check ("Decrypt: succeeded", OK);
      Check ("Round-trip: Master_Secret matches",
             P_Out.Master_Secret = P_In.Master_Secret);
      Check ("Round-trip: Suite matches", P_Out.Suite = P_In.Suite);
      Check ("Round-trip: Created_At matches",
             P_Out.Created_At = P_In.Created_At);
      Check ("Round-trip: SID_Len matches",
             P_Out.SID_Len = P_In.SID_Len);
      Check ("Round-trip: SID bytes match",
             P_Out.SID (0 .. P_In.SID_Len - 1)
               = P_In.SID (0 .. P_In.SID_Len - 1));
   end;

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Key_ID_A, TEK_A, Nonce, Ticket, Len);
      Ticket (Len - 1) := Ticket (Len - 1) xor 16#01#;
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_700_000_100, 3600, P_Out, OK);
      Check ("Tampered tag → Decrypt fails", not OK);
   end;

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
      Wrong_ID : constant T.Bytes_4 :=
        (16#DE#, 16#AD#, 16#BE#, 16#EF#);
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Wrong_ID, TEK_A, Nonce, Ticket, Len);
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_700_000_100, 3600, P_Out, OK);
      Check ("Unknown Key_ID → Decrypt fails", not OK);
   end;

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Key_ID_B, TEK_B, Nonce, Ticket, Len);
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_700_000_100, 3600, P_Out, OK);
      Check ("Rotation: ticket under Key_B decrypts", OK);
      Check ("Rotation: round-trip Master_Secret",
             OK and then P_Out.Master_Secret = P_In.Master_Secret);
   end;

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Key_ID_A, TEK_A, Nonce, Ticket, Len);
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_700_000_000 + 7200, 3600, P_Out, OK);
      Check ("Expired ticket (>Max_Age) → Decrypt fails", not OK);
   end;

   declare
      P_In, P_Out : T.Ticket_Plain;
      Ticket : Byte_Seq (0 .. 255) := (others => 0);
      Len : N32;
      Keys : TLS12_Ticket_Key_Array;
      OK : Boolean;
   begin
      P_In := Make_Plain;
      Keys := Make_Keys;
      T.Encrypt_Ticket (P_In, Key_ID_A, TEK_A, Nonce, Ticket, Len);
      T.Decrypt_Ticket (Ticket (0 .. Len - 1), Keys,
                        1_600_000_000, 86400, P_Out, OK);
      Check ("Future-dated ticket → Decrypt fails", not OK);
   end;

   Put_Line ("");
   Put_Line ("=== Total:" & Total'Image
             & " Pass:" & Pass'Image
             & " Fail:" & Fail'Image & " ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Tickets_12;
