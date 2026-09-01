--  Unit tests for clock / time handling.
--
--  Motivated by a real defect: every application-side clock callback in
--  this tree built its X509.Date_Time with Ada.Calendar.Split, which
--  works in package Calendar's implementation-defined (LOCAL) time zone
--  per RM 9.6. X.509 notBefore/notAfter are UTC, so on a host east or
--  west of Greenwich every certificate validity comparison was shifted
--  by the host's UTC offset -- and far enough east it lands on the wrong
--  DAY. It hid because the dev boxes and CI run UTC, where local == UTC.
--
--  Three things are covered here:
--    A. To_Unix_Seconds -- the calendar arithmetic every expiry decision
--       is built on. Leap years, month lengths, epoch boundaries, and
--       the fail-closed sentinel for malformed input.
--    B. The UTC conversion idiom now deployed at the callback sites,
--       asserted to be time-zone independent.
--    C. Ticket expiry windows at their exact boundaries.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Calendar.Time_Zones;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKTLS;                use SPARKTLS;
with SPARKTLS.Tickets_12;
with SPARKTLS.Client;
with Det_Random_Lib;
with X509;

procedure Test_Clock is

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

   function DT (Y, M, D, H, Mi, S : Natural) return X509.Date_Time is
     (X509.Date_Time'(Year   => Y, Month  => M, Day => D,
                      Hour   => H, Minute => Mi, Second => S));

   --  Seconds since the Unix epoch for a broken-down UTC time.
   function U (Y, M, D : Natural; H : Natural := 0;
               Mi : Natural := 0; S : Natural := 0) return Unsigned_64 is
     (T.To_Unix_Seconds (DT (Y, M, D, H, Mi, S)));

   Day : constant Unsigned_64 := 86_400;

   --  Length of a month, measured as the distance to the 1st of the next.
   function Month_Len (Y, M : Natural) return Unsigned_64 is
     (if M = 12 then U (Y + 1, 1, 1) - U (Y, 12, 1)
      else U (Y, M + 1, 1) - U (Y, M, 1));

   --  Fixed UTC clock for the config-gate cases.
   function Fixed_Now return X509.Date_Time is
     ((Year => 2026, Month => 5, Day => 15,
       Hour => 12, Minute => 0, Second => 0));

   --  A ticket that Check_Resume_Ticket_Usable will accept, so the
   --  Resume_Usable arm of Client_Config_Can_Start is genuinely live.
   function Usable_Ticket return Session_Ticket is
      Tk : Session_Ticket;
   begin
      Tk.Ticket_Len := 32;
      for I in N32 range 0 .. 31 loop
         Tk.Ticket (I) := Byte (I);
      end loop;
      Tk.Lifetime   := 7200;
      Tk.Age_Add    := 16#DEADBEEF#;
      Tk.Received_At := T.To_Unix_Seconds
        ((Year => 2026, Month => 5, Day => 15,
          Hour => 11, Minute => 0, Second => 0));
      Tk.PSK_Len := 32;
      for I in N32 range 0 .. 31 loop
         Tk.PSK (I) := Byte (16#A0# + (Natural (I) mod 16));
      end loop;
      Tk.Suite := Wire_Suite_AES_128_GCM_SHA256;
      declare
         H : constant String := "localhost";
      begin
         Tk.Server_Name.Data (1 .. H'Length) := H;
         Tk.Server_Name.Len := H'Length;
      end;
      Tk.Valid := True;
      return Tk;
   end Usable_Ticket;


begin
   Put_Line ("=== Clock / time handling ===");

   ---------------------------------------------------------------------
   Put_Line ("-- A1. epoch and simple offsets");
   ---------------------------------------------------------------------
   Check ("epoch is 0",             U (1970, 1, 1) = 0);
   Check ("epoch + 1 second",       U (1970, 1, 1, 0, 0, 1) = 1);
   Check ("epoch + 1 minute",       U (1970, 1, 1, 0, 1, 0) = 60);
   Check ("epoch + 1 hour",         U (1970, 1, 1, 1, 0, 0) = 3_600);
   Check ("epoch + 1 day",          U (1970, 1, 2) = Day);
   Check ("end of first day",       U (1970, 1, 1, 23, 59, 59) = 86_399);

   ---------------------------------------------------------------------
   Put_Line ("-- A2. known instants");
   ---------------------------------------------------------------------
   Check ("2000-01-01 = 946684800", U (2000, 1, 1) = 946_684_800);
   Check ("2024-01-01 = 1704067200", U (2024, 1, 1) = 1_704_067_200);
   Check ("2026-01-01 = 1767225600", U (2026, 1, 1) = 1_767_225_600);

   ---------------------------------------------------------------------
   Put_Line ("-- A3. 32-bit boundaries (must NOT wrap: Unsigned_64)");
   ---------------------------------------------------------------------
   --  A ticket lifetime that straddles either boundary must keep
   --  counting. These are the classic truncation cliffs.
   Check ("2038-01-19T03:14:07 = 2**31-1",
          U (2038, 1, 19, 3, 14, 7) = 2_147_483_647);
   Check ("one second past 2**31-1",
          U (2038, 1, 19, 3, 14, 8) = 2_147_483_648);
   Check ("2106-02-07T06:28:15 = 2**32-1",
          U (2106, 2, 7, 6, 28, 15) = 4_294_967_295);
   Check ("one second past 2**32-1",
          U (2106, 2, 7, 6, 28, 16) = 4_294_967_296);

   ---------------------------------------------------------------------
   Put_Line ("-- A4. leap-year rules (the 100/400 traps)");
   ---------------------------------------------------------------------
   Check ("2024 is leap (div 4)",
          U (2024, 3, 1) - U (2024, 2, 28) = 2 * Day);
   Check ("2023 is not leap",
          U (2023, 3, 1) - U (2023, 2, 28) = Day);
   Check ("2000 IS leap (div 400)",
          U (2000, 3, 1) - U (2000, 2, 28) = 2 * Day);
   Check ("2100 is NOT leap (div 100, not 400)",
          U (2100, 3, 1) - U (2100, 2, 28) = Day);
   Check ("Feb 29 2024 exists and is one day",
          U (2024, 2, 29) - U (2024, 2, 28) = Day);
   Check ("Feb has 29 days in 2024", Month_Len (2024, 2) = 29 * Day);
   Check ("Feb has 28 days in 2023", Month_Len (2023, 2) = 28 * Day);
   Check ("Feb has 29 days in 2000", Month_Len (2000, 2) = 29 * Day);
   Check ("Feb has 28 days in 2100", Month_Len (2100, 2) = 28 * Day);

   ---------------------------------------------------------------------
   Put_Line ("-- A5. every month length, leap and common year");
   ---------------------------------------------------------------------
   declare
      Common : constant array (1 .. 12) of Unsigned_64 :=
        (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
      Leap   : constant array (1 .. 12) of Unsigned_64 :=
        (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
      OK_C : Boolean := True;
      OK_L : Boolean := True;
   begin
      for M in 1 .. 12 loop
         if Month_Len (2023, M) /= Common (M) * Day then
            OK_C := False;
            Put_Line ("      common-year month" & M'Image & " wrong");
         end if;
         if Month_Len (2024, M) /= Leap (M) * Day then
            OK_L := False;
            Put_Line ("      leap-year month" & M'Image & " wrong");
         end if;
      end loop;
      Check ("all 12 month lengths, common year 2023", OK_C);
      Check ("all 12 month lengths, leap year 2024", OK_L);
   end;

   ---------------------------------------------------------------------
   Put_Line ("-- A6. malformed input yields the 0 sentinel (fail closed)");
   ---------------------------------------------------------------------
   --  0 is deliberately the "I do not know the time" value. Paired with
   --  the Decrypt_Ticket checks in C, a 0 makes a real ticket look like
   --  it came from the future, which is rejected -- never accepted.
   Check ("year before epoch -> 0", U (1969, 12, 31, 23, 59, 59) = 0);
   Check ("year 0 -> 0",            U (0, 1, 1) = 0);
   Check ("month 0 -> 0",           U (2024, 0, 1) = 0);
   Check ("month 13 -> 0",          U (2024, 13, 1) = 0);
   Check ("day 0 -> 0",             U (2024, 1, 0) = 0);
   Check ("day 32 -> 0",            U (2024, 1, 32) = 0);

   ---------------------------------------------------------------------
   Put_Line ("-- A7. strictly increasing across a long span");
   ---------------------------------------------------------------------
   declare
      Prev : Unsigned_64 := 0;
      Cur  : Unsigned_64;
      Mono : Boolean := True;
   begin
      for Y in 1970 .. 2110 loop
         for M in 1 .. 12 loop
            Cur := U (Y, M, 1);
            if Y > 1970 and then Cur <= Prev then
               Mono := False;
            end if;
            Prev := Cur;
         end loop;
      end loop;
      Check ("monotonic over 1970..2110, month by month", Mono);
   end;

   ---------------------------------------------------------------------
   Put_Line ("-- B. UTC conversion idiom is time-zone independent");
   ---------------------------------------------------------------------
   --  This is the exact shape now used at all ten callback sites. It must
   --  produce the same fields regardless of the process time zone.
   declare
      use Ada.Calendar;
      use Ada.Calendar.Formatting;
      Known : constant Time :=
        Time_Of (2024, 6, 15, 12, 30, 45, 0.0, False, Time_Zone => 0);
      Y  : Year_Number;
      M  : Month_Number;
      D  : Day_Number;
      Hr : Hour_Number;
      Mn : Minute_Number;
      Sc : Second_Number;
      SS : Second_Duration;
   begin
      Ada.Calendar.Formatting.Split
        (Known, Y, M, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      Check ("UTC split round-trips Time_Of: date",
             Y = 2024 and M = 6 and D = 15);
      Check ("UTC split round-trips Time_Of: time",
             Hr = 12 and Mn = 30 and Sc = 45);
      Check ("converted instant matches To_Unix_Seconds",
             T.To_Unix_Seconds
               (DT (Natural (Y), Natural (M), Natural (D),
                    Natural (Hr), Natural (Mn), Natural (Sc)))
             = U (2024, 6, 15, 12, 30, 45));

      --  And the bug itself: plain Ada.Calendar.Split is LOCAL. On a UTC
      --  host the two agree, which is precisely why this went unnoticed;
      --  anywhere else they diverge. Report rather than fail, so the test
      --  is meaningful in either environment.
      declare
         LY : Year_Number;
         LM : Month_Number;
         LD : Day_Number;
         LS : Day_Duration;
         use type Ada.Calendar.Time_Zones.Time_Offset;
         Off : constant Ada.Calendar.Time_Zones.Time_Offset :=
           Ada.Calendar.Time_Zones.UTC_Time_Offset (Known);
      begin
         Ada.Calendar.Split (Known, LY, LM, LD, LS);
         Put_Line ("      host UTC offset:" & Off'Image & " minutes");
         if Off = 0 then
            Check ("local == UTC on this host (offset 0), as expected",
                   LY = Y and LM = M and LD = D
                   and Natural (LS) / 3600 = Natural (Hr));
         else
            Check ("local /= UTC here -- Formatting.Split is required",
                   not (LY = Y and LM = M and LD = D
                        and Natural (LS) / 3600 = Natural (Hr)));
         end if;
      end;
   end;

   ---------------------------------------------------------------------
   Put_Line ("-- C. ticket expiry window boundaries");
   ---------------------------------------------------------------------
   declare
      TEK    : constant T.Bytes_32 := (others => 16#3C#);
      Key_ID : constant T.Bytes_4  := (16#0A#, 16#0B#, 16#0C#, 16#0D#);
      Nonce  : constant T.Bytes_12 := (others => 16#5F#);
      Born   : constant Unsigned_64 := 1_700_000_000;
      Life   : constant Unsigned_32 := 3_600;

      procedure Try (Label   : String;
                     Created : Unsigned_64;
                     Now     : Unsigned_64;
                     Max_Age : Unsigned_32;
                     Want    : Boolean)
      is
         P_In   : T.Ticket_Plain;
         P_Out  : T.Ticket_Plain;
         Wire   : Byte_Seq (0 .. 255);
         Len    : N32;
         Got    : Boolean;
      begin
         P_In.Master_Secret := (others => 16#77#);
         P_In.Suite         := 16#C02F#;
         P_In.Created_At    := Created;
         P_In.SID_Len       := 0;
         T.Encrypt_Ticket (P_In, Key_ID, TEK, Nonce, Wire, Len);
         T.Decrypt_Ticket (Wire (0 .. Len - 1), Byte_Seq (TEK),
                           Now, Max_Age, P_Out, Got);
         Check (Label, Got = Want);
      end Try;
   begin
      Try ("fresh ticket accepted",
           Born, Born, Life, True);
      Try ("mid-window accepted",
           Born, Born + 1_800, Life, True);
      Try ("exactly at Max_Age accepted (check is > not >=)",
           Born, Born + Unsigned_64 (Life), Life, True);
      Try ("one second past Max_Age rejected",
           Born, Born + Unsigned_64 (Life) + 1, Life, False);
      Try ("far past Max_Age rejected",
           Born, Born + 10 * Unsigned_64 (Life), Life, False);
      Try ("ticket from the future rejected (clock skew or forgery)",
           Born, Born - 1, Life, False);
      Try ("far-future ticket rejected",
           Born + 10 * Day, Born, Life, False);

      --  The clockless-mint case. A server with no Cfg.Get_Time used to
      --  stamp Created_At = 0; if it later gained a clock, Now is a real
      --  epoch value and the ticket reads as ancient -> rejected. That
      --  upgrade path failing closed is what makes the server-side
      --  "no clock => issue no ticket" guard safe to add.
      Try ("Created_At = 0 against a real clock is rejected",
           0, Born, Life, False);

      --  ...and the reason that guard is NECESSARY: with no clock at all
      --  both sides are 0, so Tickets_12 alone would accept forever. The
      --  protection lives in the caller, not here. This test pins that
      --  fact so a future refactor cannot quietly rely on the wrong layer.
      Try ("no clock at all: Tickets_12 alone would accept (guard is upstream)",
           0, 0, 0, True);

      --  Max_Age = 0 with a real clock means every ticket is stale.
      Try ("Max_Age = 0 rejects a one-second-old ticket",
           Born, Born + 1, 0, False);
      Try ("Max_Age = 0 accepts only the same instant",
           Born, Born, 0, True);
   end;

   ---------------------------------------------------------------------
   Put_Line ("-- D. client config gate: no clock + cert checking = no start");
   ---------------------------------------------------------------------
   --  A missing clock means notBefore/notAfter cannot be checked. Rather
   --  than discover that on the first certificate, Init refuses to start
   --  and reports Error_State / Internal_Error, so the operator sees it
   --  at startup.
   declare
      procedure Gate (Label      : String;
                      Skip       : Boolean;
                      With_Clock : Boolean;
                      With_Trust : Boolean;
                      With_Ticket : Boolean;
                      Want_Start : Boolean)
      is
         Cfg   : Config;
         Sess  : SPARKTLS.Client_Session;
         Roots : aliased Trust_Store;
      begin
         Cfg.Random      := Det_Random_Lib.Det_Random'Access;
         Cfg.Skip_Verify := Skip;
         declare
            H : constant String := "localhost";
         begin
            Cfg.Server_Name.Data (1 .. H'Length) := H;
            Cfg.Server_Name.Len := H'Length;
         end;
         if With_Clock then
            Cfg.Get_Time := Fixed_Now'Unrestricted_Access;
         end if;
         if With_Trust then
            Cfg.Trust := Roots'Unchecked_Access;
         end if;
         if With_Ticket then
            Cfg.Resume_Ticket := Usable_Ticket;
         end if;
         Sess := SPARKTLS.Client.Configure (Cfg);
         if Want_Start then
            Check (Label, State (Sess) = Client_Hello_Sent);
         else
            Check (Label, State (Sess) = Error_State);
         end if;
      end Gate;
   begin
      --  Allowed to start.
      Gate ("clock + trust starts",
            Skip => False, With_Clock => True,  With_Trust => True,
            With_Ticket => False, Want_Start => True);
      Gate ("clock + ticket, no trust starts (resumption-only client)",
            Skip => False, With_Clock => True,  With_Trust => False,
            With_Ticket => True,  Want_Start => True);
      Gate ("Skip_Verify without a clock starts (explicit opt-out)",
            Skip => True,  With_Clock => False, With_Trust => False,
            With_Ticket => False, Want_Start => True);

      --  Refused: cert checking is on and there is no clock.
      Gate ("no clock + trust is REFUSED",
            Skip => False, With_Clock => False, With_Trust => True,
            With_Ticket => False, Want_Start => False);
      Gate ("no clock + nothing is REFUSED",
            Skip => False, With_Clock => False, With_Trust => False,
            With_Ticket => False, Want_Start => False);
      --  The arm that used to let resumption excuse a missing clock. The
      --  peer decides whether resumption happens, so a config that only
      --  works while the server cooperates must not be constructible.
      Gate ("no clock + usable ticket is REFUSED (resumption is no excuse)",
            Skip => False, With_Clock => False, With_Trust => False,
            With_Ticket => True,  Want_Start => False);
   end;

   ---------------------------------------------------------------------
   New_Line;
   Put_Line ("=== Total:" & Total'Image &
             "  Pass:" & Pass'Image &
             "  Fail:" & Fail'Image & " ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Clock;
