--  Unit test: inbound KeyUpdate leaky-bucket rate limiting, and the
--  fail-closed bound on the record sequence counter.
--
--  Why this test exists. BoGo's TooManyKeyUpdates covers the flood case --
--  a peer spamming KeyUpdates with no traffic in between. It does NOT
--  cover the opposite failure, which is the one we introduced and then
--  fixed: an ABSOLUTE cap on inbound KeyUpdates would eventually be
--  exhausted by a well-behaved peer that rekeys at its RFC 8446 §5.5 AEAD
--  limit, and we would drop a conforming connection with
--  unexpected_message. That is a self-inflicted interop bug, it only
--  appears on very long-lived connections, and no adversarial suite will
--  ever produce it.
--
--  The bucket drains on RECORDS READ rather than on a clock (the core has
--  no clock -- Get_Time is an optional callback). That is also the better
--  signal, because it measures the thing that actually distinguishes the
--  two cases: whether the peer did real work between rotations.
--
--  Verifies:
--    1. A flooding peer (no traffic between KeyUpdates) drains the bucket
--       and is refused once it is empty.
--    2. A legitimate peer (real traffic between KeyUpdates) refunds a
--       token each time and can rekey indefinitely -- far past the bucket
--       depth, which is what an absolute cap got wrong.
--    3. Record_Counter cannot represent Unsigned_64'Last, so the modular
--       wrap that would reuse nonces is unrepresentable rather than merely
--       guarded.

with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;         use Interfaces;
with SPARKTLS;           use SPARKTLS;

procedure Test_Key_Update_Ratelimit is

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

   --  Model of the bucket exactly as implemented in
   --  Process_Key_Update_Message (client and server share the shape):
   --
   --     if Read_Counter >= Rekey_Refill_Records and Bucket > 0 then
   --        Bucket := Bucket - 1;            --  refund for real work
   --     end if;
   --     if Bucket >= Max_Key_Updates then
   --        reject;
   --     end if;
   --     Bucket := Bucket + 1;
   --
   --  Kept in step with the source by the constants below, which are the
   --  real ones from SPARKTLS.
   procedure Offer_Key_Update
     (Bucket       : in out Natural;
      Read_Counter : in     Unsigned_64;
      Accepted     :    out Boolean)
   is
   begin
      if Read_Counter >= Rekey_Refill_Records and then Bucket > 0 then
         Bucket := Bucket - 1;
      end if;

      if Bucket >= Max_Key_Updates then
         Accepted := False;
         return;
      end if;

      Bucket   := Bucket + 1;
      Accepted := True;
   end Offer_Key_Update;

begin
   Put_Line ("=== KeyUpdate rate limiting (leaky bucket) ===");

   --  1. Flooding peer: KeyUpdates back-to-back, no records in between,
   --     so the read counter is ~0 and nothing is ever refunded.
   declare
      Bucket   : Natural := 0;
      Accepted : Boolean;
      Refused_At : Natural := 0;
   begin
      for I in 1 .. Max_Key_Updates + 10 loop
         Offer_Key_Update (Bucket, Read_Counter => 0, Accepted => Accepted);
         if not Accepted and then Refused_At = 0 then
            Refused_At := I;
         end if;
      end loop;

      Check ("flooding peer is eventually refused", Refused_At > 0);
      Check ("refused only after the bucket depth is reached",
             Refused_At = Max_Key_Updates + 1);
   end;

   --  2. Legitimate peer: real traffic between rotations, so each
   --     KeyUpdate refunds a token. This must survive FAR past the bucket
   --     depth -- an absolute cap would have failed here, which is the
   --     interop bug this scheme exists to avoid.
   declare
      Bucket   : Natural := 0;
      Accepted : Boolean;
      All_OK   : Boolean := True;
   begin
      for I in 1 .. Max_Key_Updates * 100 loop
         Offer_Key_Update
           (Bucket,
            Read_Counter => Unsigned_64 (Rekey_Refill_Records) + 1,
            Accepted     => Accepted);
         if not Accepted then
            All_OK := False;
         end if;
      end loop;

      Check ("legitimate peer rekeys indefinitely", All_OK);
      Check ("bucket stays shallow for a legitimate peer", Bucket <= 1);
   end;

   --  3. A peer just under the refill threshold earns nothing: traffic
   --     below the bar does not buy the right to rekey repeatedly.
   declare
      Bucket   : Natural := 0;
      Accepted : Boolean;
      Refused  : Boolean := False;
   begin
      for I in 1 .. Max_Key_Updates + 5 loop
         Offer_Key_Update
           (Bucket,
            Read_Counter => Unsigned_64 (Rekey_Refill_Records) - 1,
            Accepted     => Accepted);
         if not Accepted then
            Refused := True;
         end if;
      end loop;

      Check ("traffic below the refill threshold does not refund", Refused);
   end;

   --  4. The nonce-space backstop. Record_Counter must exclude
   --     Unsigned_64'Last: Unsigned_64 is modular, so a counter that could
   --     hold 'Last would wrap to 0 on the next increment and restart the
   --     nonce sequence under an unchanged key.
   Check ("Record_Counter'Last excludes Unsigned_64'Last",
          Unsigned_64 (Record_Counter'Last) = Unsigned_64'Last - 1);
   Check ("Record_Counter'First is 0",
          Unsigned_64 (Record_Counter'First) = 0);

   --  Rotation must happen long before the arithmetic bound, or the
   --  backstop would be doing work the rekey should have done.
   Check ("rekey threshold is far below the sequence bound",
          Unsigned_64 (Rekey_After_Records) < Unsigned_64 (Record_Counter'Last) / 2**20);

   --  And the refill bar must sit below the rotation threshold, or a peer
   --  rekeying on our own schedule would never earn a refund.
   Check ("refill threshold is below the rekey threshold",
          Rekey_Refill_Records < Rekey_After_Records);

   Put_Line ("=== KeyUpdate rate limiting:" & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Key_Update_Ratelimit;
