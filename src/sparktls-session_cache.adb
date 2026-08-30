--  Reference implementation: a protected object guarding both the TLS 1.3
--  PSK cache and the TLS 1.2 ticket-encryption-key ring.
--
--  The callback procedures below are thin delegates -- they exist because
--  Config wants access-to-subprogram values, and 'Access requires a plain
--  library-level subprogram rather than a protected operation. All the state
--  lives inside the protected object, so concurrent tasks driving separate
--  Sessions serialise here and nowhere else.
--
--  Critical sections are deliberately short: these operations copy key
--  material in and out and nothing more. AES runs in the caller, outside the
--  lock, so ticket sealing and opening never serialise handshakes against
--  each other.

with SPARKTLS.Ticket_Cache;
with SPARKTLS.Tickets_12;

package body SPARKTLS.Session_Cache
  with SPARK_Mode => Off
is

   --  Ring of ticket-encryption keys. The newest seals outgoing tickets;
   --  older ones stay usable for opening until pushed out, so a rotation
   --  never invalidates tickets already in flight.
   type Key_Ring is array (0 .. TLS12_Max_Keys - 1) of TLS12_Ticket_Key;

   --  Index of the active slot. Declared as the ring's own index subtype
   --  rather than Natural: with Natural, every "Keys (Active)" carried an
   --  unprovable index check, because nothing in the type said Active is
   --  in range. Constraining the type makes an out-of-range Active
   --  UNREPRESENTABLE instead of merely guarded -- the assignments that
   --  set it (Rotate, Clear) are then checked at their source.
   subtype Key_Index is Natural range 0 .. TLS12_Max_Keys - 1;

   --  Rotation settings. Held outside the protected object on purpose: the
   --  CSPRNG is a user callback and must never be invoked while holding the
   --  lock (a potentially blocking operation would stall every other task).
   Rand_Fn  : Random_Bytes_Fn := null;
   Clock_Fn : Get_Time_Fn := null;
   Interval : Unsigned_64 := 0;

   protected Cache is

      procedure Store
        (PSK     : Bytes_48;
         PSK_Len : PSK_Length;
         Suite   : Unsigned_16;
         Age_Add : Unsigned_32;
         ID_Out  : out Ticket_ID)
         --  Ticket_Cache.Store requires a valid PSK length; a protected op
         --  cannot inherit that, so restate it here.
      with Pre => PSK_Len in 32 | 48;

      procedure Lookup
        (ID         : Byte_Seq;
         Want_Suite : Unsigned_16;
         PSK        : out Bytes_48;
         PSK_Len    : out N32;
         Suite      : out Unsigned_16;
         Found      : out Boolean)
      with
        Pre => ID'First = 0 and then ID'Length = Ticket_ID_Len,
        Post => (if Found then Suite = Want_Suite and then PSK_Len in 32 | 48);

      procedure Active_Key
        (Key_ID : out Byte_Seq;
         TEK    : out Byte_Seq;
         Found  : out Boolean)
         --  The ring stores fixed-width key material; the caller must supply
         --  buffers of exactly that width or the copies below are unprovable.
      with Pre => Key_ID'Length = 4 and then TEK'Length = 32;

      procedure Key_By_Id
        (Key_ID : Byte_Seq;
         TEK    : out Byte_Seq;
         Found  : out Boolean)
         --  Key_ID'Length is checked inline (a wrong-sized id is a miss, not
         --  an error); TEK is a destination and must be the right width.
      with Pre => TEK'Length = 32;

      procedure Rotate (New_Key_ID : Byte_Seq; New_TEK : Byte_Seq; Now_Secs : Unsigned_64);

      function Age (Now_Secs : Unsigned_64) return Unsigned_64;

      procedure Clear;

   private
      PSKs : Ticket_Store;
      Keys : Key_Ring :=
        (others =>
           (Key_ID => (others => 0), TEK => (others => 0), Valid => False, Created_At => 0));
      Active : Key_Index := 0;
      Have_Key : Boolean := False;
   end Cache;

   protected body Cache is

      procedure Store
        (PSK     : Bytes_48;
         PSK_Len : PSK_Length;
         Suite   : Unsigned_16;
         Age_Add : Unsigned_32;
         ID_Out  : out Ticket_ID) is
      begin
         --  Reuse the existing cache logic; it is already SPARK-proven and
         --  operates on a plain Ticket_Store passed in out.
         SPARKTLS.Ticket_Cache.Store
           (Cache   => PSKs,
            PSK     => PSK,
            PSK_Len => PSK_Len,
            Suite   => Suite,
            Age_Add => Age_Add,
            ID_Out  => ID_Out);
      end Store;

      procedure Lookup
        (ID         : Byte_Seq;
         Want_Suite : Unsigned_16;
         PSK        : out Bytes_48;
         PSK_Len    : out N32;
         Suite      : out Unsigned_16;
         Found      : out Boolean) is
      begin
         SPARKTLS.Ticket_Cache.Lookup
           (Cache      => PSKs,
            ID         => ID,
            Want_Suite => Want_Suite,
            PSK        => PSK,
            PSK_Len    => PSK_Len,
            Suite      => Suite,
            Found      => Found);
      end Lookup;

      procedure Active_Key (Key_ID : out Byte_Seq; TEK : out Byte_Seq; Found : out Boolean) is
      begin
         Key_ID := (others => 0);
         TEK := (others => 0);
         Found := False;
         if Have_Key and then Keys (Active).Valid then
            Key_ID := Keys (Active).Key_ID;
            TEK := Keys (Active).TEK;
            Found := True;
         end if;
      end Active_Key;

      procedure Key_By_Id (Key_ID : Byte_Seq; TEK : out Byte_Seq; Found : out Boolean) is
      begin
         TEK := (others => 0);
         Found := False;
         if Key_ID'Length /= 4 then
            return;
         end if;
         for I in Keys'Range loop
            if Keys (I).Valid and then Keys (I).Key_ID = Key_ID then
               TEK := Keys (I).TEK;
               Found := True;
               return;
            end if;
         end loop;
      end Key_By_Id;

      procedure Rotate (New_Key_ID : Byte_Seq; New_TEK : Byte_Seq; Now_Secs : Unsigned_64) is
      begin
         if New_Key_ID'Length /= 4 or else New_TEK'Length /= 32 then
            return;
         end if;
         --  Shift the ring: the new key becomes active, previous keys age
         --  by one slot, the oldest drops out. All retained slots stay
         --  usable for decryption.
         for I in reverse 1 .. Keys'Last loop
            Keys (I) := Keys (I - 1);
         end loop;
         Keys (0) := (Key_ID => New_Key_ID, TEK => New_TEK, Valid => True, Created_At => Now_Secs);
         Active := 0;
         Have_Key := True;
      end Rotate;

      function Age (Now_Secs : Unsigned_64) return Unsigned_64 is
      begin
         if not Have_Key or else not Keys (Active).Valid then
            return Now_Secs;
         end if;
         if Now_Secs <= Keys (Active).Created_At then
            return 0;
         end if;
         return Now_Secs - Keys (Active).Created_At;
      end Age;

      procedure Clear is
      begin
         PSKs := (others => <>);
         Keys :=
           (others =>
              (Key_ID => (others => 0), TEK => (others => 0), Valid => False, Created_At => 0));
         Active := 0;
         Have_Key := False;
      end Clear;

   end Cache;

   ----------------------------------------------------------------------
   --  Setup and lazy rotation
   ----------------------------------------------------------------------

   procedure Initialize
     (Random : Random_Bytes_Fn; Clock : Get_Time_Fn; Rotation_Interval : Unsigned_32 := 24 * 3600)
   is
      Key_ID : Byte_Seq (0 .. 3) := (others => 0);
      TEK    : Byte_Seq (0 .. 31) := (others => 0);
      Now    : Unsigned_64 := 0;
   begin
      Rand_Fn := Random;
      Clock_Fn := Clock;
      Interval := Unsigned_64 (Rotation_Interval);

      if Random = null then
         return;   --  no CSPRNG, no keys; tickets are simply not issued

      end if;

      if Clock /= null then
         Now := SPARKTLS.Tickets_12.To_Unix_Seconds (Clock.all);
      end if;

      --  Generated outside the lock, installed inside it.
      Random.all (Key_ID);
      Random.all (TEK);
      Cache.Rotate (Key_ID, TEK, Now);
   end Initialize;

   --  Rotate if the active key has aged past Interval. Called on the ticket
   --  path rather than from a timer task: an idle server does no work, and a
   --  busy one checks often enough. The age check and the install are each
   --  short protected operations; key generation happens between them, with
   --  the lock released.
   --
   --  Two tasks may both decide to rotate. That is harmless -- the ring
   --  absorbs an extra key and both remain valid for decryption.
   procedure Maybe_Rotate is
      Now    : Unsigned_64;
      Age    : Unsigned_64;
      Key_ID : Byte_Seq (0 .. 3) := (others => 0);
      TEK    : Byte_Seq (0 .. 31) := (others => 0);
   begin
      if Interval = 0 or else Rand_Fn = null or else Clock_Fn = null then
         return;   --  manual control, or not initialised

      end if;
      Now := SPARKTLS.Tickets_12.To_Unix_Seconds (Clock_Fn.all);

      --  Cache.Age is a protected function, hence a volatile function: SPARK
      --  forbids calling one inside a larger expression, because the value
      --  could change between evaluating it and the other operand. Bind it
      --  to a local first -- which is also what we mean, since the decision
      --  should rest on one observation of the age, not a re-read.
      Age := Cache.Age (Now);
      if Age < Interval then
         return;
      end if;
      Rand_Fn.all (Key_ID);
      Rand_Fn.all (TEK);
      Cache.Rotate (Key_ID, TEK, Now);
   end Maybe_Rotate;

   ----------------------------------------------------------------------
   --  Callback delegates
   ----------------------------------------------------------------------

   procedure Store_Session
     (PSK     : Bytes_48;
      PSK_Len : PSK_Length;
      Suite   : Unsigned_16;
      Age_Add : Unsigned_32;
      ID_Out  : out Ticket_ID) is
   begin
      Cache.Store (PSK, PSK_Len, Suite, Age_Add, ID_Out);
   end Store_Session;

   procedure Lookup_Session
     (ID         : Byte_Seq;
      Want_Suite : Unsigned_16;
      PSK        : out Bytes_48;
      PSK_Len    : out N32;
      Suite      : out Unsigned_16;
      Found      : out Boolean) is
   begin
      Cache.Lookup (ID, Want_Suite, PSK, PSK_Len, Suite, Found);
   end Lookup_Session;

   procedure Get_Active_TEK (Key_ID : out Byte_Seq; TEK : out Byte_Seq; Found : out Boolean) is
   begin
      Maybe_Rotate;
      Cache.Active_Key (Key_ID, TEK, Found);
   end Get_Active_TEK;

   procedure Get_TEK_By_Id (Key_ID : Byte_Seq; TEK : out Byte_Seq; Found : out Boolean) is
   begin
      Cache.Key_By_Id (Key_ID, TEK, Found);
   end Get_TEK_By_Id;

   procedure Rotate_TEK (New_Key_ID : Byte_Seq; New_TEK : Byte_Seq; Now_Secs : Unsigned_64) is
   begin
      Cache.Rotate (New_Key_ID, New_TEK, Now_Secs);
   end Rotate_TEK;

   --  Not an expression function: Cache.Age is a volatile function, and a
   --  volatile call may not appear in an interfering context. Binding the
   --  result to a local makes the single observation explicit.
   function Active_Key_Age (Now_Secs : Unsigned_64) return Unsigned_64 is
      Age : constant Unsigned_64 := Cache.Age (Now_Secs);
   begin
      return Age;
   end Active_Key_Age;

   procedure Reset is
   begin
      Cache.Clear;
   end Reset;

end SPARKTLS.Session_Cache;
