--  SPARKTLS.Tickets
--  RFC 5077 stateless session-ticket encryption, shared by TLS 1.2 and
--  TLS 1.3. The format is version-neutral and carries a Kind tag.
--  (Formerly SPARKTLS.Tickets_12, from when only TLS 1.2 used it.)
--
--  Wire format:
--    [ Key_ID (4) | Nonce (12) | Ciphertext (N) | Tag (16) ]
--
--  Plaintext layout (packed by Encrypt_Ticket):
--    [ secret (48) | secret_len (1) | suite (2) | created_at_u64 (8)
--    | flags (1) | age_add_u32 (4) | sni_hash (32) | sid_len (1) | sid (0..32) ]
--    flags byte: bit0 = client_auth, bit1 = extended_master_secret,
--                bit2 = kind (0 = TLS 1.2, 1 = TLS 1.3),
--                bit3 = across_names (ticket may resume under another SNI).
--    age_add is the NewSessionTicket ticket_age_add (TLS 1.3), so the
--    server can recover the true ticket age for the RFC 8446 4.2.11
--    freshness check. sni_hash is SHA-256 of the server_name the ticket
--    was issued under (all zeros if none), for the RFC 6066 3 rule that a
--    ticket resumes only under the name it was issued for.
--
--  The Kind tag, checked on Decrypt, stops a ticket sealed for one TLS
--  version being replayed against the other (SR-04). The secret is the
--  TLS 1.2 master_secret (always 48 bytes) or the TLS 1.3 resumption
--  PSK (32 or 48 bytes per the suite hash); secret_len says how many of
--  the 48 bytes are meaningful.
--
--  AES-256-GCM in encrypt-then-MAC mode; the Key_ID is included as
--  AAD so a ticket encrypted under key A can't be replayed against
--  key B (defence in depth against TEK confusion).

with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
with X509;

package SPARKTLS.Tickets
  with SPARK_Mode => On
is

   --  Convert an X509.Date_Time to seconds since the Unix epoch
   --  (1970-01-01 00:00:00 UTC). Assumes the input is already UTC
   --  (no timezone handling). Returns 0 for dates before the epoch.
   --  Used as the Created_At / Now arguments to Encrypt_Ticket and
   --  Decrypt_Ticket so the expiry window from Cfg.TLS12_Ticket_Lifetime
   --  is enforced against real wall-clock time.
   function To_Unix_Seconds (DT : X509.Date_Time) return Unsigned_64;

   subtype Bytes_48 is Byte_Seq (0 .. 47);
   subtype Bytes_32 is Byte_Seq (0 .. 31);
   subtype Bytes_16 is Byte_Seq (0 .. 15);
   subtype Bytes_12 is Byte_Seq (0 .. 11);
   subtype Bytes_4 is Byte_Seq (0 .. 3);

   --  Maximum on-wire ticket length:
   --    4 (key_id) + 12 (nonce) + 129 (plaintext max) + 16 (tag) = 161
   --  Round up to give callers a roomy buffer.
   Max_Ticket_Wire_Len : constant := 256;

   --  TLS version a ticket was sealed for. Checked on Decrypt so a
   --  1.2 ticket can't resume a 1.3 session or vice versa (SR-04).
   type Ticket_Kind is (Kind_TLS12, Kind_TLS13);

   --  Decoded ticket plaintext.
   type Ticket_Plain is record
      Secret      : Bytes_48 := (others => 0);  --  master_secret or PSK
      Secret_Len  : N32 := 48;                  --  32 | 48
      Suite       : Unsigned_16 := 0;
      Created_At  : Unsigned_64 := 0;            --  seconds since epoch
      Kind        : Ticket_Kind := Kind_TLS12;
      Client_Auth : Boolean := False;            --  SR-03: peer was mTLS-authed
      EMS         : Boolean := False;            --  extended master secret (1.2)
      --  SR-03 residuals: SNI binding (RFC 6066 3 / RFC 8446 4.6.1) and the
      --  ticket_age_add needed for the RFC 8446 4.2.11 age check.
      Across_Names : Boolean := False;           --  may resume under another SNI
      Age_Add      : Unsigned_32 := 0;           --  NST ticket_age_add (1.3)
      SNI_Hash     : Bytes_32 := (others => 0);  --  SHA-256(server_name), 0 if none
      SID_Len     : N32 := 0;                    --  0 .. 32 (1.2 only)
      SID         : Bytes_32 := (others => 0);
   end record;

   --  SHA-256 of the SNI a ticket is issued under; all zeros when the
   --  ClientHello carried no server_name. Servers compare this on resume.
   procedure Hash_Server_Name (Name : in Hostname_Buf; H : out Bytes_32);

   --  Encrypt a Ticket_Plain into wire format.
   --  Caller must supply a 12-byte CSPRNG nonce. The Key_ID (4 bytes,
   --  any value) and TEK (32 bytes) come from a Config.TLS12_Ticket_Keys
   --  entry. On return, Ticket (0 .. Ticket_Len - 1) holds the wire bytes.
   procedure Encrypt_Ticket
     (Plain      : in Ticket_Plain;
      Key_ID     : in Bytes_4;
      TEK        : in Bytes_32;
      Nonce      : in Bytes_12;
      Ticket     : out Byte_Seq;
      Ticket_Len : out N32)
   with
     Pre =>
       Ticket'First = 0
       and then Ticket'Last >= Max_Ticket_Wire_Len - 1
       and then Plain.SID_Len in 0 .. 32
       and then Plain.Secret_Len in 32 | 48,
     Post => Ticket_Len in 1 .. Max_Ticket_Wire_Len;

   --  Decrypt a wire-format ticket. Looks up the Key_ID against
   --  Keys (linear scan over up to TLS12_Max_Keys entries), then
   --  AES-GCM-decrypts under that TEK. Status = False on any of:
   --    * malformed wire (too short, length mismatch)
   --    * Key_ID not found / no valid key
   --    * AES-GCM tag mismatch (forged / wrong key)
   --    * Plaintext shape invalid
   --    * Created_At + Max_Age < Now (expired)
   --    * Created_At > Now (clock skew / forged future)
   --  Read the Key_ID a ticket names, so the caller can fetch exactly the
   --  key that sealed it. Wire layout is Key_ID (4) | Nonce (12) | Ct | Tag.
   --  This is what makes decryption the O(1) lookup the RFC 5077 notes
   --  describe, rather than trying every key in turn.
   --  Width of the Key_ID prefix. Callers MUST check a candidate ticket is
   --  at least this long before calling Ticket_Key_ID -- a peer controls the
   --  ticket length, and a 1..3 byte ticket would otherwise reach the slice
   --  below and violate the precondition.
   Ticket_Key_ID_Size : constant := 4;

   function Ticket_Key_ID (Ticket : Byte_Seq) return Byte_Seq
   with
     Pre => Ticket'First = 0 and then Ticket'Length >= Ticket_Key_ID_Size,
     Post =>
       Ticket_Key_ID'Result'First = 0 and then Ticket_Key_ID'Result'Length = Ticket_Key_ID_Size;

   --  Decrypt with a single caller-supplied key -- the one named by
   --  Ticket_Key_ID. Takes raw key bytes rather than a key record so it
   --  is independent of how the caller stores keys (Config.Get_TEK_By_Id,
   --  an HSM, a file, whatever).
   procedure Decrypt_Ticket
     (Ticket      : in Byte_Seq;
      TEK         : in Byte_Seq;
      Now         : in Unsigned_64;
      Max_Age     : in Unsigned_32;
      Expect_Kind : in Ticket_Kind;
      Plain       : out Ticket_Plain;
      Status      : out Boolean)
   with
     Pre =>
       Ticket'First = 0
       and then Ticket'Last < N32'Last
       and then TEK'First = 0
       and then TEK'Length = 32,
     Post => (if Status then Plain.Kind = Expect_Kind and then Plain.Secret_Len in 32 | 48);

end SPARKTLS.Tickets;
