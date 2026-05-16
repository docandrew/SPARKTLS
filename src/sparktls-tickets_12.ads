--  SPARKTLS.Tickets_12
--  RFC 5077 stateless TLS 1.2 session-ticket encryption.
--
--  Wire format:
--    [ Key_ID (4) | Nonce (12) | Ciphertext (N) | Tag (16) ]
--
--  Plaintext layout (packed by Encrypt_Ticket):
--    [ master_secret (48) | suite (2) | created_at_u64 (8)
--    | sid_len (1) | sid (0..32) ]
--
--  AES-256-GCM in encrypt-then-MAC mode; the Key_ID is included as
--  AAD so a ticket encrypted under key A can't be replayed against
--  key B (defence in depth against TEK confusion).

with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Tickets_12 is

   subtype Bytes_48 is Byte_Seq (0 .. 47);
   subtype Bytes_32 is Byte_Seq (0 .. 31);
   subtype Bytes_16 is Byte_Seq (0 .. 15);
   subtype Bytes_12 is Byte_Seq (0 .. 11);
   subtype Bytes_4  is Byte_Seq (0 .. 3);

   --  Maximum on-wire ticket length:
   --    4 (key_id) + 12 (nonce) + 91 (plaintext max) + 16 (tag) = 123
   --  Round up to give callers a roomy buffer.
   Max_Ticket_Wire_Len : constant := 256;

   --  Decoded ticket plaintext.
   type Ticket_Plain is record
      Master_Secret : Bytes_48 := (others => 0);
      Suite         : Unsigned_16 := 0;
      Created_At    : Unsigned_64 := 0;  --  seconds since epoch
      SID_Len       : N32 := 0;          --  0 .. 32
      SID           : Bytes_32 := (others => 0);
   end record;

   --  Encrypt a Ticket_Plain into wire format.
   --  Caller must supply a 12-byte CSPRNG nonce. The Key_ID (4 bytes,
   --  any value) and TEK (32 bytes) come from a Config.TLS12_Ticket_Keys
   --  entry. On return, Ticket (0 .. Ticket_Len - 1) holds the wire bytes.
   procedure Encrypt_Ticket
     (Plain      : in     Ticket_Plain;
      Key_ID     : in     Bytes_4;
      TEK        : in     Bytes_32;
      Nonce      : in     Bytes_12;
      Ticket     :    out Byte_Seq;
      Ticket_Len :    out N32)
   with Pre  => Ticket'First = 0
                and then Ticket'Last >= Max_Ticket_Wire_Len - 1
                and then Plain.SID_Len in 0 .. 32,
        Post => Ticket_Len in 0 .. Max_Ticket_Wire_Len;

   --  Decrypt a wire-format ticket. Looks up the Key_ID against
   --  Keys (linear scan over up to TLS12_Max_Keys entries), then
   --  AES-GCM-decrypts under that TEK. Status = False on any of:
   --    * malformed wire (too short, length mismatch)
   --    * Key_ID not found / no valid key
   --    * AES-GCM tag mismatch (forged / wrong key)
   --    * Plaintext shape invalid
   --    * Created_At + Max_Age < Now (expired)
   --    * Created_At > Now (clock skew / forged future)
   procedure Decrypt_Ticket
     (Ticket  : in     Byte_Seq;
      Keys    : in     TLS12_Ticket_Key_Array;
      Now     : in     Unsigned_64;
      Max_Age : in     Unsigned_32;
      Plain   :    out Ticket_Plain;
      Status  :    out Boolean)
   with Pre => Ticket'First = 0;

end SPARKTLS.Tickets_12;
