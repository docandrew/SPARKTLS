--  RFC 8446 §4.6.3: post-handshake KeyUpdate.
--
--  A KeyUpdate rotates the SENDER's write key only:
--
--    * We send one  -> our write key advances, our write sequence resets
--                      to 0, and the peer advances its read key.
--    * Peer sends one -> their write key advances; we advance our READ key
--                      and reset our read sequence.
--
--  There is no standalone "please rekey" message. Asking the peer to rotate
--  means sending our own KeyUpdate with request_update = update_requested,
--  which is why receive-only support cannot protect our own write direction.
--
--  WHY THIS EXISTS AT ALL. The per-record nonce is the static write IV
--  XORed with the 64-bit sequence number (RFC 8446 §5.3), so nonces are
--  derived rather than chosen. When the sequence space is exhausted there
--  are no more nonces available under that key, and Unsigned_64 is a
--  MODULAR type -- Counter + 1 at 'Last wraps silently to 0 and reuses
--  nonces, which is catastrophic for AEAD. Rekeying is the mechanism that
--  keeps that unreachable; refusing to encrypt is the backstop if it is not
--  used. TLS 1.3 removed renegotiation, so this is the only in-connection
--  remedy.
--
--  The practical trigger is not sequence exhaustion (2**64 is ~584,000
--  years at 1e6 records/sec) but the RFC 8446 §5.5 AEAD usage limit --
--  about 2**24.5 full-size records for AES-GCM, which a busy connection
--  reaches in hours.
--
--  Private child: internal to SPARKTLS, not part of the public API.

private package SPARKTLS.Key_Update with
   SPARK_Mode => On
is

   --  Wire encoding of the one-byte body (RFC 8446 §4.6.3):
   --     enum { update_not_requested(0), update_requested(1) }
   Update_Not_Requested : constant Byte := 0;
   Update_Requested     : constant Byte := 1;

   --  Handshake message type for key_update.
   HS_Key_Update : constant Byte := 24;  --  16#18#

   --  Total wire size: 1-byte type + 3-byte length + 1-byte body.
   Key_Update_Msg_Len : constant := 5;

   --  RFC 8446 §4.6.3: derive the next generation of a traffic secret and
   --  reinstall the key/IV derived from it.
   --
   --    secret_N+1 = HKDF-Expand-Label (secret_N, "traffic upd", "", Len)
   --
   --  Secret is updated in place and TK is reinstalled with a zeroed
   --  sequence counter. The caller decides WHICH direction to rotate; this
   --  routine is deliberately direction-agnostic.
   --
   --  Len selects the hash: 32 for SHA-256 suites, 48 for SHA-384.
   procedure Update_Secret
     (Secret : in out Bytes_48;
      Len    : in     N32;
      TK     : in out Traffic_Keys;
      Suite  : in     Unsigned_16)
   with Pre  => Len in 32 | 48
                and then Suite in Suite_AES_128_GCM_SHA256
                               | Suite_AES_256_GCM_SHA384
                               | Suite_CHACHA20_POLY1305_SHA256,
        Post => TK.Counter = 0
                and then TK.Suite = Suite
                and then Nonce_Space_Available (TK);

   --  Build a KeyUpdate handshake message into Out_Buf.
   --  Request is True to ask the peer to rotate in turn.
   procedure Build_Key_Update
     (Out_Buf : out Byte_Seq;
      Len     : out N32;
      Request : in  Boolean)
   with Pre  => Out_Buf'First = 0
                and then Out_Buf'Length >= Key_Update_Msg_Len,
        Post => Len = Key_Update_Msg_Len;

   --  Parse a reassembled KeyUpdate message body.
   --
   --  Msg is the complete handshake message including its 4-byte header.
   --  Valid is False for a malformed length or a request_update value
   --  outside {0, 1} -- RFC 8446 §4.6.3 requires those to be treated as
   --  illegal_parameter rather than ignored.
   --  Outcome of parsing a post-handshake KeyUpdate.
   --
   --  The two failure modes carry DIFFERENT alerts and must not be
   --  conflated:
   --    Malformed  -> decode_error.       RFC 8446 6.2 defines
   --                  decode_error as "the length of the message was
   --                  incorrect", which is exactly a KeyUpdate whose
   --                  body is absent or the wrong size.
   --    Bad_Value  -> illegal_parameter.  RFC 8446 4.6.3: a structurally
   --                  valid KeyUpdate whose request_update is outside
   --                  {0,1} MUST be illegal_parameter.
   --
   --  Reporting a single Boolean forced both onto illegal_parameter,
   --  which tlsfuzzer's test-tls13-keyupdate.py "empty KeyUpdate
   --  message" case correctly rejects: it truncates the body and
   --  expects decode_error.
   type Parse_Status is (Parse_OK, Parse_Malformed, Parse_Bad_Value);

   procedure Parse_Key_Update
     (Msg     : in  Byte_Seq;
      Request : out Boolean;
      Status  : out Parse_Status)
   with Pre => Msg'First = 0;

end SPARKTLS.Key_Update;
