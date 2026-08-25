--  SPARKTLS handshake transcript — streaming, bufferless (carve 2).
--
--  The transcript is the concatenation of every handshake message,
--  hashed at several protocol points. The digest algorithm is not
--  known until the cipher suite is negotiated, so this ADT runs BOTH
--  SHA-256 and SHA-384 contexts from the first byte and drops the
--  loser at selection ("dual streaming" -- the TLS<=1.1-era parallel
--  digest technique, bounded at exactly two by our suite set; see the
--  2026-08-25 design discussion). Consequences, all deliberate:
--
--    * No buffer. The old 32 KB Transcript array, its capacity, every
--      capacity guard and every Len bound cease to exist -- and with
--      them the non-RFC restrictions they imposed (no single message
--      over 32 KB, no handshake TOTAL over 32 KB). Reassembly's 128 KB
--      per-message bound is the only remaining limit, documented.
--
--    * Memory: two hash states (~500 B) replace 32 KB per in-flight
--      handshake, and every VC carrying an `HC : in out` shrinks by
--      the same amount.
--
--    * Verified prerequisites: streaming SHA-384 added 2026-08-25
--      (sparktlscrypto-hashing-sha384, NIST KATs 8/8); the 1.2
--      client-auth CertificateVerify audit confirms no accepted
--      scheme signs raw transcript bytes (all verify over a 256/384
--      digest), so clone-and-finalize serves every draw point.
--
--  No predicate: Started and Selected are pure phase; there is no
--  cross-field relation the base type system cannot express.

with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA384;
with SPARKTLSCrypto.Hashing.SHA512;

package SPARKTLS_Transcript with
   SPARK_Mode => On
is
   type Hash_Choice is (Both, Only_256, Only_384);

   type Transcript_State is private;

   --  Fresh transcript: both digests initialised, nothing appended.
   procedure Start (TS : out Transcript_State)
   with Global => null;

   --  Append handshake-message bytes. Feeds whichever contexts are
   --  still live; O(len), no storage.
   procedure Append (TS : in out Transcript_State; Data : Byte_Seq)
   with Global => null;

   --  Suite negotiated: drop the losing digest. Idempotent for the
   --  same choice; never call with a DIFFERENT choice after selecting.
   procedure Select_Hash (TS : in out Transcript_State; C : Hash_Choice)
   with Global => null, Pre => C /= Both;

   --  Transcript hash at this instant (clone-and-finalize; the running
   --  context is untouched, so appends may continue afterwards).
   procedure Current_256
     (TS : in Transcript_State;
      H  : out SPARKTLSCrypto.Hashing.SHA256.Digest)
   with Global => null;

   procedure Current_384
     (TS : in Transcript_State;
      H  : out SPARKTLSCrypto.Hashing.SHA384.Digest)
   with Global => null;

   --  TLS 1.2 CertificateVerify may negotiate a sha512 signature
   --  scheme (0x0601/0x0806) over the raw transcript; the third
   --  stream serves it. Runs unconditionally -- one extra pass over a
   --  few KB of handshake per connection is cheaper than conditional
   --  state. Never a suite hash, so Select_Hash does not affect it.
   procedure Current_512
     (TS : in Transcript_State;
      H  : out SPARKTLSCrypto.Hashing.SHA512.Digest)
   with Global => null;

   --  PSK binders (RFC 8446 Section 4.2.11.2): the binder covers the
   --  transcript so far PLUS a truncated ClientHello that is not part
   --  of the transcript yet (build side: mid-construction; verify
   --  side: before the CH is appended). Clone-update-finalize.
   procedure Suffix_256
     (TS     : in Transcript_State;
      Suffix : in Byte_Seq;
      H      : out SPARKTLSCrypto.Hashing.SHA256.Digest)
   with Global => null;

   procedure Suffix_384
     (TS     : in Transcript_State;
      Suffix : in Byte_Seq;
      H      : out SPARKTLSCrypto.Hashing.SHA384.Digest)
   with Global => null;

   --  RFC 8446 Section 4.4.1: on HelloRetryRequest the transcript is
   --  replaced by message_hash(04 00 00 Hash.length || Hash(CH1)).
   --  Requires the hash already selected (HRR names the suite).
   procedure Reset_For_HRR (TS : in out Transcript_State)
   with Global => null;

   --  True once any bytes have been appended (the old Len > 0 trio).
   function Started (TS : Transcript_State) return Boolean
   with Global => null;

   function Selected (TS : Transcript_State) return Hash_Choice
   with Global => null;

private
   type Transcript_State is record
      C256     : SPARKTLSCrypto.Hashing.SHA256.Context;
      C384     : SPARKTLSCrypto.Hashing.SHA384.Context;
      C512     : SPARKTLSCrypto.Hashing.SHA512.Context;
      Choice   : Hash_Choice := Both;
      Has_Data : Boolean     := False;
   end record;

end SPARKTLS_Transcript;
