--  SPARKTLS RSA-PSS-RSAE Signature Verification
--  Ported from BearSSL i32 implementation (Thomas Pornin, MIT license)
--
--  Verification only - no signing, no key generation.
--  Supports RSA keys up to 4096 bits.
--  Supports SHA-256, SHA-384, and SHA-512 hash variants.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.RSA with
   SPARK_Mode => On
is
   --  Maximum RSA key size in bits and words
   Max_RSA_Bits  : constant := 8192;
   Max_RSA_Words : constant := Max_RSA_Bits / 32;  --  256
   Max_RSA_Bytes : constant := Max_RSA_Bits / 8;   --  1024

   --  Big integer: element 0 = bit length, elements 1..N = value words
   --  (little-endian word order, each word is full 32 bits)
   subtype Big_Int_Index is Natural range 0 .. Max_RSA_Words;
   type Big_Int is array (Big_Int_Index) of Unsigned_32;

   --  Hash algorithm selector for RSA-PSS
   type PSS_Hash is (PSS_SHA256, PSS_SHA384, PSS_SHA512);

   --  Verify an RSA-PSS-RSAE signature.
   --
   --  M_Hash     : the hash of the signed message (up to 64 bytes)
   --  Hash_Len   : length of hash in bytes (32, 48, or 64)
   --  Hash_Alg   : which hash was used (determines MGF1 + salt_len)
   --  Modulus    : RSA modulus (big-endian bytes)
   --  Mod_Len    : length of modulus in bytes
   --  Exponent   : RSA public exponent (typically 65537)
   --  Signature  : RSA signature (big-endian bytes, same length as modulus)
   --  Sig_Len    : length of signature in bytes
   --
   --  Returns True if the signature is valid.
   function Verify_PSS
     (M_Hash    : in Byte_Seq;
      Hash_Len  : in N32;
      Hash_Alg  : in PSS_Hash;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   with Pre => Mod_Len >= 64 and then Mod_Len <= Max_RSA_Bytes
               and then Sig_Len = Mod_Len
               and then Hash_Len in 32 | 48 | 64
               and then M_Hash'First = 0
               and then M_Hash'Last >= N32 (Hash_Len) - 1
               and then Modulus'First = 0
               and then Modulus'Last >= N32 (Mod_Len) - 1
               and then Modulus'Last < N32'Last
               and then Signature'First = 0
               and then Signature'Last >= N32 (Sig_Len) - 1
               and then Signature'Last < N32'Last;

   --  Convenience wrappers

   function Verify_PSS_SHA256
     (Hash      : in Bytes_32;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   with Pre => Mod_Len >= 64 and then Mod_Len <= Max_RSA_Bytes
               and then Sig_Len = Mod_Len
               and then Modulus'First = 0
               and then Modulus'Last >= N32 (Mod_Len) - 1
               and then Modulus'Last < N32'Last
               and then Signature'First = 0
               and then Signature'Last >= N32 (Sig_Len) - 1
               and then Signature'Last < N32'Last;

   function Verify_PSS_SHA384
     (Hash      : in Bytes_48;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   with Pre => Mod_Len >= 64 and then Mod_Len <= Max_RSA_Bytes
               and then Sig_Len = Mod_Len
               and then Modulus'First = 0
               and then Modulus'Last >= N32 (Mod_Len) - 1
               and then Modulus'Last < N32'Last
               and then Signature'First = 0
               and then Signature'Last >= N32 (Sig_Len) - 1
               and then Signature'Last < N32'Last;

   function Verify_PSS_SHA512
     (Hash      : in Bytes_64;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   with Pre => Mod_Len >= 64 and then Mod_Len <= Max_RSA_Bytes
               and then Sig_Len = Mod_Len
               and then Modulus'First = 0
               and then Modulus'Last >= N32 (Mod_Len) - 1
               and then Modulus'Last < N32'Last
               and then Signature'First = 0
               and then Signature'Last >= N32 (Sig_Len) - 1
               and then Signature'Last < N32'Last;

end SPARKTLS.RSA;
