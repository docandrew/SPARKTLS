--  SPARKTLS MAC — HMAC-SHA-256
--
--  Derived from SPARKNaCl.MAC (R. Chapman, MIT license).
--  Uses SPARKTLS.Hashing.SHA256 (SHA-NI accelerated) internally.

with SPARKTLS.Hashing.SHA256;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.MAC with
   SPARK_Mode => On
is
   procedure HMAC_SHA_256 (Output : out Hashing.SHA256.Digest;
                           M      : in  Byte_Seq;
                           K      : in  Byte_Seq)
   with Global => null,
        Relaxed_Initialization => Output,
        Pre    => M'First = 0 and
                  M'Last <= N32'Last - 64 and
                  (if K'Length > 0 then K'First = 0),
        Post   => Output'Initialized;

end SPARKTLS.MAC;
