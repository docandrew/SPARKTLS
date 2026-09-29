--  FIPS 140-3 cryptographic algorithm self-tests (CASTs, IG 10.3.A).
--
--  One known-answer test for every approved algorithm the module offers,
--  each run through the same entry point a TLS session uses (the blinded
--  scalar multiplications, the prepared key paths the dispatchers choose).
--  The known answers are in SPARKTLS.Self_Tests.Vectors, generated from
--  sources outside this code by tools/self_test_vectors/generate.py.
--
--  SPARKTLS.Initialize (through SPARKTLS.RBG) runs them at start-up, before
--  the generator can serve
--  anything: HMAC_SHA256 first (the integrity test's own algorithm,
--  IG 10.2.A), then SPARKTLS.Integrity, then Remaining. The DRBG's own
--  health test (SP 800-90A 11.3) stays in the DRBG.
--
--  What each test covers:
--    HMAC-SHA-256 (and so SHA-256), HMAC-SHA-384 (and SHA-384), SHA-512
--    AES-GCM encrypt and decrypt, 128- and 256-bit keys
--    HKDF (SP 800-56C), the TLS 1.2 PRF with the Extended Master Secret,
--      the TLS 1.3 HKDF-Expand-Label
--    ECDSA sign and verify, P-256 and P-384; ECDH shared secret, both curves
--    RSA PKCS#1 v1.5 sign and verify (2048-bit, SHA-256)
--    Ed25519 sign and verify
--    ML-KEM-768 key generation, encapsulation, decapsulation, and the
--      implicit rejection of a modified ciphertext
package SPARKTLS.Self_Tests
  with SPARK_Mode => On
is
   --  Procedures, not functions: several of the primitives are not
   --  annotated Always_Terminates, which a function would need them to be.
   procedure HMAC_SHA256 (OK : out Boolean);

   procedure Remaining (OK : out Boolean);
end SPARKTLS.Self_Tests;
