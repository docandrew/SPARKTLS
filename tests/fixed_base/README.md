# Fixed-base TLS integration
Build fixed_base.gpr with SPARKTLS and SPARKTLSCRYPTO contracts and runtime
checks enabled. Pass a valid localhost leaf certificate, its private key, and
its CA PEM to bin/test_fixed_base_handshake. The test performs real TLS 1.3
handshakes and bidirectional encrypted application exchanges in memory.
It forces X25519 and X25519MLKEM768 separately, exercising both client and
server public-key generation. Certificate, hostname and UTC validity checks
remain enabled. Feed/drain accounting and bounded progress are checked.
The primitive oracle in sparktlscrypto/tests/base25519 independently compares
both public keys and signatures with OpenSSL.
