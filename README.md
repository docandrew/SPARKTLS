# SparkTLS

SparkTLS is a TLS 1.3 and TLS 1.2 implementation in SPARK/Ada, designed for
formal verification. The library contains no C code; the accelerated crypto
paths in SPARKTLSCrypto use x86 inline assembly, gated by runtime CPUID
dispatch.

**Note: This project is still in development and is not suitable for production use.**

## Features

- TLS 1.3 client + server handshake (full flight, HelloRetryRequest)
- TLS 1.2 client + server (mTLS, ECDHE, RSA + ECDSA suites, ChaCha20-Poly1305 per RFC 7905)
- Key exchange: X25519, secp256r1 (P-256), secp384r1 (P-384) ECDHE
- Cipher suites: ChaCha20-Poly1305-SHA256, AES-128-GCM-SHA256, AES-256-GCM-SHA384
- Signature verification: Ed25519, ECDSA P-256/P-384, RSA-PSS + RSA-PKCS1 v1.5 (SHA-256/384/512)
- X.509 certificate parsing + chain validation via SPARKx509
- TLS 1.3 PSK session resumption (psk_dhe_ke mode, forward-secret)
- TLS 1.2 client + server session ticket resumption (RFC 5077 tickets)
- ALPN with strict echo-check (RFC 7301 §3.1/§3.2)
- RecordFlux-generated message serialization/parsing with SPARK contracts
- Crypto provided by SPARKNaCl + SPARKTLSCrypto (formally verified, AES-NI / VAES / VPCLMULQDQ / AVX-512 ChaCha20 fast paths)

## Not Supported

- **TLS 1.3 0-RTT / early data.** Intentionally not implemented on
  either side. The `early_data` extension is never emitted or
  accepted; `client_early_traffic_secret` is never derived; the
  `end_of_early_data` message is never produced or consumed.

  A peer that *offers* 0-RTT is interoperable: the server silently
  drops up to 32 undecryptable early-data records during the
  CH→client-Finished window, then proceeds with a normal 1-RTT
  handshake. The client never offers 0-RTT.

- **Active GREASE emission.** SPARKTLS aims for deterministic ClientHello
  serialization. It tolerates unknown/reserved values where the TLS RFCs require
  extensibility, but it does not intentionally emit reserved GREASE cipher
  suites, groups, signature schemes, versions, or extensions to exercise peer
  tolerance. This is a deliberate product choice, not a missing MVP feature.

## Session Ticket Policy

TLS 1.3 session tickets are hostname-scoped by default. Servers only mark
NewSessionTicket values with the `resumption_across_names` ticket flag when
`Config.TLS13_Resumption_Across_Names` is set to `True`.

Leave this setting disabled unless the deployment intentionally shares a ticket
store and resumption policy across the relevant hostnames, such as a single
service fleet serving multiple names inside the same trust boundary. Enabling it
asks clients that honor the flag to treat the ticket as reusable across names, so
it should not be used to bridge unrelated services or administrative domains.

TLS 1.2 resumption uses RFC 5077 session tickets. TLS 1.2 session-ID
resumption is intentionally not implemented.

## Certificate Validation Policy

`Mode_WebPKI` is the default validation mode for public web-style TLS. It
applies RFC 5280 chain validation plus WebPKI-oriented leaf policy checks.
`Mode_RFC5280` is available for private PKI and development certificates where
WebPKI issuance policy is not the right compatibility target.

`Skip_Verify` is only a chain-validation opt-out. When `Server_Name` is set,
hostname verification still runs even with `Skip_Verify => True`, so a
self-signed development certificate for the wrong hostname is rejected. Set
`Skip_Hostname_Verify => True` as a separate explicit opt-out only when hostname
binding is not desired.

Current x509-limbo expected failures are documented in
`PRODUCTION_READINESS.md`. The release policy treats the path-building capacity
limit and public-suffix dependency as compatibility limits, and the remaining
false-reject policy cases as conservative behavior to resolve or document before
a production-facing release.

## Planned Work

- Post-quantum key exchange (ML-KEM hybrid). SPARKTLS currently *tolerates*
  PQ peers without negotiating with them: `Wire_Key_Share_Len` is sized at
  16 KB so real ClientHellos carrying `X25519MLKEM768` (1220 bytes per entry)
  parse rather than being dropped, but only X25519 / secp256r1 / secp384r1 are
  offered or selected.

- **Certificate revocation checking (CRL / OCSP).** Neither is performed.
  A certificate that has been revoked but is otherwise well-formed, in-date
  and chains to a trusted root **will be accepted** (verifiable against
  `revoked.badssl.com`, which is in the `tests/realworld` matrix as a known
  failure). We also do not send `status_request`, so no stapled OCSP
  response is requested or received. This is planned.

- **RSA-4096 server certificates (known issue, not by design).**
  RSA-2048 leaf certificates work; RSA-4096 currently fails the handshake
  (`rsa4096.badssl.com` in the realworld matrix). `Max_RSA_Key_Bytes` is
  512 bytes, so 4096-bit keys are nominally within range and this is
  believed to be a bug rather than a deliberate limit. Being tracked.

## Dependencies

| Dependency | Source | Notes |
|------------|--------|-------|
| [SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl) | git | Crypto library (SPARK proven) |
| [SPARKTLSCrypto](https://github.com/docandrew/sparktlscrypto) | git | AES-GCM, ChaCha20-Poly1305, P-256/P-384, RSA, SHA-2, HKDF |
| [SPARKx509](https://github.com/docandrew/sparkx509) | git | X.509 certificate parser |
| [sparkentropy](https://github.com/docandrew/sparkentropy) | git | Needed by `examples/` only |
| [RecordFlux](https://github.com/AdaCore/RecordFlux) | pip / GitHub | Only needed to regenerate `generated/` |

**These are not pulled automatically.** `SPARKTLSCrypto` and `SPARKx509` are not
published to the Alire community index, and `alire.toml` pins all of them by
relative path (`../sparkx509`, `../sparktlscrypto`, `../sparknacl`) so they can
be developed side by side. A checkout of `sparktls` on its own will fail to
resolve. RecordFlux is only needed if you modify the `.rflx` specs in `specs/`.

## Building

TODO

## Disclaimer

SparkTLS is a proof-of-concept project and is provided "as is" without any warranty.
Use at your own risk.
