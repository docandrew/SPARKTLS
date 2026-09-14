# SparkTLS

SparkTLS is a TLS 1.3 and TLS 1.2 implementation in SPARK/Ada. 
The library contains no C code; the accelerated crypto
paths in SPARKTLSCrypto use x86 inline assembly.

**Note: this project is pre-release and not yet suitable for production use.**

## Features

- TLS 1.3 client and server: full handshake, HelloRetryRequest, PSK
  resumption (`psk_dhe_ke` only, forward secret), KeyUpdate, exporters,
  mutual authentication, SNI-based identity selection, and a server-side
  identity set (`Config.Identities`) chosen by the client's signature
  algorithms, cipher-suite family, curves and certificate_authorities.
- TLS 1.2 client and server: ECDHE suites only (RSA and ECDSA
  authentication), extended master secret, mutual authentication,
  RFC 5077 session-ticket resumption.
- Key exchange: X25519, secp256r1 (P-256), secp384r1 (P-384).
- Cipher suites: ChaCha20-Poly1305-SHA256, AES-128-GCM-SHA256,
  AES-256-GCM-SHA384.
- Signatures: Ed25519, ECDSA P-256/P-384, RSA-PSS and RSA-PKCS#1 v1.5
  (SHA-256/384/512). Peer RSA keys from `Min_RSA_Bits` (default 2048) up
  to 8192 bits are verified on both versions, including TLS 1.2
  ServerKeyExchange signatures; a local RSA identity may be up to 4096
  bits. RSA public keys are checked for a sane exponent (odd, at least 3).
- X.509 parsing and RFC 5280 chain validation via SPARKx509, with name
  constraints (including CN-only leaves), EKU chaining, and a WebPKI
  policy mode.
- Certificate revocation: stapled OCSP (TLS 1.3 and 1.2) and
  application-supplied CRLs, evaluated for every certificate below the
  trust anchor, with `Ignore` / `Soft_Fail` / `Hard_Fail` policies and
  RFC 7633 must-staple. A `Verify_Staple` hook lets the application
  apply its own OCSP policy on top.
- OCSP stapling on the server: an identity carries its OCSP response
  (`Set_OCSP_Staple` / `Credentials.Load_Staple`) and the server staples
  it for clients that send `status_request`, as a TLS 1.3 CertificateEntry
  extension or a TLS 1.2 CertificateStatus message.
- Stateless session tickets on both versions: the resumption secret is
  sealed under a server ticket-encryption key (AES-256-GCM) and the
  ticket *is* the identity, so no server-side session store exists.
- ALPN with strict echo checking (RFC 7301).
- Key material is scrubbed when a handshake context is released and when
  a connection closes or fails; private keys handed to `Set_Identity`
  are checked against the certificate's public key.
- RecordFlux-generated message serialization and parsing with SPARK
  contracts; crypto from SPARKNaCl and SPARKTLSCrypto (AES-NI, VAES,
  VPCLMULQDQ and AVX-512 ChaCha20 fast paths).

## Verification Status

- Every unit in `sparktls`, `sparkx509` and `sparktlscrypto` discharges
  under `gnatprove --level=1` with no unproved checks; the whole-project
  run (`ci/prove.sh`) is the release gate and is expected to report only
  the handful of known findings in upstream SPARKNaCl and in
  RecordFlux-generated code.
- Constant-time behaviour of the crypto kernels is checked with a
  valgrind/ctgrind lane (`sparktlscrypto/ci/timing.sh ctgrind`) that
  poisons secrets — and, for the signature verifiers, the attacker-
  controlled inputs — and fails on any data-dependent branch or index.
  A dudect statistical lane exists for local use.
- Conformance suites (2026-09-14): BoringSSL's BoGo runner passes
  1464 of 1534 cases, with the 70 failures each documented in
  `tests/bogo/EXPECTED_FAILURES.txt` and nothing left unimplemented (see
  `tests/bogo/CLASSIFICATION.md` for the out-of-scope list); tlsfuzzer
  runs 2600+ conversations across 90 scripts with every failing script
  classified in `tests/protocol/run.sh`; TLS-Anvil passes 152 of the 199
  tests its scan enables, with the 47 failures grouped and dispositioned
  in `tests/tlsanvil/EXPECTED_FAILURES.txt`; x509-limbo 9738/9759 and
  NIST PKITS 189/249 with the deviations listed under `tests/x509/`;
  Wycheproof and NIST CAVP vectors pass in full. `tests/README.md`
  describes every lane, its baseline file and how to reproduce one case.
- The example programs and `sparktls_cli` are covered by the test lanes
  (integration and `tests/cli`) and were reviewed for the failure modes
  that get CVEs filed against sample code: path traversal, unbounded
  reads, ignored short writes, missing timeouts, world-readable key
  files, silently overwritten files, unverified CSRs and exit codes that
  hide failures.

## Not Supported

- **TLS 1.3 0-RTT / early data.** Intentionally not implemented on either
  side. The `early_data` extension is never emitted or accepted. A peer
  that *offers* 0-RTT is interoperable: the server skips up to 32
  undecryptable early-data records without disturbing its handshake read
  counter, then proceeds with a normal 1-RTT handshake.
- **Renegotiation** (TLS 1.2), including the `renegotiation_info`
  extension: not offered; an unsolicited server echo is rejected.
- **TLS 1.1 and earlier, SSL, RSA key exchange, static DH, compression.**
- **DTLS, QUIC, ECH, certificate compression, SCTs, delegated
  credentials.**
- **TLS 1.2 session-ID resumption** (tickets only) and **Ed25519 client
  authentication in TLS 1.2** (the client declines with an empty
  Certificate: PureEdDSA needs the raw transcript, which this stack does
  not keep). In TLS 1.2 an ECDSA key signs only with the hash of its own
  curve (P-256 with SHA-256, P-384 with SHA-384), so a peer that offers
  `ecdsa_secp256r1_sha256` alone cannot use a P-384 identity.
- **Fetching revocation data.** The library never performs network I/O of
  its own: OCSP evidence arrives stapled from the server and CRLs are
  attached by the application.
- **Active GREASE emission.** SparkTLS aims for deterministic ClientHello
  serialization. It tolerates unknown or reserved values where the TLS
  RFCs require extensibility, but does not intentionally emit reserved
  cipher suites, groups, signature schemes, versions, or extensions.

## Session Lifecycle

A session ends in one of two ways. `Close_Notify` is the orderly path: it
queues the close_notify alert and the session keeps being driven through
`Advance` until the peer has answered, at which point the handshake slot is
freed. `Drop` is the other one: the transport died, a timeout fired, or the
application is done with the connection. It scrubs every key and handshake
secret and frees the slot without touching the wire, and it is safe and
idempotent in every state. Call it on every path that stops driving a
session; a server that forgets does not answer anyone once `Max_Inflight`
(16) peers have disconnected mid-handshake, which scanners and browsers'
speculative connections do routinely. Close_Notify only has meaning once the
handshake is complete, and a peer that never answers it is finished with
`Drop` as well.

Neither is a callback. The library never calls the application about a
session's lifetime; everything it has to say arrives as the `Action` that
`Advance` returns (`Has_Output`, `Need_Input`, `Handshake_Done`,
`Plaintext_Ready`, `Error_Alert`, `Shutdown`), and the application drives
the socket. The only callbacks are the hooks the application installs in
`Config`: the random source, the clock, the peer-verification veto, the
client-identity selector, the OCSP-staple policy hooks and the ticket-key
ring accessors.

## Session Ticket Policy

Tickets on both versions are sealed under the server's ticket-encryption
key ring (`SPARKTLS.Ticket_Keys`), which the application owns: a single
process rotates it in place, a fleet shares the key material through its
own channel. The ring is the only long-lived copy of the keys; call
`Ticket_Keys.Reset` before the process exits.

TLS 1.3 tickets are hostname-scoped by default. Servers mark
NewSessionTicket with the `resumption_across_names` flag only when
`Config.TLS13_Resumption_Across_Names` is set. Leave it off unless the
deployment intentionally shares a ticket key ring and resumption policy
across the relevant hostnames inside one trust boundary. TLS 1.2 tickets
never resume across names; both versions bind the ticket to the cipher
suite, the client-authentication status and (TLS 1.2) the
extended-master-secret state of the original session.

A client that is configured with a resumption ticket must also supply
`Get_Time`: ticket lifetimes are enforced, and a ticket whose age cannot
be known is refused at configuration time rather than offered forever.

## Certificate Validation Policy

`Mode_WebPKI` is the default validation mode for public web-style TLS. It
applies RFC 5280 chain validation plus the CA/Browser Forum leaf policy
checks. `Mode_RFC5280` is for private PKI and development certificates
where WebPKI issuance policy is not the right target.

`Config.Min_RSA_Bits` (default 2048) is enforced in every mode. Lower it
only for a legacy PKI you control.

`Skip_Verify` is only a chain-validation opt-out. When `Server_Name` is
set, hostname verification still runs even with `Skip_Verify => True`, so
a self-signed development certificate for the wrong hostname is rejected.
`Skip_Hostname_Verify => True` is the separate, explicit opt-out.

Revocation is governed by `Config.Revocation`. `Soft_Fail` (the default)
fails on a revoked certificate and proceeds when no evidence is
available; `Hard_Fail` also fails without evidence, which with
intermediates in the chain means their issuers' CRLs must be attached; a
malformed CRL from the application's own store fails in every mode.
`Request_OCSP_Staple` independently controls whether `status_request` is
sent. The known x509-limbo and PKITS deviations are listed in
`tests/x509/` alongside the runners.

## Known Issues

- None open in the realworld matrix (`tests/realworld/run.sh`). Note that
  `revoked.badssl.com` is only refused when the runner attaches the
  issuer's CRL: the library never fetches revocation data, so without a
  stapled OCSP response or an application-supplied CRL a revoked leaf is
  accepted under the default `Soft_Fail` policy, exactly as curl accepts
  it. Use `Hard_Fail` where that is unacceptable.

## Planned Work

- TLS-Anvil and tlsfuzzer conformance runs with documented intentional gaps.
- Post-quantum key exchange: the `X25519MLKEM768` hybrid, built on the
  SPARK ML-KEM implementation. Today the stack *tolerates* PQ peers
  (ClientHellos carrying 1220-byte hybrid shares parse) but negotiates
  only classical groups.

## Dependencies

| Dependency | Source | Notes |
|------------|--------|-------|
| [SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl) | git | Core crypto (SPARK proven) |
| [SPARKTLSCrypto](https://github.com/docandrew/sparktlscrypto) | git | AES-GCM, ChaCha20-Poly1305, P-256/P-384, RSA, SHA-2, HKDF, SHA-1 (OCSP CertID only) |
| [SPARKx509](https://github.com/docandrew/sparkx509) | git | X.509, CRL and OCSP parsing |
| [sparkentropy](https://github.com/docandrew/sparkentropy) | git | Entropy source for `examples/` and tests only (brings libkeccak) |
| [RecordFlux](https://github.com/AdaCore/RecordFlux) | pip / GitHub | Only needed to regenerate `generated/` from `specs/` |

**Two of these are not pulled automatically.** `SPARKTLSCrypto` and
`SPARKx509` are not in the Alire community index; `alire.toml` pins them by
relative path (`../sparkx509`, `../sparktlscrypto`) so they can be developed
side by side. `sparknacl` resolves from the Alire index. A checkout of
`sparktls` on its own will not resolve.

## Building

Prerequisites: [Alire](https://alire.ada.dev) 2.x with GNAT 16 and
gnatprove 16 (Alire fetches the toolchain), OpenSSL for the test fixtures,
and Go for the BoGo runner (downloaded on first run). The repository ships
a Nix flake that provides all of this reproducibly:

```sh
# sibling checkouts
git clone https://github.com/docandrew/sparkx509
git clone https://github.com/docandrew/sparktlscrypto
git clone https://github.com/docandrew/sparkentropy
git clone https://github.com/docandrew/sparktls
cd sparktls

alr build                                     # the library
(cd examples && alr build)                    # example clients and servers
nix develop --command bash ci/check.sh        # the CI lane: versions + full test suite
```

Test suites can be run individually with `tests/run_all.sh unit|integration|protocol|x509|bogo|fuzz`;
`tests/bogo/run.sh -test "Pattern"` runs a subset of BoGo. Proofs:

```sh
nix develop --command bash ci/prove.sh                    # whole project, level 1 (the release gate)
nix develop --command bash ci/prove.sh -u sparktls-client.adb   # one unit
```

`sparktlscrypto/ci/timing.sh ctgrind` runs the constant-time lane. The
`cli/` directory holds `sparktls_cli`, a development tool for generating
keys, certificates and CSRs and for inspecting and verifying chains.

## Disclaimer

SparkTLS is provided "as is" without any warranty. Use at your own risk.
