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
- Heap allocation is bounded and validated: wire-declared lengths are
  converted to constrained subtypes before any allocation, so "validate
  before allocate" is enforced at the type level. Reassembly and RecordFlux
  buffers are heap-allocated and released explicitly
- `Session` is a private type and is **large — about 100 KB** (103,240 bytes
  on x86-64). It embeds its I/O buffers and a 16 KB application-data staging
  area instead of allocating them, which keeps the record path free of
  per-record heap traffic. Two consequences worth planning for: declaring one
  as an ordinary local puts ~100 KB on the stack (prefer library-level or
  heap allocation, especially inside tasks), and a server needs ~100 KB per
  concurrent connection — roughly 100 MB at 1000 connections. See
  `examples/tls_web_epoll.adb`, which holds its connection array at library
  level for this reason.
- RecordFlux-generated message serialization/parsing with SPARK contracts
- Crypto provided by SPARKNaCl + SPARKTLSCrypto (formally verified, AES-NI / VAES / VPCLMULQDQ / AVX-512 ChaCha20 fast paths)

## Not Supported (By Design)

- **TLS 1.3 0-RTT / early data.** Intentionally not implemented on
  either side. The `early_data` extension is never emitted or
  accepted; `client_early_traffic_secret` is never derived; the
  `end_of_early_data` message is never produced or consumed.
  Reason: 0-RTT records have no forward secrecy, are replayable by
  on-path attackers (pushing replay-safety into every caller), and
  the single-use-ticket "defense" is stateful and best-effort —
  collectively at odds with the project's high-integrity posture.
  PSK resumption (without early data) is fully supported.

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

## Not Yet Supported

- TLS 1.2 session-ID resumption
- Post-quantum key exchange (ML-KEM hybrid). SPARKTLS currently *tolerates*
  PQ peers without negotiating with them: `Wire_Key_Share_Len` is sized at
  16 KB so real ClientHellos carrying `X25519MLKEM768` (1220 bytes per entry)
  parse rather than being dropped, but only X25519 / secp256r1 / secp384r1 are
  offered or selected. Browser defaults have already moved to
  `X25519MLKEM768`, so peers currently fall back to classical groups.

  A plausible starting point is AWS Labs'
  [LibFormalPQC](https://github.com/awslabs/LibFormalPQC), which
  has an ML-KEM implementation in the SPARK Ada subset (`MLKEM/spark_ada`;
  there is also an `HQC/spark_ada`). It comes from the same author as
  SPARKNaCl, which this project already depends on. Note its own warning that
  it is "absolutely NOT intended for production" — constant-time properties
  are not formally verified at the generated-code level, intermediate values
  are not sanitized as FIPS 203 requires, and performance is not competitive
  with optimized implementations. Those caveats are worth reading in full
  before adopting it; several of them apply to this project too.

  Wycheproof ML-KEM known-answer vectors are already vendored under
  `tests/wycheproof/` (`mlkem_512/768/1024_*_test.json`), and tlsfuzzer has
  `test-tls13-mlkem.py`, so validation material is in place ahead of any
  implementation. BoGo's `PostQuantum*` / `*MLKEM*` / `*Kyber*` cases are
  skipped as out of scope until then — see `tests/bogo/CLASSIFICATION.md`.
- AES-CCM cipher suites (gating item for a FIPS-conformant profile)
- TLS 1.3 server-side 0-RTT (see "Not Supported" above — by design)

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

The sibling crates must sit alongside `sparktls`:

```
<parent>/
  sparktls/          <- this repo
  sparknacl/
  sparkx509/
  sparktlscrypto/
  sparkentropy/      <- only needed to build examples/
```

`ci/fetch-deps.sh` clones them at known-good commits, and is safe to re-run —
existing checkouts are left untouched:

```sh
git clone https://github.com/docandrew/sparktls.git
cd sparktls
ci/fetch-deps.sh
alr build
```

Note that committed `sparknacl` requires `gnatprove ^14.1.1` while everything
here requires `^15.1.0`; those ranges are disjoint and `alr` will refuse to
resolve. `ci/fetch-deps.sh` patches it after cloning — see the comment in that
script for why this is a stopgap.

Build the example programs (`tls_fetch`, `tls_blocking_server`, and others):

```sh
cd examples && alr build      # binaries land in bin/examples/
bin/examples/tls_fetch https://example.com/
```

## Regenerating RecordFlux Code

The `generated/` directory contains SPARK code generated from the message specs
in `specs/*.rflx` (Apache-2.0 WITH LLVM-exception, from AdaCore/RecordFlux).

**See `generated/README.md` for the authoritative regeneration procedure and
the two patches that must be re-applied afterwards.** Do not duplicate that
list here — it has gone stale before.

```sh
pip install recordflux
rflx generate -d generated/ specs/*.rflx
```

Apart from those two documented patches, everything in `generated/` must come
straight from `rflx generate` — do not hand-edit it.

Keep `generated/` in sync with `specs/`. It had drifted (found 2026-08-13):
`rflx-tls_handshake.ads`, `rflx-tls_handshake-client_hello.ads` and `.adb` were
missing the `Get_Legacy_Compression_Methods_Length` value-tracking conjuncts
that the current spec produces. Those appeared once
`Legacy_Compression_Methods_Length` was widened from `range 1 .. 1` to
`range 1 .. 255` (commit `c09330a`) — with a single-valued range the value was
static and needed no tracking. Their absence left
`Field_Size (Ctx, F_Legacy_Compression_Methods)` underdetermined, which blocked
the `Available_Space` preconditions on the following `Set_*` calls in
`SPARKTLS.Handshake.Client_Msgs`.

To check for drift: regenerate into a scratch directory and diff, ignoring the
`Generated by RecordFlux ... on <date>` header line.

## Testing

The full suite — build, unit, integration, protocol (tlsfuzzer), x509-limbo and
BoGo:

```sh
tests/run_all.sh                  # release build, all suites
tests/run_all.sh unit             # one suite: unit | integration | protocol | x509 | bogo
tests/run_all.sh --checked        # debug build, runtime checks + contracts ON
```

`--checked` compiles with `-gnata` so preconditions, postconditions, predicates
and `pragma Assert` are evaluated at runtime — it catches violations that proof
did not. Integration tests are excluded from that lane; see the note in
`tests/run_all.sh` about an RFLX 0.26.0 predicate that dereferences a null
buffer after `Take_Buffer`.

CI lanes and proof runs are in `ci/` — see `ci/README.md`. Proof should be run
through `ci/prove.sh`, which contains gnatprove in a memory cgroup so a runaway
solver cannot take the machine down.

Ad-hoc checks:

```sh
# ECDSA P-384 signature verification (NIST CAVP vectors from SigVer.rsp)
cd /tmp && unzip /path/to/186-4ecdsatestvectors.zip
alr exec -- gprbuild -P tests/ecdhe_p384_test.gpr && tests/ecdhe_p384_test

# Generate a local development certificate with the CLI
cd cli && alr -n --no-tty build
../bin/sparktls_cli devcert localhost to /tmp/key.pem /tmp/cert.pem

# Run the example SPARKTLS server
cd ..
bin/examples/tls_test_server /tmp/cert.pem /tmp/key.pem
# In another terminal:
bin/examples/tls_fetch https://127.0.0.1:8443/ -k
```

## Architecture

```
src/
  sparktls.ads/.adb              -- Session record, I/O buffers, config
  sparktls-client*.ads/.adb      -- Client handshake state machine (1.3 and 1.2)
  sparktls-server*.ads/.adb      -- Server handshake state machine (1.3 and 1.2)
  sparktls-records*.ads/.adb     -- TLS record layer (build/parse/encrypt/decrypt)
  sparktls-handshake*.ads/.adb   -- Handshake message build/parse (via RecordFlux)
  sparktls-key_schedule*.ads/.adb -- HKDF key derivation (1.3 and 1.2)
  sparktls-rflx_bridge.ads/.adb  -- SPARKNaCl <-> RecordFlux type conversion
  sparktls-tickets*.ads/.adb     -- Session ticket handling
generated/                       -- RecordFlux-generated SPARK (169 files)
specs/                           -- RecordFlux .rflx message specs (TLS 1.3 + 1.2)
cli/                             -- sparktls_cli (devcert generation, etc.)
examples/                        -- tls_fetch, tls_blocking_server, and others
```

Crypto primitives live in the SPARKTLSCrypto and SPARKNaCl crates, not here —
P-256/P-384 field, point and ECDSA operations, RSA, AES-GCM,
ChaCha20-Poly1305, SHA-2 and HKDF. X.509 parsing and chain validation live in
SPARKx509.

## Disclaimer

SparkTLS is a proof-of-concept project and is provided "as is" without any warranty.
Use at your own risk.
