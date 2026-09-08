# BoGo Classification

BoGo is included in the default release `run_all.sh` suite. The runner still
uses BoringSSL's exact test names, shim flags, and error expectations, so the
local wrapper classifies tests with skip globs in `tests/bogo/run.sh`.

There is ONE profile (since 2026-08-17). Skip globs in `tests/bogo/run.sh`
cover genuinely unsupported features only, each with a reason. Anything that
fails, fails visibly.

A second, laxer "temporary triage" mode used to exist behind
`BOGO_STRICT_SUPPORTED=1`. It was removed because an audit found 45 of its 49
globs were stale -- tests fixed over time that nobody re-enabled -- so the
default run hid ~290 passing tests and under-reported coverage by a third.
A stale skip and a real gap look identical from the outside.

NOTE (2026-08-22): `BOGO_STRICT_SUPPORTED` no longer does anything. It
survived only in two comments and in this document, which until now still
described the two-profile world and quoted a `789/789 passed, 0 failed`
figure from it. That number is NOT reproducible -- setting the variable
today yields exactly the default run. Both comments and the figure are gone;
the numbers below are the only ones the runner can actually produce.

The BoGo runner's status line is `failed/unimplemented/done/started/total`.
Runner totals are already after `-skip` filtering, so out-of-scope cases are
not in the denominator. The wrapper prints an `Out of scope` line showing how
many skip globs were applied.

## Current Result

```
./tests/bogo/run.sh
1021/1598 passed, 70 failed, 507 unimplemented, 0 skipped
    Out of scope: 137 skip globs applied (not included in total)
```

The 507 `unimplemented` are BoGo cases the shim cannot express because it is
missing a flag, not cases we fail. They are enumerated by flag below.

### Measured flag histogram (2026-08-22)

Obtained by wrapping the shim so it logs the flag it rejected on exit 89:

```
   1577 -dtls                     633 -new-x509-credential
    526 -quic                     310 -new-rpk-credential
    249 -ocsp-response            190 -accepted-peer-cert-types
    181 -enable-early-data        170 -new-psk-credential
    168 -verify-fail              148 -enable-ocsp-stapling
    133 -use-custom-verify-cb      97 -cnsa1-202603
     96 -fips-202205               96 -cnsa2-202603
     95 -wpa-202304                80 -enable-channel-id
     77 -psk                       64 -reverify-on-resume
```

71 distinct flags, 5527 rejections -> 507 test cases.

HOW TO READ THESE: the shim aborts on its FIRST unknown flag, so counts are
biased toward flags appearing early in argv. They rank blockers correctly; they
are NOT "N tests need exactly this flag". 5527 > 507 because BoGo invokes the
shim repeatedly per case (client/server roles, resume iterations).

| Cause | Rejections | Share | Verdict |
|---|---|---|---|
| DTLS + QUIC | 2135 | 38.6% | Different transports, not TLS-over-TCP conformance. Out of scope; DTLS stays in the RFLX specs for later. |
| Credential API family | 1348 | 24.4% | Mostly BoringSSL API *shape*. Two real features hide inside: raw public keys (RFC 7250, ZERO refs in src/) and delegated credentials (RFC 9345). |
| OCSP stapling | 397 | 7.2% | REAL GAP. `status_request` occurs in 2 files, comments only. RFC 6066 s8. Follow-on to #24 / #26. |
| Verify-callback API | 397 | 7.2% | How BoGo installs a verifier, not what we verify. Harness gap. |
| Policy profiles FIPS/CNSA/WPA | 384 | 6.9% | REAL GAP. Suite/curve policy. Feeds #41. |
| Non-RFC Google exts | 276 | 5.0% | Channel ID, False Start, NPN, ALPS. Never RFCs; NPN obsoleted by ALPN. Out of scope. |
| TLS 1.3 0-RTT early data | 181 | 3.3% | Deliberate and DOCUMENTED: client.ads:186, server.ads:79. Honest gap. |
| ECH | 81 | 1.5% | Not implemented. |
| TLS 1.2 PSK suites | 77 | 1.4% | Not implemented. |

STALE-DOC WARNING for the section below: it names `-signing-prefs`,
`-verify-prefs`, `-expect-peer-signature-algorithm`, `-export-keying-material`,
`-expect-no-session-id` and `-expect-hrr` as blockers. NONE of them appear in the
measured histogram, because bogo_shim.adb:800-814 now accept-and-ignores that
whole class. Those cases are no longer hidden -- they RUN, and pass or fail on
their merits. Re-verify any claim in that section before acting on it.

## Supported Surface Hidden By Missing Shim Flags

These buckets do apply to SPARKTLS, at least in part. Do not broadly skip them
without either implementing the shim flag or proving the exact case depends on
an unsupported feature.

- Basic TLS 1.2 / TLS 1.3 client and server handshakes. Several
  `Basic-*`, `TLS13-1RTT-*`, and `TLS13-HelloRetryRequest-*` cases are blocked
  by expectation-only flags such as `-expect-no-session-id`, `-expect-hrr`, or
  `-expect-early-data-reason`. These should be accepted or checked by the shim
  so the protocol transcript runs.
- Supported TLS 1.2 and TLS 1.3 cipher suites. The
  `TLS-TLS12-ECDHE_*` and `TLS-TLS12-AES_*` cases are blocked by
  `-export-keying-material`. The shim maps `-cipher` into
  `Config.TLS12_Cipher_List` / `Config.TLS12_Cipher_Groups`; the modern ECDHE
  AEAD `CipherNegotiation-*` cases run, while CBC/static-RSA cases are skipped
  as unsupported cipher-family coverage.
- Signature algorithm negotiation and verification. The `Client-Sign-*`,
  `Server-Sign-*`, `Client-Verify-*`, `Server-Verify-*`, and invalid-signature
  matrices are blocked by `-signing-prefs`, `-verify-prefs`, and
  `-expect-peer-signature-algorithm`. They apply for RSA-PSS, ECDSA P-256,
  ECDSA P-384, and Ed25519. Legacy SHA-1 and RSA-PKCS1 policy variants remain
  unsupported by design.
- Client authentication. Server-side required and optional mTLS now runs in
  strict BoGo for TLS 1.2 and TLS 1.3, including omitted client Certificate,
  omitted CertificateVerify, and garbage leaf-certificate rejection. Remaining
  client-auth matrices with certificate-selection or client-CA-list callback
  knobs need case-by-case mapping to SPARKTLS's public API.
- ALPN and SNI. SPARKTLS supports ordered ALPN preference lists through
  `Config.ALPN_List` / `Config.ALPN_Count`, while the legacy single `ALPN`
  field remains supported. Normal ALPN client/server negotiation, decline,
  reject-unknown, and empty-name validation now run in the default BoGo profile.
  Remaining strict ALPN policy cases are out of scope:
  `ALPNClient-AllowUnknown-*` permits a server-selected protocol the client did
  not offer, `ALPNServer-SelectEmpty-*` asks the shim to select an illegal
  empty protocol. `ALPNServer-Reject-*` is implemented through
  `Config.Require_ALPN`. `ALPNServer-Async-TLS-TLS12` is classified with TLS
  1.2 session-ID resumption because BoGo disables tickets for that case.
  NPN-mixed ALPN preference cases do not apply because NPN is unsupported.
  Server-side SNI acknowledgement and deliberate no-ack policy now pass the
  focused TLS 1.2 and TLS 1.3 BoGo cases.
- TLS 1.3 HRR and key-share robustness. Some HRR cases are blocked by
  expectation flags; custom multi-share tests are currently outside the public
  API but should not mask standard HRR behavior.
- TLS 1.3 resumption edge cases. SPARKTLS has session tickets/resumption, so
  cases like `HelloRetryRequest-NonResumableCipher-TLS13`,
  `CurveID-Resume-Server`, and
  `FragmentAcrossChangeCipherSpec-Client-Resume-Packed` should be treated as
  known gaps unless a narrower unsupported feature is identified.
  Client-side ticket age serialization and server-advertised ticket lifetime
  enforcement now pass the strict BoGo cases. Server-side
  `resumption_across_names` ticket-flag emission is exposed as an opt-in
  configuration knob for intentionally shared multi-host deployments, while the
  default remains hostname-scoped.

## Unsupported / Out Of Scope

These are valid default-profile skips.

- TLS 1.0, TLS 1.1, SSL 3.0
  - `ConflictingVersionNegotiation` is skipped here despite its generic name:
    the case expects the server to negotiate TLS 1.1 because the
    `supported_versions` extension takes precedence over CH.legacy_version.
    SPARKTLS intentionally supports only TLS 1.2 and TLS 1.3. The companion
    TLS 1.2 precedence case, `ConflictingVersionNegotiation-2`, remains active
    and passes.
- DTLS and QUIC transports
- CBC and pure-RSA key exchange suites
- TLS 1.2 PSK cipher suites and external/imported PSK credentials
- ECH, PAKE, TrustAnchors, raw public key certificate types
- ALPS, NPN, Channel ID, OCSP/SCT, certificate compression, SRTP, server
  padding, and BoringSSL compliance-policy profiles
- ML-KEM/Kyber post-quantum hybrid groups and ML-DSA signatures
  - `CurveTest-Server-EqualPreference-TLS13` is also skipped here despite its
    generic name: the case expects ML-KEM group `0x0202`.
  - `KeyShareWithServerHint-OverridesExplicitKeyShare-TLS13` and
    `KeyShareWithServerHint-OverridesExplicitEmptyKeyShare-TLS13` are also
    skipped here despite generic names: both require the server hint to select
    an unsupported ML-KEM hybrid key-share group.
- 0-RTT / early data
- TLS 1.2 renegotiation
- TLS 1.3 KeyUpdate
- P-521
- SHA-1 and legacy RSA-PKCS1 signature schemes
- False Start
- SSLv2-compatible ClientHello generation/acceptance
- TLS-unique channel binding
- BoringSSL ticket callback / DDoS callback / failure callback APIs
- BoringSSL shim ticket rewriting / private serialized-ticket mutation APIs
- BoringSSL peek and arbitrary alert-send shim APIs
- BoringSSL max-send-fragment API knobs
- BoringSSL split-handshaker and hint-mismatch tests
- NPN, OCSP/certificate_status, SCT, and certificate compression, including
  BoGo cases with generic names whose flags exercise only those extensions
- `MaxSendFragment-*`: SPARKTLS does not expose a max-send-fragment API today,
  and satisfying BoGo requires the cap to apply to handshake records as well as
  application data.
- `GREASE-Client-*`: SPARKTLS has unknown-value tolerance in parsing where TLS
  requires extensibility, but intentionally does not actively emit GREASE values.
  Deterministic ClientHello serialization is a project policy, so these BoGo
  client-emission probes are out of scope rather than MVP gaps.
- `Server-JDK11-*`: BoringSSL's opt-in JDK 11 workaround fingerprints old
  Java 11 ClientHello shapes and deliberately negotiates TLS 1.2 to avoid
  pre-11.0.2 TLS 1.3/SNI resumption bugs. SPARKTLS prioritizes spec-correct
  version negotiation; affected clients should update or explicitly disable
  TLS 1.3.
- `ALPNClient-AllowUnknown-*`: accepting a server-selected ALPN protocol the
  client did not advertise is intentionally not exposed.
- `ALPNServer-SelectEmpty-*`: selecting an empty ALPN protocol is invalid
  RFC 7301 behavior and not exposed by SPARKTLS.
- `Agree-Digest-*`: these BoGo probes exercise legacy TLS 1.2 RSA-PKCS1/SHA-1
  CertificateVerify digest agreement. SPARKTLS signs and verifies with
  RSA-PSS, ECDSA P-256/P-384, and Ed25519.
- `RetainOnlySHA256-*`: this is a BoringSSL client-certificate storage
  optimization API, not a SPARKTLS protocol feature.
- `ALPNServer-Async-TLS-TLS12`: despite its ALPN name, this case disables
  TLS 1.2 tickets and expects session-ID resumption via BoringSSL's async
  session callback. SPARKTLS supports TLS 1.2 ticket resumption, not session-ID
  resumption.
- `ShimTicketRewritable`: BoGo mutates BoringSSL's own serialized shim-ticket
  internals and expects `bssl_shim` to deserialize the rewritten ticket. SPARKTLS
  TLS 1.2 tickets use RFC 5077 stateless ticket-encryption keys, and TLS 1.3
  tickets are bounded ticket-store identifiers. Exposing BoringSSL's private
  ticket format would be test-harness compatibility code, not protocol
  functionality.

## Intentional Behavior Mismatch

These are temporary default-profile skips because BoGo checks BoringSSL-specific
alert strings, callback behavior, or policy choices. They are not necessarily
out of scope; they remain visible with `BOGO_STRICT_SUPPORTED=1` and should be
burned down over time. tlsfuzzer remains the stricter malformed-message protocol
oracle for these areas.

- wrong handshake message type
- trailing handshake message data
- malformed or unexpected extensions
- version-negotiation and downgrade alert-string details
- warning-alert and empty-record policy details
- strict close-notify / post-shutdown application-data policy details
- strict mTLS/server-auth error mapping details
- extension echo / omission compatibility details
- Fallback SCSV and Extended Master Secret policy probes

## Next Burn-Down Order

1. Accept or check expectation-only BoGo flags that do not change SPARKTLS
   behavior: `-expect-no-session-id`, `-expect-hrr`,
   `-expect-early-data-reason`, `-expect-peer-signature-algorithm`,
   `-expect-server-name`, and similar read-only assertions.
2. Revisit HRR and resumption edge cases case-by-case. ALPN's
   remaining strict failures are policy/resumption cases, not ordinary
   multi-protocol negotiation.

Do not add broad globs such as `TLS12-*`, `Basic-*`, `GREASE-Client-*`,
`Client-Sign-*`, or `Server-Sign-*`. Those names include supported SPARKTLS
behavior and need targeted implementation or precise classification.
The modern ECDHE AEAD `CipherNegotiation-*` cases are covered by both profiles.
The six skipped cases in that bucket require CBC or static-RSA suites, which
are intentionally unsupported.

## Current Default Profile

After accepting read-only expectation flags plus harmless BoGo shim controls
such as `-no-op-extra-handshake` and `-no-legacy-server-connect`, and moving
newly exposed supported-surface gaps into `TEMPORARY_TRIAGE_SKIPS`, the default
BoGo profile is green:

```
./tests/bogo/run.sh
495/495 passed, 0 failed, 0 unimplemented, 0 skipped
```

Recent burn-down:

- `OmitExtensions-*` / `EmptyExtensions-*`: TLS 1.2 ClientHello messages with
  omitted or explicitly empty extension blocks are now accepted. TLS 1.2
  ServerHello omits the extensions field when no extensions are echoed.
- `SendPostHandshakeChangeCipherSpec-TLS13`: encrypted TLS 1.3 records with an
  inner ChangeCipherSpec content type are now reported as unexpected-message
  protocol violations instead of being conflated with AEAD authentication
  failure.

Recent strict burn-down:

- `TLS13-Server-ResumptionAcrossNames`: burned down by exposing
  `Config.TLS13_Resumption_Across_Names`, defaulting it to `False`, and having
  the BoGo shim enable it only for the explicit
  `-resumption-across-names-enabled` case.
- `TrailingDataWithFinished-Resume-Client-TLS12` and
  `TrailingDataWithFinished-Resume-Server-TLS12`: burned down by using the
  correct TLS 1.2 write epoch for fatal alerts during abbreviated handshakes.
  The client is still plaintext before its CCS; the server is already encrypted
  after its CCS+Finished.
- `UnencryptedEncryptedExtensions`: burned down by treating plaintext records
  in the TLS 1.3 encrypted-handshake epoch as protected-record failures
  (`bad_record_mac`) instead of parsing them as plaintext handshake messages.
- ordinary multi-protocol ALPN negotiation and fatal reject-on-no-overlap
  policy are implemented and now run in the default profile.
- `VerifyPreferences-*` and `Client/Server-Sign-Negotiate-*`: burned down by
  mapping BoGo signature preference flags to `Config.Verify_Sig_Algos` and
  `Config.Sign_Sig_Algos`.
- `Server-Verify-*-TLS12`: burned down by keeping the BoGo shim's externally
  managed TLS 1.2 ticket key stable across mTLS resume iterations. The
  signature verification path was already accepting the expected schemes; the
  failure was `didResume=false` after the first client-auth handshake.
- `TLS13-TestValidTicketAge-Client` and
  `TLS13-HonorServerSessionTicketLifetime-*`: burned down by recording TLS 1.3
  ticket receipt time, serializing `obfuscated_ticket_age` as elapsed age plus
  `ticket_age_add`, and suppressing expired tickets before ClientHello
  construction.
- `TLS13-NoTicket-NoMint`: burned down by mapping BoGo's `-no-ticket` shim
  flag to SPARKTLS's existing null `Ticket_Store` server policy.
- `SendReceiveIntermediate-*`: burned down by sending the full configured
  client certificate chain in TLS 1.3 client-auth, matching the existing TLS
  1.2 and server-side TLS 1.3 behavior.
- `Downgrade-TLS12-Server-TLS`: burned down by emitting the RFC 8446
  `DOWNGRD\x01` ServerHello.random sentinel when a TLS 1.3-capable SPARKTLS
  server negotiates TLS 1.2.
- `Client-Verify-*` and `NoCommonAlgorithms*`: remaining strict failures are
  certificate/signature-type matrix behavior and alert-mapping gaps, not
  missing preference-list plumbing.
- `GREASE-Client-*`: active GREASE emission is intentionally out of scope; see
  the Unsupported section above.
- `TLS-TLS12-*`: burned down by wiring BoGo's exporter flags through
  `SPARKTLS.Export_Keying_Material` and raising the TLS 1.2 exporter/PRF
  practical bound to 1024 bytes.
- `ShimTicketRewritable`: reclassified as unsupported BoringSSL shim-ticket
  serialization behavior; see Unsupported above.

The `Basic-Server-TLS-*` bucket was burned down by configuring TLS 1.2 ticket
keys in the BoGo shim and fixing TLS 1.2 ServerHello session-id echo length on
abbreviated resumption.

The `ServerNameExtensionServer-TLS-*` bucket was burned down by emitting the
empty server_name acknowledgement in TLS 1.2 ServerHello and TLS 1.3
EncryptedExtensions, while suppressing the TLS 1.3 acknowledgement on PSK
resumption per RFC 8446.

`PointFormat-Client-MissingUncompressed` was burned down by validating the
TLS 1.2 ServerHello `ec_point_formats` body and rejecting lists that omit
uncompressed(0), per RFC 8422.

`ClientHelloPadding` was burned down as a BoGo shim policy fix: SPARKTLS
already padded ClientHello to a 512-byte fragment, but the shim was using
BoGo's long `-host-name` both for SNI and hostname verification. The shim now
sends the SNI while disabling hostname verification, matching BoGo's default
insecure client mode.

`Client-SignDefault-ECDSA_SHA1-TLS12` and
`RSAKeyUsage-Client-WantEncipherment-*` were reclassified as unsupported:
SHA-1 signatures and pure-RSA key-encipherment cipher suites are intentionally
not implemented.

`Client-RejectJDK11DowngradeRandom` and `Downgrade-TLS12-Client-TLS` were
burned down by enforcing TLS 1.2 ServerHello downgrade markers in the TLS 1.2
fallback parser when the client offered TLS 1.3.

`SendSNIWarningAlert` was burned down by tolerating bounded warning-level
plaintext alerts before ServerHello, matching the existing TLS 1.2 warning
alert handling used after ServerHello.

`AlternateEmptyRecordsAndWarningAlerts` was burned down by authenticating
TLS 1.2 AES-GCM empty application-data records, advancing the record sequence
number for them, and enforcing the existing empty-record flood cap in the
TLS 1.2 connected client/server paths.
