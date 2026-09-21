# BoGo Classification

BoGo (BoringSSL's TLS test runner) is part of the default `tests/run_all.sh`
suite. The runner keeps BoringSSL's exact test names, shim flags and error
expectations; `tests/bogo/run.sh` drives our shim (`tests/bogo/bogo_shim.adb`)
against it and classifies the outcome in three places:

- **Skip globs** in `run.sh` (`UNSUPPORTED_SKIPS`): features SPARKTLS does not
  implement, each with a reason. These cases are removed from the runner's
  denominator and reported as "Out of scope".
- **`EXPECTED_FAILURES.txt`**: every case that runs and fails, one name per
  line, with a comment block explaining each family. A run is diffed against
  this list; any other failure is a regression and fails the lane.
- **Unimplemented** (shim exit 89): cases the shim cannot express because it
  lacks a flag. These are the remaining coverage gaps, listed below.

There is ONE profile. A laxer "temporary triage" mode used to exist and hid
~290 passing tests behind stale globs; a stale skip and a real gap look
identical from the outside, so it was removed (2026-08-17).

## Current Result (2026-09-21)

```
./tests/bogo/run.sh
1675/1745 passed, 70 failed, 0 unimplemented, 0 skipped
    Out of scope: 194 skip entries applied (not included in total)
    Failures match EXPECTED_FAILURES.txt exactly (70 known).
```

History: 1021/1598 (2026-08-22) -> 1073/1735 (2026-09-13, after the
security burndown) -> 1393/1576 -> 1462/1536 -> 1464/1534 (2026-09-14) ->
1477/1547 (2026-09-20) -> 1675/1745 (2026-09-21, skip-list audit).

### What the 2026-09-21 audit did

A full run with every skip glob removed (7908 cases: 1974 pass, 1218 fail,
4716 unimplemented) showed 497 currently skipped cases passing. They were
judged family by family: a case that passes because we refuse the
feature it targets (TLS 1.0/1.1, CBC, P-521, pure RSA key exchange) is a
pass for the wrong reason and stays skipped; a case whose pass means what
the test says was unskipped. Globs were narrowed to literal names of the
cases that still fail (each with a reason in `run.sh`):

- `*RSA_PKCS1_*` hid 89 passing cases: RSA PKCS#1 v1.5 IS implemented for
  TLS 1.2, only SHA-1 and the `_LEGACY` code point are out.
- `*RSA_WITH_AES_*` also matched the ECDHE_RSA AEAD suites we support.
- Whole families that pass and were dropped from the skip list:
  HelloRequest/renegotiation refusal, SkipChangeCipherSpec, unsolicited
  certificate extensions, NoClientCertificateRequested, several singles.
- Partial families narrowed with literals: ECDSA_SHA1 (TLS 1.3 refusals
  pass), Server-JDK11, ExportKeyingMaterial (exporters are implemented),
  KeyShareWithServerHint, CustomKeyShares, Agree-Digest, NoSSL3,
  RetainOnlySHA256, EMS-Renego, RSAKeyUsage, CertificateSelection cipher
  suite and signature-algorithm families, CertCompression and SCT
  refusals.

The 4716 unimplemented cases are features, not shim gaps: DTLS 2060,
TLS 1.0/1.1 732, QUIC 652, BoringSSL compliance profiles 348,
ALPS/NPN/ChannelID 265, external PSK 177, 0-RTT 172, ECH 106, the rest
BoringSSL-specific APIs.

## Sweep of 2026-09-14

### What this sweep did

- Shim flags for BoringSSL's verifier API: `-verify-fail`,
  `-expect-verify-result`, `-use-custom-verify-callback`,
  `-reverify-on-resume`, `-use-old-client-cert-callback`. 96 cases moved from
  unimplemented to running.
- Server-side OCSP stapling, a real feature: `Identity.OCSP_Staple` /
  `Set_OCSP_Staple` / `Credentials.Load_Staple`; the server staples for a
  client that sent `status_request` (TLS 1.3 CertificateEntry extension,
  TLS 1.2 CertificateStatus). Client-side `Config.Verify_Staple` verdict hook.
  Shim flags `-ocsp-response`, `-use-ocsp-callback`, `-set-ocsp-in-callback`,
  `-decline-ocsp-callback`, `-fail-ocsp-callback`. All 112 OCSP cases pass.
- The TLS 1.3 client now sends its fatal alert on certificate, CertificateVerify
  and Finished rejections (it used to close the connection silently).
- Both servers read the client's authentication flight as a message stream
  (messages packed into one record or split across records reassemble).
- TLS 1.2 client resumption: the session_id echo is now recognised, so a
  server that renews the ticket during an abbreviated handshake works, and a
  server echoing a session_id we never offered a ticket for is refused.
- PSK offers with several identities verify against the correct binder
  transcript; unknown psk_key_exchange_modes decline the PSK rather than
  aborting; non-minimal ticket_flags are refused.
- Multi-credential selection: `Config.Identities` (a server-side identity
  set chosen by the client's signature_algorithms, cipher-suite family,
  ECDSA curve and, for `Must_Match_Issuer` identities, its
  certificate_authorities), per-identity `Sign_Prefs` honoured by selection
  and by the scheme negotiators, `Select_Client_Identity` receives
  certificate_types, and `Local_Identity` reports the choice. The shim maps
  BoGo's credential blocks onto it. Nothing is left unimplemented.
- Raw public keys, delegated credentials, trust anchor identifiers and the
  certificate-callback failure cases became explicit out-of-scope skips.

## Remaining Unimplemented

None. Every remaining BoGo case either runs or is an explicit out-of-scope
skip with a reason in `run.sh`.

## Known Failures (74, all in EXPECTED_FAILURES.txt)

The comment blocks in `EXPECTED_FAILURES.txt` are authoritative. The families:

- **Alert-choice deviations (32)**: `CertificateVerificationFail-*-Sync*`.
  BoGo pins BoringSSL's alert for a failed verify callback (handshake_failure
  for the legacy callback, certificate_unknown for the custom one). We refuse
  the chain but say bad_certificate, because BoGo's test leaf has an empty
  subject with a non-critical SAN, which RFC 5280 4.2.1.6 forbids and
  x509-limbo expects rejected, so validation fails structurally before the
  application veto hook (which would say certificate_unknown) can run.
- **No re-verification on resumption (16)**:
  `CertificateVerificationFailsOnResume-*`. Tickets carry no peer chain.
- **Ed25519 in TLS 1.2 (11)**: `*-Ed25519-TLS12`, `*VerifyDefault-Ed25519-*`,
  `CertificateSelection-Client-ClientCertificateTypes-ECDSA-Ed25519-*`.
  Ed25519 client authentication in TLS 1.2 is intentionally declined (the
  streaming transcript cannot provide PureEdDSA's second pass); the verify
  variants are the mirror image.
- **Client sends an empty Certificate where BoringSSL aborts (12)**:
  `CertificateSelection-Client-*-MatchNone-*`. RFC 8446 4.4.2 and RFC 5246
  7.4.6 require the empty Certificate when no credential fits; BoGo pins
  BoringSSL's handshake_failure. Intentional.
- **TLS 1.2 ECDSA curve/hash coupling (1)**:
  `CertificateSelection-Client-SignatureAlgorithmECDSACurve-TLS-TLS12`: a
  P-384 key asked to sign with ecdsa_secp256r1_sha256; our signer binds
  P-384 to SHA-384.
- **One-offs**: `Resume-Server-NoPSKBinder-SecondBinder` (alert choice),
  `CertificateRequestInResumption-TLS13` (undiagnosed), `ExtraPSKIdentity`
  siblings if any; see the list's comment blocks.

## Out Of Scope (skip globs, with reasons in run.sh)

TLS 1.0/1.1; CBC and static-RSA cipher suites; external PSKs and TLS 1.2 PSK
suites; DTLS and QUIC; ECH; 0-RTT early data; renegotiation; channel ID, NPN,
false start, ALPS, SCTs, token binding; post-quantum hybrids; raw public keys
(RFC 7250) and the `client/server_certificate_type` negotiation; delegated
credentials (RFC 9345); trust anchor identifiers; TLS 1.2 session-ID
resumption; certificate-selection probes that only offer CBC or static-RSA
suites; the 0-RTT ticket-age-window probes; BoringSSL shim-only mechanisms (ticket/DDoS/certificate callbacks
that must fail, shim ticket rewriting, hint mismatch, TLS-unique, SRTP);
active GREASE emission.

## Rules

- Do not add broad globs such as `TLS12-*`, `Basic-*`, `Client-Sign-*`. Those
  names include supported behaviour; use targeted implementation or a precise
  glob with a reason.
- A failing case is either fixed or listed in `EXPECTED_FAILURES.txt` with
  the reason. Never both silent and failing.
- Re-run `tests/bogo/flag_histogram.sh` when the unimplemented count changes
  materially; it ranks the blocking shim flags (biased toward flags early in
  argv, since the shim aborts on the first unknown one).
