#!/bin/bash
#  BoGo (BoringSSL adversarial test runner) integration.
#
#  Self-bootstrapping: on first run, downloads Go + clones BoringSSL +
#  builds the runner — into a cache directory under tests/bogo/_cache.
#  On subsequent runs the cache is reused.
#
#  Skips gracefully when network is unavailable or the toolchain
#  can't build for some reason.
#
#  Usage:
#    ./tests/bogo/run.sh                  # run the default test set
#    ./tests/bogo/run.sh -test "Pattern"  # filter tests
#    BOGO_WORKERS=8 ./tests/bogo/run.sh   # adjust parallelism
#    BOGO_PIPE=1 ./tests/bogo/run.sh      # emit per-test result lines

set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
SHIM="$REPO_ROOT/bin/tests/bogo_shim"
CACHE="$DIR/_cache"
GO_BIN="$CACHE/go/bin/go"
BORING_DIR="$CACHE/boringssl"
RUNNER="$CACHE/bogo_runner"
# Keep the default deterministic for CI and run_all.sh. Some BoGo resumption
# tests are sensitive to wall-clock/ticket-age scheduling when multiple shim
# processes run concurrently. Developers can still opt in to parallelism with
# BOGO_WORKERS=N for exploratory runs.
WORKERS="${BOGO_WORKERS:-1}"
# Always use runner pipe output internally. The wrapper redirects the raw
# runner output to last_results.log and prints its own concise summary, and
# pipe output contains exact per-test PASS/FAIL/UNIMPLEMENTED lines. The
# runner's non-pipe progress counter can retain internal unimplemented counts
# even when no selected test reports UNIMPLEMENTED.
PIPE_ARG=(-pipe)

GO_VER="1.23.4"
GO_URL="https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
BORING_URL="https://boringssl.googlesource.com/boringssl"
#  Pinned. BoGo is an upstream test suite that gains new cases over
#  time; an unpinned clone means CI fails the day BoringSSL adds a
#  test for something we do not implement (this happened with the
#  PostQuantumEnabledByDefault* cases). Bump deliberately, then
#  triage any new failures into the skip lists below.
BORING_REV="${BORING_REV:-0b2b80bdb886ea106021512a16b66cfddafa8302}"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

#  --update-baseline: rewrite EXPECTED_FAILURES.txt from the LAST run's
#  results. Deliberately does NOT re-run: refreshing a baseline from a fresh
#  run would bake in whatever that run happened to produce, including a
#  regression. Inspect the diff the previous run printed, then update.
if [ "${1:-}" = "--update-baseline" ]; then
    if [ ! -f "$CACHE/last_results.log" ]; then
        echo "No $CACHE/last_results.log -- run the suite first."
        exit 1
    fi
    if [ ! -f "$CACHE/last_run_full" ]; then
        echo "Last run was FILTERED (-test ...). Refusing to rewrite the"
        echo "baseline from a partial result set -- it would drop every"
        echo "known failure that run did not execute. Do a full run first."
        exit 1
    fi
    HDR=$(sed -n '/^#/p' "$DIR/EXPECTED_FAILURES.txt" 2>/dev/null)
    { [ -n "$HDR" ] && echo "$HDR"
      grep -ao 'FAILED ([^)]*)' "$CACHE/last_results.log" \
        | sed 's/^FAILED (//; s/)$//' | sort -u
    } > "$DIR/EXPECTED_FAILURES.txt.new"
    mv "$DIR/EXPECTED_FAILURES.txt.new" "$DIR/EXPECTED_FAILURES.txt"
    echo "Baseline updated: $(grep -vc '^#' "$DIR/EXPECTED_FAILURES.txt") known failures."
    exit 0
fi

echo "=== BoGo (BoringSSL adversarial TLS tests) ==="

mkdir -p "$CACHE"

# --- 1. Build the shim ------------------------------------------------
# Always invoke gprbuild, not only when the binary is missing. Incremental
# no-op rebuilds are fast, and this prevents stale shim executables from
# reporting old flag-support behavior after source changes.
echo "  Building bogo_shim ..."
if ! command -v alr >/dev/null 2>&1; then
    echo "  SKIP: alire not found, can't build shim"
    exit 0
fi
if ! (cd "$REPO_ROOT" &&
      HOME="${HOME:-/home/doc}" \
      XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" \
      XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}" \
      alr exec -- gprbuild -P "$REPO_ROOT/tests/bogo/bogo_shim.gpr") \
      2>&1 | tail -3
then
    echo "  SKIP: shim build failed"
    exit 0
fi

# --- 2. Install Go locally if not on PATH and not cached -------------
if command -v go >/dev/null 2>&1; then
    GO_BIN=$(command -v go)
elif [ ! -x "$GO_BIN" ]; then
    echo "  Fetching Go $GO_VER (one-time, ~75 MB) ..."
    if ! command -v curl >/dev/null 2>&1; then
        echo "  SKIP: curl not available, can't fetch Go"
        exit 0
    fi
    if ! curl -L -s -f -o "$CACHE/go.tar.gz" "$GO_URL"; then
        echo "  SKIP: Go download failed (network?)"
        exit 0
    fi
    if ! tar -xzf "$CACHE/go.tar.gz" -C "$CACHE/" 2>/dev/null; then
        echo "  SKIP: Go tarball extract failed"
        exit 0
    fi
    rm -f "$CACHE/go.tar.gz"
fi

if [ ! -x "$GO_BIN" ]; then
    echo "  SKIP: Go binary still missing after install attempt"
    exit 0
fi

# --- 3. Clone BoringSSL if not cached --------------------------------
if [ ! -d "$BORING_DIR" ]; then
    echo "  Cloning BoringSSL (one-time, shallow ~80 MB) ..."
    if ! command -v git >/dev/null 2>&1; then
        echo "  SKIP: git not available"
        exit 0
    fi
    if ! git clone -q "$BORING_URL" "$BORING_DIR" 2>&1; then
        echo "  SKIP: BoringSSL clone failed (network?)"
        exit 0
    fi
    if ! git -C "$BORING_DIR" checkout -q "$BORING_REV" 2>&1; then
        echo "  SKIP: BoringSSL revision $BORING_REV not found"
        exit 0
    fi
fi
#  A cache from before the pin was introduced may sit at a different
#  revision; realign it so local and CI runs agree.
if [ -d "$BORING_DIR/.git" ] &&
   [ "$(git -C "$BORING_DIR" rev-parse HEAD 2>/dev/null)" != "$BORING_REV" ]; then
    echo "  Cached BoringSSL is at a different revision; checking out $BORING_REV"
    git -C "$BORING_DIR" fetch -q origin "$BORING_REV" 2>/dev/null || true
    git -C "$BORING_DIR" checkout -q "$BORING_REV" 2>/dev/null || \
        echo "  WARNING: could not realign; results may differ from CI"
fi

# --- 4. Build the runner if not cached -------------------------------
if [ ! -x "$RUNNER" ]; then
    echo "  Building bogo_runner (one-time, ~2 min) ..."
    (cd "$BORING_DIR" && \
     "$GO_BIN" test -c -o "$RUNNER" ./ssl/test/runner) 2>&1 | tail -5
    if [ ! -x "$RUNNER" ]; then
        echo "  SKIP: bogo_runner build failed"
        exit 0
    fi
fi

# --- 5. Run the BoGo runner against our shim -------------------------
#  -idle-timeout 3s : most tests handshake in <100ms
#  -allow-unimplemented : let runner pass-through tests our shim
#                         returns 89 on (unsupported flags)
#  -loose-errors : map every un-mapped error to "" (we don't yet
#                  produce BoringSSL-specific error strings)
#
#  -skip SKIPS : drop BoGo tests for genuinely unsupported features only,
#                each with a reason in UNSUPPORTED_SKIPS below. There is
#                ONE mode -- see the "ONE MODE ONLY" note further down.
#                Anything failing fails visibly. See CLASSIFICATION.md.
#
#  Pattern syntax: semicolon-separated globs (Go path.Match), no
#  comma support. `*` matches anything except `-`.
UNSUPPORTED_SKIPS=(
  # TLS 1.0 / 1.1 (we ship 1.2 + 1.3 only)
  '*-TLS11-*' '*-TLS1-*' '*-TLS11' '*-TLS1'
  'TLS1-*' 'TLS11-*'
  'ConflictingVersionNegotiation'
  # CBC ciphers (AEAD-only by design — RFC 7366 / Lucky13)
  '*_CBC_*' 'MaxCBCPadding' 'CBCRecordSplitting*'
  # Post-quantum KEM hybrids are not implemented.
  '*MLKEM*' '*Kyber*' 'PostQuantumNotEnabledByDefaultForAServer'
  'CurveTest-Server-EqualPreference-TLS13'
  'KeyShareWithServerHint-OverridesExplicitKeyShare-TLS13'
  'KeyShareWithServerHint-OverridesExplicitEmptyKeyShare-TLS13'
  # Pure-RSA key exchange (we offer only ECDHE_RSA)
  '*RSA_WITH_AES_*' '*RSA_WITH_3DES_*' 'Basic-Server-RSA-*'
  # External/imported PSK APIs and TLS 1.2 PSK cipher suites are not
  # implemented. SPARKTLS supports ticket-based resumption separately.
  'PSK-*' '*ECDHE_PSK*' '*EmptyPSKHint*' 'EmptyECDHEPSKHint'
  'CheckECDSACurve-PSK-*'
  # TLS-ECH (draft, not implemented)
  'TLS-ECH-*'
  # DTLS and QUIC transports are separate protocols/APIs, not SPARKTLS's
  # stream-oriented TLS-over-TCP surface.
  '*-DTLS*' 'DTLS*' '*-QUIC*' 'QUIC*'
  # DTLS split-alert probes are named without a DTLS token but pass -dtls.
  'SendSplitAlert-*' 'StrayChangeCipherSpec'
  # ALPS/NPN/ChannelID/OCSP/SCT/server-padding/exporter callback APIs are
  # BoringSSL-specific or separately-scoped extensions not implemented by
  # SPARKTLS today.
  'ALPS-*' '*ALPS*' '*NPN*' '*ChannelID*' '*OCSP*'
  '*NextProtocol*' '*CertificateStatus*' 'SkipCertificateStatus'
  '*StatusRequest*'
  'AllExtensions-Client-Permute-*'
  'UnsolicitedCertificateExtensions-*'
  'ExtraClientEncryptedExtension-*'
  'IgnoreExtensionsOnIntermediates-*'
  'NoClientCertificateRequested-*'
  'SendDuplicateExtensionsOnCerts-*'
  'SendExtensionOnClientCertificate-*'
  'SendNoClientCertificateExtensions-*'
  'SendNoExtensionsOnIntermediate-*'
  # These ALPN-prefixed cases are specifically ALPN-vs-NPN preference tests.
  'ALPNServer-Preferred-*' 'ALPNServer-Preferred-Swapped-*'
  '*SignedCertificateTimestamp*' '*SCT*'
  '*ServerPadding*' '*server-padding*' '*ExportKeyingMaterial*'
  '*ExportTrafficSecrets*'
  # BoringSSL callback / auxiliary APIs not exposed by SPARKTLS.
  '*TicketCallback*' 'Server-DDoS-*' '*Fail*Callback*'
  '*EarlyCallback*' '*SRTP*' '*TLSUnique*' 'TLS-HintMismatch-*'
  'Peek-*' 'ShimSendAlert-*'
  # Post-quantum key exchange (X25519MLKEM768 etc.) is not implemented.
  # These assert PQ is on by default, which is a policy decision we have
  # not taken; they are not conformance failures.
  'PostQuantum*' '*MLKEM*' '*Kyber*'
  # BoringSSL compliance profiles exercise policy knobs we do not expose.
  'Compliance-*'
  # Active GREASE emission is intentionally out of scope. SPARKTLS keeps
  # ClientHello serialization deterministic while tolerating unknown values
  # where TLS extensibility requires it.
  'GREASE-Client-*'
  # BoringSSL's opt-in JDK 11 workaround fingerprints old Java 11 ClientHellos
  # and intentionally negotiates TLS 1.2 to avoid pre-11.0.2 TLS 1.3/SNI
  # resumption bugs. SPARKTLS prioritizes spec-correct negotiation; affected
  # clients should update or explicitly disable TLS 1.3.
  'Server-JDK11-*'
  # These signature-digest agreement probes are for legacy RSA-PKCS1/SHA-1
  # TLS 1.2 CertificateVerify behavior. SPARKTLS intentionally signs and
  # verifies with RSA-PSS, ECDSA P-256/P-384, and Ed25519.
  'Agree-Digest-*'
  # BoringSSL-specific ALPN policy knobs that deliberately allow or synthesize
  # protocol states normal SPARKTLS callers should not use.
  'ALPNClient-AllowUnknown-*'
  'ALPNServer-SelectEmpty-*'
  # BoringSSL retains only SHA-256 hashes of client certificates as an internal
  # memory optimization. SPARKTLS retains parsed certificate material according
  # to its own bounded state model and does not expose this API.
  'RetainOnlySHA256-*'
  # BoringSSL max-send-fragment API knob. SPARKTLS currently fragments
  # application writes at the protocol maximum and does not expose a
  # caller-configurable cap that also constrains handshake records.
  'MaxSendFragment-*'
  # bssl_shim async split-handshaker close-notify control flow. Ordinary
  # close_notify, shim-initiated shutdown, and split handshake records are
  # covered by other BoGo cases; this exact case depends on BoringSSL shim
  # execution-mode semantics rather than SPARKTLS protocol behavior.
  'Shutdown-Shim-TLS-Async-SplitHandshakeRecords'
  'Shutdown-Shim-TLS-Sync-SplitHandshakeRecords'
  # 0-RTT / EarlyData (removed by design — see no_0rtt memory)
  '*EarlyData*'
  # False Start and SSLv2-compatible ClientHello are not supported.
  'FalseStart*' 'NoFalseStart*' 'ExtraHandshake-FalseStart'
  'SendV2ClientHello-*'
  # Renegotiation (TLS 1.2 reneg intentionally rejected)
  'Renegotiat*' 'Shutdown-Shim-HelloRequest-*' 'SendHalfHelloRequest-*'
  # KeyUpdate: TLS 1.3 post-handshake rekey IS implemented (RFC 8446 4.6.3).
  # Only the DTLS variants remain out of scope, because DTLS itself is not
  # implemented -- these are excluded for that reason, not because rekeying
  # is unsupported.
  '*KeyUpdate*DTLS*' 'KeyUpdate-*-DTLS'
  # PQ signatures (ML-DSA not in scope)
  '*ML-DSA*'
  # SHA-1 / legacy RSA-PKCS1 / MD5-SHA1 sig schemes (deprecated).
  # SPARKTLS signs with RSA-PSS, ECDSA P-256/P-384, and Ed25519.
  '*RSA_PKCS1_*' '*ECDSA_SHA1*' '*MD5_SHA1*' '*SHA1-Fallback*'
  # Delegated credentials (RFC 9345) are not implemented.
  'DelegatedCredentials-*'
  'Server-SignDefault-ECDSA_SHA1-TLS12'
  'Client-SignDefault-ECDSA_SHA1-TLS12'
  # P-521 (not supported — we offer P-256/P-384/X25519)
  '*ECDSA_P521*' '*P521*' '*P-521*'
  # PAKE (RFC 8773 draft, not implemented)
  'PAKE*'
  # TrustAnchors extension (RFC 9450 draft, not implemented)
  '*TrustAnchors*'
  # Server certificate type (RFC 7250 raw public key, not implemented)
  'ServerCertificateType*'
  # TLS certificate compression (RFC 8879) is not implemented.
  'CertCompression*' '*CertCompression*'
  # SSL 3.0 (not supported)
  'NoSSL3*'
  # Disables every protocol version, including the TLS versions we support.
  'DisableEverything'

  # UNSKIPPED 2026-08-18 (task #54): the resumption / session-ticket
  # family, ~30 globs. Skipped as behaviours "SPARKTLS intentionally does
  # not expose THROUGH THE BOGO SHIM today" -- again a harness limitation
  # rather than a protocol decision. Measure, then re-skip individually.
  #
  # CORRECTION 2026-08-20: this block used to claim "we implement it
  # (tickets and session IDs)". The session-ID half was FALSE. Resumption
  # here is ticket/PSK-only -- Session_Cache.Lookup_Session is keyed by a
  # TICKET identity (Pre: ID'Length = Ticket_ID_Len) and returns a PSK, and
  # every Session_ID reference in the server is Legacy_Session_ID appearing
  # only in frame conditions (= 'Old), i.e. the RFC 8446 compatibility echo,
  # never a cache key. Measuring was still right: it surfaced 20 real gaps
  # (re-skipped below with the honest reason) and left the rest measured.
  #   was: 'Resume-*' 'TLS13-TestBadTicketAge-Client'
  #        'TLS13-Client-*TicketFlags*' 'TLS13-Client-EmptyTicketFlags'
  #        'TLS13-Client-NonminimalTicketFlags'
  #        'TLS13-SendBadKEModeSessionTicket-Server'
  #        'CertificateInResumption-TLS13' 'CertificateRequestInResumption-TLS13'
  #        'CurveID-Resume-Client-TLS13' 'ResumeTLS12SessionID-TLS13'
  #        'SupportTicketsWithSessionID' 'TicketSessionIDLength-*'
  #        'TLS12-NoTicket-*' 'TLS13-NoTicket-NoAccept'
  #        'SendEmptySessionTicket-*' 'CustomTicketExtension-TLS13'
  #        'ExtraPSKIdentity-TLS13' 'TLS13-TicketAgeSkew-*'
  #        'SessionTicketsDisabled-*' 'TLS12NoSessionID-TLS13'
  #        'TLS12SessionID-TLS13' 'TLS13SessionID-TLS13'
  #        'EchoTLS13CompatibilitySessionID'
  #        'TLS13-Client-*ResumptionAcrossNames'
  #        'EmptySessionID' 'Client-ShortSessionID' 'Client-TooLongSessionID'
  #        'Basic-Client-NoTicket-*' 'Basic-Server-NoTickets-*'
  # RE-SKIPPED 2026-08-20 (task #74): TLS 1.2 session-ID resumption
  # (RFC 5246 s7.3, the stateful abbreviated handshake keyed by session_id)
  # is NOT implemented, and is a DELIBERATE NON-GOAL -- it is the only
  # resumption mechanism requiring a server-side cache of master secrets,
  # which contradicts the stateless-ticket design (RFC 5077 TEKs for TLS
  # 1.2, ticket-store identifiers for TLS 1.3), the app-owned-storage model
  # (#28/#31), and the bounded-static-memory direction. TLS 1.3 removed
  # session-ID resumption entirely, so it is TLS-1.2-only investment.
  # Resumption itself IS supported and measured -- only this mechanism is
  # absent. All 20 fail with "didResume is false, but we expected the
  # opposite". Verified individually; families with other symptoms are
  # deliberately left UNSKIPPED (Basic-Client-RenewTicket-* fails with
  # "bad record MAC", a different and unexplained defect -- see #75).
  'Basic-Client-NoTicket-*' 'Basic-Server-NoTickets-*'
  'Client-ShortSessionID' 'Resume-Server-NoTickets-TLS12-TLS12'
  'ResumeTLS12SessionID-TLS13' 'SupportTicketsWithSessionID'

  # Despite the ALPN prefix, this TLS 1.2 case disables tickets and expects
  # session-ID resumption through BoringSSL's async session callback.
  'ALPNServer-Async-TLS-TLS12'
  'CurveID-Resume-Server' 'FragmentAcrossChangeCipherSpec-Client-Resume-Packed'
  'HelloRetryRequest-NonResumableCipher-TLS13'
  # BoringSSL rewrites its own serialized shim ticket internals for this test.
  # SPARKTLS TLS 1.2 tickets use RFC 5077 stateless TEKs, and TLS 1.3 tickets
  # are bounded ticket-store identifiers, so there is no compatible public API
  # to expose here.
  'ShimTicketRewritable'

  # BoringSSL client-auth matrix exercises shim behaviors and
  # per-iteration assertions we do not currently model. SPARKTLS mTLS
  # coverage lives in tests/integration/run.sh.
  # UNSKIPPED 2026-08-18 (task #54): the certificate-validation and
  # client-auth family. These were skipped as "shim behaviours we do not
  # currently model", which is a HARNESS justification, not a protocol
  # decision -- and it was hiding our coverage of certificate PATH
  # VALIDATION, which is the most security-critical thing this library
  # does. Precedent: 45 of 49 "temporary triage" globs turned out to be
  # stale, hiding ~290 passing tests. Measure, then re-skip only what is
  # genuinely a shim gap, individually and with a reason.
  #   was: 'ClientAuth-*' 'TLS12-Client-ClientAuth-*' 'TLS13-Client-ClientAuth-*'
  #        'NoClientCertificate-*' 'RejectEmptyCertificateAuthorities-*'
  #        'CertificateSelection-*' 'ClientCertificateType*'
  #        'CertificateVerification*' '*VerifyDefault*'

  # BoringSSL compatibility edge cases for features/policies that are
  # intentionally not supported right now.
  'FallbackSCSV' 'NoFallbackSCSV'
  'SendFallbackSCSV'
  # Arbitrary client key_share lists, including unknown/GREASE groups,
  # are a BoGo shim compatibility surface. SPARKTLS exposes a single
  # initial key_share group plus standard HRR fallback.
  'CustomKeyShares-*'
  # Oversized certificate-chain stress profile. SPARKTLS intentionally
  # bounds reassembled handshake messages and retained intermediates.
  'LargeMessage*'
  # EMS (RFC 7627) skips REMOVED 2026-08-18 -- see task #63. EMS is being
  # completed rather than deferred: it is the triple-handshake mitigation.
  # Status 2026-08-19 after wiring -expect-extended-master-secret into the
  # shim: 14/19 pass. ExtendedMasterSecret-TLS12-Server passes, so the
  # RFC 7627 s4 session_hash derivation is verified against BoringSSL on
  # the server path. Still failing and deliberately left visible:
  # ExtendedMasterSecret-TLS12-Client (client path) and the NoToYes /
  # YesToNo / YesToYes resumption-transition cases (RFC 7627 s5.3).
  #
  # The renegotiation EMS cases ARE skipped below -- not a gap, a
  # protocol decision: we do not implement renegotiation at all.
  'ExtendedMasterSecret-Renego-*'
  'Ed25519DefaultDisable-*'
  'PostQuantumNotEnabledByDefaultInClients'
  'SendClientVersion-RSA' 'SkipChangeCipherSpec-*'
  'NoCommonSignatureAlgorithms-TLS12-Fallback' 'NoCommonCurves'
  # RSA key-encipherment suites are pure-RSA key exchange, which is
  # intentionally unsupported.
  'RSAKeyUsage-Client-WantEncipherment-*'
  # These negotiation cases expect CBC or static-RSA cipher suites from
  # BoGo's legacy preference string. The modern ECDHE AEAD cases run.
  'CipherNegotiation-1' 'CipherNegotiation-2' 'CipherNegotiation-3'
  'CipherNegotiation-4' 'CipherNegotiation-7' 'CipherNegotiation-8'
)

# Join with ';' for the runner.
# ONE MODE ONLY (2026-08-17). There used to be a second, laxer mode with a
# "temporary triage" skip list, and BOGO_STRICT_SUPPORTED=1 to bypass it.
# An audit found 45 of those 49 globs were STALE: the tests had been fixed
# over time and nobody re-enabled them, so the default run hid ~290 passing
# tests and under-reported its own coverage by more than a third.
#
# A stale skip and a real gap look identical from the outside, and a laxer
# default mode is where skips go to be forgotten. So there is now one mode.
# Anything genuinely out of scope belongs in UNSUPPORTED_SKIPS with a
# reason; anything failing should fail visibly until it is fixed.
SKIPS=$(IFS=';'; echo "${UNSUPPORTED_SKIPS[*]}")
OUT_OF_SCOPE_GLOBS=${#UNSUPPORTED_SKIPS[@]}
TEMPORARY_TRIAGE_GLOBS=0

RUN_STATUS=0
"$RUNNER" \
    -shim-path "$SHIM" \
    -allow-unimplemented \
    -loose-errors \
    -num-workers "$WORKERS" \
    -idle-timeout 3s \
    -skip "$SKIPS" \
    "${PIPE_ARG[@]}" \
    "$@" > "$CACHE/last_results.log" 2>&1
RUN_STATUS=$?

#  Mark whether this run covered the WHOLE suite. A filtered run (-test ...)
#  produces a partial result set; diffing that against a full-suite baseline
#  reports every unrun known failure as "newly passing", and --update-baseline
#  would then wipe the baseline. Found while testing the diff, 2026-08-22.
if [ $# -eq 0 ]; then touch "$CACHE/last_run_full"; else rm -f "$CACHE/last_run_full"; fi

#  Stats line is "failed/unimplemented/done/started/total"
#  (per ssl/test/runner/runner.go:2244).
LAST=$(grep -oE "[0-9]+/[0-9]+/[0-9]+/[0-9]+/[0-9]+" "$CACHE/last_results.log" \
       | tail -1)

if [ -n "$LAST" ]; then
    FAILED=$(echo "$LAST" | cut -d/ -f1)
    UNIMPL=$(echo "$LAST" | cut -d/ -f2)
    DONE=$(echo "$LAST" | cut -d/ -f3)
    STARTED=$(echo "$LAST" | cut -d/ -f4)
    TOTAL=$(echo "$LAST" | cut -d/ -f5)
    PASSED=$(( DONE - FAILED - UNIMPL ))
    SKIPPED=$(( TOTAL - STARTED ))
else
    PASSED=$(grep -ao '^PASSED ([^)]*)' "$CACHE/last_results.log" | wc -l)
    FAILED=$(grep -ao '^FAILED ([^)]*)' "$CACHE/last_results.log" | wc -l)
    UNIMPL=$(grep -ao '^UNIMPLEMENTED ([^)]*)' "$CACHE/last_results.log" | wc -l)
    DONE=$(( PASSED + FAILED + UNIMPL ))
    STARTED=$DONE
    TOTAL=$DONE
    SKIPPED=0
fi

echo
echo "=== BoGo: $PASSED/$TOTAL passed, $FAILED failed, $UNIMPL unimplemented, $SKIPPED skipped ==="
echo "    Out of scope: $OUT_OF_SCOPE_GLOBS skip globs applied (not included in total)"
if [ "${TEMPORARY_TRIAGE_GLOBS:-0}" -gt 0 ]; then
    echo "    Temporary triage: $TEMPORARY_TRIAGE_GLOBS skip globs applied (not included in total)"
fi

BASELINE="$DIR/EXPECTED_FAILURES.txt"

#  Regression detection by DIFF, not by count.
#
#  Counts cannot identify a regression: a run that fixes one test and breaks
#  another shows the same totals. On 2026-08-22 the totals moved 1021/70 ->
#  1020/71 and finding the single moved test cost a full extra suite run,
#  because no baseline list existed.
#
#  The old code here dumped failures truncated at 80 names. Truncation is how
#  defects hide -- never truncate the regression list.
if [ -f "$BASELINE" ] && [ ! -f "$CACHE/last_run_full" ]; then
    echo "    (filtered run -- not diffed against EXPECTED_FAILURES.txt)"
    [ "${FAILED:-0}" -gt 0 ] && exit 1
    exit 0
fi

if [ -f "$BASELINE" ]; then
    ACTUAL=$(mktemp); EXPECTED=$(mktemp)
    grep -ao 'FAILED ([^)]*)' "$CACHE/last_results.log" \
      | sed 's/^FAILED (//; s/)$//' | sort -u > "$ACTUAL"
    grep -v '^#' "$BASELINE" | grep -v '^[[:space:]]*$' | sort -u > "$EXPECTED"

    NEW_FAIL=$(comm -23 "$ACTUAL" "$EXPECTED")
    NEW_PASS=$(comm -13 "$ACTUAL" "$EXPECTED")
    rm -f "$ACTUAL" "$EXPECTED"

    if [ -n "$NEW_FAIL" ]; then
        echo
        echo "!!! REGRESSION: $(echo "$NEW_FAIL" | wc -l) test(s) newly FAILING:"
        echo "$NEW_FAIL" | sed 's/^/    /'
    fi
    if [ -n "$NEW_PASS" ]; then
        echo
        echo ">>> $(echo "$NEW_PASS" | wc -l) test(s) newly PASSING (update the baseline):"
        echo "$NEW_PASS" | sed 's/^/    /'
        echo "    Refresh with: $0 --update-baseline"
    fi
    if [ -z "$NEW_FAIL" ] && [ -z "$NEW_PASS" ]; then
        echo "    Failures match EXPECTED_FAILURES.txt exactly ($FAILED known)."
    fi

    #  Exit non-zero ONLY on regression. Known failures are already tracked,
    #  each with an owning task; failing the run on them would make the signal
    #  useless. Newly-passing is not a failure but must be visible.
    [ -n "$NEW_FAIL" ] && exit 1
    exit 0
fi

#  No baseline: fall back to listing everything, untruncated.
if [ "${FAILED:-0}" -gt 0 ]; then
    echo "Failed cases (no EXPECTED_FAILURES.txt to diff against):"
    grep -ao 'FAILED ([^)]*)' "$CACHE/last_results.log" \
      | sed 's/^FAILED (//; s/)$//' | sort | sed 's/^/    /'
    exit 1
fi
exit 0
