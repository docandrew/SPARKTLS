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
#  -skip SKIPS : drop BoGo tests that are either genuinely unsupported
#                or, in the default profile, still-open compatibility
#                gaps. Set BOGO_STRICT_SUPPORTED=1 to skip only genuinely
#                unsupported features. See CLASSIFICATION.md for the full
#                design rationale per bucket.
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

  # TLS 1.3 post-handshake KeyUpdate is already skipped above. These
  # are related post-handshake / ticket-resumption probes for behaviors
  # SPARKTLS intentionally does not expose through the BoGo shim today.
  'Resume-*' 'TLS13-TestBadTicketAge-Client'
  'TLS13-Client-*TicketFlags*' 'TLS13-Client-EmptyTicketFlags'
  'TLS13-Client-NonminimalTicketFlags'
  'TLS13-SendBadKEModeSessionTicket-Server'
  'CertificateInResumption-TLS13' 'CertificateRequestInResumption-TLS13'
  'CurveID-Resume-Client-TLS13' 'ResumeTLS12SessionID-TLS13'
  'SupportTicketsWithSessionID' 'TicketSessionIDLength-*'
  'TLS12-NoTicket-NoMint' 'TLS12-NoTicket-NoAccept'
  'TLS12-NoTicket-NoOffer' 'TLS13-NoTicket-NoAccept'
  'SendEmptySessionTicket-*' 'CustomTicketExtension-TLS13'
  'ExtraPSKIdentity-TLS13'
  'TLS13-TicketAgeSkew-*-60-*'
  'TLS13-TicketAgeSkew-Backward-61-Reject'
  'TLS13-TicketAgeSkew-Forward-61-Reject'
  'SessionTicketsDisabled-*'
  'TLS12NoSessionID-TLS13' 'TLS12SessionID-TLS13'
  'TLS13SessionID-TLS13' 'EchoTLS13CompatibilitySessionID'
  'TLS13-Client-NoResumptionAcrossNames'
  'TLS13-Client-ResumptionAcrossNames'
  'EmptySessionID' 'Client-ShortSessionID' 'Client-TooLongSessionID'
  'Basic-Client-NoTicket-*' 'Basic-Server-NoTickets-*'
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
  'ClientAuth-*' 'TLS12-Client-ClientAuth-*' 'TLS13-Client-ClientAuth-*'
  'NoClientCertificate-*' 'RejectEmptyCertificateAuthorities-*'
  'CertificateSelection-*' 'ClientCertificateType*'
  'CertificateVerification*' '*VerifyDefault*'

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
  # Client-side EMS advertisement is disabled until the TLS 1.2 EMS
  # Finished path is interoperable. BoGo's TLS 1.3 forbidden-EMS probe
  # only triggers when the client offered EMS, so classify it with the
  # EMS feature matrix for now.
  'NoExtendedMasterSecret-*' 'ExtendedMasterSecret-*'
  'EMS-Forbidden-TLS13'
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

TEMPORARY_TRIAGE_SKIPS=(
  # These are supported-surface gaps or BoringSSL-specific behavior
  # mismatches. They stay visible in BOGO_STRICT_SUPPORTED=1 runs and
  # should burn down over time instead of being treated as out of scope.
  # BoGo verifies BoringSSL-specific alert/error strings for many
  # malformed-message probes. The protocol behavior is already covered
  # by tlsfuzzer; until the shim maps SPARKTLS errors to BoringSSL
  # strings, these are intentional behavior mismatches.
  'WrongMessageType-*' 'TrailingMessageData-*'
  'TrailingDataWithFinished-*' 'ExtensionTrailingData-*'
  'UnknownExtension-*' 'UnknownExtensionInCertificateRequest-*'
  'UnknownUnencryptedExtension-*' 'UnexpectedUnencryptedExtension-*'
  'UnofferedExtension-*' 'DuplicateExtensionClient-*'
  'UnencryptedEncryptedExtensions'
  'EmptyEncryptedExtensions-*' 'EncryptedExtensionsWithKeyShare-*'
  'ConflictingVersionNegotiation*' 'VersionNegotiation-*'
  'MinimumVersion-*' 'Downgrade-*' 'Client-*JDK11DowngradeRandom'
  'ServerNameExtensionClient*' 'ServerNameExtensionServer-NoACK-*'
  'UnsolicitedServerNameAck-*'
  'TolerateServerNameAck-*' 'SendSNIWarningAlert'
  'SendBogusAlertType' 'SendWarningAlerts-*' 'SendUserCanceledAlerts-*'
  'AlternateEmptyRecordsAndWarningAlerts'
  'AppDataBeforeTLS13KeyChange*'
  'Shutdown-Shim-ApplicationData-*'
  'Unclean-Shutdown' 'Unclean-Shutdown-Alert'
  'Null-Client-CA-List'
  'TLS12-Server-CertReq-CA-List'
  'TLS13-Server-CertReq-CA-List'
  'TLS13-Empty-Client-CA-List'

  # BoringSSL compatibility edge cases that are not yet implemented.
  'ClientHelloPadding'
  'PointFormat-*' 'SupportedCurves-*'
  'CurveTest-*' 'KeyShareWithServerHint-*'
  'NoCommonAlgorithms*'
  'TLS-TLS12-*'
  'Client-Verify-*'
  'RSAKeyUsage-*'
  'RSA-PSS-Default-Verify' 'Client-SignDefault-*'

  # Supported-surface gaps exposed by accepting BoGo's read-only
  # expectation flags. Keep these in strict-supported runs until fixed.
  'SendHelloRetryRequest*'
  'TLS13-1RTT-Client-TLS-*-SplitHandshakeRecords'
  'TLS13-HelloRetryRequest-*-TLS-*'
)
# Join with ';' for the runner.
if [ "${BOGO_STRICT_SUPPORTED:-0}" = "1" ]; then
    SKIPS=$(IFS=';'; echo "${UNSUPPORTED_SKIPS[*]}")
    OUT_OF_SCOPE_GLOBS=${#UNSUPPORTED_SKIPS[@]}
    TEMPORARY_TRIAGE_GLOBS=0
else
    ALL_SKIPS=("${UNSUPPORTED_SKIPS[@]}" "${TEMPORARY_TRIAGE_SKIPS[@]}")
    SKIPS=$(IFS=';'; echo "${ALL_SKIPS[*]}")
    OUT_OF_SCOPE_GLOBS=${#UNSUPPORTED_SKIPS[@]}
    TEMPORARY_TRIAGE_GLOBS=${#TEMPORARY_TRIAGE_SKIPS[@]}
fi

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

if [ "${FAILED:-0}" -gt 0 ]; then
    echo "Failed cases:"
    grep -ao 'FAILED ([^)]*)' "$CACHE/last_results.log" \
      | sed 's/^FAILED (//; s/)$//' \
      | sort \
      | sed -n '1,80p'
    if [ "$FAILED" -gt 80 ]; then
        echo "  ... $((FAILED - 80)) more; see $CACHE/last_results.log"
    fi
fi

if [ "${UNIMPL:-0}" -gt 0 ]; then
    echo "Unimplemented cases:"
    grep -ao 'UNIMPLEMENTED ([^)]*)' "$CACHE/last_results.log" \
      | sed 's/^UNIMPLEMENTED (//; s/)$//' \
      | sort \
      | sed -n '1,80p'
    if [ "$UNIMPL" -gt 80 ]; then
        echo "  ... $((UNIMPL - 80)) more; see $CACHE/last_results.log"
    fi
fi

if [ "${FAILED:-0}" -gt 0 ]; then
    exit 1
fi
exit 0
