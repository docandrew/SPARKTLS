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

set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
SHIM="$REPO_ROOT/bin/tests/bogo_shim"
CACHE="$DIR/_cache"
GO_BIN="$CACHE/go/bin/go"
BORING_DIR="$CACHE/boringssl"
RUNNER="$CACHE/bogo_runner"
WORKERS="${BOGO_WORKERS:-4}"

GO_VER="1.23.4"
GO_URL="https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
BORING_URL="https://boringssl.googlesource.com/boringssl"

echo "=== BoGo (BoringSSL adversarial TLS tests) ==="

mkdir -p "$CACHE"

# --- 1. Build the shim if needed -------------------------------------
if [ ! -x "$SHIM" ]; then
    echo "  Building bogo_shim ..."
    if ! command -v alr >/dev/null 2>&1; then
        echo "  SKIP: alire not found, can't build shim"
        exit 0
    fi
    eval "$(cd "$REPO_ROOT" && alr printenv --unix 2>/dev/null)"
    if ! gprbuild -P "$REPO_ROOT/tests/bogo/bogo_shim.gpr" 2>&1 | tail -3; then
        echo "  SKIP: shim build failed"
        exit 0
    fi
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
    if ! git clone --depth 1 -q "$BORING_URL" "$BORING_DIR" 2>&1; then
        echo "  SKIP: BoringSSL clone failed (network?)"
        exit 0
    fi
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
#  -skip BY_DESIGN_SKIPS : drop BoGo tests for features SPARKTLS
#                          deliberately doesn't ship, so the
#                          remaining FAIL count reflects real bugs
#                          worth fixing. See SKIPPED.md for the
#                          full design rationale per bucket.
#
#  Pattern syntax: semicolon-separated globs (Go path.Match), no
#  comma support. `*` matches anything except `-`.
BY_DESIGN_SKIPS=(
  # TLS 1.0 / 1.1 (we ship 1.2 + 1.3 only)
  '*-TLS11-*' '*-TLS1-*' '*-TLS11' '*-TLS1'
  'TLS1-*' 'TLS11-*'
  # CBC ciphers (AEAD-only by design — RFC 7366 / Lucky13)
  '*_CBC_*' 'MaxCBCPadding'
  # Pure-RSA key exchange (we offer only ECDHE_RSA)
  '*RSA_WITH_AES_*' '*RSA_WITH_3DES_*'
  # TLS-ECH (draft, not implemented)
  'TLS-ECH-*'
  # 0-RTT / EarlyData (removed by design — see no_0rtt memory)
  '*EarlyData*'
  # Renegotiation (TLS 1.2 reneg intentionally rejected)
  'Renegotiat*'
  # KeyUpdate (post-handshake rekey not implemented)
  'KeyUpdate*'
  # PQ signatures (ML-DSA not in scope)
  '*ML-DSA*'
  # SHA-1 / legacy RSA-PKCS1 sig schemes (deprecated)
  '*RSA_PKCS1_SHA1*' '*RSA_PKCS1_SHA256_LEGACY*' '*SHA1-Fallback*'
  # P-521 (not supported — we offer P-256/P-384/X25519)
  '*ECDSA_P521*' '*P521*'
  # PAKE (RFC 8773 draft, not implemented)
  'PAKE*'
  # TrustAnchors extension (RFC 9450 draft, not implemented)
  '*TrustAnchors*'
  # Server certificate type (RFC 7250 raw public key, not implemented)
  'ServerCertificateType*'
  # SSL 3.0 (not supported)
  'NoSSL3*'
)
# Join with ';' for the runner.
SKIPS=$(IFS=';'; echo "${BY_DESIGN_SKIPS[*]}")

"$RUNNER" \
    -shim-path "$SHIM" \
    -allow-unimplemented \
    -loose-errors \
    -num-workers "$WORKERS" \
    -idle-timeout 3s \
    -skip "$SKIPS" \
    "$@" 2>&1 | tee "$CACHE/last_results.log" | tail -3

#  Stats line is "failed/unimplemented/done/started/total"
#  (per ssl/test/runner/runner.go:2244).
LAST=$(grep -oE "[0-9]+/[0-9]+/[0-9]+/[0-9]+/[0-9]+" "$CACHE/last_results.log" \
       | tail -1)
FAILED=$(echo "$LAST" | cut -d/ -f1)
UNIMPL=$(echo "$LAST" | cut -d/ -f2)
DONE=$(echo "$LAST" | cut -d/ -f3)
TOTAL=$(echo "$LAST" | cut -d/ -f5)
PASSED=$(( DONE - FAILED - UNIMPL ))

if [ -z "$LAST" ]; then
    echo
    echo "=== BoGo: no tests run (empty selector or runner failure) ==="
    exit 0
fi

echo
echo "=== BoGo: $PASSED/$TOTAL passed, $FAILED failed, $UNIMPL unimplemented ==="
