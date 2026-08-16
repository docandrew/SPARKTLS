#!/bin/bash
# Benchmark SPARKTLS handshake throughput vs OpenSSL
#
# Measures:
#   1. Handshakes/sec: OpenSSL client → SPARKTLS server
#   2. Handshakes/sec: OpenSSL client → OpenSSL server (baseline)
#   3. x509 certificate validation throughput
#
# Prerequisites: openssl, tls_test_server binary, x509_validate binary
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/.."

# ---------------------------------------------------------------------------
# Force a RELEASE build before measuring.
#
# run_all.sh --checked leaves the tree built with SPARKTLS_BUILD_MODE=debug
# (-Og, no inlining), SPARKTLS_CONTRACTS=enabled (-gnata) and runtime checks
# unsuppressed. Benchmarking whatever happens to be on disk after a test run
# therefore measures an unoptimized binary with assertions live: measured
# 2026-08-16, that reported SPARKTLS handshakes at 0.66x OpenSSL, where the
# release build is 1.55x. Rebuild here so the script cannot be fooled.
# Set BENCH_NO_REBUILD=1 to skip (e.g. when measuring a tree you built
# deliberately some other way).
# ---------------------------------------------------------------------------
if [ "${BENCH_NO_REBUILD:-0}" != "1" ]; then
    echo "Rebuilding in release mode (set BENCH_NO_REBUILD=1 to skip)..."
    export SPARKTLS_BUILD_MODE=optimize
    export SPARKTLS_CONTRACTS=disabled
    export SPARKTLS_RUNTIME_CHECKS=disabled
    export ALR_NON_INTERACTIVE=1
    ( cd "$REPO" && alr build ) > /tmp/bench_build.log 2>&1 || {
        echo "Release rebuild FAILED; see /tmp/bench_build.log" >&2; exit 1; }
    ( cd "$REPO/examples" && alr exec -- gprbuild -P sparktls_examples.gpr -j0 ) \
        >> /tmp/bench_build.log 2>&1 || {
        echo "Examples rebuild FAILED; see /tmp/bench_build.log" >&2; exit 1; }
    ( cd "$REPO" && alr exec -- gprbuild -P tests/x509/x509_validate.gpr -j0 ) \
        >> /tmp/bench_build.log 2>&1 || true
fi
SPARKTLS_SERVER="$REPO/bin/examples/tls_blocking_server"
X509_VALIDATE="$REPO/bin/tests/x509_validate"
CERT="$REPO/tests/certs/server.crt"
KEY="$REPO/tests/certs/server.key"
PORT_SPARK=8443
PORT_OSSL=8444
DURATION=10

# Generate test certs if needed
if [ ! -f "$CERT" ]; then
    mkdir -p "$(dirname "$CERT")"
    openssl genpkey -algorithm ED25519 -out "$KEY" 2>/dev/null
    openssl req -new -x509 -key "$KEY" -out "$CERT" \
        -days 365 -subj "/CN=localhost" 2>/dev/null
    echo "Generated test certs"
fi

echo "============================================"
echo "  SPARKTLS Handshake Benchmark"
echo "============================================"
echo ""

# -----------------------------------------------------------
# Test 1: OpenSSL s_time → SPARKTLS server
# -----------------------------------------------------------
echo "--- Test 1: OpenSSL client → SPARKTLS server ---"

# Start SPARKTLS server in background
if [ -f "$SPARKTLS_SERVER" ]; then
    # Blocking server accepts connections in a loop on port 8443
    $SPARKTLS_SERVER "$CERT" "$KEY" &
    SPARK_PID=$!
    sleep 1

    if kill -0 $SPARK_PID 2>/dev/null; then
        RESULT=$(openssl s_time -connect localhost:$PORT_SPARK \
            -new -time $DURATION 2>&1 || true)
        echo "$RESULT" | tail -4
        kill $SPARK_PID 2>/dev/null || true
        wait $SPARK_PID 2>/dev/null || true
    else
        echo "  SPARKTLS server failed to start"
    fi
else
    echo "  SPARKTLS server not found: $SPARKTLS_SERVER"
    echo "  Build with: cd examples && alr build"
fi

echo ""

# -----------------------------------------------------------
# Test 2: OpenSSL s_time → OpenSSL s_server (baseline)
# -----------------------------------------------------------
echo "--- Test 2: OpenSSL client → OpenSSL server (baseline) ---"

openssl s_server -key "$KEY" -cert "$CERT" -accept $PORT_OSSL \
    -tls1_3 -quiet -naccept 100000 &>/dev/null &
OSSL_PID=$!
sleep 1

if kill -0 $OSSL_PID 2>/dev/null; then
    RESULT=$(openssl s_time -connect localhost:$PORT_OSSL \
        -new -time $DURATION 2>&1 || true)
    echo "$RESULT" | tail -4
    kill $OSSL_PID 2>/dev/null || true
    wait $OSSL_PID 2>/dev/null || true
else
    echo "  OpenSSL server failed to start"
fi

echo ""

# -----------------------------------------------------------
# Test 3: x509 certificate validation throughput
# -----------------------------------------------------------
# Measured IN-PROCESS on both sides.
#
# This test used to run a shell loop that fork/exec'd a whole binary per
# validation, plus a `date` subprocess per iteration to check the clock.
# At ~16 ms per spawn it reported ~60 validations/sec for BOTH sides --
# i.e. it measured process creation, not certificate validation, and so
# showed the two as equal no matter how either performed. In-process the
# real figure is ~5000/sec.
#
# It also compared unlike work: it validated tests/certs/server.crt, which
# carries no extendedKeyUsage. SPARKTLS requires EKU serverAuth on a TLS
# leaf (CA/Browser Forum baseline requirements); bare `openssl verify`
# ignores EKU unless given -purpose. So OpenSSL was timing a SUCCESS and
# SPARKTLS a FAILURE. We now mint a CA -> leaf chain carrying SAN, EKU
# serverAuth and KU digitalSignature, and pass -purpose sslserver to
# OpenSSL, so both sides do the same work and both succeed.
# -----------------------------------------------------------
echo "--- Test 3: x509 certificate validation throughput ---"

X509_ITERS="${X509_ITERS:-5000}"
CHAIN_DIR="$(mktemp -d)"
trap 'rm -rf "$CHAIN_DIR"' EXIT

# CA
openssl genpkey -algorithm ED25519 -out "$CHAIN_DIR/ca.key" 2>/dev/null
openssl req -new -x509 -key "$CHAIN_DIR/ca.key" -out "$CHAIN_DIR/ca.crt" \
    -days 365 -subj "/CN=Bench Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Leaf issued BY the CA (not self-signed)
openssl genpkey -algorithm ED25519 -out "$CHAIN_DIR/leaf.key" 2>/dev/null
openssl req -new -key "$CHAIN_DIR/leaf.key" -out "$CHAIN_DIR/leaf.csr" \
    -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$CHAIN_DIR/leaf.csr" -CA "$CHAIN_DIR/ca.crt" \
    -CAkey "$CHAIN_DIR/ca.key" -CAcreateserial -out "$CHAIN_DIR/leaf.crt" \
    -days 365 -extfile <(printf "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n") 2>/dev/null

if [ -f "$X509_VALIDATE" ] && [ -f "$CHAIN_DIR/leaf.crt" ]; then
    # Sanity: both must AGREE the chain is valid, or the numbers are
    # comparing different work and must not be reported.
    # NB: "|| RC=$?" is required -- under `set -e` a bare non-zero exit here
    # would terminate the script before we could inspect it, which is exactly
    # the case this check exists to detect.
    SP_RC=0
    "$X509_VALIDATE" "$CHAIN_DIR/leaf.crt" "$CHAIN_DIR/ca.crt" --hostname localhost >/dev/null 2>&1 || SP_RC=$?
    OS_RC=0
    openssl verify -purpose sslserver -CAfile "$CHAIN_DIR/ca.crt" "$CHAIN_DIR/leaf.crt" >/dev/null 2>&1 || OS_RC=$?
    if [ "$SP_RC" -ne 0 ] || [ "$OS_RC" -ne 0 ]; then
        echo "  SKIPPED: validators disagree on the test chain" \
             "(sparktls=$SP_RC openssl=$OS_RC) -- would compare unlike work"
    else
        # SPARKTLS: N validations inside one process
        SP_OUT=$("$X509_VALIDATE" "$CHAIN_DIR/leaf.crt" "$CHAIN_DIR/ca.crt" \
                    --hostname localhost --repeat "$X509_ITERS" 2>&1 | tail -1)
        echo "  SPARKTLS x509: $SP_OUT"

        # OpenSSL: same count in ONE process by repeating the cert argument,
        # so spawn cost is amortised the same way.
        ARGS=(); for _ in $(seq "$X509_ITERS"); do ARGS+=("$CHAIN_DIR/leaf.crt"); done
        START=$(date +%s%N)
        openssl verify -purpose sslserver -CAfile "$CHAIN_DIR/ca.crt" "${ARGS[@]}" >/dev/null 2>&1 || true
        MS=$(( ($(date +%s%N) - START) / 1000000 ))
        [ "$MS" -lt 1 ] && MS=1
        echo "  OpenSSL x509:  $X509_ITERS validations in ${MS} ms ($((X509_ITERS * 1000 / MS))/sec)"
    fi
else
    echo "  x509_validate or test chain not found"
fi

echo ""
echo "============================================"
echo "  Done"
echo "============================================"
