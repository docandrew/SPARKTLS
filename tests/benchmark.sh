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
echo "--- Test 3: x509 certificate validation throughput ---"

if [ -f "$X509_VALIDATE" ]; then
    # Use a known-good cert from the system or our test certs
    TEST_CERT="$CERT"
    TEST_TRUST="$CERT"  # self-signed, so trust = cert

    START=$(date +%s%N)
    COUNT=0
    END=$(($(date +%s) + 5))
    while [ $(date +%s) -lt $END ]; do
        $X509_VALIDATE "$TEST_CERT" "$TEST_TRUST" --hostname localhost >/dev/null 2>&1 && true
        COUNT=$((COUNT + 1))
    done
    ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
    RATE=$((COUNT * 1000 / ELAPSED))
    echo "  SPARKTLS x509: $COUNT validations in ${ELAPSED}ms ($RATE/sec)"

    # Compare: openssl verify
    START=$(date +%s%N)
    COUNT=0
    END=$(($(date +%s) + 5))
    while [ $(date +%s) -lt $END ]; do
        openssl verify -CAfile "$TEST_TRUST" "$TEST_CERT" >/dev/null 2>&1 && true
        COUNT=$((COUNT + 1))
    done
    ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
    RATE=$((COUNT * 1000 / ELAPSED))
    echo "  OpenSSL x509:  $COUNT validations in ${ELAPSED}ms ($RATE/sec)"
else
    echo "  x509_validate not found"
fi

echo ""
echo "============================================"
echo "  Done"
echo "============================================"
