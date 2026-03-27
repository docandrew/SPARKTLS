#!/bin/bash
# SPARKTLS integration test suite
# Tests client and server against OpenSSL and each other
# for all 3 supported TLS 1.3 cipher suites.

CERT=tests/tlscipher.lan.crt
KEY=tests/tlscipher.lan.key
CLIENT=obj/examples/tls_test_client
SERVER=obj/examples/tls_test_server
PORT=8443
PASS=0
FAIL=0
TOTAL=0

cleanup() {
    fuser -k $PORT/tcp 2>/dev/null || true
    sleep 1
}

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
}

# Check prerequisites
for f in "$CERT" "$KEY" "$CLIENT" "$SERVER"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Missing $f"
        echo "Run 'make tlscert' in tests/ and build examples first."
        exit 1
    fi
done

echo "=== SPARKTLS Integration Tests ==="
echo ""

# --- Client vs OpenSSL s_server ---
echo "--- Client vs OpenSSL s_server ---"
for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
    cleanup
    openssl s_server -cert "$CERT" -key "$KEY" -accept $PORT -tls1_3 \
        -ciphersuites "$suite" -www 2>/dev/null &
    BGPID=$!
    sleep 1

    output=$(timeout 15 "$CLIENT" 2>&1 || true)
    kill $BGPID 2>/dev/null
    wait $BGPID 2>/dev/null || true

    if echo "$output" | grep -q "HANDSHAKE COMPLETE"; then
        pass "Client -> OpenSSL ($suite)"
    else
        fail "Client -> OpenSSL ($suite)"
        echo "$output" | grep -E "ERROR|error" | head -3
    fi
done

# --- Server vs OpenSSL s_client ---
echo ""
echo "--- Server vs OpenSSL s_client ---"
for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
    cleanup
    "$SERVER" "$CERT" "$KEY" > /tmp/sparktls_server_test.txt 2>&1 &
    BGPID=$!
    sleep 2

    # Send data then close stdin so s_client exits
    echo "test $suite" | timeout 10 openssl s_client \
        -connect 127.0.0.1:$PORT -tls1_3 -ciphersuites "$suite" \
        > /tmp/sparktls_client_test.txt 2>&1 || true
    sleep 1
    kill $BGPID 2>/dev/null
    wait $BGPID 2>/dev/null || true

    server_out=$(cat /tmp/sparktls_server_test.txt)
    client_out=$(cat /tmp/sparktls_client_test.txt)

    if echo "$server_out" | grep -q "HANDSHAKE COMPLETE" && \
       echo "$client_out" | grep -q "Cipher is $suite"; then
        pass "OpenSSL -> Server ($suite)"
    else
        fail "OpenSSL -> Server ($suite)"
        echo "$server_out" | grep -E "ERROR|error" | head -3
    fi
done

# --- SPARKTLS Client vs SPARKTLS Server ---
echo ""
echo "--- SPARKTLS Client vs SPARKTLS Server ---"
cleanup
"$SERVER" "$CERT" "$KEY" > /tmp/sparktls_server_test.txt 2>&1 &
BGPID=$!
sleep 2

client_out=$(timeout 15 "$CLIENT" 2>&1 || true)
sleep 1
kill $BGPID 2>/dev/null
wait $BGPID 2>/dev/null || true
server_out=$(cat /tmp/sparktls_server_test.txt)

if echo "$client_out" | grep -q "HANDSHAKE COMPLETE" && \
   echo "$server_out" | grep -q "HANDSHAKE COMPLETE"; then
    client_cipher=$(echo "$client_out" | grep "Cipher:" | head -1 | xargs)
    pass "Client -> Server ($client_cipher)"
else
    fail "Client -> Server"
    echo "$client_out" | grep -E "ERROR|error" | head -3
fi

# --- Summary ---
cleanup
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
