#!/bin/bash
# SPARKTLS integration tests: client and server against OpenSSL.
# Tests all supported cipher suites and both TLS versions.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
CERT_DIR="$DIR/../certs"
FETCH="$REPO_ROOT/bin/examples/tls_fetch"
SERVER="$REPO_ROOT/bin/examples/tls_blocking_server"
PORT=8443
PASS=0
FAIL=0

cleanup() {
    for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K\d+'); do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
}

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Check prerequisites
for f in "$FETCH" "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key"; do
    if [ ! -f "$f" ]; then
        echo "Error: $f not found."
        echo "Run ./tests/run_all.sh from repo root first."
        exit 1
    fi
done

echo "=== SPARKTLS Integration Tests ==="
echo ""

# --- Client vs OpenSSL s_server (TLS 1.3) ---
echo "--- Client vs OpenSSL s_server (TLS 1.3) ---"
for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
    cleanup
    openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -accept $PORT -tls1_3 -ciphersuites "$suite" -www 2>/dev/null &
    sleep 2

    output=$(timeout 15 "$FETCH" -k "https://localhost:$PORT/" 2>&1 || true)
    cleanup

    if echo "$output" | grep -q "HTTP/1"; then
        pass "Client -> OpenSSL TLS 1.3 ($suite)"
    else
        fail "Client -> OpenSSL TLS 1.3 ($suite)"
        echo "    $output" | head -1
    fi
done

# --- Client vs OpenSSL s_server (TLS 1.2) ---
echo ""
echo "--- Client vs OpenSSL s_server (TLS 1.2) ---"
for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384; do
    cleanup
    openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -accept $PORT -tls1_2 -cipher "$suite" -www 2>/dev/null &
    sleep 2

    output=$(timeout 15 "$FETCH" -k "https://localhost:$PORT/" 2>&1 || true)
    cleanup

    if echo "$output" | grep -q "HTTP/1"; then
        pass "Client -> OpenSSL TLS 1.2 ($suite)"
    else
        fail "Client -> OpenSSL TLS 1.2 ($suite)"
        echo "    $output" | head -1
    fi
done

# --- Server vs OpenSSL s_client (TLS 1.3) ---
echo ""
echo "--- Server vs OpenSSL s_client (TLS 1.3) ---"
for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" 2>/dev/null &
    sleep 2

    output=$(echo "GET /" | timeout 10 openssl s_client \
        -connect 127.0.0.1:$PORT -tls1_3 -ciphersuites "$suite" \
        -quiet 2>&1 || true)
    cleanup

    if echo "$output" | grep -q "GET /\|HTTP"; then
        pass "OpenSSL -> Server TLS 1.3 ($suite)"
    else
        fail "OpenSSL -> Server TLS 1.3 ($suite)"
        echo "    $(echo "$output" | grep -i error | head -1)"
    fi
done

# --- Server vs OpenSSL s_client (TLS 1.2) ---
echo ""
echo "--- Server vs OpenSSL s_client (TLS 1.2) ---"
for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384; do
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" 2>/dev/null &
    sleep 2

    output=$(echo "GET /" | timeout 10 openssl s_client \
        -connect 127.0.0.1:$PORT -tls1_2 -cipher "$suite" \
        -quiet 2>&1 || true)
    cleanup

    if echo "$output" | grep -q "GET /\|HTTP"; then
        pass "OpenSSL -> Server TLS 1.2 ($suite)"
    else
        fail "OpenSSL -> Server TLS 1.2 ($suite)"
        echo "    $(echo "$output" | grep -i error | head -1)"
    fi
done

# --- Client vs real internet (skip-verify, tests TLS handshake only) ---
echo ""
echo "--- Client vs real servers (-k) ---"
for url in https://example.com/ https://www.google.com/; do
    output=$(timeout 15 "$FETCH" -k "$url" 2>&1 || true)
    if echo "$output" | grep -q "HTTP/1\|HTTP/2"; then
        pass "Client -> $url"
    else
        fail "Client -> $url"
        echo "    $output" | head -1
    fi
done

# --- Summary ---
cleanup
echo ""
TOTAL=$((PASS + FAIL))
echo "=== Integration: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
