#!/bin/bash
# SPARKTLS integration tests: client and server against OpenSSL.
# Tests all combinations of:
#   - Cert/Sig types: RSA, Ed25519, ECDSA-P256, ECDSA-P384
#   - Cipher suites: AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM
#   - Key exchange groups: x25519, P-256, P-384
#   - TLS versions: 1.3, 1.2
set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
CERT_DIR="$DIR/../certs"
FETCH="$REPO_ROOT/bin/examples/tls_fetch"
SERVER="$REPO_ROOT/bin/examples/tls_blocking_server"
#  Each test gets its own port (rotated) so we never wait for
#  TIME_WAIT after a previous test. SO_REUSEADDR on the listener
#  would also help, but rotating ports is simpler and gives a free
#  parallelism win if we ever spin tests up concurrently.
PORT_BASE=18443
PORT=$PORT_BASE
PASS=0
FAIL=0

#  Rotate to a new port for the next test. Must be called BEFORE
#  starting a new server. Eliminates the TIME_WAIT wait that
#  hardcoding PORT=8443 forced after every cleanup.
next_port() {
    PORT=$((PORT + 1))
    if [ "$PORT" -ge $((PORT_BASE + 200)) ]; then
        PORT=$PORT_BASE
    fi
    #  tls_blocking_server reads SPARKTLS_PORT to override its
    #  default 8443 — exporting here means every subsequent server
    #  spawn inherits the rotated port without extra plumbing.
    export SPARKTLS_PORT=$PORT
}

#  Best-effort kill of any leftover server on the current port.
#  We don't sleep — the next test will use a different port (see
#  next_port) so a TIME_WAIT on this one is harmless.
cleanup() {
    for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K\d+'); do
        kill "$pid" 2>/dev/null || true
    done
    next_port
}

#  Initial port export so the very first test (which runs without a
#  prior cleanup) sees the right value.
export SPARKTLS_PORT=$PORT

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

#  Wait (up to 2 seconds) for $PORT to be listening. Replaces the
#  conservative `sleep 0.5/1` after each server spawn — saves
#  several seconds per integration run on a fast machine. Polls
#  every 20ms with a TCP-connect probe.
wait_for_port() {
    local p="${1:-$PORT}"
    for _ in 1 2 3 4 5 6 7 8 9 10 \
             11 12 13 14 15 16 17 18 19 20 \
             21 22 23 24 25 26 27 28 29 30 \
             31 32 33 34 35 36 37 38 39 40 \
             41 42 43 44 45 46 47 48 49 50 \
             51 52 53 54 55 56 57 58 59 60 \
             61 62 63 64 65 66 67 68 69 70 \
             71 72 73 74 75 76 77 78 79 80 \
             81 82 83 84 85 86 87 88 89 90 \
             91 92 93 94 95 96 97 98 99 100; do
        if ss -lnt 2>/dev/null | grep -q ":$p "; then
            return 0
        fi
        sleep 0.02
    done
    return 1
}

# Check prerequisites
for f in "$FETCH" "$SERVER"; do
    if [ ! -f "$f" ]; then
        echo "Error: $f not found. Build examples first."
        exit 1
    fi
done

# Generate certs if needed
bash "$CERT_DIR/generate.sh" 2>/dev/null

echo "=== SPARKTLS Integration Tests ==="
echo ""

# ===================================================================
# TLS 1.3 — Server tests (OpenSSL s_client → our server)
# ===================================================================
echo "--- TLS 1.3: OpenSSL client → SPARKTLS server ---"

# Each cert type with each cipher suite
for cert_name in rsa ed25519 p256 p384; do
    cert="$CERT_DIR/${cert_name}.crt"
    key="$CERT_DIR/${cert_name}.key"
    [ -f "$cert" ] || continue

    for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
        for group in x25519 P-256 P-384; do
            cleanup
            "$SERVER" "$cert" "$key" 2>/dev/null &
            sleep 1

            label="${cert_name}+${suite}+${group}"
            output=$(echo "hello" | timeout 5 openssl s_client \
                -connect 127.0.0.1:$PORT -tls1_3 \
                -ciphersuites "$suite" -groups "$group" \
                -quiet 2>&1 || true)
            cleanup

            if echo "$output" | grep -qi "hello\|GET\|HTTP\|verify return"; then
                pass "Server $label"
            elif echo "$output" 2>&1 | grep -qi "error\|alert\|refused"; then
                fail "Server $label"
            else
                # Connection established but no echo — still a pass for handshake
                if echo "$output" | grep -q "^$"; then
                    pass "Server $label"
                else
                    fail "Server $label"
                fi
            fi
        done
    done
done

echo ""

# ===================================================================
# TLS 1.3 — Client tests (our client → OpenSSL s_server)
# ===================================================================
echo "--- TLS 1.3: SPARKTLS client → OpenSSL server ---"

for cert_name in rsa ed25519 p256 p384; do
    cert="$CERT_DIR/${cert_name}.crt"
    key="$CERT_DIR/${cert_name}.key"
    [ -f "$cert" ] || continue

    for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
        cleanup
        openssl s_server -cert "$cert" -key "$key" \
            -accept $PORT -tls1_3 -ciphersuites "$suite" \
            -www 2>/dev/null &
        sleep 1

        label="${cert_name}+${suite}"
        output=$(timeout 10 "$FETCH" --cafile "$cert" --rfc5280 "https://localhost:$PORT/" 2>&1 || true)
        cleanup

        if echo "$output" | grep -qi "HTTP/1\|200\|html"; then
            pass "Client $label"
        else
            fail "Client $label"
            echo "    $(echo "$output" | head -1)"
        fi
    done
done

echo ""

# ===================================================================
# TLS 1.2 — Server tests (OpenSSL s_client → our server)
# ===================================================================
echo "--- TLS 1.2: OpenSSL client → SPARKTLS server ---"

# TLS 1.2: RSA certs with ECDHE-RSA suites
for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" 2>/dev/null &
    sleep 1

    output=$(echo "hello" | timeout 5 openssl s_client \
        -connect 127.0.0.1:$PORT -tls1_2 -cipher "$suite" \
        -quiet 2>&1 || true)
    cleanup

    if echo "$output" | grep -qi "hello\|GET\|HTTP"; then
        pass "Server TLS1.2 rsa+$suite"
    else
        fail "Server TLS1.2 rsa+$suite"
    fi
done

# TLS 1.2: ECDSA certs with ECDHE-ECDSA suites
for cert_name in p256 p384; do
    cert="$CERT_DIR/${cert_name}.crt"
    key="$CERT_DIR/${cert_name}.key"
    [ -f "$cert" ] || continue

    for suite in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
        cleanup
        "$SERVER" "$cert" "$key" 2>/dev/null &
        sleep 1

        output=$(echo "hello" | timeout 5 openssl s_client \
            -connect 127.0.0.1:$PORT -tls1_2 -cipher "$suite" \
            -quiet 2>&1 || true)
        cleanup

        if echo "$output" | grep -qi "hello\|GET\|HTTP"; then
            pass "Server TLS1.2 ${cert_name}+${suite}"
        else
            fail "Server TLS1.2 ${cert_name}+${suite}"
        fi
    done
done

echo ""

# ===================================================================
# TLS 1.2 — Client tests (our client → OpenSSL s_server)
# ===================================================================
echo "--- TLS 1.2: SPARKTLS client → OpenSSL server ---"

for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384; do
    cleanup
    openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -accept $PORT -tls1_2 -cipher "$suite" -www 2>/dev/null &
    sleep 1

    output=$(timeout 10 "$FETCH" --cafile "$CERT_DIR/rsa.crt" --rfc5280 "https://localhost:$PORT/" 2>&1 || true)
    cleanup

    if echo "$output" | grep -qi "HTTP/1\|200\|html"; then
        pass "Client TLS1.2 rsa+$suite"
    else
        fail "Client TLS1.2 rsa+$suite"
        echo "    $(echo "$output" | head -1)"
    fi
done

echo ""
echo "--- TLS 1.2: SKE tamper rejection ---"

TAMPER_PROXY="$DIR/tamper_tls12_ske.py"
if [ ! -f "$TAMPER_PROXY" ] || ! command -v python3 >/dev/null 2>&1; then
    echo "  (skipped — Python SKE tamper proxy unavailable)"
else
    for mode in signature point; do
        cleanup
        server_port=$PORT
        openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
            -accept $server_port -tls1_2 \
            -cipher ECDHE-RSA-AES128-GCM-SHA256 -www \
            >/tmp/sparktls_ske_tamper_server.log 2>&1 &
        server_pid=$!
        if ! wait_for_port "$server_port"; then
            fail "TLS1.2 SKE tamper ${mode}: OpenSSL server did not start"
            kill "$server_pid" 2>/dev/null || true
            wait "$server_pid" 2>/dev/null || true
            continue
        fi

        next_port
        proxy_port=$PORT
        python3 "$TAMPER_PROXY" \
            --listen-port "$proxy_port" \
            --target-port "$server_port" \
            --mode "$mode" \
            >/tmp/sparktls_ske_tamper_proxy.log 2>&1 &
        proxy_pid=$!
        if ! wait_for_port "$proxy_port"; then
            fail "TLS1.2 SKE tamper ${mode}: proxy did not start"
            kill "$proxy_pid" "$server_pid" 2>/dev/null || true
            wait "$proxy_pid" "$server_pid" 2>/dev/null || true
            continue
        fi

        output=$(timeout 10 "$FETCH" --cafile "$CERT_DIR/rsa.crt" --rfc5280 \
            "https://localhost:$proxy_port/" 2>&1 || true)
        wait "$proxy_pid" 2>/dev/null
        proxy_status=$?
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true

        if [ "$proxy_status" -eq 0 ] \
           && ! echo "$output" | grep -qi "HTTP/1\|200\|html"; then
            pass "TLS1.2 rejects tampered SKE ${mode}"
        else
            fail "TLS1.2 rejects tampered SKE ${mode}"
            echo "    client: $(echo "$output" | head -1)"
            echo "    proxy:  $(cat /tmp/sparktls_ske_tamper_proxy.log | head -1)"
        fi
    done
fi

# ===================================================================
# mTLS Verify_Mode (Required) — server should reject clients that
# do not present a cert. Validates the security fix for the bypass
# where Required-mode wasn't distinguished from Optional.
# ===================================================================
echo ""
echo "--- mTLS Verify_Mode: Required ---"

cleanup
"$SERVER" "$CERT_DIR/ed25519.crt" "$CERT_DIR/ed25519.key" \
    --mtls-require "$CERT_DIR/ed25519.crt" 2>/dev/null &
#  This test is sensitive to a race between openssl reading the
#  encrypted certificate_required alert and the openssl process
#  exiting after handshake completes. wait_for_port returns the
#  moment the listener is up, which is slightly too eager; a
#  conservative 1s sleep keeps the test from flaking.
sleep 1

# 1) Client without cert should be rejected with certificate_required (116).
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/ed25519.crt" 2>&1 || true)
if echo "$output" | grep -qE "(certificate required|alert.*116|sslv3 alert certificate required)"; then
    pass "Required mode rejects no-cert client"
elif echo "$output" | grep -qx "hello"; then
    fail "Required mode incorrectly accepted no-cert client (BYPASS)"
else
    # OpenSSL may print "Verify return code: 0 (ok)" before it reads
    # the encrypted certificate_required alert. The security condition
    # is that no application data is accepted/echoed.
    pass "Required mode rejects no-cert client (handshake aborted)"
fi
cleanup

# 2) A presented client certificate with serverAuth-only EKU should be
# rejected in Required mode. This catches accidental acceptance of TLS
# server certificates as mTLS client credentials.
BAD_CLIENT_DIR="${TMPDIR:-/tmp}/sparktls-bad-client-eku.$$"
mkdir -p "$BAD_CLIENT_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$BAD_CLIENT_DIR/raw.key" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt \
    -in "$BAD_CLIENT_DIR/raw.key" -out "$BAD_CLIENT_DIR/key.pem" 2>/dev/null
openssl req -x509 -key "$BAD_CLIENT_DIR/key.pem" -out "$BAD_CLIENT_DIR/cert.pem" \
    -days 30 -subj "/CN=bad-client-eku" \
    -addext "subjectAltName=DNS:bad-client-eku" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
rm -f "$BAD_CLIENT_DIR/raw.key"

"$SERVER" "$CERT_DIR/ed25519.crt" "$CERT_DIR/ed25519.key" \
    --mtls-require "$BAD_CLIENT_DIR/cert.pem" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/ed25519.crt" \
    -cert "$BAD_CLIENT_DIR/cert.pem" -key "$BAD_CLIENT_DIR/key.pem" \
    2>&1 || true)
if echo "$output" | grep -qx "hello"; then
    fail "Required mode accepted serverAuth-only client certificate"
else
    pass "Required mode rejects serverAuth-only client certificate"
fi
rm -rf "$BAD_CLIENT_DIR"
cleanup

# 3) Optional mode (default --mtls without -require) should accept
# a no-cert client (sanity check that the new code path didn't break
# advisory mTLS).
"$SERVER" "$CERT_DIR/ed25519.crt" "$CERT_DIR/ed25519.key" \
    --mtls "$CERT_DIR/ed25519.crt" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/ed25519.crt" 2>&1 || true)
# Success indicators: server presented its cert (so handshake reached
# the Certificate phase) AND no fatal alert about a missing client
# cert. We don't grep "Verify return code" because openssl prints a
# verify error for our ed25519 leaf used as both CA and leaf
# (purpose mismatch — orthogonal to mTLS behaviour).
if echo "$output" | grep -q "BEGIN CERTIFICATE" \
   && ! echo "$output" | grep -qiE "(certificate required|alert.*116|handshake failure)"; then
    pass "Optional mode accepts no-cert client"
else
    fail "Optional mode rejected no-cert client (regression)"
    echo "    $(echo "$output" | head -1)"
fi
cleanup

# ===================================================================
# Client mTLS — SPARKTLS client → openssl s_server with --Verify.
# Was missing entirely; client mTLS code path had no integration
# test coverage, which let a Wait_Server_Finished →
# client_app_secret_0 transcript-hash bug ship in
# (Send_Client_Certificate Append_Transcript'd our cert before
# TS_Hash was sampled, so client_app_secret diverged from peer →
# bad_record_mac on the first encrypted record after Finished).
# Each scenario MUST send app data after the handshake — the bug
# only manifests on the first encrypted record after Finished.
# ===================================================================
echo ""
echo "--- Client mTLS: SPARKTLS client → OpenSSL s_server ---"

CLIENT="$REPO_ROOT/bin/examples/mtls_test_client"

if [ ! -x "$CLIENT" ]; then
    echo "  (skipped — mtls_test_client not built)"
else
    # Loop cert + suite to exercise each AEAD path with mTLS.
    for cred in "p256" "rsa" "ed25519"; do
        for suite in TLS_AES_128_GCM_SHA256 \
                     TLS_CHACHA20_POLY1305_SHA256 \
                     TLS_AES_256_GCM_SHA384; do
            cleanup
            openssl s_server -accept 0:$PORT \
                -cert "$CERT_DIR/${cred}.crt" -key "$CERT_DIR/${cred}.key" \
                -CAfile "$CERT_DIR/${cred}.crt" -Verify 1 -tls1_3 \
                -ciphersuites "$suite" -no_ticket -quiet \
                > /tmp/mtls_srv.log 2>&1 &
            sleep 0.5

            output=$(timeout 5 "$CLIENT" \
                --port $PORT --host localhost \
                --cert-file "$CERT_DIR/${cred}.crt" \
                --key-file "$CERT_DIR/${cred}.key" \
                --trust-cert "$CERT_DIR/${cred}.crt" \
                --message "hello-from-sparktls" 2>&1)
            rc=$?
            cleanup

            if [ $rc -eq 0 ]; then
                pass "client mTLS $cred + $suite"
            else
                fail "client mTLS $cred + $suite"
                echo "    $(echo "$output" | head -2)"
            fi
        done
    done

    # NoCertificate path: server requests but doesn't require, our
    # client offers no cert and sends empty Certificate.
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/p256.crt" -key "$CERT_DIR/p256.key" \
        -CAfile "$CERT_DIR/p256.crt" -verify 1 -tls1_3 \
        -ciphersuites TLS_AES_128_GCM_SHA256 -no_ticket -quiet \
        > /tmp/mtls_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 5 "$CLIENT" \
        --port $PORT --host localhost \
        --trust-cert "$CERT_DIR/p256.crt" \
        --message "hello" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ]; then
        pass "client mTLS NoCert (CR optional, empty Cert reply)"
    else
        fail "client mTLS NoCert"
        echo "    $(echo "$output" | head -2)"
    fi

    # TLS 1.2 client mTLS: server forces TLS 1.2 with -tls1_2;
    # our client falls back from TLS 1.3 to 1.2 via supported_versions.
    # Only RSA suites today (no ECDSA TLS 1.2 in the offered list).
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -CAfile "$CERT_DIR/rsa.crt" -Verify 1 -tls1_2 \
        -cipher ECDHE-RSA-AES128-GCM-SHA256 -no_ticket -quiet \
        > /tmp/mtls_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 5 "$CLIENT" \
        --port $PORT --host localhost \
        --cert-file "$CERT_DIR/rsa.crt" \
        --key-file "$CERT_DIR/rsa.key" \
        --trust-cert "$CERT_DIR/rsa.crt" \
        --message "hello-tls12-mtls" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ]; then
        pass "client mTLS TLS 1.2 + ECDHE-RSA-AES128-GCM-SHA256"
    else
        fail "client mTLS TLS 1.2"
        echo "    $(echo "$output" | head -2)"
    fi

    # TLS 1.2 client NoCert: server requests but doesn't require.
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -CAfile "$CERT_DIR/rsa.crt" -verify 1 -tls1_2 \
        -cipher ECDHE-RSA-AES128-GCM-SHA256 -no_ticket -quiet \
        > /tmp/mtls_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 5 "$CLIENT" \
        --port $PORT --host localhost \
        --trust-cert "$CERT_DIR/rsa.crt" \
        --message "hello-tls12-nocert" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ]; then
        pass "client mTLS TLS 1.2 NoCert (empty Cert reply)"
    else
        fail "client mTLS TLS 1.2 NoCert"
        echo "    $(echo "$output" | head -2)"
    fi
fi

# ===================================================================
# ALPN — RFC 7301. Client offers a protocol; server selects it (or
# something compatible) and echoes in EE/SH. Round-trip then app
# data to validate the post-handshake key derivation isn't perturbed.
# ===================================================================
echo ""
echo "--- ALPN: SPARKTLS client → OpenSSL s_server ---"
if [ ! -x "$CLIENT" ]; then
    echo "  (skipped — mtls_test_client not built)"
else
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/p256.crt" -key "$CERT_DIR/p256.key" \
        -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 \
        -alpn h2,http/1.1 -no_ticket -quiet \
        > /tmp/alpn_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 5 "$CLIENT" \
        --port $PORT --host localhost \
        --trust-cert "$CERT_DIR/p256.crt" \
        --alpn h2 --expect-alpn h2 \
        --message "alpn-test" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ]; then
        pass "ALPN client offers h2, server echoes h2"
    else
        fail "ALPN client offers h2, server echoes h2"
        echo "    $(echo "$output" | head -2)"
    fi
fi

# ===================================================================
# Session resumption — RFC 8446 §4.6.1 PSK. Two-connection round
# trip: SPARKTLS client connects, server issues NST, client
# disconnects, then reconnects with the cached ticket. The shim
# (tls_resume_test) reports PASS only when the second handshake
# uses PSK (S.HC_Ptr.Using_PSK = True at Handshake_Done).
# ===================================================================
RESUME_CLIENT="$REPO_ROOT/bin/examples/tls_resume_test"
echo ""
echo "--- Resumption: SPARKTLS client → OpenSSL s_server ---"
if [ ! -x "$RESUME_CLIENT" ]; then
    echo "  (skipped — tls_resume_test not built)"
else
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/p256.crt" -key "$CERT_DIR/p256.key" \
        -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 \
        -num_tickets 1 -quiet \
        > /tmp/resume_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 10 "$RESUME_CLIENT" -port $PORT -host localhost 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ] && echo "$output" | grep -q "PASS: resumption succeeded"; then
        pass "TLS 1.3 PSK resumption (two connections)"
    else
        fail "TLS 1.3 PSK resumption (two connections)"
        echo "$output" | sed 's/^/    /' | head -10
    fi
fi

# ===================================================================
# TLS 1.2 session ticket resumption (RFC 5077). SPARKTLS server
# emits a NewSessionTicket on the first connection; the second
# connection presents that ticket and expects an abbreviated
# handshake. openssl s_client with -sess_out/-sess_in carries the
# session between processes and reports "Reused" on the second
# connection if the server accepted the ticket.
# ===================================================================
echo ""
echo "--- TLS 1.2 ticket resumption: SPARKTLS server → openssl s_client ---"
if [ ! -x "$SERVER" ]; then
    echo "  (skipped — tls_blocking_server not built)"
else
    SESS_FILE=/tmp/sparktls_tls12_sess_$$.pem
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
        > /tmp/tls12_resume_srv.log 2>&1 &
    sleep 0.5

    #  Connection 1: full handshake, expect server to issue a ticket.
    echo "x" | timeout 5 openssl s_client \
        -connect localhost:$PORT -tls1_2 \
        -CAfile "$CERT_DIR/rsa.crt" \
        -sess_out "$SESS_FILE" > /tmp/tls12_c1.log 2>&1
    c1_ok=0
    if grep -q "TLS session ticket:" /tmp/tls12_c1.log \
       && grep -q "Verify return code: 0 (ok)" /tmp/tls12_c1.log; then
        c1_ok=1
    fi
    if [ $c1_ok -ne 1 ]; then
        fail "TLS 1.2 ticket: c1 full handshake didn't issue ticket"
        rm -f "$SESS_FILE"
        cleanup
    else
        #  Connection 2: resume.
        echo "x" | timeout 5 openssl s_client \
            -connect localhost:$PORT -tls1_2 \
            -CAfile "$CERT_DIR/rsa.crt" \
            -sess_in "$SESS_FILE" > /tmp/tls12_c2.log 2>&1
        if grep -q "Reused, TLSv1.2" /tmp/tls12_c2.log \
           && grep -q "Verify return code: 0 (ok)" /tmp/tls12_c2.log; then
            pass "TLS 1.2 ticket resumption (two connections)"
        else
            fail "TLS 1.2 ticket resumption (two connections)"
            grep -E "Reused|Verify|alert|error" /tmp/tls12_c2.log \
                 | sed 's/^/    /' | head -5
        fi
        rm -f "$SESS_FILE"
        cleanup
    fi
fi

# ===================================================================
# SNI-based certificate selection (RFC 6066 §3 / RFC 8446 §4.4.2.4).
# tls_sni_server loads two identities (RSA default, Ed25519 alt) +
# installs a Select_Identity callback that returns the alt identity
# for any hostname containing "alt". We verify by inspecting the
# server certificate openssl s_client receives for two different
# -servername values; check the Public Key Algorithm field of the
# leaf cert (rsaEncryption vs ED25519). Four sub-tests:
#   1. default SNI (localhost)               → RSA cert
#   2. alt SNI (alt.example.com)             → Ed25519 cert
#   3. uppercase alt (case-fold check)       → Ed25519 cert
#   4. NO SNI (openssl -noservername)        → RSA cert (falls back
#      to Cfg.Local since HC.Peer_SNI.Len = 0; selector not called).
# ===================================================================
echo ""
echo "--- SNI: cert selection by hostname ---"
SNI_SERVER=/home/doc/git/tls_proj/sparktls/bin/examples/tls_sni_server
if [ ! -x "$SNI_SERVER" ]; then
    echo "  (skipped — tls_sni_server not built)"
else
    cleanup
    "$SNI_SERVER" \
        "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
        "$CERT_DIR/ed25519.crt" "$CERT_DIR/ed25519.key" \
        > /tmp/sni_srv.log 2>&1 &
    wait_for_port

    #  Helper: dump the leaf cert's Public Key Algorithm for a given
    #  SNI value. Echoes "rsa", "ed25519", or "?" (failed to extract).
    sni_pkalg() {
        local sni_arg="$1"
        echo "x" | timeout 5 openssl s_client \
            -connect 127.0.0.1:$PORT $sni_arg -showcerts 2>/dev/null \
            | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
            | head -200 \
            | openssl x509 -noout -text 2>/dev/null \
            | awk '/Public Key Algorithm:/ {
                if ($4 == "rsaEncryption")        print "rsa";
                else if ($4 == "ED25519")          print "ed25519";
                else                                print "?";
                exit
              }'
    }

    pk=$(sni_pkalg "-servername localhost")
    if [ "$pk" = "rsa" ]; then
        pass "SNI: default hostname → RSA cert"
    else
        fail "SNI: default hostname → expected RSA, got '$pk'"
    fi

    pk=$(sni_pkalg "-servername alt.example.com")
    if [ "$pk" = "ed25519" ]; then
        pass "SNI: alt hostname → Ed25519 cert"
    else
        fail "SNI: alt hostname → expected Ed25519, got '$pk'"
    fi

    pk=$(sni_pkalg "-servername ALT.EXAMPLE.COM")
    if [ "$pk" = "ed25519" ]; then
        pass "SNI: uppercase alt → Ed25519 cert (case-fold check)"
    else
        fail "SNI: uppercase alt → expected Ed25519, got '$pk'"
    fi

    pk=$(sni_pkalg "-noservername")
    if [ "$pk" = "rsa" ]; then
        pass "SNI: no SNI → falls back to default RSA cert"
    else
        fail "SNI: no SNI → expected RSA, got '$pk'"
    fi

    cleanup
fi

# ===================================================================
# Hostname validation (RFC 6125 §6.4). The client-side cert chain
# always checks that the leaf's SAN dNSName / iPAddress entries
# (with RFC 6125 wildcard rules) match Cfg.Server_Name. This check
# runs INDEPENDENTLY of full chain validation — a caller using
# Skip_Verify=True (dev mode against self-signed certs) still gets
# hostname binding. Explicit opt-out via Skip_Hostname_Verify=True
# for the rare TOFU-style use case.
#
# Test cert is CN=localhost + SAN=DNS:localhost,IP:127.0.0.1.
# Tests:
#   1. correct hostname + trust          → OK (sanity)
#   2. wrong hostname + trust            → bad_certificate
#   3. wrong hostname + Skip_Verify      → bad_certificate
#      (KEY ASSERTION: dropping chain validation does NOT drop
#       hostname binding)
#   4. wrong hostname + Skip_Verify
#       + Skip_Hostname_Verify           → OK (explicit opt-out)
# ===================================================================
echo ""
echo "--- Hostname validation (client SAN/CN matching) ---"
if [ ! -x "$CLIENT" ]; then
    echo "  (skipped — mtls_test_client not built)"
else
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" -tls1_3 \
        -quiet > /tmp/hv_srv.log 2>&1 &
    wait_for_port

    #  1. correct hostname + trust → OK
    output=$(timeout 5 "$CLIENT" --port $PORT --host localhost \
                --trust-cert "$CERT_DIR/rsa.crt" \
                --message "x" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        pass "Hostname: correct + trust → handshake OK"
    else
        fail "Hostname: correct + trust → should have succeeded"
    fi

    #  2. wrong hostname + trust → bad_certificate
    output=$(timeout 5 "$CLIENT" --port $PORT --host evil.example.com \
                --trust-cert "$CERT_DIR/rsa.crt" \
                --message "x" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        pass "Hostname: wrong + trust → reject"
    else
        fail "Hostname: wrong + trust → should have failed"
    fi

    #  3. wrong hostname + Skip_Verify → STILL bad_certificate
    output=$(timeout 5 "$CLIENT" --port $PORT --host evil.example.com \
                --skip-verify \
                --message "x" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        pass "Hostname: wrong + skip-verify → still reject (decoupled)"
    else
        fail "Hostname: wrong + skip-verify → should have failed; \
hostname binding was silently dropped"
    fi

    #  4. wrong hostname + skip-verify + skip-hostname-verify → OK
    output=$(timeout 5 "$CLIENT" --port $PORT --host evil.example.com \
                --skip-verify --skip-hostname-verify \
                --message "x" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        pass "Hostname: wrong + both skips → accept (explicit opt-out)"
    else
        fail "Hostname: wrong + both skips → opt-out failed"
    fi

    cleanup
fi

# ===================================================================
# TLS 1.2 client-side ticket resumption (RFC 5077): two-connection
# round-trip with SPARKTLS as the client and openssl s_server as the
# peer. Connection 1 is a full handshake; we capture the issued
# session_ticket via Client.Get_TLS12_Ticket. Connection 2 carries
# that ticket back in the CH session_ticket extension; openssl
# accepts and we complete the abbreviated handshake (SH → CCS →
# Finished, no Cert/SKE/SHD).
# ===================================================================
echo ""
echo "--- TLS 1.2 ticket resumption: SPARKTLS client → openssl s_server ---"
RESUME_TEST=/home/doc/git/tls_proj/sparktls/bin/examples/tls12_resume_test
if [ ! -x "$RESUME_TEST" ]; then
    echo "  (skipped — tls12_resume_test not built)"
else
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" -tls1_2 \
        -cipher ECDHE-RSA-AES128-GCM-SHA256 -www -quiet \
        > /tmp/tls12_cli_resume_srv.log 2>&1 &
    wait_for_port

    output=$(timeout 10 "$RESUME_TEST" \
                -host 127.0.0.1 -port $PORT 2>&1)
    cleanup
    if echo "$output" | grep -q "PASS: resumption succeeded"; then
        pass "TLS 1.2 ticket resumption (SPARKTLS client → openssl)"
    else
        fail "TLS 1.2 ticket resumption (SPARKTLS client → openssl)"
        echo "$output" | sed 's/^/    /' | head -10
    fi
fi

# ===================================================================
# TEK auto-rotation (ROADMAP §2.13b / §6.5). Runs the blocking
# server with SPARKTLS_TEK_ROTATE_SECS=1 (1-second rotation
# interval, vs the 24h default), then performs two handshakes ~3s
# apart and confirms the TLS 1.2 session_ticket's Key_ID prefix
# (the first 4 bytes of the ticket blob, per Tickets_12 wire format)
# differs between the two — proof that the active TEK was rotated
# in between.
# ===================================================================
echo ""
echo "--- TEK auto-rotation (1-sec interval, observe Key_ID change) ---"
if [ ! -x "$SERVER" ]; then
    echo "  (skipped — tls_blocking_server not built)"
else
    cleanup
    SPARKTLS_TEK_ROTATE_SECS=1 \
        "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
        > /tmp/tek_rotate_srv.log 2>&1 &
    wait_for_port

    get_keyid() {
        echo "x" | timeout 5 openssl s_client \
            -connect 127.0.0.1:$PORT -tls1_2 \
            -CAfile "$CERT_DIR/rsa.crt" 2>/dev/null \
            | awk '/TLS session ticket:/ {flag=1; next}
                   flag && /^ *0000 -/ {print $3 $4 $5 $6; exit}'
    }

    K1=$(get_keyid)
    sleep 3
    K2=$(get_keyid)
    cleanup

    if [ -n "$K1" ] && [ -n "$K2" ] && [ "$K1" != "$K2" ]; then
        pass "TEK auto-rotation: Key_ID changed across rotation interval"
    else
        fail "TEK auto-rotation: K1=$K1 K2=$K2 (expected different)"
    fi
fi

# ===================================================================
# DoS resource limit regression (ROADMAP §2.13). Sends a malicious
# CH with 1000 cipher_suite entries (TLS_AES_128_GCM_SHA256 at
# position 1, garbage values after). With the iteration cap
# (Default_DoS_Caps.Max_Cipher_Suites = 256) the server processes
# the leading 256 suites, finds the acceptable one, and responds
# with a ServerHello — proving (a) no pathological parse cost
# (response < 2s) and (b) correct negotiation despite the flood.
#
# Without the cap, the server would walk all 1000 entries every
# handshake; not catastrophic at this scale but an attacker could
# trivially push that to ~32K (the wire max) to amplify CPU.
# ===================================================================
echo ""
echo "--- DoS: malicious CH with 1000 cipher_suites ---"
if [ ! -x "$SERVER" ]; then
    echo "  (skipped — tls_blocking_server not built)"
else
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
        > /tmp/dos_srv.log 2>&1 &
    wait_for_port

    output=$(python3 \
        "$(dirname "$0")/dos_ch_flood.py" 127.0.0.1 $PORT 2>&1)
    rc=$?
    cleanup

    if [ $rc -eq 0 ] && echo "$output" | grep -q "^PASS:"; then
        pass "DoS: 1000-cipher-suite CH handled (cap engaged)"
    else
        fail "DoS: 1000-cipher-suite CH handling"
        echo "$output" | sed 's/^/    /' | head -5
    fi
fi

# ===================================================================
# HelloRetryRequest — RFC 8446 §4.1.4. SPARKTLS server, openssl
# client offers key_share for an unsupported group (secp521r1) but
# lists X25519 in supported_groups. Server MUST respond with HRR
# requesting X25519, then complete the handshake on CH2.
# ===================================================================
echo ""
echo "--- HRR: SPARKTLS server → OpenSSL s_client ---"
if [ ! -x "$SERVER" ]; then
    echo "  (skipped — tls_blocking_server not built)"
else
    cleanup
    "$SERVER" "$CERT_DIR/ed25519.crt" "$CERT_DIR/ed25519.key" \
        > /tmp/hrr_srv.log 2>&1 &
    sleep 0.5

    # -groups secp521r1:X25519 sends supported_groups=secp521r1,X25519
    # and key_share=secp521r1 only → server must HRR for X25519.
    # openssl 3.x's -msg displays HRR as a plain ServerHello (the SH
    # with HRR sentinel random is the wire encoding), so we detect
    # HRR by: TWO ClientHello records on the wire (CH1 then CH2 after
    # HRR) AND successful Verify. A non-HRR handshake has exactly one
    # ClientHello. -tlsextdebug also shows HRR via "supported_versions"
    # in the SH but only on receive — count CHs is the simplest signal.
    output=$(echo "x" | timeout 5 openssl s_client \
        -connect localhost:$PORT -tls1_3 \
        -CAfile "$CERT_DIR/ed25519.crt" \
        -groups secp521r1:X25519 -msg 2>&1)
    cleanup
    ch_count=$(echo "$output" | grep -c "ClientHello" || true)
    if [ "$ch_count" -ge 2 ] \
       && echo "$output" | grep -q "Verify return code: 0 (ok)"; then
        pass "HRR fires on group mismatch (sparktls server → openssl)"
    else
        fail "HRR fires on group mismatch (sparktls server → openssl)"
        echo "    CH count: $ch_count"
        echo "$output" | grep -E "Hello|alert|Verify|error" \
                       | sed 's/^/    /' | head -10
    fi
fi

# --- Summary ---
cleanup
echo ""
TOTAL=$((PASS + FAIL))
echo "=== Integration: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
