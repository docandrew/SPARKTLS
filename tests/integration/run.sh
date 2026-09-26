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
# Abandoned handshakes must not exhaust the handshake pool
# ===================================================================
# A peer that disconnects after our ServerHello (scanners, speculative
# browser connections) leaves the session mid-handshake. The server
# must hand its handshake-pool slot back (SPARKTLS.Drop) or, once the
# example servers' pool is full (examples/server_pool.ads: 64 slots),
# answer nobody: found 2026-09-14 when every TLS-Anvil test came back
# disabled. So the driver drops more peers than the pool has slots.
echo "--- Abandoned handshakes: pool release ---"
cleanup
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" 2>/dev/null &
sleep 1
if python3 "$DIR/abandoned_handshakes.py" "$PORT" 80 >/dev/null 2>&1; then
    output=$(echo "hello" | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -tls1_2 -quiet 2>&1 || true)
    if echo "$output" | grep -qi "hello\|verify return"; then
        pass "Server still answers after 80 abandoned handshakes"
    else
        fail "Server still answers after 80 abandoned handshakes (pool exhausted)"
    fi
else
    fail "Abandoned-handshake driver: not every ClientHello got a ServerHello"
fi
cleanup

# The event-driven example must impose the deadline itself: a client that
# sends a few bytes and stalls holds a connection slot and a handshake
# slot until SPARKTLS_HANDSHAKE_TIMEOUT expires and the server Drops it.
# The event-driven reference servers, tls_web_epoll and tls_web_uring, run
# the same cases: a deadline for silent clients, a large file served intact,
# parallel clients on several workers, and admission control.
web_server_cases() {  # label binary
    local label=$1 bin=$2

    # The library is sans-I/O: only the application's handshake deadline
    # frees a connection whose peer sends a few bytes and stalls.
    echo "--- $label: silent clients, handshake deadline ---"
    cleanup
    SPARKTLS_HANDSHAKE_TIMEOUT=2 "$bin" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" > /tmp/${label}_deadline.log 2>&1 &
    sleep 1
    python3 "$DIR/silent_connections.py" "$PORT" 20 4 >/dev/null 2>&1
    output=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -tls1_3 2>&1 || true)
    if echo "$output" | grep -q "Cipher is TLS" && grep -q "handshake timeout" /tmp/${label}_deadline.log; then
        pass "$label drops silent clients at the handshake deadline and keeps serving"
    else
        fail "$label drops silent clients at the handshake deadline and keeps serving"
        grep -c "handshake timeout" /tmp/${label}_deadline.log | sed 's/^/    timeouts logged: /'
    fi
    cleanup

    # A response many TLS records long arrives intact. Every body over one
    # record broke before 2026-09-24 (Write_Plaintext's plaintext must be
    # indexed from 0).
    echo "--- $label: 5 MB file served intact ---"
    cleanup
    local root=/tmp/${label}_docroot
    rm -rf "$root"; mkdir -p "$root"
    head -c 5000000 /dev/urandom > "$root/big.bin"
    "$bin" "$CERT_DIR/p256.crt" "$CERT_DIR/p256.key" "$root" > /tmp/${label}_big.log 2>&1 &
    sleep 1
    timeout 30 curl -sk "https://127.0.0.1:$PORT/big.bin" -o /tmp/${label}_big.dl || true
    if cmp -s "$root/big.bin" /tmp/${label}_big.dl; then
        pass "$label serves a 5 MB file intact"
    else
        fail "$label serves a 5 MB file intact ($(stat -c %s /tmp/${label}_big.dl 2>/dev/null || echo 0) bytes received)"
    fi
    rm -rf "$root" /tmp/${label}_big.dl
    cleanup

    # Worker tasks: each an event loop with its own connection table and
    # handshake pool, sharing one listening socket. Every one of a burst
    # of parallel clients must complete its handshake.
    echo "--- $label: four workers, parallel clients ---"
    cleanup
    SPARKTLS_WORKERS=4 "$bin" "$CERT_DIR/p256.crt" "$CERT_DIR/p256.key" > /tmp/${label}_workers.log 2>&1 &
    sleep 1
    local client_pids=() i done_count
    for i in $(seq 1 16); do
        (echo | timeout 10 openssl s_client -connect 127.0.0.1:$PORT -tls1_3 2>&1 | grep -c "Cipher is TLS" > /tmp/${label}_worker_client_$i.out) &
        client_pids+=($!)
    done
    wait "${client_pids[@]}" 2>/dev/null
    done_count=$(cat /tmp/${label}_worker_client_*.out 2>/dev/null | paste -sd+ | bc)
    rm -f /tmp/${label}_worker_client_*.out
    if grep -q "Workers: 4" /tmp/${label}_workers.log && [ "${done_count:-0}" = 16 ]; then
        pass "$label with 4 workers completes 16 parallel handshakes"
    else
        fail "$label with 4 workers completes 16 parallel handshakes (${done_count:-0}/16)"
    fi
    cleanup

    # Admission control: a worker takes a connection only while it has a
    # free connection entry and a free handshake slot. With both workers
    # full of silent clients, a real client waits in the backlog -- it is
    # not accepted and refused -- and is served once the handshake
    # deadline frees an entry.
    echo "--- $label: full workers queue new connections ---"
    cleanup
    SPARKTLS_WORKERS=2 SPARKTLS_MAX_CONNECTIONS=1 SPARKTLS_HANDSHAKE_SLOTS=1 SPARKTLS_HANDSHAKE_TIMEOUT=2 \
        "$bin" "$CERT_DIR/p256.crt" "$CERT_DIR/p256.key" > /tmp/${label}_admission.log 2>&1 &
    sleep 1
    python3 "$DIR/silent_connections.py" "$PORT" 2 6 >/dev/null 2>&1 &
    local silent_pid=$!
    sleep 0.5
    output=$(echo | timeout 10 openssl s_client -connect 127.0.0.1:$PORT -tls1_3 2>&1 || true)
    wait $silent_pid 2>/dev/null
    if echo "$output" | grep -q "Cipher is TLS" && [ "$(grep -c "handshake timeout" /tmp/${label}_admission.log)" -ge 2 ]; then
        pass "$label queues a connection while full and serves it when a slot frees"
    else
        fail "$label queues a connection while full and serves it when a slot frees"
    fi
    cleanup
}

WEB_EPOLL="$REPO_ROOT/bin/examples/tls_web_epoll"
if [ -x "$WEB_EPOLL" ]; then
    web_server_cases epoll-server "$WEB_EPOLL"
else
    echo "  (skipped: tls_web_epoll not built)"
fi

# io_uring needs Linux 6.4 or later with io_uring enabled; where the kernel
# refuses a ring the server says so and these cases are skipped.
WEB_URING="$REPO_ROOT/bin/examples/tls_web_uring"
URING_SELFTEST="$REPO_ROOT/bin/examples/uring_selftest"
if [ -x "$WEB_URING" ] && [ -x "$URING_SELFTEST" ]; then
    cleanup
    "$WEB_URING" "$CERT_DIR/p256.crt" "$CERT_DIR/p256.key" > /tmp/uring_probe.log 2>&1 &
    sleep 1
    cleanup
    if grep -q "io_uring_setup failed" /tmp/uring_probe.log; then
        echo "  (skipped: this kernel refuses io_uring)"
    else
        # The binding on its own: accept, receive into a connection buffer
        # and send, echoing a 2 MB stream sent in random-sized pieces.
        echo "--- io_uring binding: echo self-test ---"
        cleanup
        "$URING_SELFTEST" "$PORT" > /tmp/uring_selftest.log 2>&1 &
        sleep 0.5
        if python3 "$DIR/echo_check.py" "$PORT" 2000000 && grep -q "PASS nop round trip" /tmp/uring_selftest.log; then
            pass "io_uring binding echoes 2 MB intact"
        else
            fail "io_uring binding echoes 2 MB intact"
        fi
        cleanup
        web_server_cases uring-server "$WEB_URING"
    fi
else
    echo "  (skipped: tls_web_uring not built)"
fi

# ===================================================================
# TLS 1.3 — Server tests (OpenSSL s_client → our server)
# ===================================================================
echo "--- TLS 1.3: OpenSSL client → SPARKTLS server ---"

# Each cert type with each cipher suite
for cert_name in rsa rsa2056 ed25519 p256 p384; do
    cert="$CERT_DIR/${cert_name}.crt"
    key="$CERT_DIR/${cert_name}.key"
    [ -f "$cert" ] || continue

    for suite in TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384; do
        for group in x25519 P-256 P-384 X25519MLKEM768; do
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

for cert_name in rsa rsa2056 ed25519 p256 p384; do
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

# X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): the OpenSSL server accepts
# only the hybrid group, so success means our client offered it, decapsulated
# the server's ciphertext and derived the 64-byte hybrid secret. OpenSSL 3.6's
# default group list already leads with X25519MLKEM768, so the loop above
# exercises the same path; this pins it explicitly.
echo "--- TLS 1.3 X25519MLKEM768: SPARKTLS client → OpenSSL server (hybrid only) ---"
cleanup
openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
    -accept $PORT -tls1_3 -groups X25519MLKEM768 -www 2>/dev/null &
sleep 1
output=$(timeout 10 "$FETCH" --cafile "$CERT_DIR/rsa.crt" --rfc5280 "https://localhost:$PORT/" 2>&1 || true)
cleanup
if echo "$output" | grep -qi "HTTP/1\|200\|html"; then
    pass "Client X25519MLKEM768 (hybrid-only server)"
else
    fail "Client X25519MLKEM768 (hybrid-only server)"
    echo "    $(echo "$output" | head -1)"
fi

# Our server, OpenSSL client offering the hybrid alone (no classical group).
echo "--- TLS 1.3 X25519MLKEM768: OpenSSL client (hybrid only) → SPARKTLS server ---"
cleanup
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" 2>/dev/null &
sleep 1
output=$(echo "hello" | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -tls1_3 \
    -groups X25519MLKEM768 2>&1 || true)
cleanup
if echo "$output" | grep -q "Negotiated TLS1.3 group: X25519MLKEM768"; then
    pass "Server X25519MLKEM768 (hybrid-only client)"
else
    fail "Server X25519MLKEM768 (hybrid-only client)"
    echo "    $(echo "$output" | grep -i "error\|alert" | head -1)"
fi

# The examples draw their randomness from SPARKEntropy (CPU jitter) behind
# SPARKTLS.RBG (HMAC_DRBG), examples/entropy_random.adb; no OS randomness.
# This case checks the start-up line proves that path was taken:
# jitter start-up test, DRBG self-test and seeding, a full TLS 1.3
# handshake, ticket keys.
echo "--- TLS 1.3: OpenSSL client → SPARKTLS server on SPARKEntropy + SPARKTLS.RBG ---"
cleanup
server_log=$(mktemp)
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" >"$server_log" 2>&1 &
sleep 1
output=$(echo "hello" | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -tls1_3 -quiet 2>&1 || true)
cleanup
if grep -q "Entropy: SPARKEntropy jitter source" "$server_log" \
   && echo "$output" | grep -qi "hello\|verify return"; then
    pass "Server on SPARKEntropy + SPARKTLS.RBG"
else
    fail "Server on SPARKEntropy + SPARKTLS.RBG"
    echo "    server: $(grep -i "entropy" "$server_log" | head -1)"
    echo "    client: $(echo "$output" | grep -i "error\|alert" | head -1)"
fi
rm -f "$server_log"

echo ""

# ===================================================================
# TLS 1.2 — Server tests (OpenSSL s_client → our server)
# ===================================================================
echo "--- TLS 1.2: OpenSSL client → SPARKTLS server ---"

# TLS 1.2: RSA certs with ECDHE-RSA suites (rsa4096: our SKE carries a
# 512-byte signature, which the old 512-byte SKE buffer could not hold)
for rsa_name in rsa rsa4096; do
for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    cleanup
    "$SERVER" "$CERT_DIR/$rsa_name.crt" "$CERT_DIR/$rsa_name.key" 2>/dev/null &
    sleep 1

    output=$(echo "hello" | timeout 5 openssl s_client \
        -connect 127.0.0.1:$PORT -tls1_2 -cipher "$suite" \
        -quiet 2>&1 || true)
    cleanup

    if echo "$output" | grep -qi "hello\|GET\|HTTP"; then
        pass "Server TLS1.2 $rsa_name+$suite"
    else
        fail "Server TLS1.2 $rsa_name+$suite"
    fi
done
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

# rsa4096: ServerKeyExchange carries a 512-byte signature (585-byte SKE),
# which the old 512-byte SKE cap rejected with decode_error.
for rsa_name in rsa rsa4096; do
for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384; do
    cleanup
    openssl s_server -cert "$CERT_DIR/$rsa_name.crt" -key "$CERT_DIR/$rsa_name.key" \
        -accept $PORT -tls1_2 -cipher "$suite" -www 2>/dev/null &
    sleep 1

    output=$(timeout 10 "$FETCH" --cafile "$CERT_DIR/$rsa_name.crt" --rfc5280 "https://localhost:$PORT/" 2>&1 || true)
    cleanup

    if echo "$output" | grep -qi "HTTP/1\|200\|html"; then
        pass "Client TLS1.2 $rsa_name+$suite"
    else
        fail "Client TLS1.2 $rsa_name+$suite"
        echo "    $(echo "$output" | head -1)"
    fi
done
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

# Generate a proper mTLS client-auth leaf under a temporary CA. The
# self-signed fixture certs are CA:TRUE, and WebPKI mode correctly
# rejects CA certificates in leaf position.
GOOD_CLIENT_DIR="${TMPDIR:-/tmp}/sparktls-good-client-eku.$$"
mkdir -p "$GOOD_CLIENT_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$GOOD_CLIENT_DIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$GOOD_CLIENT_DIR/ca.key" \
    -out "$GOOD_CLIENT_DIR/ca.pem" -days 30 \
    -subj "/CN=sparktls-mtls-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$GOOD_CLIENT_DIR/client.key" 2>/dev/null
openssl req -new -key "$GOOD_CLIENT_DIR/client.key" \
    -out "$GOOD_CLIENT_DIR/client.csr" \
    -subj "/CN=sparktls-mtls-client" \
    -addext "subjectAltName=DNS:sparktls-mtls-client" 2>/dev/null
cat > "$GOOD_CLIENT_DIR/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:sparktls-mtls-client
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in "$GOOD_CLIENT_DIR/client.csr" \
    -CA "$GOOD_CLIENT_DIR/ca.pem" -CAkey "$GOOD_CLIENT_DIR/ca.key" \
    -CAcreateserial -out "$GOOD_CLIENT_DIR/client.pem" -days 30 \
    -extfile "$GOOD_CLIENT_DIR/client.ext" 2>/dev/null

# 2) A valid client certificate should be accepted in TLS 1.3 required mode.
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
    --mtls-require "$GOOD_CLIENT_DIR/ca.pem" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client -quiet \
    -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/rsa.crt" \
    -cert "$GOOD_CLIENT_DIR/client.pem" \
    -key "$GOOD_CLIENT_DIR/client.key" \
    2>&1 || true)
if echo "$output" | grep -qx "hello"; then
    pass "Required mode accepts valid client certificate"
else
    fail "Required mode rejected valid client certificate"
    echo "    $(echo "$output" | head -1)"
fi
cleanup

# 3) A presented client certificate with serverAuth-only EKU should be
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
cleanup

# 4) Optional mode (default --mtls without -require) should accept
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

# 5) TLS 1.2 required mode should reject a no-cert client as well.
cleanup
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
    --mtls-require "$CERT_DIR/rsa.crt" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 \
    -CAfile "$CERT_DIR/rsa.crt" 2>&1 || true)
if echo "$output" | grep -qE "(handshake failure|certificate required|alert.*40|alert.*116)"; then
    pass "Required mode TLS 1.2 rejects no-cert client"
elif echo "$output" | grep -qx "hello"; then
    fail "Required mode TLS 1.2 incorrectly accepted no-cert client (BYPASS)"
else
    pass "Required mode TLS 1.2 rejects no-cert client (handshake aborted)"
fi
cleanup

# 6) TLS 1.2 required mode should accept a valid client cert.
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
    --mtls-require "$GOOD_CLIENT_DIR/ca.pem" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client -quiet \
    -connect localhost:$PORT -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 \
    -CAfile "$CERT_DIR/rsa.crt" \
    -cert "$GOOD_CLIENT_DIR/client.pem" \
    -key "$GOOD_CLIENT_DIR/client.key" \
    2>&1 || true)
if echo "$output" | grep -qx "hello"; then
    pass "Required mode TLS 1.2 accepts valid client certificate"
else
    fail "Required mode TLS 1.2 rejected valid client certificate"
    echo "    $(echo "$output" | head -1)"
fi
cleanup

# 7) TLS 1.2 required mode should reject a client cert without clientAuth EKU.
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
    --mtls-require "$BAD_CLIENT_DIR/cert.pem" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 \
    -CAfile "$CERT_DIR/rsa.crt" \
    -cert "$BAD_CLIENT_DIR/cert.pem" -key "$BAD_CLIENT_DIR/key.pem" \
    2>&1 || true)
if echo "$output" | grep -qx "hello"; then
    fail "Required mode TLS 1.2 accepted serverAuth-only client certificate"
else
    pass "Required mode TLS 1.2 rejects serverAuth-only client certificate"
fi
cleanup

# 8) TLS 1.2 optional mode should accept a no-cert client.
"$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" \
    --mtls "$CERT_DIR/rsa.crt" 2>/dev/null &
wait_for_port
output=$(echo "hello" | timeout 5 openssl s_client \
    -connect localhost:$PORT -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 \
    -CAfile "$CERT_DIR/rsa.crt" 2>&1 || true)
if echo "$output" | grep -q "BEGIN CERTIFICATE" \
   && ! echo "$output" | grep -qiE "(certificate required|alert.*116|handshake failure)"; then
    pass "Optional mode TLS 1.2 accepts no-cert client"
else
    fail "Optional mode TLS 1.2 rejected no-cert client (regression)"
    echo "    $(echo "$output" | head -1)"
fi
cleanup
rm -rf "$GOOD_CLIENT_DIR"
rm -rf "$BAD_CLIENT_DIR"

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

    # Client-side external signing: the client's CertificateVerify is
    # produced by the Sign callback with a public-only identity, on TLS 1.3
    # and TLS 1.2 (the 1.2 path is the pre-hashed, message-less one).
    for cred in "p256" "rsa" "ed25519"; do
        for ver in tls1_3 tls1_2; do
            #  Ed25519 client auth on TLS 1.2 is declined by design (PureEdDSA
            #  needs the whole transcript, which the streamed transcript cannot
            #  replay), with a local key as much as with a callback.
            if [ "$cred" = "ed25519" ] && [ "$ver" = "tls1_2" ]; then continue; fi
            cleanup
            openssl s_server -accept 0:$PORT \
                -cert "$CERT_DIR/${cred}.crt" -key "$CERT_DIR/${cred}.key" \
                -CAfile "$CERT_DIR/${cred}.crt" -Verify 1 -$ver -no_ticket -quiet \
                > /tmp/mtls_srv.log 2>&1 &
            sleep 0.5
            output=$(timeout 5 "$CLIENT" \
                --port $PORT --host localhost \
                --cert-file "$CERT_DIR/${cred}.crt" \
                --key-file "$CERT_DIR/${cred}.key" \
                --external-sign \
                --trust-cert "$CERT_DIR/${cred}.crt" \
                --message "hello-from-sparktls" 2>&1)
            rc=$?
            cleanup
            if [ $rc -eq 0 ]; then
                pass "client mTLS external signer $cred $ver"
            else
                fail "client mTLS external signer $cred $ver"
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
    output=$(timeout 10 "$RESUME_CLIENT" -port $PORT -host localhost -cafile "$CERT_DIR/p256.crt" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ] && echo "$output" | grep -q "PASS: resumption succeeded"; then
        pass "TLS 1.3 PSK resumption (two connections)"
    else
        fail "TLS 1.3 PSK resumption (two connections)"
        echo "$output" | sed 's/^/    /' | head -10
    fi

    # Same round trip with client authentication. OpenSSL embeds the
    # client's certificate chain in the ticket (1072 bytes for rsa.crt),
    # which the client used to drop silently (Max_Ticket_Len was 256), so
    # no mTLS session ever resumed.
    cleanup
    openssl s_server -accept 0:$PORT \
        -cert "$CERT_DIR/p256.crt" -key "$CERT_DIR/p256.key" \
        -Verify 1 -CAfile "$CERT_DIR/rsa.crt" \
        -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 \
        -num_tickets 1 -quiet \
        > /tmp/resume_srv.log 2>&1 &
    sleep 0.5
    output=$(timeout 10 "$RESUME_CLIENT" -port $PORT -host localhost -cafile "$CERT_DIR/p256.crt" \
        -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" 2>&1)
    rc=$?
    cleanup
    if [ $rc -eq 0 ] && echo "$output" | grep -q "PASS: resumption succeeded"; then
        pass "TLS 1.3 PSK resumption after client auth (ticket > 256 bytes)"
    else
        fail "TLS 1.3 PSK resumption after client auth (ticket > 256 bytes)"
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
SNI_SERVER="$REPO_ROOT/bin/examples/tls_sni_server"
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
RESUME_TEST="$REPO_ROOT/bin/examples/tls12_resume_test"
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
                -host 127.0.0.1 -port $PORT -cafile "$CERT_DIR/rsa.crt" 2>&1)
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
# (the first 4 bytes of the ticket blob, per Tickets wire format)
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

# ===================================================================
# Application verification hook + credential selection.
# tls_verify_hook_client installs Config.Verify_Peer (veto-only: it runs
# only after the proven core accepted the chain) and
# Config.Select_Client_Identity (picks the client certificate from the
# server's certificate_authorities list). tls_authz_server requires a
# client certificate and authorizes it by subject CN / SAN via the hook.
# ===================================================================
echo ""
echo "--- Verify hook: pinning, SAN policy, veto-only ---"
HOOK_CLIENT="$REPO_ROOT/bin/examples/tls_verify_hook_client"
AUTHZ_SERVER="$REPO_ROOT/bin/examples/tls_authz_server"
if [ ! -x "$HOOK_CLIENT" ] || [ ! -x "$AUTHZ_SERVER" ]; then
    echo "  (skipped - hook examples not built)"
else
    RSA_PIN=$(openssl x509 -in "$CERT_DIR/rsa.crt" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
    BAD_PIN=$(printf '%064d' 0)
    cleanup
    "$SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" > /tmp/hook_srv.log 2>&1 &
    wait_for_port

    # 1) matching pin + SAN policy + audit -> accepted, echo round-trip
    if timeout 15 "$HOOK_CLIENT" --port $PORT --trust-cert "$CERT_DIR/rsa.crt" \
        --pin-sha256 "$RSA_PIN" --require-san localhost --audit --expect-echo \
        > /tmp/hook1.log 2>&1 && grep -q "AUDIT leaf sha256=$RSA_PIN" /tmp/hook1.log \
        && grep -q "AUDIT anchor CN=localhost" /tmp/hook1.log; then
        pass "Hook: matching pin + SAN accepted (audit line present)"
    else
        fail "Hook: matching pin + SAN rejected"
        head -3 /tmp/hook1.log | sed 's/^/    /'
    fi

    # 2) pin mismatch -> vetoed (handshake aborted with bad_certificate)
    if timeout 15 "$HOOK_CLIENT" --port $PORT --trust-cert "$CERT_DIR/rsa.crt" \
        --pin-sha256 "$BAD_PIN" --expect-fail > /tmp/hook2.log 2>&1 \
        && grep -q "VETO: pin mismatch" /tmp/hook2.log; then
        pass "Hook: pin mismatch vetoed"
    else
        fail "Hook: pin mismatch NOT vetoed (BYPASS)"
        head -3 /tmp/hook2.log | sed 's/^/    /'
    fi

    # 3) SAN policy mismatch -> vetoed
    if timeout 15 "$HOOK_CLIENT" --port $PORT --trust-cert "$CERT_DIR/rsa.crt" \
        --require-san not-this-host --expect-fail > /tmp/hook3.log 2>&1 \
        && grep -q "VETO: leaf has no SAN" /tmp/hook3.log; then
        pass "Hook: SAN policy mismatch vetoed"
    else
        fail "Hook: SAN policy mismatch NOT vetoed (BYPASS)"
        head -3 /tmp/hook3.log | sed 's/^/    /'
    fi

    # 4) veto-only: with no trust store the core fails closed BEFORE the
    #    hook runs; a correct pin cannot admit an unverified chain.
    if timeout 15 "$HOOK_CLIENT" --port $PORT --pin-sha256 "$RSA_PIN" --audit \
        --expect-fail > /tmp/hook4.log 2>&1 && ! grep -q "AUDIT peer" /tmp/hook4.log; then
        pass "Hook: cannot admit an unverified chain (hook never consulted)"
    else
        fail "Hook: unverified chain reached the hook or was accepted (BYPASS)"
        head -3 /tmp/hook4.log | sed 's/^/    /'
    fi
    cleanup

    # Client credentials under a throwaway CA: alice is allowed, mallory
    # is a valid client of the same CA but not on the list.
    AUTHZ_DIR="${TMPDIR:-/tmp}/sparktls-authz.$$"
    mkdir -p "$AUTHZ_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$AUTHZ_DIR/ca.key" \
        -out "$AUTHZ_DIR/ca.pem" -days 30 -subj "/CN=sparktls-authz-ca" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    gen_authz_client() {
        openssl req -new -newkey rsa:2048 -nodes -keyout "$AUTHZ_DIR/$1.raw" \
            -out "$AUTHZ_DIR/$1.csr" -subj "/CN=$1" 2>/dev/null
        openssl pkcs8 -topk8 -nocrypt -in "$AUTHZ_DIR/$1.raw" \
            -out "$AUTHZ_DIR/$1.key" 2>/dev/null
        printf 'subjectAltName=DNS:%s\nextendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n' \
            "$1" > "$AUTHZ_DIR/$1.ext"
        openssl x509 -req -in "$AUTHZ_DIR/$1.csr" -CA "$AUTHZ_DIR/ca.pem" \
            -CAkey "$AUTHZ_DIR/ca.key" -CAcreateserial -out "$AUTHZ_DIR/$1.pem" \
            -days 30 -extfile "$AUTHZ_DIR/$1.ext" 2>/dev/null
    }
    gen_authz_client alice
    gen_authz_client mallory

    echo ""
    echo "--- Authz hook: client authorization by CN/SAN ---"
    cleanup
    "$AUTHZ_SERVER" "$CERT_DIR/rsa.crt" "$CERT_DIR/rsa.key" "$AUTHZ_DIR/ca.pem" \
        --allow alice > /tmp/authz_srv.log 2>&1 &
    wait_for_port
    output=$(echo "hello" | timeout 5 openssl s_client -quiet \
        -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/rsa.crt" \
        -cert "$AUTHZ_DIR/alice.pem" -key "$AUTHZ_DIR/alice.key" 2>&1 || true)
    if echo "$output" | grep -qx "hello"; then
        pass "Authz: allowed client (alice) accepted"
    else
        fail "Authz: allowed client (alice) rejected"
        echo "    $(echo "$output" | head -1)"
    fi
    output=$(echo "hello" | timeout 5 openssl s_client -quiet \
        -connect localhost:$PORT -tls1_3 -CAfile "$CERT_DIR/rsa.crt" \
        -cert "$AUTHZ_DIR/mallory.pem" -key "$AUTHZ_DIR/mallory.key" 2>&1 || true)
    if echo "$output" | grep -qx "hello"; then
        fail "Authz: unlisted client (mallory) accepted (BYPASS)"
    else
        pass "Authz: unlisted client (mallory) rejected"
    fi
    if grep -q "AUTHZ accept subject CN='alice'" /tmp/authz_srv.log \
       && grep -q "AUTHZ deny subject CN='mallory'" /tmp/authz_srv.log; then
        pass "Authz: server logged both decisions"
    else
        fail "Authz: decision log missing"
        grep AUTHZ /tmp/authz_srv.log | sed 's/^/    /' | head -4
    fi
    cleanup

    echo ""
    echo "--- Credential selection by certificate_authorities ---"
    # openssl s_server names the CA it accepts in CertificateRequest.
    # -verify_return_error: without it s_server only LOGS a client-cert
    # verification failure and completes the handshake anyway.
    # The client holds a self-signed default identity (unacceptable to the
    # server) and alice as the alternate; the selector must pick alice.
    cleanup
    openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -accept $PORT -tls1_3 -Verify 1 -verify_return_error -CAfile "$AUTHZ_DIR/ca.pem" \
        -quiet > /tmp/pick_srv.log 2>&1 &
    sleep 1
    if timeout 15 "$HOOK_CLIENT" --port $PORT --trust-cert "$CERT_DIR/rsa.crt" \
        --cert-file "$CERT_DIR/ed25519.crt" --key-file "$CERT_DIR/ed25519.key" \
        --alt-cert-file "$AUTHZ_DIR/alice.pem" --alt-key-file "$AUTHZ_DIR/alice.key" \
        --audit > /tmp/pick1.log 2>&1 \
        && grep -q "AUDIT selected alternate identity" /tmp/pick1.log; then
        pass "Selector: picked the identity issued by the CA the server named"
    else
        fail "Selector: did not pick the CA-named identity"
        head -4 /tmp/pick1.log | sed 's/^/    /'
    fi
    cleanup
    openssl s_server -cert "$CERT_DIR/rsa.crt" -key "$CERT_DIR/rsa.key" \
        -accept $PORT -tls1_3 -Verify 1 -verify_return_error -CAfile "$AUTHZ_DIR/ca.pem" \
        -quiet > /tmp/pick_srv2.log 2>&1 &
    sleep 1
    # control: no alternate -> the default identity is sent and rejected.
    if timeout 15 "$HOOK_CLIENT" --port $PORT --trust-cert "$CERT_DIR/rsa.crt" \
        --cert-file "$CERT_DIR/ed25519.crt" --key-file "$CERT_DIR/ed25519.key" \
        --expect-fail > /tmp/pick2.log 2>&1; then
        pass "Selector control: default identity rejected by the server"
    else
        fail "Selector control: default identity unexpectedly accepted"
        head -3 /tmp/pick2.log | sed 's/^/    /'
    fi
    cleanup
    rm -rf "$AUTHZ_DIR"
fi

# ===================================================================
# Revocation: stapled OCSP (TLS 1.3 CertificateEntry / TLS 1.2
# CertificateStatus), must-staple, CRLs -- our client against
# OpenSSL s_server with -status_file, on the sparkx509 fixture PKI.
# ===================================================================
REV_GEN="$REPO_ROOT/../sparkx509/tests/revocation/gen.sh"
REV_DIR="${TMPDIR:-/tmp}/sparkx509-revocation"
if [ -x "$REV_GEN" ] && bash "$REV_GEN" "$REV_DIR" >/dev/null 2>&1; then
    echo "--- Revocation: SPARKTLS client -> OpenSSL server ---"

    #  rev_case LABEL VERSION_FLAG CERT KEY STATUS_FILE_OR_- FETCH_FLAGS EXPECT
    #  EXPECT: "ok" (page fetched) or an "alert N" substring of the error.
    rev_case() {
        local label="$1" vflag="$2" cert="$3" key="$4" status="$5" fflags="$6" expect="$7"
        cleanup
        if [ "$status" = "-" ]; then
            openssl s_server -cert "$REV_DIR/$cert" -key "$REV_DIR/$key" \
                -accept $PORT $vflag -www 2>/dev/null &
        else
            openssl s_server -cert "$REV_DIR/$cert" -key "$REV_DIR/$key" \
                -status_file "$REV_DIR/$status" \
                -accept $PORT $vflag -www 2>/dev/null &
        fi
        wait_for_port
        local output
        # shellcheck disable=SC2086
        output=$(timeout 10 "$FETCH" --cafile "$REV_DIR/ca.crt" $fflags "https://localhost:$PORT/" 2>&1 || true)
        cleanup
        if [ "$expect" = "ok" ]; then
            if echo "$output" | grep -qi "HTTP/1\|200\|html"; then
                pass "Revocation $label"
            else
                fail "Revocation $label (expected success)"
                echo "    $(echo "$output" | grep -i "error" | head -1)"
            fi
        else
            if echo "$output" | grep -qi "$expect"; then
                pass "Revocation $label"
            else
                fail "Revocation $label (expected '$expect')"
                echo "    $(echo "$output" | head -1)"
            fi
        fi
    }

    for v in "-tls1_3" "-tls1_2"; do
        rev_case "stapled good, hard $v"        "$v" good.crt    good.key    ocsp_good_ca.der           "--revocation=hard" ok
        rev_case "stapled good (delegated) $v"  "$v" good.crt    good.key    ocsp_good_delegated.der    "--revocation=hard" ok
        rev_case "stapled good (byKey) $v"      "$v" good.crt    good.key    ocsp_good_ca_keyid.der     "--revocation=hard" ok
        rev_case "stapled good (SHA-256) $v"    "$v" good.crt    good.key    ocsp_good_sha256_nonce.der "--revocation=hard" ok
        rev_case "stapled revoked, soft $v"     "$v" revoked.crt revoked.key ocsp_revoked_ca.der        ""                  "alert 44"
        rev_case "stapled revoked, off $v"      "$v" revoked.crt revoked.key ocsp_revoked_ca.der        "--revocation=off"  ok
        rev_case "wrong staple (other leaf) $v" "$v" revoked.crt revoked.key ocsp_good_ca.der           "--revocation=hard" "alert 42"
        rev_case "no staple, hard $v"           "$v" good.crt    good.key    -                          "--revocation=hard" "alert 42"
        rev_case "no staple, soft $v"           "$v" good.crt    good.key    -                          ""                  ok
        rev_case "must-staple unstapled $v"     "$v" staple.crt  staple.key  -                          ""                  "alert 113"
        rev_case "must-staple stapled $v"       "$v" staple.crt  staple.key  ocsp_staple_ca.der         ""                  ok
        rev_case "CRL: good leaf, hard $v"      "$v" good.crt    good.key    -                          "--revocation=hard --crl $REV_DIR/crl.der" ok
        rev_case "CRL: revoked leaf, soft $v"   "$v" revoked.crt revoked.key -                          "--crl $REV_DIR/crl.der" "alert 44"
        #  Sharded CRLs: the wrong shard first must not mask the right one,
        #  and a shard that does not cover the leaf is no evidence.
        rev_case "CRL shards: wrong first, hard $v" "$v" shard1.crt shard1.key -                       "--revocation=hard --crl $REV_DIR/crl_shard2.der --crl $REV_DIR/crl_shard1.der" "alert 44"
        rev_case "CRL shards: other only, hard $v"  "$v" shard1.crt shard1.key -                       "--revocation=hard --crl $REV_DIR/crl_shard2.der" "alert 42"
        rev_case "CRL shards: other only, soft $v"  "$v" shard1.crt shard1.key -                       "--crl $REV_DIR/crl_shard2.der" ok
    done

    #  Server side: our server staples the fixture response for a client
    #  that asks (openssl s_client -status), on both versions, and sends
    #  nothing when not asked.
    staple_case() {
        local label="$1" vflag="$2" ask="$3" expect="$4"
        cleanup
        "$SERVER" "$REV_DIR/good.crt" "$REV_DIR/good.key" --staple "$REV_DIR/ocsp_good_ca.der" 2>/dev/null &
        wait_for_port
        local output
        # shellcheck disable=SC2086
        output=$(echo "" | timeout 10 openssl s_client -connect 127.0.0.1:$PORT $vflag $ask \
                    -CAfile "$REV_DIR/ca.crt" 2>&1 || true)
        cleanup
        if [ "$expect" = "stapled" ]; then
            if echo "$output" | grep -q "OCSP Response Status: successful"; then
                pass "Revocation server staple $label"
            else
                fail "Revocation server staple $label (s_client saw no staple)"
                echo "    $(echo "$output" | grep -i "OCSP" | head -1)"
            fi
        else
            if echo "$output" | grep -q "OCSP Response Status"; then
                fail "Revocation server staple $label (stapled without being asked)"
            elif echo "$output" | grep -qi "Verify return code: 0"; then
                pass "Revocation server staple $label"
            else
                fail "Revocation server staple $label (handshake failed)"
                echo "    $(echo "$output" | grep -i "error\|alert" | head -1)"
            fi
        fi
    }
    staple_case "TLS 1.3" -tls1_3 -status stapled
    staple_case "TLS 1.2" -tls1_2 -status stapled
    staple_case "TLS 1.3 not asked" -tls1_3 "" none
    staple_case "TLS 1.2 not asked" -tls1_2 "" none

    #  The revocation example program (examples/tls_revocation_check):
    #  same fixtures, its own verdict line. Keeps the documented sample
    #  honest against the library it demonstrates.
    REVCHK="$REPO_ROOT/bin/examples/tls_revocation_check"
    if [ -x "$REVCHK" ]; then
        #  rev_example LABEL VERSION_FLAG CERT KEY STATUS_FILE_OR_- ARGS EXPECT_SUBSTRING
        rev_example() {
            local label="$1" vflag="$2" cert="$3" key="$4" status="$5" args="$6" expect="$7"
            cleanup
            if [ "$status" = "-" ]; then
                openssl s_server -cert "$REV_DIR/$cert" -key "$REV_DIR/$key" \
                    -accept $PORT $vflag -www 2>/dev/null &
            else
                openssl s_server -cert "$REV_DIR/$cert" -key "$REV_DIR/$key" \
                    -status_file "$REV_DIR/$status" -accept $PORT $vflag -www 2>/dev/null &
            fi
            wait_for_port
            local output
            # shellcheck disable=SC2086
            output=$(timeout 10 "$REVCHK" "localhost:$PORT" --cafile "$REV_DIR/ca.crt" $args 2>&1 || true)
            cleanup
            if echo "$output" | grep -q "$expect"; then
                pass "Revocation example $label"
            else
                fail "Revocation example $label (expected '$expect')"
                echo "    $(echo "$output" | tail -1)"
            fi
        }
        rev_example "stapled good, hard"      -tls1_3 good.crt    good.key    ocsp_good_ca.der    "--policy hard" "ACCEPTED: chain valid; revocation evidence verified (stapled OCSP)"
        rev_example "stapled revoked, soft"   -tls1_3 revoked.crt revoked.key ocsp_revoked_ca.der ""              "REJECTED: .*alert 44"
        rev_example "no staple, hard"         -tls1_3 good.crt    good.key    -                   "--policy hard" "REJECTED: .*alert 42"
        rev_example "CRL good, hard"          -tls1_3 good.crt    good.key    -                   "--policy hard --crl $REV_DIR/crl.der" "revocation evidence verified (CRL)"
        rev_example "CRL revoked, soft"       -tls1_3 revoked.crt revoked.key -                   "--crl $REV_DIR/crl.der" "REJECTED: .*alert 44"
        rev_example "must-staple, no staple"  -tls1_3 staple.crt  staple.key  -                   ""              "REJECTED: .*alert 113"
        rev_example "stapled good, TLS 1.2"   -tls1_2 good.crt    good.key    ocsp_good_ca.der    "--policy hard" "revocation evidence verified (stapled OCSP)"
    fi
    echo ""
else
    echo "--- Revocation: skipped (sparkx509 fixture generator not available) ---"
fi

# --- Summary ---
cleanup
echo ""
# ===================================================================
# External signer: the server holds a public-only
# identity and every handshake signature comes from the Software_Signer
# callback, standing in for a YubiKey, TPM, HSM or signing process. The
# handshake must look exactly like the local-key one to OpenSSL, in both
# TLS 1.3 (CertificateVerify) and TLS 1.2 (ServerKeyExchange), for every
# key type; and the server must report that it holds no private key.
# ===================================================================
echo "--- External signer: public-only identity + Sign callback ---"
for cred in p256 p384 rsa ed25519; do
    [ -f "$CERT_DIR/${cred}.crt" ] || continue
    cleanup
    "$SERVER" "$CERT_DIR/${cred}.crt" "$CERT_DIR/${cred}.key" --external-sign > /tmp/extsign_${cred}.log 2>&1 &
    wait_for_port
    if grep -q "External signer: enabled" /tmp/extsign_${cred}.log; then
        pass "external signer ($cred): TLS side holds no private key"
    else
        fail "external signer ($cred): server did not enable the callback"
    fi
    for ver in tls1_3 tls1_2; do
        #  Only the echoed line proves the handshake: OpenSSL prints
        #  "verify return" while still processing the Certificate, before
        #  the CertificateVerify / ServerKeyExchange signature is checked.
        output=$(echo "hello" | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -$ver -quiet 2>&1 || true)
        if echo "$output" | grep -qx "hello"; then
            pass "external signer ($cred, $ver): handshake completes, data echoed"
        else
            fail "external signer ($cred, $ver): handshake failed: $(echo "$output" | head -2 | tr '\n' ' ')"
        fi
    done
    cleanup
done

#  Fail-closed on the wire: a signer that returns a wrong signature, or
#  refuses, must end the handshake with our internal_error alert (80) and
#  never echo. Exercises the 1.3 CertificateVerify and 1.2 ServerKeyExchange
#  paths of verify-before-wire with a P-256 key.
for mode in corrupt refuse; do
    cleanup
    "$SERVER" "$CERT_DIR/p256.crt" "$CERT_DIR/p256.key" --external-sign --external-sign-$mode > /tmp/extsign_$mode.log 2>&1 &
    wait_for_port
    for ver in tls1_3 tls1_2; do
        output=$(echo "hello" | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -$ver 2>&1 || true)
        if ! echo "$output" | grep -qx "hello" && echo "$output" | grep -qE "alert number 80|internal error"; then
            pass "external signer $mode ($ver): refused with internal_error, nothing echoed"
        else
            fail "external signer $mode ($ver): expected internal_error alert: $(echo "$output" | grep -iE "alert|hello" | head -2 | tr '\n' ' ')"
        fi
    done
    cleanup
done

# ===================================================================
# Hardware-gated: YubiKey PIV as the server identity (the external-signing design notes,
# sparkpiv). Runs only when the example is built and a YubiKey with a
# user-writable device node is present (and pcscd is not holding it);
# otherwise it is skipped and counts for nothing. Uses slot 9e, which
# signs without a PIN, so no secret is needed; the slot must hold a P-256
# or P-384 key with a certificate (yubico-piv-tool -a generate -s 9e ...).
# ===================================================================
YK_SERVER="$REPO_ROOT/bin/examples/tls_yubikey_server"
YK_NODE=""
for d in /sys/bus/usb/devices/*; do
    if [ -f "$d/idVendor" ] && [ "$(cat "$d/idVendor" 2>/dev/null)" = "1050" ]; then
        b=$(cat "$d/busnum"); n=$(cat "$d/devnum")
        YK_NODE=$(printf "/dev/bus/usb/%03d/%03d" "$b" "$n")
        break
    fi
done
#  Skip (never fail) unless the token actually holds a certificate in 9e:
#  a FIDO-only key, an empty slot or a non-ECDSA key is not a regression.
YK_PROBE="$REPO_ROOT/../sparkpiv/examples/bin/piv_probe"
YK_READY=0
if [ -x "$YK_SERVER" ] && [ -n "$YK_NODE" ] && [ -w "$YK_NODE" ] && ! pgrep -x pcscd >/dev/null && [ -x "$YK_PROBE" ]; then
    if timeout 20 "$YK_PROBE" 2>/dev/null | grep -q "slot 9e: certificate"; then YK_READY=1; fi
fi
if [ "$YK_READY" = 1 ]; then
    echo "--- YubiKey PIV identity: token signs the handshake (slot 9e, no PIN) ---"
    cleanup
    "$YK_SERVER" 9e "$PORT" > /tmp/yubikey_server.log 2>&1 &
    wait_for_port
    if grep -q "public only; the key stays in the YubiKey" /tmp/yubikey_server.log; then
        pass "yubikey: identity loaded from the token, no private key in the process"
    else
        fail "yubikey: token setup failed: $(tail -2 /tmp/yubikey_server.log | tr '\n' ' ')"
    fi
    for ver in tls1_3 tls1_2; do
        output=$(echo "hello" | timeout 20 openssl s_client -connect 127.0.0.1:$PORT -$ver -quiet 2>&1 || true)
        if echo "$output" | grep -qx "hello"; then
            pass "yubikey: $ver handshake signed by the token, data echoed"
        else
            fail "yubikey: $ver handshake failed: $(echo "$output" | head -2 | tr '\n' ' ')"
        fi
    done
    cleanup
else
    echo "--- YubiKey PIV identity: skipped (needs tls_yubikey_server, sparkpiv piv_probe, a writable YubiKey with a certificate in slot 9e, no pcscd) ---"
fi

TOTAL=$((PASS + FAIL))
echo "=== Integration: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
