#!/bin/bash
# SPARKTLS protocol compliance tests using tlsfuzzer.
# Wraps the existing run_tlsfuzzer.sh with proper paths.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
CERT_DIR="$DIR/../certs"
TLSFUZZER_DIR="$DIR/tlsfuzzer"
VENV_DIR="$DIR/.venv"
SERVER="$REPO_ROOT/bin/examples/tls_blocking_server"
PORT=8443

# Check prerequisites
if [ ! -f "$SERVER" ]; then
    echo "Error: $SERVER not found. Build first."
    exit 1
fi

# Setup tlsfuzzer
if [ ! -d "$TLSFUZZER_DIR" ]; then
    echo "Cloning tlsfuzzer..."
    git clone --depth 1 https://github.com/tlsfuzzer/tlsfuzzer.git "$TLSFUZZER_DIR"
fi

# Setup Python venv
if [ ! -d "$VENV_DIR" ]; then
    echo "Setting up Python venv..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install -q git+https://github.com/tlsfuzzer/tlslite-ng.git
else
    source "$VENV_DIR/bin/activate"
fi

# Generate RSA cert if needed
bash "$CERT_DIR/generate.sh"

CERT="$CERT_DIR/rsa.crt"
KEY="$CERT_DIR/rsa.key"

# All TLS 1.3 test scripts
ALL_TESTS=(
    conversation ccs empty-alert finished record-padding
    zero-content-type zero-length-data unencrypted-alert
    connection-abort invalid-ciphers nociphers record-layer-limits
    version-negotiation legacy-version count-tickets
    session-resumption serverhello-random multiple-ccs-messages
    ecdhe-curves signature-algorithms lengths shuffled-extentions
    symetric-ciphers psk_dhe_ke non-support finished-plaintext
)

# Use command-line args or all tests
if [ $# -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=("${ALL_TESTS[@]}")
fi

# Start server
kill $(ss -tlnp | grep $PORT | grep -oP 'pid=\K\d+') 2>/dev/null || true
sleep 1
$SERVER "$CERT" "$KEY" 2>/dev/null &
SERVER_PID=$!
sleep 2

if ! ss -tlnp | grep -q ":$PORT"; then
    echo "Error: server failed to start"
    exit 1
fi

echo "=== SPARKTLS Protocol Compliance (tlsfuzzer) ==="
echo "Date: $(date)"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
RESULTS=""

for test in "${TESTS[@]}"; do
    script="$TLSFUZZER_DIR/scripts/test-tls13-${test}.py"
    if [ ! -f "$script" ]; then
        RESULTS="$RESULTS$test: SKIP (script not found)\n"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        continue
    fi

    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "Server died! Restarting..."
        $SERVER "$CERT" "$KEY" 2>/dev/null &
        SERVER_PID=$!
        sleep 2
    fi

    # Per-test arguments
    declare -a extra_args=()
    need_restart=false
    case "$test" in
        count-tickets) extra_args=(-t 1) ;;
        certificate-verify)
            extra_args=(-c "$CERT" -k "$KEY")
            kill $SERVER_PID 2>/dev/null || true; sleep 1
            $SERVER "$CERT" "$KEY" --mtls "$CERT" 2>/dev/null &
            SERVER_PID=$!; sleep 2
            need_restart=true ;;
        zero-content-type)
            extra_args=(-e "zero content type during application data"
                        -e "zero content type and padding during application data") ;;
        zero-length-data)
            extra_args=(-e "zero-length app data"
                        -e "zero-length app data with padding"
                        -e "zero-length app data with large padding"
                        -e "zero-length app data interleaved in handshake"
                        -e "zero-len app data with padding interleaved in handshake"
                        -e "zero-len app data with large padding interleaved in handshake") ;;
    esac

    output=$(PYTHONPATH="$TLSFUZZER_DIR" timeout 120 python3 "$script" \
        -h localhost -p $PORT "${extra_args[@]}" 2>&1 || true)

    pass=$(echo "$output" | grep "^PASS:" | grep -oP '\d+' || echo 0)
    fail=$(echo "$output" | grep "^FAIL:" | grep -oP '\d+' || echo 0)
    total=$(echo "$output" | grep "^TOTAL:" | grep -oP '\d+' || echo 0)

    if [ "$fail" = "0" ] && [ "$pass" != "0" ]; then
        status="PASS ($pass/$total)"
    elif [ "$total" = "0" ]; then
        status="ERROR"
        fail=1
    else
        status="FAIL ($pass/$total)"
    fi

    echo "  $test: $status"
    RESULTS="$RESULTS$test: $status\n"
    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))

    if $need_restart; then
        kill $SERVER_PID 2>/dev/null || true; sleep 1
        $SERVER "$CERT" "$KEY" 2>/dev/null &
        SERVER_PID=$!; sleep 2
    fi
done

kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Protocol: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL SKIP=$TOTAL_SKIP ==="
echo ""
echo -e "$RESULTS"

[ $TOTAL_FAIL -eq 0 ] && exit 0 || exit 1
