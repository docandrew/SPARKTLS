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
LOG_ROOT="${TLSFUZZER_LOG_ROOT:-$DIR/logs}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$LOG_ROOT/$RUN_ID"

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

# Setup Python venv (prefer uv, fall back to python3 -m venv)
if [ ! -d "$VENV_DIR" ]; then
    echo "Setting up Python venv..."
    if command -v uv > /dev/null 2>&1; then
        uv venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        uv pip install git+https://github.com/tlsfuzzer/tlslite-ng.git
    else
        python3 -m venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        pip install -q git+https://github.com/tlsfuzzer/tlslite-ng.git
    fi
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
    #  ---------------- TLS 1.2 CORPUS (added 2026-08-18) ----------------
    #  These resolve via the unprefixed fallback above. They were never
    #  runnable before: run.sh only ever built "test-tls13-<name>.py",
    #  which was correct while the project was TLS 1.3 only and silently
    #  became a coverage hole the moment TLS 1.2 shipped. 111 of
    #  tlsfuzzer's 171 scripts were unreachable BY NAME as a result.
    #
    #  Selected for what we actually implement: TLS 1.2 with ECDHE
    #  (X25519 / P-256 / P-384) and AEAD only (AES-GCM, ChaCha20-Poly1305).
    #  Deliberately NOT listed: CBC/Lucky13, RSA key exchange/Bleichenbacher,
    #  3DES/RC4/export, SSLv2/v3, DHE/FFDHE, heartbeat, encrypt-then-mac and
    #  the renegotiation family -- all features we do not support, so they
    #  would only generate noise to re-classify. Add them if that changes.

    #  Core protocol + record layer
    conversation ccs lengths extensions empty-extensions
    version-numbers invalid-version downgrade-protection
    record-layer-fragmentation invalid-content-type zero-length-data
    serverhello-random invalid-session-id
    invalid-client-hello invalid-client-hello-w-record-overflow
    invalid-cipher-suites invalid-compression-methods
    large-hello large-number-of-extensions client-hello-max-size

    #  Robustness / adversarial -- should hold regardless of feature set
    message-duplication message-skipping
    truncating-of-client-hello truncating-of-finished
    fuzzed-ciphertext fuzzed-finished fuzzed-plaintext
    ssl-death-alert early-application-data connection-abort

    #  AEAD + key exchange we implement
    aes-gcm-nonces chacha20 x25519 ecdhe-padded-shared-secret

    #  Signatures / certificates
    sig-algs signature-algorithms certificate-request certificate-verify
    ecdsa-in-certificate-verify eddsa-in-certificate-verify
    rsa-pss-sigs-on-certificate-verify

    #  Extensions + resumption
    alpn-negotiation invalid-server-name-extension
    sessionID-resumption session-ticket-resumption
    resumption-with-wrong-ciphers

    #  KNOWN GAPS -- expected to fail, listed so they stay measurable:
    #    record-size-limit  RFC 8449 is parsed but not honoured (see #54)
    #    extended-master-*  RFC 7627 Finished path incomplete (see #63)
    record-size-limit
    extended-master-secret-extension
    extended-master-secret-extension-with-client-cert
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
echo "Logs: $LOG_DIR"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_EXPECTED_UNSUPPORTED=0
TOTAL_EXPECTED_MISMATCH=0
TOTAL_UNEXPECTED=0
RESULTS=""
mkdir -p "$LOG_DIR"

failed_probe_summary() {
    local log_file="$1"
    awk '
        /^FAILED:/ { in_failed = 1; next }
        in_failed && /^\t/ {
            name = $0
            sub(/^\t/, "", name)
            gsub(/\047/, "", name)
            print name
            next
        }
        in_failed && !/^\t/ { in_failed = 0 }
    ' "$log_file" | sort | uniq -c | awk '
        NR <= 8 {
            count = $1
            sub(/^ *[0-9]+ /, "")
            printf "      %sx %s\n", count, $0
        }
        END {
            if (NR > 8) {
                printf "      ... %d more unique failed probes\n", NR - 8
            }
        }'
}

classify_failure() {
    local test="$1"

    FAIL_LABEL="FAIL - UNEXPECTED"
    FAIL_REASON="unclassified tlsfuzzer failure; inspect log"
    FAIL_CLASS="unexpected"

    case "$test" in
        ecdhe-curves)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="unsupported groups and malformed curve points are intentionally rejected"
            FAIL_CLASS="unsupported" ;;
        psk_dhe_ke)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="tlsfuzzer external-PSK modes are outside the supported ticket-resumption path"
            FAIL_CLASS="unsupported" ;;
        session-resumption)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="tlsfuzzer resumption edge cases exceed the current ticket-resumption profile"
            FAIL_CLASS="unsupported" ;;
        symetric-ciphers)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="CCM and NULL cipher suites are intentionally unsupported"
            FAIL_CLASS="unsupported" ;;
        version-negotiation)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="TLS 1.0/1.1 and TLS 1.3 draft fallback paths are intentionally unsupported"
            FAIL_CLASS="unsupported" ;;

        connection-abort)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="close behavior after NewSessionTicket differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        count-tickets)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="ticket-count behavior differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        empty-alert)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="empty encrypted alert and padding handling differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        finished)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="malformed Finished padding/truncation alert behavior differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        multiple-ccs-messages)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="middlebox-compat CCS tolerance is intentionally narrow"
            FAIL_CLASS="mismatch" ;;
        non-support)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="unsupported-feature alert codes differ from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        record-layer-limits)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="maximum-size padded Finished record handling differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
        signature-algorithms)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="pathologically large/duplicated signature-algorithm lists are bounded"
            FAIL_CLASS="mismatch" ;;
        zero-content-type)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="zero content-type handling differs from tlsfuzzer expectation"
            FAIL_CLASS="mismatch" ;;
    esac
}

for test in "${TESTS[@]}"; do
    #  Resolve the script name. Historically this only ever built
    #  "test-tls13-<name>.py", which made every NON-TLS-1.3 script in
    #  tlsfuzzer unreachable BY NAME -- 111 of the 171 shipped scripts,
    #  including the whole TLS 1.2 and generic-attack corpus, despite us
    #  shipping TLS 1.2. Fall back to the unprefixed "test-<name>.py" so
    #  1.2-era tests (extended-master-secret, etc.) can be listed too.
    script="$TLSFUZZER_DIR/scripts/test-tls13-${test}.py"
    if [ ! -f "$script" ]; then
        script="$TLSFUZZER_DIR/scripts/test-${test}.py"
    fi
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
    script_timeout="${TLSFUZZER_SCRIPT_TIMEOUT:-120}"
    need_restart=false
    FAIL_LABEL=""
    FAIL_REASON=""
    FAIL_CLASS=""
    case "$test" in
        count-tickets) extra_args=(-t 1) ;;
        finished)
            script_timeout="${TLSFUZZER_FINISHED_SCRIPT_TIMEOUT:-300}" ;;
        serverhello-random)
            extra_args=(-e "TLS 1.3 with secp521r1"
                        -e "TLS 1.3 with x448"
                        -e "TLS 1.3 with ffdhe2048"
                        -e "TLS 1.3 with ffdhe3072") ;;
        lengths)
            extra_args=(-n "${TLSFUZZER_LENGTHS_N:-100}"
                        -t "${TLSFUZZER_LENGTHS_TIMEOUT:-10}")
            script_timeout="${TLSFUZZER_LENGTHS_SCRIPT_TIMEOUT:-300}" ;;
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

    log_file="$LOG_DIR/$test.log"
    set +e
    PYTHONPATH="$TLSFUZZER_DIR" timeout "$script_timeout" python3 "$script" \
        -h localhost -p $PORT "${extra_args[@]}" >"$log_file" 2>&1
    cmd_status=$?
    set -e

    pass=$(awk '/^PASS: [0-9]+$/ { v=$2 } END { if (v == "") print 0; else print v }' "$log_file")
    fail=$(awk '/^FAIL: [0-9]+$/ { v=$2 } END { if (v == "") print 0; else print v }' "$log_file")
    total=$(awk '/^TOTAL: [0-9]+$/ { v=$2 } END { if (v == "") print 0; else print v }' "$log_file")
    display_total="$total"
    if [ $((pass + fail)) -gt "$display_total" ]; then
        display_total=$((pass + fail))
    fi

    counted_fail=0
    fail_class="none"
    if [ "$cmd_status" -eq 124 ]; then
        status="ERROR - UNEXPECTED (timeout=${script_timeout}s, log=$log_file)"
        counted_fail=1
        fail_class="unexpected"
    elif [ "$total" = "0" ]; then
        status="ERROR - UNEXPECTED (no summary, exit=$cmd_status, log=$log_file)"
        counted_fail=1
        fail_class="unexpected"
    elif [ "$fail" = "0" ] && [ "$pass" != "0" ] && [ "$cmd_status" -eq 0 ]; then
        status="PASS (pass=$pass fail=$fail total=$display_total exit=$cmd_status)"
    else
        classify_failure "$test"
        status="$FAIL_LABEL (pass=$pass fail=$fail total=$display_total exit=$cmd_status, log=$log_file)"
        fail_class="$FAIL_CLASS"
        if [ "$fail" = "0" ]; then
            counted_fail=1
        else
            counted_fail="$fail"
        fi
    fi

    echo "  $test: $status"
    if [ "$counted_fail" != "0" ] && [ -s "$log_file" ]; then
        if [ -n "${FAIL_REASON:-}" ] && [ "$fail_class" != "unexpected" ]; then
            echo "      reason: $FAIL_REASON"
        elif [ -n "${FAIL_REASON:-}" ] && [ "$fail_class" = "unexpected" ]; then
            echo "      reason: $FAIL_REASON"
        fi
        failed_summary="$(failed_probe_summary "$log_file")"
        if [ -n "$failed_summary" ]; then
            echo "$failed_summary"
        fi
    fi
    RESULTS="$RESULTS$test: $status\n"
    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + counted_fail))
    case "$fail_class" in
        unsupported)
            TOTAL_EXPECTED_UNSUPPORTED=$((TOTAL_EXPECTED_UNSUPPORTED + counted_fail)) ;;
        mismatch)
            TOTAL_EXPECTED_MISMATCH=$((TOTAL_EXPECTED_MISMATCH + counted_fail)) ;;
        unexpected)
            TOTAL_UNEXPECTED=$((TOTAL_UNEXPECTED + counted_fail)) ;;
    esac

    if $need_restart; then
        kill $SERVER_PID 2>/dev/null || true; sleep 1
        $SERVER "$CERT" "$KEY" 2>/dev/null &
        SERVER_PID=$!; sleep 2
    fi
done

kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Protocol: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL SKIP=$TOTAL_SKIP ==="
echo "    Expected Unsupported Feature failures: $TOTAL_EXPECTED_UNSUPPORTED"
echo "    Expected Intentional Behavior Mismatch failures: $TOTAL_EXPECTED_MISMATCH"
echo "    Unexpected failures: $TOTAL_UNEXPECTED"
echo ""
echo -e "$RESULTS"

[ $TOTAL_UNEXPECTED -eq 0 ] && exit 0 || exit 1
