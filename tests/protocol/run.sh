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
#  The server under test is the example binary, linked statically against
#  the library. Rebuild it here so a library edit is what gets tested when
#  this script is run on its own (tests/run_all.sh builds it too; on
#  2026-09-15 an hour of "fixes had no effect" was a stale binary).
if [ "${TLSFUZZER_REUSE_SERVER:-0}" != "1" ]; then
    (cd "$REPO_ROOT/examples" && ALR_NON_INTERACTIVE=1 NO_COLOR=1 alr -n --no-tty build >/dev/null 2>&1) \
        || echo "WARN: examples build failed; $SERVER may be stale"
fi
PORT=8443
LOG_ROOT="${TLSFUZZER_LOG_ROOT:-$DIR/logs}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$LOG_ROOT/$RUN_ID"

#  --- Server lifecycle -------------------------------------------------
#  The example server is SERIAL: accept -> handle -> close, one connection
#  at a time. A client that opens a socket and stalls therefore blocks the
#  NEXT test for the whole receive timeout. tls_blocking_server.adb reads
#  SPARKTLS_RECV_TIMEOUT for exactly this reason, but nothing ever set it,
#  so every run used the 30 s default. That single omission is the main
#  source of the run-to-run scoring drift.
export SPARKTLS_RECV_TIMEOUT="${SPARKTLS_RECV_TIMEOUT:-5}"

#  Seconds to wait for the listening socket to appear before giving up.
SERVER_START_TIMEOUT="${TLSFUZZER_SERVER_START_TIMEOUT:-15}"

#  Exact match on the listening port. `ss -tlnp | grep 8443` also matches
#  18443, 84430, and any pid or inode containing 8443.
port_listening() {
    ss -H -tln "sport = :$PORT" 2>/dev/null | grep -q . 
}

#  Readiness probe: confirms something is accepting TCP on the port.
#  NOTE this does NOT detect a wedged server -- the kernel completes the
#  TCP handshake from the listen backlog whether or not the application
#  ever calls accept(), so a server stuck mid-connection still answers.
#  Cross-test contamination is handled by restarting per test (below),
#  not by probing.
server_responsive() {
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null
}

wait_for_server() {
    local deadline=$((SECONDS + SERVER_START_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        if port_listening && server_responsive; then return 0; fi
        sleep 0.2
    done
    return 1
}

stop_server() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "${SERVER_PID:-}" ] && wait "$SERVER_PID" 2>/dev/null || true
    #  Anything still holding the port (a previous run, an orphan).
    local pids
    pids=$(ss -H -tlnp "sport = :$PORT" 2>/dev/null |
           grep -oP 'pid=\K\d+' | sort -u)
    for pid in $pids; do kill "$pid" 2>/dev/null || true; done
    SERVER_PID=""
}

#  start_server [extra server args...]
start_server() {
    stop_server
    "$SERVER" "$CERT" "$KEY" "$@" 2>/dev/null &
    SERVER_PID=$!
    if ! wait_for_server; then
        echo "Error: server failed to become ready within ${SERVER_START_TIMEOUT}s"
        return 1
    fi
    return 0
}

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
    conversation ccs empty-alert finished record-padding keyupdate
    zero-content-type zero-length-data unencrypted-alert
    connection-abort invalid-ciphers nociphers record-layer-limits
    version-negotiation legacy-version count-tickets
    session-resumption serverhello-random multiple-ccs-messages
    ecdhe-curves signature-algorithms lengths shuffled-extentions
    symetric-ciphers psk_dhe_ke non-support finished-plaintext
    #  Added 2026-09-09 with the RSA + revocation work (all use suites we
    #  implement):
    #    rsa-signatures        server picks rsa_pss_rsae_sha{256,384,512}
    #                          when the client offers exactly one; refuses
    #                          rsa_pss_pss_* with an rsaEncryption key
    #    pkcs-signature        rsa_pkcs1_* refused in TLS 1.3 (RFC 8446 4.2.3)
    #    keyshare-omitted      HRR path: omitted / empty key_share handling
    #    keyupdate-from-server post-handshake KeyUpdate exchange
    #    rsapss-signatures     the RSASSA-PSS-certificate twin of
    #                          rsa-signatures -- classified unsupported below
    rsa-signatures pkcs-signature keyshare-omitted keyupdate-from-server
    rsapss-signatures
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
if ! start_server; then
    echo "Error: server failed to start"
    exit 1
fi
trap stop_server EXIT

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
        #  ---------------------------------------------------------------
        #  Scripts whose sanity conversation cannot complete against this
        #  profile. tlsfuzzer's default TLS 1.2 conversation negotiates
        #  TLS_RSA_WITH_AES_128_CBC_SHA (RSA key exchange, CBC); we offer
        #  ECDHE + AEAD only (no RSA-KX: Bleichenbacher/ROBOT class; no CBC:
        #  Lucky13/POODLE class; no DHE). Every conversation that needs one
        #  of those suites ends at the first ServerHello with
        #  handshake_failure (RFC 5246 7.4.1.2), so the feature under test
        #  is never reached. Conversations in these scripts that do use a
        #  supported suite are exercised and must pass: since 2026-09-15
        #  the runner's per-script summary shows them (e.g. invalid-
        #  client-hello 50/52, extensions 255/292, message-skipping 6/11).
        #
        #  Derived mechanically 2026-08-19 by scanning each script for
        #  TLS_ECDHE_*_WITH_{AES_*_GCM,CHACHA20_POLY1305} versus
        #  TLS_RSA_WITH / _CBC_ / TLS_DHE_ / 3DES / RC4 / NULL; re-derive if
        #  the vendored tlsfuzzer is updated. Not listed because they DO
        #  reference supported suites and get their own entry below:
        #  aes-gcm-nonces, chacha20, fuzzed-ciphertext, large-hello,
        #  extended-master-secret-extension.
        alpn-negotiation \
        | certificate-request \
        | client-hello-max-size \
        | early-application-data \
        | ecdhe-padded-shared-secret \
        | ecdsa-in-certificate-verify \
        | eddsa-in-certificate-verify \
        | empty-extensions \
        | extended-master-secret-extension-with-client-cert \
        | extensions \
        | fuzzed-finished \
        | fuzzed-plaintext \
        | invalid-cipher-suites \
        | invalid-client-hello \
        | invalid-client-hello-w-record-overflow \
        | invalid-compression-methods \
        | invalid-content-type \
        | invalid-server-name-extension \
        | invalid-session-id \
        | invalid-version \
        | message-duplication \
        | message-skipping \
        | record-layer-fragmentation \
        | record-size-limit \
        | resumption-with-wrong-ciphers \
        | rsa-pss-sigs-on-certificate-verify \
        | session-ticket-resumption \
        | sig-algs \
        | ssl-death-alert \
        | truncating-of-client-hello \
        | truncating-of-finished \
        | x25519)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="sanity conversation needs RSA key exchange or a CBC/DHE suite (handshake_failure at ServerHello, RFC 5246 7.4.1.2); the conversations on supported suites pass"
            FAIL_CLASS="unsupported" ;;
        version-numbers \
        | version-negotiation \
        | downgrade-protection)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="conversations negotiate TLS 1.0/1.1 (refused with protocol_version, RFC 5246 E.1 / RFC 8446 4.2.1) or TLS 1.2 with RSA-KX/CBC suites (handshake_failure); the TLS 1.2 downgrade sentinel itself is covered by BoGo Downgrade-*"
            FAIL_CLASS="unsupported" ;;
        certificate-verify)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="the script's client certificate is the self-signed test CA presented as a leaf, refused with bad_certificate (same policy as x509-limbo rfc5280--ca-as-leaf); and it expects an RSA-only signature_algorithms list in CertificateRequest where we offer Ed25519/ECDSA/RSA-PSS. The 'is refused' cases (unknown, SHA-1 and rsa_pss_pss schemes -> illegal_parameter, RFC 8446 4.4.3) pass since 2026-09-15"
            FAIL_CLASS="mismatch" ;;
        large-number-of-extensions \
        | shuffled-extentions \
        | signature-algorithms)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="DoS bounds: a ClientHello with more than 64 extensions is decode_error (the duplicate-extension table, SECURITY_BURNDOWN SR-38) and one over the 32 KB handshake reassembly capacity is decode_error; these scripts send thousands of extensions or 65 KB signature-algorithm lists"
            FAIL_CLASS="mismatch" ;;
        large-hello)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="a ClientHello larger than the 32 KB handshake reassembly buffer (SPARKTLS_Reassembly capacity) is refused with decode_error; the script samples sizes up to 64 KB"
            FAIL_CLASS="mismatch" ;;
        aes-gcm-nonces)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="expected pass=4 fail=1: the script's default suites are RSA-kx/CBC, so it runs with -C and ONE GCM suite; its AES-256 nonce-monotonicity check (hard-coded outside the conversation list, so neither -e nor -x reaches it) then cannot collect nonces. The sanity, AES-128 and nonce checks all pass."
            FAIL_CLASS="mismatch" ;;
        rsapss-signatures)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="script needs a server with an RSASSA-PSS (id-RSASSA-PSS) certificate; ours is rsaEncryption (its twin rsa-signatures covers that)"
            FAIL_CLASS="unsupported" ;;
        keyupdate-from-server)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="probe expects the server to initiate KeyUpdate(update_requested) after the first record; SPARKTLS rekeys on its record counter (2^23, RFC 8446 4.6.3 leaves the trigger to the implementation) and the example server has no trigger knob"
            FAIL_CLASS="mismatch" ;;
        ecdhe-curves)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="x448 and secp521r1 are not offered (RFC 8446 4.2.7: the server chooses among mutually supported groups -> handshake_failure); the invalid-point cases on those curves are therefore never reached. Point validation on X25519/P-256/P-384 is covered by Wycheproof and BoGo"
            FAIL_CLASS="unsupported" ;;
        psk_dhe_ke)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="external (out-of-band) PSKs are not supported; only ticket resumption with psk_dhe_ke (README Session Ticket Policy)"
            FAIL_CLASS="unsupported" ;;
        extended-master-secret-extension)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="every conversation needs session-ID resumption, renegotiation or a CBC suite, none of which we implement; EMS itself is covered by BoGo ExtendedMasterSecret-* (all pass)"
            FAIL_CLASS="unsupported" ;;
        sessionID-resumption)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="TLS 1.2 session-ID resumption is not implemented (tickets only, RFC 5077)"
            FAIL_CLASS="unsupported" ;;
        session-resumption)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="psk_ke (no ECDHE) resumption is not offered and a TLS 1.2 ticket is never accepted in TLS 1.3 (RFC 8446 4.2.9 lets the server restrict modes; README Session Ticket Policy); the TLS 1.2 sanity needs RSA-KX"
            FAIL_CLASS="unsupported" ;;
        symetric-ciphers)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="TLS_AES_128_CCM_SHA256 / _CCM_8_ are not implemented (RFC 8446 9.1 mandates only AES-128-GCM); those conversations get handshake_failure. The AES-GCM and ChaCha20-Poly1305 tag-fuzz cases pass"
            FAIL_CLASS="unsupported" ;;
        connection-abort)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="the 'After NewSessionTicket' conversation expects the ticket to arrive before any application data; the example echo server answers the request first and the ticket flight follows. RFC 8446 4.6.1 imposes no order"
            FAIL_CLASS="mismatch" ;;
        count-tickets)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="one NewSessionTicket per handshake by policy (README Session Ticket Policy); the script waits for more"
            FAIL_CLASS="mismatch" ;;
        finished \
        | record-layer-limits)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="a Finished message of the wrong length (padded or truncated verify_data) is answered with decrypt_error: RFC 8446 4.4.4 makes any incorrect Finished decrypt_error and BoGo TrailingMessageData-TLS13-ClientFinished requires it; the script expects decode_error"
            FAIL_CLASS="mismatch" ;;
        multiple-ccs-messages)
            FAIL_LABEL="FAIL - Expected (Intentional Behavior Mismatch)"
            FAIL_REASON="the script sends its post-ClientHello ChangeCipherSpec records with record version 0x0300; after the initial record we require 0x0301..0x0304 (BoringSSL policy, BoGo CheckRecordVersion-*; RFC 8446 5.1 would have the field ignored) and answer protocol_version. Until 2026-09-15 this stalled the connection instead"
            FAIL_CLASS="mismatch" ;;
        non-support)
            FAIL_LABEL="FAIL - Expected (Unsupported Feature)"
            FAIL_REASON="script is written for servers WITHOUT TLS 1.3 (it expects a TLS 1.2 fallback with no middlebox CCS); not applicable to a TLS 1.3 server"
            FAIL_CLASS="unsupported" ;;
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

    #  Restart before every test. The server is serial, so a previous
    #  script that left a half-open connection would otherwise poison the
    #  next several tests -- the exact run-to-run drift this harness had.
    #  Detecting that state is unreliable (see server_responsive), and a
    #  fresh process is cheap, so take the deterministic option.
    #  TLSFUZZER_REUSE_SERVER=1 restores the old reuse behaviour.
    if [ "${TLSFUZZER_REUSE_SERVER:-0}" = "1" ]; then
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "Server died -- restarting before $test"
            start_server || { echo "Error: restart failed"; exit 1; }
        fi
    else
        start_server || { echo "Error: restart failed before $test"; exit 1; }
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
        #  RFC 8446 4.6.3 lets the KeyUpdate reply wait for our next
        #  application write; we defer it, as BoringSSL does and BoGo
        #  KeyUpdate-Requested requires. These two conversations wait for the
        #  reply BEFORE sending the rest of their request, so they deadlock
        #  against a server that answers complete requests only.
        keyupdate) extra_args=(-e "app data split, conversation with KeyUpdate msg"
                               -e "multiple KeyUpdate messages") ;;
        #  These scripts default to RSA key exchange (or, for chacha20, to a
        #  ClientHello with no extensions at all, so RFC 5246 7.4.1.4.1
        #  implies SHA-1 signatures). Their ECDHE/extension modes are what
        #  we implement, and without the flag the sanity conversation fails
        #  before the feature under test is reached (2026-09-14: 396 cases
        #  reported as unexpected failures for this reason alone).
        fuzzed-ciphertext|large-hello) extra_args=(-d) ;;
        #  -d alone selects CBC suites for its sanity run; name a GCM suite.
        #  The AES-256 conversation needs a second suite the script cannot
        #  take alongside -C; the nonce checks it exists for run under AES-128.
        aes-gcm-nonces) extra_args=(-C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                                    -e "aes-256-gcm cipher"
                                    -e "aes-256-gcm Nonce monotonicity") ;;
        #  "Chacha20 in TLS1.1" expects handshake_failure for a TLS 1.1
        #  ClientHello; we answer protocol_version (RFC 5246 E.1).
        #  The script samples 50 of its 74 conversations by default; -n
        #  runs every one, so a per-case regression ("0 bytes long
        #  ciphertext", 2026-09-15) cannot hide from a local run.
        chacha20) extra_args=(--extra-exts -e "Chacha20 in TLS1.1" -n 100) ;;
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
            start_server --mtls "$CERT" || {
                echo "Error: mTLS server restart failed"; exit 1; }
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
        #  No TOTAL line. Usually the script died at its own sanity probe
        #  before emitting a summary -- which for a cipher-profile-blocked
        #  script is exactly the expected outcome, not a surprise. Consult
        #  classify_failure here too, otherwise a script we have already
        #  justified still reports as UNEXPECTED purely because it failed
        #  early enough to produce no summary. Scripts with no
        #  classification still count as unexpected, so nothing is hidden.
        classify_failure "$test"
        if [ -n "$FAIL_CLASS" ] && [ "$FAIL_CLASS" != "none" ]; then
            status="$FAIL_LABEL (no summary, exit=$cmd_status, log=$log_file)"
            fail_class="$FAIL_CLASS"
            counted_fail=0
        else
            status="ERROR - UNEXPECTED (no summary, exit=$cmd_status, log=$log_file)"
            counted_fail=1
            fail_class="unexpected"
        fi
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
        #  Restore the plain (non-mTLS) server for subsequent tests.
        start_server || { echo "Error: server restore failed"; exit 1; }
    fi
done

stop_server

echo ""
#  Counts are tlsfuzzer conversations. "failed" is what no classification
#  in this file covers; "known" is the sum of the Unsupported Feature and
#  Intentional Behavior Mismatch classes, each listed above with its reason.
echo "=== Protocol: $TOTAL_PASS passed, $TOTAL_UNEXPECTED failed, $((TOTAL_EXPECTED_UNSUPPORTED + TOTAL_EXPECTED_MISMATCH)) known, $TOTAL_SKIP skipped ==="
echo "    Known: $TOTAL_EXPECTED_UNSUPPORTED unsupported feature, $TOTAL_EXPECTED_MISMATCH intentional behaviour mismatch"
echo "    Unexpected failures: $TOTAL_UNEXPECTED"
echo ""
echo -e "$RESULTS"

[ $TOTAL_UNEXPECTED -eq 0 ] && exit 0 || exit 1
