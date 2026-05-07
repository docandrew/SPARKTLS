#!/bin/bash
# TLS-Anvil adversarial protocol test suite.
#
# Runs the TLS-Anvil docker image against a sparktls test server.
# TLS-Anvil generates RFC-compliance + adversarial test cases for
# both TLS 1.2 and TLS 1.3, far broader than tlsfuzzer's scripted
# set. Catches state-machine, alert-sequencing, and extension-
# handling edge cases.
#
# Skipped automatically if Docker isn't available.
set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
SERVER="$REPO_ROOT/bin/examples/tls_blocking_server"
PORT=8443
# Container writes output as root via volume mount, so we need a
# directory we can clean afterwards. Per-run unique dir avoids the
# need for sudo-rm of stale runs.
OUTPUT_DIR="${TLSANVIL_OUTPUT_DIR:-/tmp/tlsanvil_out_$$}"

if ! command -v docker >/dev/null 2>&1; then
    echo "=== TLS-Anvil ==="
    echo "  SKIP: docker not installed"
    exit 0
fi

# Detect how to invoke docker. Detached subshells from run_all.sh
# may not inherit the docker group even if the parent shell does,
# so we probe direct → sg → sudo and capture a wrapper string.
if docker info >/dev/null 2>&1; then
    DOCKER_PREFIX=""           # direct
elif getent group docker | grep -qw "$USER" \
     && sg docker -c "docker info" >/dev/null 2>&1; then
    DOCKER_PREFIX="sg docker -c "  # one-string wrap
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
    DOCKER_PREFIX="sudo "
else
    echo "=== TLS-Anvil ==="
    echo "  SKIP: docker not accessible (add \$USER to docker group)"
    exit 0
fi
docker_run() {
    if [ "$DOCKER_PREFIX" = "sg docker -c " ]; then
        sg docker -c "docker $*"
    else
        ${DOCKER_PREFIX}docker "$@"
    fi
}

if [ ! -f "$SERVER" ]; then
    echo "FAIL: tls_blocking_server not built"
    exit 2
fi

cleanup() {
    for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K\d+'); do
        kill "$pid" 2>/dev/null || true
    done
    sleep 0.5
}

cleanup
mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"/*

echo "=== TLS-Anvil adversarial protocol test ==="
echo "Pulling TLS-Anvil image (fast if cached)..."
docker_run pull ghcr.io/tls-attacker/tlsanvil:latest 2>&1 | tail -1

# Start sparktls server. Use ECDSA P-256 cert: TLS-Anvil's cert
# scanner crashes on Ed25519 server certs. RSA also works.
"$SERVER" "$REPO_ROOT/tests/certs/p256.crt" \
          "$REPO_ROOT/tests/certs/p256.key" 2>/dev/null &
sleep 2

if ! ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
    echo "FAIL: server didn't start on port $PORT"
    exit 2
fi

echo "Running TLS-Anvil (this takes ~30 min for full suite)..."
# strength=1: smaller t-wise covering arrays, ~10x faster than default
docker_run run --rm --network host -v "$OUTPUT_DIR:/output" \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -outputFolder /output -strength 1 \
    server -connect "127.0.0.1:$PORT" >"$OUTPUT_DIR/run.log" 2>&1
RC=$?

cleanup

# Summarize results from per-test JSON files.
if [ -d "$OUTPUT_DIR/results" ]; then
    python3 - <<EOF
import json, glob
counts = {}
fails = []
for f in glob.glob("$OUTPUT_DIR/results/*/_testRun.json"):
    try:
        with open(f) as fh: d = json.load(fh)
        r = d.get('Result', 'UNKNOWN')
        counts[r] = counts.get(r, 0) + 1
        if r == 'FULLY_FAILED':
            method = d.get('TestMethod', {})
            name = method.get('MethodName', '?') if isinstance(method, dict) else '?'
            fails.append((d.get('TestId'), name, d.get('FailedReason', '')[:100]))
    except Exception:
        pass
total = sum(counts.values())
print(f"=== TLS-Anvil: {total} test cases run ===")
for k in ('STRICTLY_SUCCEEDED', 'CONCEPTUALLY_SUCCEEDED', 'PARTIALLY_FAILED',
         'FULLY_FAILED', 'DISABLED', 'TEST_SUITE_ERROR'):
    if k in counts: print(f"  {k}: {counts[k]}")
if fails:
    print()
    print("FULLY_FAILED:")
    for tid, n, fr in fails[:20]:
        print(f"  [{tid}] {n}")
        if fr: print(f"    {fr}")
EOF
    # Treat any FULLY_FAILED as a regression failure.
    fail_count=$(find "$OUTPUT_DIR/results" -name '_testRun.json' \
        -exec grep -l '"Result": "FULLY_FAILED"' {} \; 2>/dev/null | wc -l)
    [ "$fail_count" -eq 0 ] && exit 0 || exit 1
else
    echo "=== TLS-Anvil: no output (rc=$RC) ==="
    exit $RC
fi
