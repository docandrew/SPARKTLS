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
PORT="${TLSANVIL_PORT:-8443}"
export SPARKTLS_PORT="$PORT"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
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

# Always rebuild the library + example binary so the run reflects
# the current source. Easy to forget and chase a stale binary.
echo "Rebuilding sparktls + examples..."
(cd "$REPO_ROOT" && alr -n --no-tty build 2>&1 | tail -2)
(cd "$REPO_ROOT/examples" && alr -n --no-tty build 2>&1 | tail -2)

cleanup() {
    for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K\d+'); do
        kill "$pid" 2>/dev/null || true
    done
    sleep 0.5
}

cleanup
mkdir -p "$OUTPUT_DIR"
#  The container writes as root, so a reused directory may not be
#  cleanable; -ignoreCache above keeps a stale scan report from being
#  reused either way (2026-09-14: an empty cached report disabled every test).
rm -rf "$OUTPUT_DIR"/* 2>/dev/null || echo "  (note: stale files in $OUTPUT_DIR could not be removed)"

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
    -outputFolder /output -strength 1 -ignoreCache \
    server -connect "127.0.0.1:$PORT" >"$OUTPUT_DIR/run.log" 2>&1
RC=$?

cleanup

#  Summarise, diff against EXPECTED_FAILURES.txt and set the exit code.
#  A run in which every test is DISABLED (the feature scan found nothing,
#  as on 2026-09-14 when the cipher-suite cap hid every suite from
#  TLS-Scanner) is a failed run, not a clean one.
python3 "$DIR/summarize.py" "$OUTPUT_DIR" --expected "$DIR/EXPECTED_FAILURES.txt" \
    $([ "${1:-}" = "--update-baseline" ] && echo --update-baseline)
exit $?

