#!/bin/bash
# Download x509-limbo and generate test case directories.
# Each test case becomes a directory with PEM files and metadata.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
LIMBO_DIR="$DIR/x509-limbo"
OUT_DIR="$DIR/generated"

# Pinned corpus revision. x509-limbo adds cases continuously, and an unpinned
# clone made CI run cases the baseline had never seen (2026-09-15: seven new
# ones between the May and September corpora). Bump deliberately: run
# tests/x509/run.sh against the new revision, triage every new failure into
# EXPECTED_FAILURES.txt or fix it, and commit both together.
LIMBO_URL="https://github.com/C2SP/x509-limbo.git"
LIMBO_REF="${LIMBO_REF:-118721335e675edde10015df89b138cf292d7554}"   # main 2026-09-14

if [ ! -f "$LIMBO_DIR/limbo.json" ]; then
    echo "Downloading x509-limbo test vectors @ ${LIMBO_REF:0:12}..."
    mkdir -p "$LIMBO_DIR"
    git -C "$LIMBO_DIR" init --quiet
    git -C "$LIMBO_DIR" fetch --quiet --depth 1 "$LIMBO_URL" "$LIMBO_REF"
    git -C "$LIMBO_DIR" checkout --quiet FETCH_HEAD
elif [ "$(git -C "$LIMBO_DIR" rev-parse HEAD 2>/dev/null)" != "$LIMBO_REF" ]; then
    echo "WARN: $LIMBO_DIR is at $(git -C "$LIMBO_DIR" rev-parse --short HEAD 2>/dev/null)," \
         "pin is ${LIMBO_REF:0:12}; delete tests/x509/x509-limbo and tests/x509/generated to refresh"
fi

# Generate test directories
echo "Generating test cases..."
python3 "$DIR/generate_cases.py" "$LIMBO_DIR/limbo.json" "$OUT_DIR"
