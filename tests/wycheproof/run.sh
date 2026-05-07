#!/bin/bash
# Run Project Wycheproof crypto test vectors against SPARKTLS primitives.
#
# Setup: clones google/wycheproof on first run (~120 MB).
# Builds wycheproof_runner if missing.
# Iterates a curated set of JSON vector files and reports pass/fail.
set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
WP_DIR="$DIR/wycheproof"
RUNNER="$REPO_ROOT/bin/tests/wycheproof_runner"

if [ ! -d "$WP_DIR/testvectors_v1" ]; then
    echo "Cloning Wycheproof test vectors (sparse, ~30 MB)..."
    rm -rf "$WP_DIR"
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/google/wycheproof.git "$WP_DIR" 2>&1 | tail -3
    git -C "$WP_DIR" sparse-checkout set testvectors_v1 2>&1 | tail -3
fi

if [ ! -f "$RUNNER" ]; then
    echo "Building wycheproof_runner..."
    (cd "$DIR" && alr exec -- gprbuild -P wycheproof_runner.gpr 2>&1 | tail -3)
fi

if [ ! -f "$RUNNER" ]; then
    echo "FAIL: wycheproof_runner not built"
    exit 2
fi

python3 "$DIR/run_wycheproof.py" "$WP_DIR"
