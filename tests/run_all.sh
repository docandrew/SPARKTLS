#!/bin/bash
# SPARKTLS comprehensive test suite.
#
# Usage:
#   ./tests/run_all.sh              # run everything
#   ./tests/run_all.sh integration  # run only integration tests
#   ./tests/run_all.sh protocol     # run only protocol compliance
#   ./tests/run_all.sh unit         # run only unit tests
#   ./tests/run_all.sh x509         # run only x509-limbo tests
#
# Prerequisites: OpenSSL, Python 3, git.
# Everything else is set up automatically on first run.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/.."
cd "$REPO_ROOT"

SUITES="${@:-unit integration protocol}"
OVERALL_PASS=0
OVERALL_FAIL=0

section() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo ""
}

# --- Build ---
section "Building SPARKTLS"
alr build 2>&1 | tail -3
cd examples && alr build 2>&1 | tail -3
cd "$REPO_ROOT"

# --- Generate test certificates ---
section "Generating test certificates"
bash tests/certs/generate.sh

# --- Run requested test suites ---

if echo "$SUITES" | grep -q "unit"; then
    section "Unit Tests"
    UNIT_PASS=0
    UNIT_FAIL=0

    # PRF-12 test
    if [ -f bin/examples/test_prf12 ]; then
        output=$(bin/examples/test_prf12 2>&1 || true)
        pass=$(echo "$output" | grep -c "PASS" || echo 0)
        fail=$(echo "$output" | grep -c "FAIL" || echo 0)
        echo "  test_prf12: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # ECDSA/ECDHE tests (if built)
    for test_bin in bin/tests/ecdsa_p256_test bin/tests/ecdhe_p384_test; do
        if [ -f "$test_bin" ]; then
            name=$(basename "$test_bin")
            output=$("$test_bin" 2>&1 || true)
            pass=$(echo "$output" | grep -c "PASS" || echo 0)
            fail=$(echo "$output" | grep -c "FAIL" || echo 0)
            echo "  $name: $pass passed, $fail failed"
            UNIT_PASS=$((UNIT_PASS + pass))
            UNIT_FAIL=$((UNIT_FAIL + fail))
        fi
    done

    echo ""
    echo "=== Unit: $UNIT_PASS passed, $UNIT_FAIL failed ==="
    OVERALL_PASS=$((OVERALL_PASS + UNIT_PASS))
    OVERALL_FAIL=$((OVERALL_FAIL + UNIT_FAIL))
fi

if echo "$SUITES" | grep -q "integration"; then
    section "Integration Tests"
    if bash tests/integration/run.sh; then
        OVERALL_PASS=$((OVERALL_PASS + 1))
    else
        OVERALL_FAIL=$((OVERALL_FAIL + 1))
    fi
fi

if echo "$SUITES" | grep -q "protocol"; then
    section "Protocol Compliance Tests"
    if bash tests/protocol/run.sh; then
        OVERALL_PASS=$((OVERALL_PASS + 1))
    else
        OVERALL_FAIL=$((OVERALL_FAIL + 1))
    fi
fi

if echo "$SUITES" | grep -q "x509"; then
    section "x509-limbo Certificate Validation Tests"
    if bash tests/x509/run.sh; then
        OVERALL_PASS=$((OVERALL_PASS + 1))
    else
        OVERALL_FAIL=$((OVERALL_FAIL + 1))
    fi
fi

# --- Summary ---
echo ""
echo "================================================================"
echo "  OVERALL: $OVERALL_PASS suites passed, $OVERALL_FAIL suites failed"
echo "================================================================"
[ $OVERALL_FAIL -eq 0 ] && exit 0 || exit 1
