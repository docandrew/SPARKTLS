#!/bin/bash
# Run x509-limbo certificate validation tests against SPARKTLS.
#
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
GEN_DIR="$DIR/generated"
VALIDATOR="$REPO_ROOT/bin/tests/x509_validate"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

if [ ! -d "$GEN_DIR" ] || [ ! -f "$GEN_DIR/manifest.txt" ]; then
    echo "x509-limbo test cases not found; downloading/generating them now..."
    bash "$DIR/generate.sh"
fi

if [ ! -f "$VALIDATOR" ]; then
    echo "Validator not found; building it now..."
    cd "$REPO_ROOT"
    alr -n --no-tty exec -- gprbuild -q -P tests/x509/x509_validate.gpr
fi

echo "=== x509-limbo Certificate Validation Tests ==="
cat "$GEN_DIR/manifest.txt"
echo ""

PASS=0
FAIL=0
ERRORS=0
FIRST_FAILURES=""

for tc_dir in "$GEN_DIR"/*/; do
    [ -f "$tc_dir/expect.txt" ] || continue

    expected=$(cat "$tc_dir/expect.txt" | tr -d '\n')
    hostname=$(grep "^hostname=" "$tc_dir/meta.txt" | cut -d= -f2)
    vtime=$(grep "^time=" "$tc_dir/meta.txt" | cut -d= -f2)
    mode=$(grep "^mode=" "$tc_dir/meta.txt" 2>/dev/null | cut -d= -f2)
    tc_name=$(basename "$tc_dir")

    # Build command
    cmd=("$VALIDATOR" "$tc_dir/peer.pem" "$tc_dir/trust.pem")
    [ -f "$tc_dir/intermediates.pem" ] && cmd+=("$tc_dir/intermediates.pem")
    [ -n "$hostname" ] && cmd+=(--hostname "$hostname")
    [ -n "$vtime" ] && cmd+=(--time "$vtime")
    [ "$mode" = "rfc5280" ] && cmd+=(--mode rfc5280)

    # Run
    if timeout 10 "${cmd[@]}" > /dev/null 2>&1; then
        actual="SUCCESS"
    else
        rc=$?
        if [ $rc -eq 1 ]; then
            actual="FAILURE"
        else
            actual="ERROR"
            ERRORS=$((ERRORS + 1))
            continue
        fi
    fi

    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        if [ $FAIL -le 20 ]; then
            FIRST_FAILURES="$FIRST_FAILURES  FAIL: $tc_name expected=$expected got=$actual\n"
        fi
    fi

    # Progress
    TOTAL=$((PASS + FAIL))
    if [ $((TOTAL % 500)) -eq 0 ]; then
        echo "  ... $TOTAL tests (pass=$PASS fail=$FAIL errors=$ERRORS)"
    fi
done

TOTAL=$((PASS + FAIL))
echo ""
if [ -n "$FIRST_FAILURES" ]; then
    echo "First failures:"
    echo -e "$FIRST_FAILURES"
fi
echo "=== x509-limbo: $PASS/$TOTAL passed, $FAIL failed, $ERRORS errors ==="
[ $FAIL -eq 0 ] && [ $ERRORS -eq 0 ] && exit 0 || exit 1
