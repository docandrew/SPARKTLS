#!/bin/bash
# SPARKTLS comprehensive test suite.
#
# Usage:
#   ./tests/run_all.sh                 # release build, the default lanes
#                                      # (unit integration protocol x509 bogo),
#                                      # then chains the --checked pass
#                                      # (NO_CHAIN=1 to run the release pass alone)
#   ./tests/run_all.sh unit            # one lane; any of:
#       unit         unit-test programs + Wycheproof/CAVP vectors (+ realworld
#                    CA-chain checks when the network is reachable)
#       cli          sparktls_cli: every subcommand and key algorithm, checked
#                    against OpenSSL and a real handshake (tests/cli)
#       integration  SPARKTLS <-> OpenSSL round trips (tests/integration)
#       protocol     tlsfuzzer scripts (tests/protocol)
#       x509         x509-limbo + NIST PKITS validators (tests/x509)
#       bogo         BoringSSL BoGo runner (tests/bogo; first run ~10 min setup)
#       fuzz         opt-in: replay fuzz seed corpora through checked parsers
#       tlsanvil     opt-in: TLS-Anvil via docker (~30 min; tests/tlsanvil)
#   ./tests/run_all.sh --checked       # debug build, runtime checks + contracts
#                                      # ON, runs unit + protocol + x509
#   ./tests/run_all.sh --checked unit  # combine to filter lanes
# Env: CHECKED_BUILD=1 has the same effect as --checked.
#
# Every lane ends with one summary line of the form
#   === <lane>: <passed>[/<total>] passed, <failed> failed[, <known> known][, <skipped> skipped] ===
# and a results table closes the run. "failed" is always the count that
# is NOT already in the lane's expected-failures baseline; "known" is
# what the baseline covers. A lane fails the run only on a regression.
# The last table is also written to tests/_results/last_run.txt.
#
# Mirrors SPARKNaCl's tests/Makefile pattern: a release-mode "fast"
# build for normal testing and a debug-mode "slow" build with checks
# and contracts on for catching runtime violations the proof missed.
#
# Prerequisites: OpenSSL, Python 3, git.
# Everything else is set up automatically on first run.
# Don't set -e: we want to run all suites even if some fail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/.."
cd "$REPO_ROOT"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

# --- Parse args ---
# --checked (or env CHECKED_BUILD=1) builds with runtime checks +
# assertions/contracts ON. Default release build has -gnatp (suppress
# checks) for speed; the checked build catches bounds / range / overflow
# / Pre / Post / pragma Assert violations at runtime against the same
# tests, exposing bugs that static proof might have missed.
#
# Mirrors SPARKNaCl's tests/Makefile {ftestall, stestall} pattern:
#   ftestall: -O3 + -gnatp + no -gnata    (release equivalent)
#   stestall: -O0 -g + runtime-checks-on + -gnata    (checked)
# Specifically pairs --checked with BUILD_MODE=debug. The combination
# -O3 -gnatn + -gnata is known to mis-inline contract-evaluating code
# (see memory/spark_inline_rebuild.md); SPARKNaCl avoids it by using
# debug mode for the checked variant.
#
# Integration tests are excluded from --checked because RFLX 0.26.0
# generated specs declare Dynamic_Predicates that dereference
# Buffer.all without a null guard. After Take_Buffer (legitimate use)
# the predicate fires under -gnata and raises Constraint_Error. This
# is upstream RFLX behavior on the pristine generated code, not a bug
# in our code, and is unrelated to the contracts we want to verify
# at runtime in --checked. Integration coverage stays in release mode.
CHECKED_BUILD="${CHECKED_BUILD:-0}"
SUITES_ARG=()
for a in "$@"; do
    case "$a" in
        --checked|--runtime-checks)
            CHECKED_BUILD=1 ;;
        *) SUITES_ARG+=("$a") ;;
    esac
done

if [ "$CHECKED_BUILD" = "1" ]; then
    # In --checked we run unit + x509 + protocol — what SPARKNaCl's
    # stestall covers. Integration is release-only (see comment above).
    SUITES="${SUITES_ARG[*]:-unit protocol x509}"
else
    SUITES="${SUITES_ARG[*]:-unit cli integration protocol x509 bogo}"
fi
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
if [ "$CHECKED_BUILD" = "1" ]; then
    section "Building SPARKTLS (CHECKED: runtime checks + contracts ON, debug mode)"
    export SPARKTLS_RUNTIME_CHECKS=enabled
    export SPARKTLS_CONTRACTS=enabled
    #  Mirror SPARKNaCl's stestall: debug build (-O0 -g) + checks +
    #  contracts. Avoids -O3 -gnatn + -gnata mis-inlining bugs.
    export SPARKTLS_BUILD_MODE=debug
    # Force a clean of obj dir so the checks-on switches are picked up
    # even when we just toggled from a cached release build.
    rm -rf obj/* lib/*.a lib/*.so 2>/dev/null
else
    section "Building SPARKTLS"
fi

#  NOTE: "cmd | tail -3" reports TAIL's status, not cmd's, and this script
#  deliberately runs without "set -e". Both FATAL checks below were therefore
#  UNREACHABLE -- a failed build scrolled past and the suite carried on against
#  whatever binaries happened to be in bin/. That is how the 2026-08-19 run
#  scored the protocol suite against an 08-18 tls_blocking_server. Capture the
#  status explicitly instead of relying on the pipeline.
build_or_die() {   #  $1 = stage name, $2 = optional crate dir
    local out rc
    out=$(cd "${2:-.}" && alr -n --no-tty build 2>&1); rc=$?
    printf '%s\n' "$out" | tail -3
    if [ $rc -ne 0 ]; then
        echo "FATAL: $1 build failed (exit $rc)"
        exit 1
    fi
}

build_or_die "Library" 
cd examples
if [ "$CHECKED_BUILD" = "1" ]; then
    rm -rf obj/* 2>/dev/null
fi
build_or_die "Examples"
cd "$REPO_ROOT"
#  The CLI is its own crate; CI ran the library and examples only until
#  2026-09-14 and never built or exercised it.
if [ -f cli/alire.toml ]; then
    build_or_die "CLI" cli
fi

# Build x509 validator if .gpr exists
if [ -f tests/x509/x509_validate.gpr ]; then
    eval $(alr -n --no-tty printenv --unix)
    cd tests/x509
    if ! gprbuild -q -P x509_validate.gpr 2>&1 | tail -3; then :; fi
    rc=${PIPESTATUS[0]}
    if [ "$rc" -ne 0 ]; then
        echo "FATAL: x509 validator build failed (exit $rc)"
        exit 1
    fi
    cd "$REPO_ROOT"
fi

# Build crypto unit tests. MUST go through build_or_die: on 2026-08-26 a
# failed unit build ("no selector PSK for HC_Box") scrolled past the old
# ungated "alr build | tail -3" and the suite scored 4187 passes against
# stale binaries. Release tests run -gnatp, so staleness never crashes --
# a hard build gate is the only tell.
if [ -f tests/unit/alire.toml ]; then
    build_or_die "Unit tests" tests/unit
fi

# --- Generate test certificates ---
section "Generating test certificates"
bash tests/certs/generate.sh

# ---------------------------------------------------------------------
# Results ledger. Every lane records one row; the table at the end and
# the exit status come from here and nowhere else.
# ---------------------------------------------------------------------
RESULT_ROWS=()
record() {   # lane passed failed known skipped status
    RESULT_ROWS+=("$1|$2|$3|$4|$5|$6")
}

#  Pull "<p>[/t] passed, <f> failed[, <k> known][, <s> skipped]" out of a
#  lane's own "=== Name: ... ===" summary line. Prints "p f k s".
summary_numbers() {   # $1 = lane label regex, stdin = lane output
    local line p f k s
    line=$(grep -E "^=== $1" | tail -1)
    p=$(grep -oE '[0-9]+(/ ?[0-9]+)? passed' <<<"$line" | grep -oE '^[0-9]+'); p=${p:-0}
    f=$(grep -oE '[0-9]+ failed' <<<"$line" | grep -oE '^[0-9]+'); f=${f:-0}
    k=$(grep -oE '[0-9]+ known' <<<"$line" | grep -oE '^[0-9]+'); k=${k:-0}
    s=$(grep -oE '[0-9]+ (skipped|disabled)' <<<"$line" | grep -oE '^[0-9]+'); s=${s:-0}
    echo "$p $f $k $s"
}

#  Run a lane script, echo its output as it goes, record its row from its
#  summary line and exit status.
run_lane() {   # lane label-regex command...
    local lane=$1 label=$2; shift 2
    local out rc p f k s status
    out=$("$@" 2>&1); rc=$?
    printf '%s\n' "$out"
    read -r p f k s <<<"$(printf '%s\n' "$out" | summary_numbers "$label")"
    if [ $rc -eq 0 ]; then status=PASS; else status=FAIL; fi
    #  A lane that produced no summary line at all did not run to the end.
    if ! printf '%s\n' "$out" | grep -qE "^=== $label"; then status=FAIL; fi
    record "$lane" "$p" "$f" "$k" "$s" "$status"
}

# ---------------------------------------------------------------------
# Unit lane: every test program the unit project builds, plus the
# vector suites. The program list comes from the project file so a test
# that is built but never run cannot happen again (12 programs, ~230
# checks, were in that state until 2026-09-14). Output shapes are
# normalised by tests/support/count_results.py.
# ---------------------------------------------------------------------
UNIT_PASS=0; UNIT_FAIL=0; UNIT_SKIP=0
run_unit() {   # label command...
    local label=$1; shift
    local out rc p f s
    if [ ! -x "$1" ]; then
        printf '  %-30s %s\n' "$label" "FAIL: not built ($1)"
        UNIT_FAIL=$((UNIT_FAIL + 1)); return
    fi
    out=$("$@" 2>&1); rc=$?
    read -r p f s <<<"$(printf '%s\n' "$out" | python3 tests/support/count_results.py --rc $rc)"
    printf '  %-30s %5d passed %3d failed' "$label" "$p" "$f"
    [ "$s" -gt 0 ] && printf ' %3d skipped' "$s"
    echo
    if [ "$f" -gt 0 ]; then
        printf '%s\n' "$out" | grep -E 'FAIL|Error|exception' | head -5 | sed 's/^/      /'
    fi
    UNIT_PASS=$((UNIT_PASS + p)); UNIT_FAIL=$((UNIT_FAIL + f)); UNIT_SKIP=$((UNIT_SKIP + s))
}

if echo "$SUITES" | grep -q "unit"; then
    section "Unit Tests"
    #  Fixture prerequisites (best effort; the tests skip or fail loudly).
    command -v curl >/dev/null && bash tests/cavp/fetch_sha.sh >/dev/null 2>&1 || true
    if [ -x ../sparkx509/tests/revocation/gen.sh ]; then
        bash ../sparkx509/tests/revocation/gen.sh >/dev/null 2>&1 ||
            echo "  WARN: revocation fixture regeneration failed; test_revocation may use stale fixtures"
    fi

    run_unit test_prf12 bin/examples/test_prf12
    mapfile -t UNIT_MAINS < <(grep -oE '"test_[a-z0-9_]+\.adb"' tests/unit/unit_tests.gpr | tr -d '"' | sed 's/\.adb$//')
    for t in "${UNIT_MAINS[@]}"; do
        case "$t" in
            test_ocsp_staple)
                run_unit "$t" bin/tests/$t tests/certs/p256.crt tests/certs/p256.key ;;
            test_external_sign)
                run_unit "$t" bin/tests/$t tests/certs/p256.crt tests/certs/p256.key tests/certs/rsa.crt tests/certs/rsa.key ;;
            test_rsa_crt)
                for kp in "tests/certs/rsa.crt tests/certs/rsa.key" \
                          "tests/certs/rsa2056.crt tests/certs/rsa2056.key" \
                          "tests/protocol/tlsfuzzer/tests/rsa4096.crt tests/protocol/tlsfuzzer/tests/rsa4096.key"; do
                    set -- $kp
                    [ -f "$1" ] && [ -f "$2" ] && run_unit "$t ($(basename "$2"))" bin/tests/$t "$1" "$2"
                done ;;
            *) run_unit "$t" bin/tests/$t ;;
        esac
    done
    for t in ecdsa_p256_test ecdhe_p384_test; do
        [ -x bin/tests/$t ] && run_unit "$t" bin/tests/$t
    done
    #  Binaries in bin/tests that no project builds any more are stale and
    #  say nothing about the current source.
    for b in bin/tests/test_*; do
        n=$(basename "$b")
        printf '%s\n' "${UNIT_MAINS[@]}" | grep -qx "$n" ||
            echo "  WARN: stale binary $b (not in tests/unit/unit_tests.gpr)"
    done
    echo ""
    echo "=== Unit: $UNIT_PASS passed, $UNIT_FAIL failed, $UNIT_SKIP skipped ==="
    record unit "$UNIT_PASS" "$UNIT_FAIL" 0 "$UNIT_SKIP" "$([ $UNIT_FAIL -eq 0 ] && echo PASS || echo FAIL)"

    section "Test Vectors (Wycheproof, NIST CAVP)"
    if [ -d tests/wycheproof/wycheproof/testvectors_v1 ] || command -v git >/dev/null; then
        run_lane wycheproof "Wycheproof" bash tests/wycheproof/run.sh
    else
        echo "  wycheproof: skipped (git unavailable)"; record wycheproof 0 0 0 0 SKIP
    fi
    if [ -f tests/cavp/ecdsa_SigVer.rsp ] || command -v curl >/dev/null; then
        run_lane cavp "CAVP" bash tests/cavp/run.sh
    else
        echo "  cavp: skipped (curl unavailable)"; record cavp 0 0 0 0 SKIP
    fi

    if [ -z "${CI:-}" ] && [ -f /etc/ssl/certs/ca-certificates.crt ] && getent hosts www.google.com >/dev/null 2>&1; then
        section "Real-world CA chains (network)"
        run_lane realworld "Real-world" bash tests/realworld/run.sh
    fi
fi

if echo "$SUITES" | grep -q "cli"; then
    section "sparktls_cli"
    run_lane cli "CLI" bash tests/cli/run.sh
fi

if echo "$SUITES" | grep -q "integration"; then
    section "Integration Tests (SPARKTLS <-> OpenSSL)"
    run_lane integration "Integration" bash tests/integration/run.sh
fi

if echo "$SUITES" | grep -q "protocol"; then
    section "Protocol Compliance Tests (tlsfuzzer)"
    run_lane protocol "Protocol" bash tests/protocol/run.sh
fi

if echo "$SUITES" | grep -q "fuzz"; then
    section "Fuzz regression (checked parsers over the seed corpora)"
    [ -d tests/fuzz/seeds ] || python3 tests/fuzz/make_seeds.py || true
    if bash tests/fuzz/run.sh build > /dev/null 2>&1; then
        run_lane fuzz "Fuzz" bash tests/fuzz/run.sh regress
    else
        echo "  fuzz: build failed"; record fuzz 0 1 0 0 FAIL
    fi
fi

if echo "$SUITES" | grep -q "x509"; then
    section "x509-limbo Certificate Validation Tests"
    run_lane x509-limbo "x509-limbo" bash tests/x509/run.sh
    PKITS_DIR="tests/bogo/_cache/boringssl/pki/testdata/nist-pkits"
    if [ -f "$PKITS_DIR/pkits_testcases-inl.h" ]; then
        section "NIST PKITS"
        run_lane pkits "PKITS" python3 tests/x509/pkits_runner.py "$PKITS_DIR" bin/tests/x509_validate \
            --expected tests/x509/PKITS_EXPECTED_FAILURES.txt
    else
        echo "  PKITS: skipped (BoGo cache not present; run the bogo lane once)"
        record pkits 0 0 0 0 SKIP
    fi
fi

if echo "$SUITES" | grep -q "bogo"; then
    section "BoGo Adversarial Tests"
    run_lane bogo "BoGo" bash tests/bogo/run.sh
fi

if echo "$SUITES" | grep -q "tlsanvil"; then
    section "TLS-Anvil (docker, ~30 min)"
    run_lane tlsanvil "TLS-Anvil" bash tests/tlsanvil/run.sh
fi

# ---------------------------------------------------------------------
# Results table
# ---------------------------------------------------------------------
#  The verdict is computed BEFORE the table is printed: the table goes
#  through tee, i.e. a subshell, and anything set inside it is lost.
OVERALL=PASS
for row in "${RESULT_ROWS[@]}"; do
    IFS='|' read -r lane p f k s st <<<"$row"
    [ "$st" = FAIL ] && OVERALL=FAIL
done
mkdir -p tests/_results 2>/dev/null
{
    echo ""
    echo "================================================================"
    echo "  RESULTS  ($(date -u +%Y-%m-%dT%H:%M:%SZ), $([ "$CHECKED_BUILD" = "1" ] && echo checked || echo release) build)"
    echo "================================================================"
    printf '  %-13s %7s %7s %7s %8s  %s\n' Lane Passed Failed Known Skipped Status
    for row in "${RESULT_ROWS[@]}"; do
        IFS='|' read -r lane p f k s st <<<"$row"
        printf '  %-13s %7s %7s %7s %8s  %s\n' "$lane" "$p" "$f" "$k" "$s" "$st"
    done
    echo ""
    echo "  OVERALL: $OVERALL"
    echo "================================================================"
} | tee tests/_results/last_run.txt

if [ "$CHECKED_BUILD" = "0" ] && [ ${#SUITES_ARG[@]} -eq 0 ] && [ "${NO_CHAIN:-0}" = "0" ]; then
    echo ""
    echo "================================================================"
    echo "  Release pass complete -- chaining --checked pass"
    echo "================================================================"
    if bash "$0" --checked; then CHECKED_FAIL=0; else CHECKED_FAIL=1; fi
    [ "$OVERALL" = PASS ] && [ $CHECKED_FAIL -eq 0 ] && exit 0 || exit 1
fi
[ "$OVERALL" = PASS ] && exit 0 || exit 1
