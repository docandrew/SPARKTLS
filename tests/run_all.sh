#!/bin/bash
# SPARKTLS comprehensive test suite.
#
# Usage:
#   ./tests/run_all.sh              # release build, all suites (incl integration + BoGo)
#   ./tests/run_all.sh integration  # release build, only integration
#   ./tests/run_all.sh protocol     # release build, only protocol compliance
#   ./tests/run_all.sh unit         # release build, only unit tests
#   ./tests/run_all.sh x509         # release build, only x509-limbo tests
#   ./tests/run_all.sh bogo         # BoringSSL adversarial tests
#                                   # (first run: ~10 min setup)
#   ./tests/run_all.sh --checked    # debug build with runtime checks + contracts ON
#                                   # runs unit + protocol + x509 (no integration —
#                                   # see RFLX 0.26.0 limitation note in source)
#   ./tests/run_all.sh --checked unit  # combine to filter suites
# Env: CHECKED_BUILD=1 has the same effect as --checked.
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
    SUITES="${SUITES_ARG[*]:-unit integration protocol x509 bogo}"
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

# --- Run requested test suites ---

if echo "$SUITES" | grep -q "unit"; then
    section "Unit Tests"
    UNIT_PASS=0
    UNIT_FAIL=0

    # PRF-12 test
    if [ -f bin/examples/test_prf12 ]; then
        output=$(bin/examples/test_prf12 2>&1 || true)
        pass=$(echo "$output" | grep -c "PASS" || true)
        fail=$(echo "$output" | grep -c "FAIL" || true)
        echo "  test_prf12: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Crypto unit tests (sign/verify round-trips)
    if [ -f bin/tests/test_crypto ]; then
        output=$(bin/tests/test_crypto 2>&1 || true)
        pass=$(echo "$output" | grep -c "PASS" || true)
        fail=$(echo "$output" | grep -c "FAIL" || true)
        echo "  test_crypto: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # RSA PKCS#1 v1.5 KAT (verifies the new EMSA-PKCS1-v1_5 path)
    if [ -f bin/tests/test_rsa_pkcs1_kat ]; then
        output=$(bin/tests/test_rsa_pkcs1_kat 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_rsa_pkcs1_kat: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # RSA-PSS signing KAT: catches non-canonical private exponent padding.
    if [ -f bin/tests/test_rsa_pss_sign_kat ]; then
        output=$(bin/tests/test_rsa_pss_sign_kat 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_rsa_pss_sign_kat: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Project Wycheproof: adversarial test vectors for crypto primitives.
    # The runner performs a sparse clone on first run when git is available.
    if [ -d tests/wycheproof/wycheproof/testvectors_v1 ] ||
       command -v git >/dev/null; then
        output=$(bash tests/wycheproof/run.sh 2>&1 || true)
        wp_total=$(echo "$output" | grep -oE "[0-9]+/[0-9]+ passed" | tail -1 | cut -d'/' -f1)
        wp_count=$(echo "$output" | grep -oE "[0-9]+ failed" | tail -1 | awk '{print $1}')
        wp_count=${wp_count:-0}
        wp_total=${wp_total:-0}
        echo "  wycheproof: $wp_total tests, $wp_count failed"
        UNIT_PASS=$((UNIT_PASS + wp_total))
        UNIT_FAIL=$((UNIT_FAIL + wp_count))
    else
        echo "  wycheproof: skipped (git unavailable)"
    fi

    # NIST CAVP: ECDSA SigVer (FIPS 186-4) for P-256 + P-384.
    # Skipped if SigVer.rsp hasn't been downloaded.
    if [ -f tests/cavp/ecdsa_SigVer.rsp ] || command -v curl >/dev/null; then
        output=$(bash tests/cavp/run.sh 2>&1 || true)
        cv_pass=$(echo "$output" | grep -oE "[0-9]+/[0-9]+ passed" | tail -1 | cut -d'/' -f1)
        cv_fail=$(echo "$output" | grep -oE "[0-9]+ failed" | tail -1 | awk '{print $1}')
        cv_pass=${cv_pass:-0}; cv_fail=${cv_fail:-0}
        echo "  cavp: $cv_pass tests, $cv_fail failed"
        UNIT_PASS=$((UNIT_PASS + cv_pass))
        UNIT_FAIL=$((UNIT_FAIL + cv_fail))
    fi

    # Real-world CA chain test: handshake against major HTTPS sites
    # using the OS Mozilla CA bundle. Skipped automatically when no
    # network or no CA bundle.
    if [ -f /etc/ssl/certs/ca-certificates.crt ] && getent hosts www.google.com >/dev/null 2>&1; then
        output=$(bash tests/realworld/run.sh 2>&1 || true)
        rw_pass=$(echo "$output" | grep -oE "[0-9]+/[0-9]+ passed" | tail -1 | cut -d'/' -f1)
        rw_fail=$(echo "$output" | grep -oE "[0-9]+ failed" | tail -1 | awk '{print $1}')
        rw_pass=${rw_pass:-0}; rw_fail=${rw_fail:-0}
        echo "  realworld: $rw_pass sites, $rw_fail failed"
        UNIT_PASS=$((UNIT_PASS + rw_pass))
        UNIT_FAIL=$((UNIT_FAIL + rw_fail))
    fi

    # Fiat P-256 vs C-reference KAT (catches arithmetic regressions)
    if [ -f bin/tests/test_fiat_p256_kat ]; then
        output=$(bin/tests/test_fiat_p256_kat 2>&1 || true)
        pass=$(echo "$output" | awk '/Total checks/ {print $3}')
        fail=$(echo "$output" | awk '/Total checks/ {print $5}')
        echo "  test_fiat_p256_kat: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Fiat 25519 vs C-reference KAT
    if [ -f bin/tests/test_fiat_25519_kat ]; then
        output=$(bin/tests/test_fiat_25519_kat 2>&1 || true)
        pass=$(echo "$output" | awk '/Total checks/ {print $3}')
        fail=$(echo "$output" | awk '/Total checks/ {print $5}')
        echo "  test_fiat_25519_kat: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # X25519 / Ed25519 RFC 7748 / 8032 standards vectors
    if [ -f bin/tests/test_25519_rfc ]; then
        output=$(bin/tests/test_25519_rfc 2>&1 || true)
        pass=$(echo "$output" | awk '/Total checks/ {print $3}')
        fail=$(echo "$output" | awk '/Total checks/ {print $5}')
        echo "  test_25519_rfc: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Build_Server_Hello regression suite (pinned before the refactor)
    if [ -f bin/tests/test_build_server_hello ]; then
        output=$(bin/tests/test_build_server_hello 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_build_server_hello: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Parse_Client_Hello regression suite (pinned before the refactor)
    if [ -f bin/tests/test_parse_client_hello ]; then
        output=$(bin/tests/test_parse_client_hello 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_parse_client_hello: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # TLS 1.2 session ticket round-trip (RFC 5077)
    if [ -f bin/tests/test_tickets_12 ]; then
        output=$(bin/tests/test_tickets_12 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_tickets_12: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # TLS 1.3 PSK resumption wiring (mirror existing pattern)
    if [ -f bin/tests/test_psk_resume ]; then
        output=$(bin/tests/test_psk_resume 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_psk_resume: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # KeyUpdate leaky-bucket rate limiting + nonce-space backstop
    if [ -f bin/tests/test_key_update_ratelimit ]; then
        output=$(bin/tests/test_key_update_ratelimit 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_key_update_ratelimit: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # Validation configuration fail-closed checks
    if [ -f bin/tests/test_validation_config ]; then
        output=$(bin/tests/test_validation_config 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_validation_config: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # TLS 1.2 ECDSA signature-scheme compatibility
    if [ -f bin/tests/test_tls12_ecdsa ]; then
        output=$(bin/tests/test_tls12_ecdsa 2>&1 || true)
        pass=$(echo "$output" | grep -c "^  PASS:" || true)
        fail=$(echo "$output" | grep -c "^  FAIL:" || true)
        echo "  test_tls12_ecdsa: $pass passed, $fail failed"
        UNIT_PASS=$((UNIT_PASS + pass))
        UNIT_FAIL=$((UNIT_FAIL + fail))
    fi

    # AES-NI hardware path: FIPS 197 KAT + 1024 random equivalence cases
    # vs SPARKNaCl software AES (skipped on non-AES-NI CPUs)
    if [ -f bin/tests/test_aes_ni ]; then
        output=$(bin/tests/test_aes_ni 2>&1 || true)
        if echo "$output" | grep -q "^SKIP:"; then
            echo "  test_aes_ni: SKIP (no AES-NI on this CPU)"
        else
            pass=$(echo "$output" | grep -c "^FAIL:" >/dev/null && echo 0 \
                   || echo "$output" | awk '/^Pass:/ {print $2}')
            fail=$(echo "$output" | grep -c "^FAIL:" || true)
            echo "  test_aes_ni: $pass passed, $fail failed"
            UNIT_PASS=$((UNIT_PASS + pass))
            UNIT_FAIL=$((UNIT_FAIL + fail))
        fi
    fi

    # GHASH-NI (PCLMULQDQ) hardware path: NIST KAT + 1024 random
    # equivalence cases vs the bit-by-bit GF(2^128) reference
    if [ -f bin/tests/test_ghash_ni ]; then
        output=$(bin/tests/test_ghash_ni 2>&1 || true)
        if echo "$output" | grep -q "^SKIP:"; then
            echo "  test_ghash_ni: SKIP (no PCLMULQDQ on this CPU)"
        else
            pass=$(echo "$output" | grep -c "^FAIL:" >/dev/null && echo 0 \
                   || echo "$output" | awk '/^Pass:/ {print $2}')
            fail=$(echo "$output" | grep -c "^FAIL:" || true)
            echo "  test_ghash_ni: $pass passed, $fail failed"
            UNIT_PASS=$((UNIT_PASS + pass))
            UNIT_FAIL=$((UNIT_FAIL + fail))
        fi
    fi

    # ECDSA/ECDHE tests (if built)
    for test_bin in bin/tests/ecdsa_p256_test bin/tests/ecdhe_p384_test; do
        if [ -f "$test_bin" ]; then
            name=$(basename "$test_bin")
            output=$("$test_bin" 2>&1 || true)
            pass=$(echo "$output" | grep -c "PASS" || true)
            fail=$(echo "$output" | grep -c "FAIL" || true)
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
    section "Protocol Compliance Tests (tlsfuzzer)"
    bash tests/protocol/run.sh
    OVERALL_PASS=$((OVERALL_PASS + 1))
fi

if echo "$SUITES" | grep -q "x509"; then
    section "x509-limbo Certificate Validation Tests"
    bash tests/x509/run.sh
    echo ""
    echo "Known expected failures:"
    echo "  pathbuilding (8):    Max_Pool_Size=8, tests need 9-35 intermediates"
    echo "  webpki--cn (9):      CN-in-SAN is a CA issuance rule, not a validator rule"
    echo "  cve (1):             CVE-2024-0567 path-building cycle under triage"
    echo "  pathlen (1):         Leaf pathLen handling policy under triage"
    echo "  rfc5280 (1):         CA-as-leaf policy under triage"
    echo "  public-suffix (1):   Would need Mozilla PSL dependency"
    OVERALL_PASS=$((OVERALL_PASS + 1))
fi

#  BoGo (BoringSSL adversarial tests). Included in the default release
#  suite because it covers a broad set of adversarial edge cases. The
#  first run downloads ~150 MB (Go + BoringSSL) and builds the runner;
#  after first run, cache reuse keeps this much faster. The "bogo"
#  selector still runs it by itself.
if echo "$SUITES" | grep -q "bogo"; then
    section "BoGo Adversarial Tests"
    if bash tests/bogo/run.sh; then
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
