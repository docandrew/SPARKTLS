#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_ROOT="$(cd "$DIR/.." && pwd)"
REPO_ROOT="$(cd "$CLI_ROOT/.." && pwd)"
BIN="$REPO_ROOT/bin/sparktls_cli"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

PASS=0
FAIL=0
WORKDIR=""

cleanup() {
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

run_ok() {
    local name="$1"
    shift
    if "$@" >"$WORKDIR/$name.out" 2>"$WORKDIR/$name.err"; then
        pass "$name"
    else
        echo "    command: $*" >&2
        cat "$WORKDIR/$name.err" >&2
        fail "$name"
    fi
}

run_fail() {
    local name="$1"
    shift
    if "$@" >"$WORKDIR/$name.out" 2>"$WORKDIR/$name.err"; then
        echo "    command unexpectedly succeeded: $*" >&2
        fail "$name"
    else
        pass "$name"
    fi
}

contains() {
    local name="$1"
    local file="$2"
    local pattern="$3"
    if grep -q "$pattern" "$file"; then
        pass "$name"
    else
        echo "    missing pattern: $pattern" >&2
        echo "    file: $file" >&2
        fail "$name"
    fi
}

exists_nonempty() {
    local name="$1"
    local file="$2"
    if [ -s "$file" ]; then
        pass "$name"
    else
        echo "    missing or empty: $file" >&2
        fail "$name"
    fi
}

echo "== build sparktls_cli =="
if (cd "$CLI_ROOT" && alr -n --no-tty build); then
    pass "build"
else
    fail "build"
    echo "sparktls_cli tests: $PASS passed, $FAIL failed"
    exit 1
fi

WORKDIR="$(mktemp -d)"
cd "$WORKDIR" || exit 1

echo ""
echo "== command-line help and usage =="
run_ok help "$BIN" --help
contains "help mentions generate" "$WORKDIR/help.out" "generate <algo> key to <file>"
contains "help mentions devcert" "$WORKDIR/help.out" "devcert <name>"
contains "help documents PEM/DER input" "$WORKDIR/help.out" "certificate inputs may be PEM or DER"
run_fail "unknown command rejected" "$BIN" no-such-command
contains "unknown command message" "$WORKDIR/unknown command rejected.err" "Unknown command"

echo ""
echo "== key and certificate workflows =="
run_ok "generate ca key" "$BIN" generate p256 key to ca.key
exists_nonempty "ca key written" ca.key
contains "ca key is PEM" ca.key "BEGIN PRIVATE KEY"

run_ok "create ca cert" "$BIN" create ca for "CLI Test CA" using ca.key to ca.crt valid-for 30 with-org TestOrg
exists_nonempty "ca cert written" ca.crt
contains "ca cert is PEM" ca.crt "BEGIN CERTIFICATE"

run_ok "generate server key" "$BIN" generate p256 key to server.key
run_ok "sign server cert" "$BIN" sign server.key with-ca ca.key ca.crt for localhost to server.crt valid-for 30 with-san localhost,127.0.0.1 with-org TestOrg
exists_nonempty "server cert written" server.crt

run_ok "show server cert" "$BIN" show server.crt --brief
contains "show includes subject" "$WORKDIR/show server cert.out" "Subject:"
contains "show includes localhost" "$WORKDIR/show server cert.out" "localhost"

run_ok "verify server cert" "$BIN" verify server.crt --ca ca.crt --host localhost
contains "verify valid result" "$WORKDIR/verify server cert.out" "Result: VALID"

run_fail "verify rejects wrong hostname" "$BIN" verify server.crt --ca ca.crt --host example.com
contains "verify invalid result" "$WORKDIR/verify rejects wrong hostname.out" "Result: INVALID"

echo ""
echo "== development certificate workflow =="
run_ok "devcert p384" "$BIN" devcert dev.local to dev.key dev.crt algo p384 valid-for 30 with-san dev.local,127.0.0.1
exists_nonempty "dev key written" dev.key
exists_nonempty "dev cert written" dev.crt

echo ""
echo "== CSR workflow =="
run_ok "create csr" "$BIN" create csr for csr.local using server.key to server.csr with-san csr.local
exists_nonempty "csr written" server.csr
contains "csr is PEM" server.csr "BEGIN CERTIFICATE REQUEST"

run_ok "sign csr" "$BIN" sign-csr server.csr with-ca ca.key ca.crt to csr.crt valid-for 30
exists_nonempty "csr cert written" csr.crt

echo ""
echo "sparktls_cli tests: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
