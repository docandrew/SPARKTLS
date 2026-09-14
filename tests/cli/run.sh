#!/bin/bash
# sparktls_cli smoke lane: every subcommand, every key algorithm, checked
# against OpenSSL and against a real handshake with the material it made.
#
#   tests/cli/run.sh            # builds cli/ if needed, ~15 s
#
# Summary line: === CLI: <passed>/<total> passed, <failed> failed ===
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
CLI="$REPO_ROOT/bin/sparktls_cli"
SERVER="$REPO_ROOT/bin/examples/tls_blocking_server"
export ALR_NON_INTERACTIVE=1 NO_COLOR=1

if [ ! -x "$CLI" ]; then
    (cd "$REPO_ROOT/cli" && alr -n --no-tty build 2>&1 | tail -2)
fi
if [ ! -x "$CLI" ]; then
    echo "=== CLI: 0/1 passed, 1 failed ==="; echo "  FAIL: bin/sparktls_cli not built"; exit 1
fi

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); [ -n "${2:-}" ] && printf '%s\n' "$2" | head -5 | sed 's/^/      /'; }
check() {   # label command...   (must succeed)
    local label=$1; shift; local out
    if out=$("$@" 2>&1); then pass "$label"; else fail "$label" "$out"; fi
}
check_fails() {   # label command...   (must fail)
    local label=$1; shift; local out
    if out=$("$@" 2>&1); then fail "$label (unexpectedly succeeded)" "$out"; else pass "$label"; fi
}

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PORT=${SPARKTLS_CLI_TEST_PORT:-18630}
echo "=== sparktls_cli smoke tests ($W) ==="

for algo in ed25519 p256 p384; do
    K="$W/$algo"; mkdir -p "$K"
    check "$algo: generate key"        "$CLI" generate "$algo" key to "$K/ca.key"
    check "$algo: create ca"           "$CLI" create ca for "Test CA $algo" using "$K/ca.key" to "$K/ca.crt" valid-for 30
    check "$algo: generate leaf key"   "$CLI" generate "$algo" key to "$K/leaf.key"
    check "$algo: sign leaf with ca"   "$CLI" sign "$K/leaf.key" with-ca "$K/ca.key" "$K/ca.crt" for localhost to "$K/leaf.crt" with-san localhost,127.0.0.1 valid-for 30
    check "$algo: create csr"          "$CLI" create csr for example.test using "$K/leaf.key" to "$K/leaf.csr" with-san example.test
    check "$algo: sign-csr"            "$CLI" sign-csr "$K/leaf.csr" with-ca "$K/ca.key" "$K/ca.crt" to "$K/csr-leaf.crt" valid-for 30
    check "$algo: devcert"             "$CLI" devcert localhost to "$K/dev.key" "$K/dev.crt" algo "$algo"
    check "$algo: show"                "$CLI" show "$K/leaf.crt"
    check "$algo: verify leaf"         "$CLI" verify "$K/leaf.crt" --ca "$K/ca.crt" --host localhost
    check "$algo: verify csr-signed"   "$CLI" verify "$K/csr-leaf.crt" --ca "$K/ca.crt" --host example.test
    check_fails "$algo: verify rejects wrong host"  "$CLI" verify "$K/leaf.crt" --ca "$K/ca.crt" --host other.test
    check_fails "$algo: verify rejects wrong ca"    "$CLI" verify "$K/leaf.crt" --ca "$K/dev.crt"
    #  OpenSSL must agree with everything we produced.
    check "$algo: openssl parses key"   openssl pkey -in "$K/leaf.key" -noout
    check "$algo: openssl parses cert"  openssl x509 -in "$K/leaf.crt" -noout -text
    check "$algo: openssl verifies chain" openssl verify -CAfile "$K/ca.crt" "$K/leaf.crt"
    check "$algo: openssl verifies csr"  openssl req -in "$K/leaf.csr" -noout -verify
    check "$algo: openssl accepts devcert" openssl verify -CAfile "$K/dev.crt" "$K/dev.crt"
    #  And a handshake: our server with the CLI's material, OpenSSL client.
    if [ -x "$SERVER" ]; then
        SPARKTLS_PORT=$PORT "$SERVER" "$K/leaf.crt" "$K/leaf.key" >/dev/null 2>&1 &
        SPID=$!; sleep 0.7
        out=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -CAfile "$K/ca.crt" -verify_return_error 2>&1)
        kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
        if echo "$out" | grep -q "Verify return code: 0 (ok)" && echo "$out" | grep -q "Cipher is TLS"; then
            pass "$algo: handshake with CLI-issued certificate, chain verified by OpenSSL"
        else
            fail "$algo: handshake with CLI-issued certificate" "$(echo "$out" | grep -E 'Verify|error|alert' | head -3)"
        fi
        PORT=$((PORT + 1))
    fi
done

check_fails "rejects unknown command" "$CLI" frobnicate
check_fails "rejects missing key file" "$CLI" create ca for x using "$W/nope.key" to "$W/nope.crt"

#  Hardening checks (2026-09-14 security sweep).
K="$W/p256"
mode=$(stat -c %a "$K/leaf.key")
if [ "$mode" = "600" ]; then pass "private key file is mode 0600"; else fail "private key file is mode 0600 (got $mode)"; fi
mode=$(stat -c %a "$K/leaf.crt")
if [ "$mode" = "644" ]; then pass "certificate file is mode 0644"; else fail "certificate file is mode 0644 (got $mode)"; fi
check_fails "refuses to overwrite an existing key file"   "$CLI" generate p256 key to "$K/leaf.key"
check_fails "refuses to overwrite an existing certificate" "$CLI" devcert localhost to "$W/x.key" "$K/leaf.crt"
check_fails "rejects an IPv4 SAN octet above 255 (sign)"   "$CLI" sign "$K/leaf.key" with-ca "$K/ca.key" "$K/ca.crt" for h to "$W/bad1.crt" with-san 999.1.1.1
check_fails "rejects an IPv4 SAN octet above 255 (csr)"    "$CLI" create csr for h using "$K/leaf.key" to "$W/bad1.csr" with-san 999.1.1.1
check_fails "rejects valid-for 0"                          "$CLI" sign "$K/leaf.key" with-ca "$K/ca.key" "$K/ca.crt" for h to "$W/bad2.crt" valid-for 0
check_fails "rejects valid-for beyond year 9999"           "$CLI" sign "$K/leaf.key" with-ca "$K/ca.key" "$K/ca.crt" for h to "$W/bad3.crt" valid-for 4000000
LONG=$(printf 'a%.0s' $(seq 1 300))
check_fails "rejects an over-long name instead of truncating" "$CLI" devcert "$LONG" to "$W/l.key" "$W/l.crt"
check_fails "rejects an over-long output path"             "$CLI" generate p256 key to "$W/$LONG.key"
[ -f "$W/bad1.crt" ] || [ -f "$W/bad2.crt" ] || [ -f "$W/bad3.crt" ] || [ -f "$W/l.key" ] && fail "a refused command still wrote a file" || pass "refused commands leave no files behind"
#  Proof of possession: a CSR whose signature was corrupted must not be signed.
python3 - "$K/leaf.csr" "$W/tampered.csr" <<'PY'
import base64, sys
pem = open(sys.argv[1]).read().splitlines()
der = bytearray(base64.b64decode("".join(l for l in pem if not l.startswith("-----"))))
der[-1] ^= 0x01                    # last byte of the signature
b = base64.b64encode(bytes(der)).decode()
open(sys.argv[2], "w").write("-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(b[i:i+64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE REQUEST-----\n")
PY
check_fails "sign-csr refuses a CSR whose signature does not verify" "$CLI" sign-csr "$W/tampered.csr" with-ca "$K/ca.key" "$K/ca.crt" to "$W/tampered.crt"
check "sign-csr still accepts a genuine CSR"               "$CLI" sign-csr "$K/leaf.csr" with-ca "$K/ca.key" "$K/ca.crt" to "$W/genuine.crt"
check "issued leaf carries EKU serverAuth"                 sh -c "openssl x509 -in '$K/leaf.crt' -noout -ext extendedKeyUsage | grep -q 'Server Authentication'"

TOTAL=$((PASS + FAIL))
echo "=== CLI: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
