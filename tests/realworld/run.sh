#!/bin/bash
# Real-world CA chain interop test.
#
# Hits a curated list of well-known HTTPS sites with tls_fetch using
# the OS Mozilla CA bundle. Validates that we successfully handshake
# against actual production cert chains — catches a class of issues
# the self-signed test certs miss (e.g., the original RSA-PKCS#1 v1.5
# routing bug, intermediate cert chain parsing, real-world DN
# encodings, multi-byte pathLenConstraint, etc.).
#
# Skipped automatically if the network or CA bundle is unavailable.
set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
FETCH="$REPO_ROOT/bin/examples/tls_fetch"

# Locate Mozilla CA bundle (covers Debian/Ubuntu, RHEL/Fedora, Alpine).
CA_BUNDLE=""
for c in /etc/ssl/certs/ca-certificates.crt \
         /etc/pki/tls/certs/ca-bundle.crt \
         /etc/ssl/cert.pem; do
    if [ -f "$c" ]; then CA_BUNDLE="$c"; break; fi
done

if [ -z "$CA_BUNDLE" ]; then
    echo "=== Real-world CA chain test ==="
    echo "  SKIP: no OS CA bundle found"
    exit 0
fi

if [ ! -f "$FETCH" ]; then
    echo "FAIL: tls_fetch not built at $FETCH"
    exit 2
fi

# DNS / connectivity sanity check — skip if offline.
if ! getent hosts www.google.com >/dev/null 2>&1; then
    echo "=== Real-world CA chain test ==="
    echo "  SKIP: no DNS / offline"
    exit 0
fi

echo "=== Real-world CA chain test ==="
echo "  CA bundle: $CA_BUNDLE"

# Curated list. Diverse on:
#   * cert algorithm (RSA-2048/3072/4096, ECDSA P-256/P-384)
#   * chain depth (1-3 intermediates is typical)
#   * issuer (LE, DigiCert, Sectigo, GlobalSign, ISRG)
#   * server stack (boringssl, OpenSSL, rustls, NSS, IIS)
#   * SAN encodings (wildcards, IP literals, IDN)
SITES=(
    "https://www.google.com/"
    "https://github.com/"
    "https://www.cloudflare.com/"
    "https://letsencrypt.org/"
    "https://www.mozilla.org/"
    "https://www.python.org/"
    "https://en.wikipedia.org/wiki/Main_Page"
    "https://www.bbc.com/"
    "https://www.cisa.gov/"
)

PASS=0
FAIL=0
SKIP=0

for url in "${SITES[@]}"; do
    host=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
    if ! getent hosts "$host" >/dev/null 2>&1; then
        echo "  SKIP: $host (no DNS resolution)"
        SKIP=$((SKIP + 1))
        continue
    fi

    # We're testing TLS chain validation, not HTTP behaviour.
    # Pass criterion: -v output includes "TLS 1.3 handshake complete"
    # (means cert chain validated AND key exchange succeeded). Some
    # sites enforce HTTP/2 via ALPN and return 403 to HTTP/1.1
    # clients (e.g. Akamai-fronted .gov sites); that's a perfectly
    # valid TLS handshake from our perspective.
    output=$(timeout 15 "$FETCH" --cafile "$CA_BUNDLE" --rfc5280 -v -I "$url" 2>&1)
    rc=$?
    if echo "$output" | grep -qE "TLS 1\.[23] handshake complete"; then
        # Distinguish HTTP-200 (full success) from handshake-only.
        if echo "$output" | grep -qE "^HTTP/[12]\.[01]? [12345]"; then
            echo "  PASS: $host"
        else
            echo "  PASS: $host (handshake OK, no HTTP response — likely h2-only)"
        fi
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $host (rc=$rc)"
        # Print last error context line for triage.
        echo "    $(echo "$output" | grep -E 'TLS error|fatal|error' | head -1)"
        FAIL=$((FAIL + 1))
    fi
done

# ---------------------------------------------------------------------------
# badssl.com matrix: deliberately-misconfigured endpoints.
#
# The curated list above is all TLS 1.3 (verified 2026-08-16: every one of
# the nine negotiates TLSv1.3). Combined with tlsfuzzer/BoGo/integration --
# which exercise TLS 1.2 only over loopback -- that left "TLS 1.2 against a
# real server" untested by anything, which is exactly the configuration
# where badssl.com currently fails for us.
#
# These entries are "expect", not "must connect": most of these hosts are
# SUPPOSED to be rejected, and accepting one is a security failure, not a
# pass. Format:  <host>|<expect>|<why>
#   connect = handshake must complete
#   reject  = handshake must fail (we must NOT accept the cert)
#
# NOTE: a "reject" entry passing tells us we refused, not that we refused
# for the right reason. Asserting the specific alert/Error_Code is a
# follow-up -- see the note on error-code granularity in the tracker.
# ---------------------------------------------------------------------------
BADSSL=(
    "badssl.com|connect|apex, valid cert, TLS 1.2 only"
    "sha256.badssl.com|connect|SHA-256 leaf, should be accepted"
    "ecc256.badssl.com|connect|ECDSA P-256 leaf"
    "ecc384.badssl.com|connect|ECDSA P-384 leaf"
    "rsa2048.badssl.com|connect|RSA-2048 leaf"
    "rsa4096.badssl.com|connect|RSA-4096 leaf"
    "extended-validation.badssl.com|connect|EV cert"
    "tls-v1-2.badssl.com:1012|connect|TLS 1.2 pinned port"
    "expired.badssl.com|reject|notAfter in the past"
    "wrong.host.badssl.com|reject|SAN does not match hostname"
    "self-signed.badssl.com|reject|no path to a trust anchor"
    "untrusted-root.badssl.com|reject|root not in the bundle"
    "incomplete-chain.badssl.com|reject|intermediate not served"
    "sha1-intermediate.badssl.com|reject|SHA-1 in the chain"
    "revoked.badssl.com|reject|revoked cert"
    "null.badssl.com|reject|null cipher"
    "rc4.badssl.com|reject|RC4"
    "3des.badssl.com|reject|3DES"
    "dh480.badssl.com|reject|480-bit DH"
    "no-common-name.badssl.com|reject|no CN and no SAN"
)

echo ""
echo "=== badssl.com matrix ==="
BS_PASS=0
BS_FAIL=0

if ! getent hosts badssl.com >/dev/null 2>&1; then
    echo "  SKIP: badssl.com does not resolve"
    SKIP=$((SKIP + ${#BADSSL[@]}))
else
    for entry in "${BADSSL[@]}"; do
        host="${entry%%|*}"
        rest="${entry#*|}"
        expect="${rest%%|*}"
        why="${rest#*|}"

        output=$(timeout 15 "$FETCH" --cafile "$CA_BUNDLE" -v -I "https://$host/" 2>&1)
        if echo "$output" | grep -qE "TLS 1\.[23] handshake complete"; then
            got="connect"
        else
            got="reject"
        fi

        if [ "$got" = "$expect" ]; then
            echo "  PASS: $host ($expect) -- $why"
            BS_PASS=$((BS_PASS + 1))
        else
            echo "  FAIL: $host expected=$expect got=$got -- $why"
            if [ "$got" = "reject" ]; then
                echo "    $(echo "$output" | grep -E 'TLS error' | head -1)"
            else
                echo "    ACCEPTED a cert we should have refused"
            fi
            BS_FAIL=$((BS_FAIL + 1))
        fi
    done
    PASS=$((PASS + BS_PASS))
    FAIL=$((FAIL + BS_FAIL))
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "=== Real-world: $PASS/$TOTAL passed, $FAIL failed, $SKIP skipped ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
