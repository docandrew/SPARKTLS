#!/bin/bash
#  ACVP lane (offline): NIST's published sample vector sets and the sets
#  BoringSSL ships with acvptool, run through BoringSSL's acvptool against
#  tests/acvp/acvp_wrapper, every answer compared with the expected result.
#  See acvp.py for what is and is not covered.
#
#  Pins (bump deliberately, then rerun and triage):
#    ACVP_SERVER_REF  usnistgov/ACVP-Server commit for the sample sets
#    BORING_REV       taken from tests/bogo/run.sh: the same BoringSSL
#                     checkout builds bogo_runner and acvptool
#
#  Output ends with "=== ACVP: <p> passed, <f> failed ==="; exit status 0 only when
#  nothing failed.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
CACHE="$DIR/_cache"
mkdir -p "$CACHE"

ACVP_SERVER_REF="${ACVP_SERVER_REF:-975de31eb83d87039ec88934fdc47d8c312b892d}"   # master 2026-08-12
NIST_DIR="$CACHE/nist-$ACVP_SERVER_REF"
NIST_SETS=(
    ACVP-AES-GCM-1.0 SHA2-256-1.0 SHA2-384-1.0 SHA2-512-1.0
    HMAC-SHA2-256-1.0 HMAC-SHA2-384-1.0
    TLS-v1.2-KDF-RFC7627 TLS-v1.3-KDF-RFC8446 hmacDRBG-SP800-90Ar1
    ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203
    ECDSA-SigVer-FIPS186-5 EDDSA-SigVer-1.0 RSA-SigVer-FIPS186-5
)

BORING_REV="$(sed -n 's/^BORING_REV="\${BORING_REV:-\([0-9a-f]*\)}"$/\1/p' "$REPO_ROOT/tests/bogo/run.sh")"
BORING_DIR="$REPO_ROOT/tests/bogo/_cache/boringssl"
BORING_URL="https://boringssl.googlesource.com/boringssl"
ACVPTOOL="$CACHE/acvptool-$BORING_REV"
WRAPPER="$REPO_ROOT/bin/tests/acvp_wrapper"

fail() { echo "FAIL: $*"; echo "=== ACVP: 0 passed, 1 failed ==="; exit 1; }

[ -n "$BORING_REV" ] || fail "could not read BORING_REV from tests/bogo/run.sh"

# --- NIST sample sets ------------------------------------------------------
for set in "${NIST_SETS[@]}"; do
    for f in prompt expectedResults; do
        out="$NIST_DIR/$set/$f.json"
        [ -s "$out" ] && continue
        mkdir -p "$NIST_DIR/$set"
        curl -sfL --retry 3 -o "$out.tmp" \
            "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$ACVP_SERVER_REF/gen-val/json-files/$set/$f.json" \
            && mv "$out.tmp" "$out" || fail "could not fetch NIST $set/$f.json"
    done
done

# --- BoringSSL checkout (shared with BoGo) and acvptool ---------------------
if [ ! -d "$BORING_DIR/.git" ]; then
    git clone -q "$BORING_URL" "$BORING_DIR" || fail "BoringSSL clone failed"
fi
if [ "$(git -C "$BORING_DIR" rev-parse HEAD)" != "$BORING_REV" ]; then
    git -C "$BORING_DIR" fetch -q origin "$BORING_REV" 2>/dev/null || true
    git -C "$BORING_DIR" checkout -q "$BORING_REV" || fail "BoringSSL $BORING_REV not available"
fi
if [ ! -x "$ACVPTOOL" ]; then
    (cd "$BORING_DIR" && go build -o "$ACVPTOOL" ./util/fipstools/acvp/acvptool) \
        || fail "acvptool build failed"
fi

# --- wrapper ----------------------------------------------------------------
eval "$(cd "$REPO_ROOT" && alr -n --no-tty printenv --unix)"
gprbuild -q -P "$DIR/acvp_wrapper.gpr" || fail "acvp_wrapper build failed"

python3 "$DIR/acvp.py" "$ACVPTOOL" "$WRAPPER" "$NIST_DIR" \
    "$BORING_DIR/util/fipstools/acvp/acvptool/test"
