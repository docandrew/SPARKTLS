#!/bin/bash
# Run NIST CAVP test vectors against SPARKTLS.
# Currently covers: ECDSA SigVer (FIPS 186-4) for P-256/P-384.
#
# CAVP archives are downloaded from NIST CSRC on first run.
set +e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$DIR/../.."
RUNNER="$REPO_ROOT/bin/tests/wycheproof_runner"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

if [ ! -f "$RUNNER" ]; then
    echo "Building runner..."
    (cd "$DIR/../wycheproof"
     alr -n --no-tty exec -- gprbuild -P wycheproof_runner.gpr 2>&1 | tail -3)
fi
if [ ! -f "$RUNNER" ]; then
    echo "FAIL: runner not built"
    exit 2
fi

# Fetch ECDSA SigVer.rsp if missing.
SIGVER="$DIR/ecdsa_SigVer.rsp"
if [ ! -f "$SIGVER" ]; then
    echo "Downloading NIST CAVP ECDSA test vectors..."
    TMP=$(mktemp -d)
    curl -sSL https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip \
        -o "$TMP/cavp.zip"
    unzip -q "$TMP/cavp.zip" -d "$TMP"
    cp "$TMP/186-4ecdsatestvectors/SigVer.rsp" "$SIGVER"
    rm -rf "$TMP"
fi

echo "=== NIST CAVP ECDSA SigVer ==="
python3 "$DIR/run_cavp.py" "$SIGVER"
