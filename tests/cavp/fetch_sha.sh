#!/bin/bash
# Fetch the NIST CAVP SHAVS byte-oriented SHA-1 vectors into tests/cavp
# (used by tests/unit/test_sha1_cavp). Idempotent; needs curl + unzip.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$DIR/SHA1ShortMsg.rsp" ] && [ -f "$DIR/SHA1LongMsg.rsp" ] && [ -f "$DIR/SHA1Monte.rsp" ]; then
    exit 0
fi
echo "Downloading NIST CAVP SHA byte test vectors..."
TMP=$(mktemp -d)
curl -sSL https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip \
    -o "$TMP/sha.zip"
unzip -q "$TMP/sha.zip" -d "$TMP"
cp "$TMP/shabytetestvectors/SHA1ShortMsg.rsp" "$TMP/shabytetestvectors/SHA1LongMsg.rsp" \
   "$TMP/shabytetestvectors/SHA1Monte.rsp" "$DIR/"
rm -rf "$TMP"
