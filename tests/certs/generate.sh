#!/bin/bash
# Generate test certificates for SPARKTLS test suite.
# Uses sparktls_cli for Ed25519/P-256/P-384, OpenSSL for RSA.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/../.."
CLI="$REPO/bin/sparktls_cli"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

# Build CLI if needed
if [ ! -f "$CLI" ]; then
    echo "Building sparktls_cli..."
    (cd "$REPO/cli" && alr -n --no-tty build 2>/dev/null)
fi

# Ed25519
echo "Generating Ed25519 test certificate..."
"$CLI" devcert localhost to "$DIR/ed25519.key" "$DIR/ed25519.crt" algo ed25519
echo "  Created ed25519.crt and ed25519.key"

# ECDSA P-256
echo "Generating ECDSA P-256 test certificate..."
"$CLI" devcert localhost to "$DIR/p256.key" "$DIR/p256.crt" algo p256
echo "  Created p256.crt and p256.key"

# ECDSA P-384
echo "Generating ECDSA P-384 test certificate..."
"$CLI" devcert localhost to "$DIR/p384.key" "$DIR/p384.crt" algo p384
echo "  Created p384.crt and p384.key"

# RSA-2048 (OpenSSL — we don't have RSA key generation)
echo "Generating RSA-2048 test certificate..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$DIR/rsa_raw.key" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt \
    -in "$DIR/rsa_raw.key" -out "$DIR/rsa.key" 2>/dev/null
openssl req -x509 -key "$DIR/rsa.key" -out "$DIR/rsa.crt" \
    -days 365 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
rm -f "$DIR/rsa_raw.key"
echo "  Created rsa.crt and rsa.key"

# Convenience symlinks for default server cert (Ed25519)
ln -sf ed25519.crt "$DIR/server.crt"
ln -sf ed25519.key "$DIR/server.key"

echo "All test certificates ready."
