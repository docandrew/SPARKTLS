#!/bin/bash
# Generate test certificates for SPARKTLS test suite.
# Run from repo root: ./tests/certs/generate.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# RSA-2048 (for tlsfuzzer protocol tests)
if [ ! -f "$DIR/rsa.key" ]; then
    echo "Generating RSA-2048 test certificate..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$DIR/rsa_raw.key" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt \
        -in "$DIR/rsa_raw.key" -out "$DIR/rsa.key" 2>/dev/null
    openssl req -x509 -key "$DIR/rsa.key" -out "$DIR/rsa.crt" \
        -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    rm -f "$DIR/rsa_raw.key"
    echo "  Created rsa.crt and rsa.key"
fi

# Ed25519 (for cipher suite tests)
if [ ! -f "$DIR/ed25519.key" ]; then
    echo "Generating Ed25519 test certificate..."
    openssl genpkey -algorithm ED25519 -out "$DIR/ed25519.key" 2>/dev/null
    openssl req -x509 -key "$DIR/ed25519.key" -out "$DIR/ed25519.crt" \
        -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    echo "  Created ed25519.crt and ed25519.key"
fi

# ECDSA P-256 (for ECDSA cipher suite tests)
if [ ! -f "$DIR/p256.key" ]; then
    echo "Generating ECDSA P-256 test certificate..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$DIR/p256.key" 2>/dev/null
    openssl req -x509 -key "$DIR/p256.key" -out "$DIR/p256.crt" \
        -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    echo "  Created p256.crt and p256.key"
fi

echo "All test certificates ready."
