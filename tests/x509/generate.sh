#!/bin/bash
# Download x509-limbo and generate test case directories.
# Each test case becomes a directory with PEM files and metadata.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
LIMBO_DIR="$DIR/x509-limbo"
OUT_DIR="$DIR/generated"

# Clone x509-limbo if not present
if [ ! -f "$LIMBO_DIR/limbo.json" ]; then
    echo "Downloading x509-limbo test vectors..."
    git clone --depth 1 https://github.com/C2SP/x509-limbo.git "$LIMBO_DIR"
fi

# Generate test directories
echo "Generating test cases..."
python3 "$DIR/generate_cases.py" "$LIMBO_DIR/limbo.json" "$OUT_DIR"
