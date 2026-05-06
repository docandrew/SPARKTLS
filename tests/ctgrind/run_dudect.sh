#!/bin/bash
# Run dudect statistical timing harnesses against the OPTIMIZE build.
# (ctgrind build has -fno-tree-vectorize which skews timing — for
# dudect we want production-realistic cycle counts.)
#
# Compile-and-run takes ~30s per harness (50K samples × 2 classes).

set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/../.."
BIN="$REPO/bin/tests/ctgrind"

echo "Rebuilding library + harnesses in optimize mode..."
( cd "$DIR" && SPARKTLSCRYPTO_BUILD_MODE=optimize alr build >/dev/null 2>&1 )
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed; aborting"
  exit 2
fi

echo "=== dudect statistical timing analysis ==="
echo ""

run_one() {
  local name="$1"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  echo "--- $name ---"
  "$exe"
  echo ""
}

run_one dudect_x25519
run_one dudect_p256_ecdsa
run_one dudect_p384_ecdsa
run_one dudect_aead
