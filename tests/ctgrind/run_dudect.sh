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
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "Rebuilding library + harnesses in optimize mode..."
#  Capture rather than discard: a silent "Rebuild failed" is
#  undiagnosable in CI, where the tree differs from a dev box.
build_log="$(mktemp)"
( cd "$DIR" && SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build ) >"$build_log" 2>&1
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed; aborting. Build output:"
  sed "s/^/    /" "$build_log"
  rm -f "$build_log"
  exit 2
fi

echo "=== dudect statistical timing analysis ==="
echo ""

rm -f "$build_log"

run_one() {
  local name="$1"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  echo "--- $name ---"
  local out
  out=$("$exe" 2>&1)
  local status=$?
  echo "$out"
  echo ""
  if echo "$out" | grep -q "TIMING DEPENDS ON SECRET INPUT"; then
    return 1
  fi
  return "$status"
}

fail=0
run_one dudect_x25519      || fail=1
run_one dudect_p256_ecdsa  || fail=1
run_one dudect_p384_ecdsa  || fail=1
run_one dudect_aead        || fail=1

if [ "$fail" -eq 0 ]; then
  echo "=== ALL dudect checks pass ==="
else
  echo "=== DUDECT TIMING REGRESSION ==="
fi

exit "$fail"
