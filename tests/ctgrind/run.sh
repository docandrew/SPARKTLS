#!/bin/bash
# Run each ctgrind harness under valgrind/memcheck and report.
#
# Expected results:
#   ct_chacha20_poly1305 — 0 errors (constant-time)
#   ct_x25519            — 0 errors (Montgomery ladder w/ cswap)
#   ct_ed25519           — 0 errors (constant-time scalar mult)
#   ct_poly1305_scalar   — 0 errors (only field arithmetic)
#   ct_negative_control  — >0 errors (deliberately leaky — proves the
#                          harness has teeth)
#
# Re-run after any change to the crypto modules. A sudden 0->non-zero
# transition on any non-control harness is a constant-time regression.

set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/../.."
BIN="$REPO/bin/tests/ctgrind"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind not installed; aborting"
  exit 2
fi

#  Always rebuild in ctgrind mode — the optimize build emits AVX-512
#  instructions that Valgrind 3.22 can't decode. This also guarantees
#  a clean separation between the ctgrind binaries and the bench /
#  unit-test binaries (which need the optimize build).
echo "Rebuilding library + harnesses in ctgrind mode..."
#  Capture rather than discard: a silent "Rebuild failed" is
#  undiagnosable in CI, where the tree differs from a dev box.
build_log="$(mktemp)"
( cd "$DIR" && SPARKTLSCRYPTO_BUILD_MODE=ctgrind alr -n --no-tty build ) >"$build_log" 2>&1
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed; aborting. Build output:"
  sed "s/^/    /" "$build_log"
  rm -f "$build_log"
  exit 2
fi

rm -f "$build_log"

#  Alire's toolchain gcc links against the system dynamic loader
#  (/lib64/ld-linux-x86-64.so.2), which does not exist under nix on a hosted
#  runner. The binaries then fail to launch, and a canary that never runs
#  reports zero memcheck errors -- surfacing as "control should have leaked
#  but didn't" rather than as an execution failure. Repoint the interpreter
#  at nix's loader when running inside a nix shell.
#  Ported from SPARKTLSCrypto tests/timing/run_ctgrind.sh (commit 8b5486d,
#  "GH Runner valgrind patch"); this copy of the harness never received it.
if [ -n "${NIX_CC:-}" ] && [ -f "$NIX_CC/nix-support/dynamic-linker" ]; then
  nix_ld="$(cat "$NIX_CC/nix-support/dynamic-linker")"
  if ! command -v patchelf >/dev/null 2>&1; then
    echo "patchelf not installed; aborting"
    exit 2
  fi
  for exe in "$BIN"/*; do
    if [ -x "$exe" ] && [ -f "$exe" ]; then
      patchelf --set-interpreter "$nix_ld" "$exe"
    fi
  done
fi

run_one() {
  local name="$1" expect_errs="$2"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  local out
  out=$(valgrind --tool=memcheck --error-exitcode=1 \
                 --track-origins=yes --quiet "$exe" 2>&1)
  local errs
  errs=$(echo "$out" | grep -c "Use of uninitialised\|Conditional jump.*uninitialised")
  if [ "$expect_errs" = "0" ]; then
    if [ "$errs" -eq 0 ]; then
      echo "  PASS  $name (0 errors — constant-time)"
    else
      echo "  FAIL  $name ($errs errors — secret-dependent op detected)"
      echo "$out" | sed 's/^/      /' | head -20
      return 1
    fi
  else
    if [ "$errs" -gt 0 ]; then
      echo "  PASS  $name ($errs errors — control caught a leak as expected)"
    else
      echo "  FAIL  $name (0 errors — control should have leaked but didn't;"
      echo "        harness plumbing is broken)"
      #  Surface what valgrind actually said. The canary is memcheck's
      #  deterministic undefined-value tracking, not a timing measurement, so
      #  runner noise does not explain a miss. Likely causes are that
      #  Ctgrind.Make_Undefined did not take effect (client request compiled
      #  to a no-op) or the compiler folded the secret-dependent branch.
      #  Without this dump the two are indistinguishable from a CI log.
      echo "      --- valgrind output ---"
      echo "$out" | sed 's/^/      /' | head -30
      echo "      --- valgrind version ---"
      valgrind --version 2>&1 | sed 's/^/      /'
      return 1
    fi
  fi
}

echo "=== ctgrind constant-time analysis ==="
echo ""
fail=0
run_one ct_negative_control 1   || fail=1   # canary: must trigger
run_one ct_chacha20_poly1305 0  || fail=1
run_one ct_poly1305_scalar   0  || fail=1
run_one ct_x25519            0  || fail=1
run_one ct_ed25519           0  || fail=1
run_one ct_p256_ecdsa        0  || fail=1
run_one ct_p384_ecdsa        0  || fail=1
run_one ct_hkdf              0  || fail=1
run_one ct_aes_gcm           0  || fail=1
run_one ct_aead_decrypt      0  || fail=1
run_one ct_key_schedule      0  || fail=1
run_one ct_rfc6979           0  || fail=1
run_one ct_hmac              0  || fail=1

echo ""
if [ "$fail" -eq 0 ]; then
  echo "=== ALL constant-time checks pass ==="
  rc=0
else
  echo "=== CONSTANT-TIME REGRESSION ==="
  rc=1
fi

#  Restore the regular optimize build so subsequent bench / unit-test
#  runs see the AVX-512 codegen they expect.
echo "Restoring optimize build..."
( cd "$DIR" && SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 )
( cd "$REPO" && SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 )
( cd "$REPO/tests/unit" && \
  SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 )
( cd "$REPO/examples" && \
  SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 )

exit "$rc"
