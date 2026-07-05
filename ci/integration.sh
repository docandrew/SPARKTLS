#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${TMPDIR:-/tmp}/sparktls-integration.$$.log"
trap 'rm -f "$OUT"' EXIT

set +e
tests/integration/run.sh 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
set -e

summary="$(grep -E '^=== Integration: [0-9]+/[0-9]+ passed, [0-9]+ failed ===$' "$OUT" | tail -1 || true)"

if [ "$rc" -eq 0 ]; then
  exit 0
fi

echo ""
echo "Unexpected integration failure set."
if [ -n "$summary" ]; then
  echo "$summary"
fi
exit "$rc"
