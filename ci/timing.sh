#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

case "${1:-ctgrind}" in
  ctgrind)
    tests/ctgrind/run.sh
    ;;
  dudect)
    tests/ctgrind/run_dudect.sh
    ;;
  all)
    tests/ctgrind/run.sh
    tests/ctgrind/run_dudect.sh
    ;;
  *)
    echo "usage: ci/timing.sh [ctgrind|dudect|all]" >&2
    exit 2
    ;;
esac
