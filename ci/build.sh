#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "== building library =="
alr -n --no-tty build

echo "== building examples =="
(
  cd examples
  alr -n --no-tty build
)

echo "== building unit test binaries =="
(
  cd tests/unit
  alr -n --no-tty build
)
