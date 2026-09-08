#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

ci/versions.sh

echo "== full test suite =="
tests/run_all.sh
