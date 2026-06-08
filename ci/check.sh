#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

ci/versions.sh
ci/build.sh

echo "== unit tests =="
tests/run_all.sh unit

echo "== integration tests =="
ci/integration.sh
