#!/usr/bin/env bash
#  ACVP lane: see tests/acvp/run.sh. Needs network access the first time
#  (NIST sample sets, BoringSSL checkout, Go modules).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1
alr -n --no-tty build
exec tests/acvp/run.sh
