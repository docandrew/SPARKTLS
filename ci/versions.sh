#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

show() {
  printf '\n== %s ==\n' "$1"
}

show "host tools"
command -v nix >/dev/null 2>&1 && nix --version || true
command -v alr >/dev/null 2>&1 && alr -n --no-tty version || true
command -v openssl >/dev/null 2>&1 && openssl version -a | sed -n '1,4p' || true
command -v valgrind >/dev/null 2>&1 && valgrind --version || true
command -v tcpdump >/dev/null 2>&1 && tcpdump --version | sed -n '1,2p' || true
command -v python3 >/dev/null 2>&1 && python3 --version || true

show "alire toolchain"
if command -v alr >/dev/null 2>&1; then
  alr -n --no-tty exec -- gnat --version 2>/dev/null | sed -n '1,2p' || true
  alr -n --no-tty exec -- gprbuild --version 2>/dev/null | sed -n '1,2p' || true
  alr -n --no-tty exec -- gnatprove --version 2>/dev/null | sed -n '1,2p' || true
fi

show "python"
command -v python3 >/dev/null 2>&1 && python3 --version || true
