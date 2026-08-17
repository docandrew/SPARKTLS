#!/usr/bin/env bash
# Run gnatprove with memory containment so a runaway solver cannot take the
# machine down.
#
# Why: gnatprove's own --memlimit is NOT reliably enforced. Solvers have been
# observed at 5.2 GB RSS against a 2000 MB limit. On a 60 GB box that is
# enough, when several coincide, to trigger a system-wide OOM kill (90 such
# events in chungus's kernel log). A cgroup cap makes the kernel kill a solver
# inside the scope instead of choosing a victim across the whole system: you
# lose one VC, not the workstation.
#
# Usage:
#   ci/prove.sh                          # full project, level 1
#   ci/prove.sh -u sparktls-client.adb   # one unit
#   ci/prove.sh --level=3 -u rflx-tls_handshake-server_hello.adb
#   PROVE_MEM=32G ci/prove.sh            # override the cap
#   PROVE_JOBS=24 ci/prove.sh            # override parallelism
#   PROVE_TEE=findings_x.txt ci/prove.sh # tee output to a file
#
# Any extra arguments are passed through to gnatprove unchanged.
#
# Sizing: set PROVE_MEM to roughly 80% of RAM. MemoryHigh is derived at 85%
# of that so the kernel throttles and reclaims *before* the hard cap, which
# is often enough to ride out a spike without killing anything.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

# --- defaults -------------------------------------------------------------
# Cap defaults to ~80% of physical RAM, so this works unmodified on both the
# 60 GB and the 251 GB machine.
if [[ -z "${PROVE_MEM:-}" ]]; then
    mem_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    PROVE_MEM="$(( mem_kb * 80 / 100 / 1024 / 1024 ))G"
fi
PROVE_SWAP="${PROVE_SWAP:-16G}"
PROVE_JOBS="${PROVE_JOBS:-0}"        # 0 = all cores
PROVE_LEVEL_ARGS=()
[[ "$*" == *"--level"* ]] || PROVE_LEVEL_ARGS=(--level=1)

# MemoryHigh at 85% of the cap: throttle before killing.
high_num="${PROVE_MEM%G}"
PROVE_HIGH="$(( high_num * 85 / 100 ))G"

# Proof-only configuration pragmas. SPARK refuses to analyse a protected
# object without a concurrency profile (SPARK RM 9(2)), and SPARKTLS.
# Session_Cache is exactly that. The pragmas live here rather than in
# sparktls.gpr because pragma Profile is partition-wide: in the project file
# it would impose Ravenscar/Jorvik on every consumer of the library. Passed
# via -cargs, it reaches gnatprove and never `alr build`. See ci/proof.adc.
#
# -cargs consumes everything after it, so this must come last -- which also
# means a caller supplying its own -cargs would be overridden. Detect that
# and let the caller win, since it is doing something deliberate.
PROVE_CARGS=(-cargs "-gnatec=${ROOT}/ci/proof.adc")
if [[ "$*" == *"-cargs"* ]]; then
    echo "== NOTE: caller passed -cargs; ci/proof.adc NOT applied."
    echo "   Session_Cache will fail SPARK legality (needs pragma Profile)."
    echo "   Add -gnatec=${ROOT}/ci/proof.adc to your own -cargs group."
    PROVE_CARGS=()
fi

GNATPROVE_ARGS=(
    -j"${PROVE_JOBS}"
    "${PROVE_LEVEL_ARGS[@]}"
    --counterexamples=off
    --output=oneline
    "$@"
    "${PROVE_CARGS[@]}"
)

# --- containment ----------------------------------------------------------
# Prefer a user-scope cgroup (no sudo). Requires the memory controller to be
# delegated to the user slice — true on modern systemd, verify with:
#   cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers
RUNNER=()
if command -v systemd-run >/dev/null 2>&1 &&
   systemd-run --user --scope -p MemoryMax=1G -q /bin/true >/dev/null 2>&1; then
    RUNNER=(systemd-run --user --scope --quiet
            -p "MemoryMax=${PROVE_MEM}"
            -p "MemoryHigh=${PROVE_HIGH}"
            -p "MemorySwapMax=${PROVE_SWAP}")
    echo "== contained: MemoryMax=${PROVE_MEM} MemoryHigh=${PROVE_HIGH} MemorySwapMax=${PROVE_SWAP}"
else
    echo "== WARNING: no user-scope cgroup available; running UNCONTAINED."
    echo "   A runaway solver can OOM-kill the machine. See ci/README.md."
fi

echo "== gnatprove ${GNATPROVE_ARGS[*]}"
echo "== started $(date '+%F %T')"

if [[ -n "${PROVE_TEE:-}" ]]; then
    "${RUNNER[@]}" alr gnatprove "${GNATPROVE_ARGS[@]}" 2>&1 | tee "${PROVE_TEE}"
else
    "${RUNNER[@]}" alr gnatprove "${GNATPROVE_ARGS[@]}"
fi

echo "== finished $(date '+%F %T')"
