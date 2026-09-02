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

# Counterexamples: OFF by default because generating them is expensive and
# yields NOTHING for a check that timed out -- a timeout has no model to
# report. Turn it on ONLY when triaging a finding that fails WITHOUT the
# "[provers reached time and memory limit]" tag: that means the prover
# DECIDED rather than gave up, so the check may be genuinely false and a
# counterexample will show you the inputs.
#   PROVE_CEX=on ci/prove.sh -u sparktls-server.adb
PROVE_CEX="${PROVE_CEX:-off}"
PROVE_LEVEL_ARGS=()
[[ "$*" == *"--level"*    ]] || PROVE_LEVEL_ARGS=(--level=1)
# Per-prover memory cap. Level 1 defaults to 1000 MB, which is the binding
# limit for most of our exhaustion findings: at 60 s / 4000 MB six of seven
# remaining Build_Client_Hello checks and 45 of 49 sparknacl-sign checks
# prove (measured 2026-09-02, cold sessions). 4000 MB x PROVE_JOBS=8 = 32 GB,
# well inside PROVE_MEM. Set explicitly here so it no longer depends on any
# dependency project's Prove package. Timeout and level are unchanged.
[[ "$*" == *"--memlimit"* ]] || PROVE_LEVEL_ARGS+=(--memlimit=4000)
# Prover set. Colibri2 (CEA, LGPL-2.1) is the solver RecordFlux routes its
# 2**N Fits_Into arithmetic to; FSF gnatprove ships its driver and config
# but not the binary. flake.nix provides it, and the gate ASSUMES the flake
# environment: a missing binary is a misconfigured run, not a reason to
# quietly prove with fewer provers (a silent downgrade would make the
# ledger incomparable). Run as: nix develop --command bash ci/prove.sh ...
if [[ "$*" != *"--prover"* ]]; then
    if ! command -v colibri2 >/dev/null 2>&1; then
        echo "== FATAL: colibri2 not on PATH. Run inside the flake: nix develop --command bash ci/prove.sh ..." >&2
        exit 1
    fi
    PROVE_LEVEL_ARGS+=(--prover=z3,cvc5,altergo,colibri2)
fi

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
    --counterexamples="$PROVE_CEX"
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
