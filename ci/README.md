# Reproducible Build and Test

This directory contains the command surface used by CI and by local
reproduction through `nix develop`.

## Default CI Lane

Run:

```sh
nix develop --command bash ci/check.sh
```

This prints tool versions and runs the full release-mode suite:

- `tests/run_all.sh`

That covers build, unit, integration, protocol, and x509-limbo checks. The
GitHub Actions workflow runs this lane on both x86_64 and aarch64 Linux.

## Timing Lane

Run:

```sh
nix develop --command bash ci/timing.sh ctgrind
```

The GitHub Actions workflow runs `ci/timing.sh all` as a separate x86_64 job,
covering both ctgrind and dudect. This lane is kept off ARM because the ctgrind
harness is currently x86_64-only: its project file pins baseline x86 code
generation to keep Valgrind away from unsupported AVX-512 instructions.

## Proof

GNATprove is intentionally not part of the default CI gate. Full-project proof
is too expensive and too dependent on prover/toolchain details for normal pull
requests. Keep proof as a manual or scheduled workflow with saved artifacts.

### Always run proofs through `ci/prove.sh`

```sh
ci/prove.sh                                        # full project, level 1
ci/prove.sh -u sparktls-client.adb                 # one unit
ci/prove.sh --level=3 -u rflx-tls_handshake-server_hello.adb
PROVE_TEE=findings_$(date +%b_%d).txt ci/prove.sh  # tee to a findings file
```

Extra arguments pass straight through to `gnatprove`.

**Why the wrapper exists.** `gnatprove`'s own `--memlimit` is not reliably
enforced — solvers have been seen at 5.2 GB RSS against a 2000 MB limit. When
several spike at once this triggers a *system-wide* OOM kill and takes the
machine down (90 such events in one box's kernel log). `ci/prove.sh` runs
gnatprove inside a user-scope cgroup, so the kernel kills a solver *inside the
scope* instead of choosing a victim across the system. You lose one VC, not
the workstation.

No `sudo` is required, but the memory controller must be delegated to the user
slice. Verify with:

```sh
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers   # want: memory
```

If it is unavailable the script warns and runs uncontained rather than
failing.

**Sizing.** Defaults derive from the machine, so the same script works
everywhere: `MemoryMax` = 80% of RAM, `MemoryHigh` = 85% of that (the kernel
throttles and reclaims before the hard cap, which often rides out a spike
without killing anything), `MemorySwapMax` = 16 GB. Override with
`PROVE_MEM`, `PROVE_SWAP`, `PROVE_JOBS`, `PROVE_TEE`.

**Swap matters too.** The cgroup cap bounds the blast radius; swap absorbs
transient spikes so they degrade to slow rather than fatal. A 60 GB box with
an 8 GB swapfile has very little cushion. To resize (do this with no proof
run in flight):

```sh
sudo swapoff /swap.img
sudo fallocate -l 64G /swap.img
sudo chmod 600 /swap.img
sudo mkswap /swap.img
sudo swapon /swap.img
```

`/etc/fstab` already references `/swap.img`, so it persists across reboots.

**Reading results.** Owned findings are everything not from RecordFlux or
SPARKNaCl:

```sh
grep -v "rflx-\|sparknacl" findings_X.txt | grep -cE "medium:|high:"
```

Note that per-VC results can be load-dependent: a marginal VC that proves in
an isolated `-u` run may miss the `--timeout=180` set in `sparktls.gpr` during
a saturated full-project run. When a finding matters, re-verify that unit in
isolation before treating it as real.
