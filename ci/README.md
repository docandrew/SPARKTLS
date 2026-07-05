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
