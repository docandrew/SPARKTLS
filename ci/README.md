# Reproducible Build and Test

This directory contains the command surface used by CI and by local
reproduction through `nix develop`.

## Default CI Lane

Run:

```sh
nix develop --command bash ci/check.sh
```

This prints tool versions, builds the library, examples, and unit test
binaries, then runs:

- `tests/run_all.sh unit`
- `tests/integration/run.sh` through `ci/integration.sh`

`ci/integration.sh` is strict about unexpected regressions, but accepts the
current known integration gap: the missing `tests/integration/dos_ch_flood.py`
case, reported as `82/83 passed, 1 failed`.

## Timing Lane

Run:

```sh
nix develop --command bash ci/timing.sh ctgrind
```

The GitHub Actions workflow runs `ctgrind` as a separate job. `dudect` remains
available through `ci/timing.sh dudect`, but is not a default PR gate because it
is statistical and more host-noise-sensitive.

## Proof

GNATprove is intentionally not part of the default CI gate. Full-project proof
is too expensive and too dependent on prover/toolchain details for normal pull
requests. Keep proof as a manual or scheduled workflow with saved artifacts.
