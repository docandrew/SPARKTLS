# SparkTLS test lanes

`tests/run_all.sh [lane ...]` runs the lanes below and closes with one
results table (also written to `tests/_results/last_run.txt`). Every lane
prints exactly one summary line in the same shape:

    === <lane>: <passed>[/<total>] passed, <failed> failed[, <known> known][, <skipped> skipped] ===

`failed` is what the lane's baseline does **not** cover, so it is the number
that matters: a lane fails the run only on a regression. `known` is the
size of the documented baseline. A lane with no summary line did not run to
the end and is reported as failed.

| Lane | What it runs | Time | Needs | Baseline (known failures) |
|------|--------------|------|-------|---------------------------|
| `unit` | every program in `tests/unit/unit_tests.gpr` (list is read from the project file, so nothing can be built-but-never-run) plus `test_prf12`; then Wycheproof and NIST CAVP vectors; then the real-world CA-chain checks when the network is reachable | 1 min | OpenSSL, python3, curl | none: all must pass |
| `cli` | `sparktls_cli`: every subcommand for ed25519, P-256 and P-384; each output parsed and verified by OpenSSL, plus a handshake with the CLI-issued certificate (`tests/cli`) | 15 s | OpenSSL | none |
| `integration` | SparkTLS client and server against OpenSSL: every cert type, suite and group on both versions, resumption, mTLS, OCSP, CRL, HRR, DoS caps, abandoned handshakes | 8 min | OpenSSL, python3 | none |
| `protocol` | tlsfuzzer scripts against `tls_blocking_server` (`tests/protocol/run.sh`) | 3 min | python3 (venv is created on first run) | classification `case` in `run.sh`, one reason per script |
| `x509` | x509-limbo corpus, then NIST PKITS (needs the BoGo cache for the PKITS data) | 4 min | python3 | `tests/x509/EXPECTED_FAILURES.txt`, `tests/x509/PKITS_EXPECTED_FAILURES.txt` |
| `bogo` | BoringSSL's BoGo runner against `tests/bogo/bogo_shim` | 2 min (10 min first-time setup) | Go (fetched if missing), git | `tests/bogo/EXPECTED_FAILURES.txt`; out-of-scope globs in `run.sh` |
| `fuzz` (opt-in) | replays the fuzz seed corpora through the checked parsers | 1 min | build of `tests/fuzz` | none |
| `tlsanvil` (opt-in) | TLS-Anvil via docker against `tls_blocking_server` | 30 min | docker | `tests/tlsanvil/EXPECTED_FAILURES.txt` |

Default lanes: `unit cli integration protocol x509 bogo`, followed by a second
pass with runtime checks and contracts on (`--checked`, see the header of
`run_all.sh`). `NO_CHAIN=1` skips the second pass.

## Baselines

A count cannot tell one fixed case from one broken case, so every lane with
documented failures diffs the run against a list of names. New failures
are printed under `!!! REGRESSION` and fail the lane; newly passing cases
are printed under `>>>` with the command that refreshes the list. Refresh
only after reading the diff, and say why in the commit: the comment blocks
at the top of `tests/bogo/EXPECTED_FAILURES.txt` are the model.

    tests/bogo/run.sh --update-baseline
    tests/x509/run.sh --update-baseline
    tests/tlsanvil/run.sh --update-baseline
    tests/x509/PKITS_EXPECTED_FAILURES.txt   (edit by hand; keyed "<test number> <title>")

## Pinned dependencies

CI checks out only this repository. Everything else it tests against is
fetched at a **commit pin**, never a branch head:

| What | Pin | Bump procedure |
|---|---|---|
| sparkx509, sparktlscrypto, sparkentropy | `*_REF` in `ci/fetch-deps.sh` | After the sibling commit is **pushed**, set the SHA (check with `git ls-remote <url> refs/heads/<branch>`), run the affected lanes locally against that checkout, commit the bump with the sparktls change that needs it. |
| x509-limbo corpus | `LIMBO_REF` in `tests/x509/generate.sh` | Delete `tests/x509/x509-limbo` and `tests/x509/generated`, run `tests/x509/run.sh`, triage every new failure into `EXPECTED_FAILURES.txt` (annotated, corpus SHA in the header) or fix it, update the README numbers, commit pin and baseline together. |

Unpinned, CI silently tests code and corpora the local box never ran: on
2026-09-15 the sibling heads were ahead of the local checkouts and the
corpus had grown by seven cases the baseline had never seen. A sibling
commit that sparktls depends on is not done until the pin here moves.

## Reproducing one case

    # BoGo: one or more test-name globs, results in tests/bogo/_cache/last_results.log
    BOGO_PIPE=1 tests/bogo/run.sh -test "Resume-Server-NoPSKBinder*;KeyUpdate-*"
    BOGO_SHIM_TRACE=/tmp/shim.trace tests/bogo/run.sh -test "Name"   # per-record trace from the shim

    # tlsfuzzer: one or more script names; per-script logs in tests/protocol/logs/<run id>/
    tests/protocol/run.sh keyupdate chacha20
    # a single conversation of one script, straight from the venv:
    PYTHONPATH=tests/protocol/tlsfuzzer tests/protocol/.venv/bin/python \
        tests/protocol/tlsfuzzer/tlsfuzzer/_apps/test_tls13_keyupdate.py -h localhost -p 8443 "app data split, conversation with KeyUpdate msg"

    # x509-limbo: the validator directly on a generated case
    bin/tests/x509_validate tests/x509/generated/<id>/peer.pem tests/x509/generated/<id>/trust.pem --hostname example.com

    # PKITS: one section
    python3 tests/x509/pkits_runner.py tests/bogo/_cache/boringssl/pki/testdata/nist-pkits bin/tests/x509_validate --section 4.14

    # TLS-Anvil: one test class; per-test JSON under <output>/results/<id>/_testRun.json
    TLSANVIL_OUTPUT_DIR=/tmp/anvil tests/tlsanvil/run.sh   # then rerun the container with -tags <TestClass> if needed
    python3 tests/tlsanvil/summarize.py /tmp/anvil --expected tests/tlsanvil/EXPECTED_FAILURES.txt

    # integration: run.sh is a flat script; copy the block for the case and
    # run it with SPARKTLS_PORT set, or drive the example binaries by hand:
    SPARKTLS_PORT=8443 bin/examples/tls_blocking_server tests/certs/rsa.crt tests/certs/rsa.key
    bin/examples/tls_fetch --port 8443 ...

## The example server under test

`tls_blocking_server` is what tlsfuzzer and TLS-Anvil talk to. It handles
one connection per task, echoes application data back one line at a time
once its input is drained (so a partial HTTP request is answered after the
KeyUpdate that follows it, as a real server would), and reads these
variables:

    SPARKTLS_PORT=N            listen port (8443)
    SPARKTLS_RECV_TIMEOUT=S    per-connection receive timeout in seconds (30; the harnesses use 5)
    SPARKTLS_TRACE=1           one line per connection accepted and finished

Every connection ends with `SPARKTLS.Drop`, which hands the handshake
slot back to the server's `Handshake_Pool` when a peer disconnects
mid-handshake. A server that forgets this stops answering once as many
such peers as the pool has slots (64 in `tls_blocking_server`) have gone,
which is how every TLS-Anvil test came back "disabled" on 2026-09-14.

`tls_web_epoll` is the event-driven reference. It runs one or more worker
tasks, each an epoll loop with its own connection table and handshake
pool, both allocated at start-up. The workers share one listening socket,
which each watches (`EPOLLEXCLUSIVE`) only while it has a free connection
entry and a free handshake slot, so connections queue in the backlog
rather than being refused. Each worker keeps a per-connection handshake
deadline and idle timeout, swept once a second, and Drops whatever is past
them: the library is sans-I/O and cannot see a silent peer, so the
application's loop has to. Its variables:

    SPARKTLS_PORT=N               listen port (8443)
    SPARKTLS_WORKERS=N            worker tasks (1)
    SPARKTLS_MAX_CONNECTIONS=N    open connections per worker (256)
    SPARKTLS_HANDSHAKE_SLOTS=N    handshakes in flight per worker (64)
    SPARKTLS_HANDSHAKE_TIMEOUT=S  seconds from accept to handshake done (10)
    SPARKTLS_IDLE_TIMEOUT=S       seconds between requests (60)

`tls_web_uring` is the same server on Linux io_uring: completion-based I/O
in place of readiness, through `examples/io_uring.ads`, a pure-Ada binding
to the kernel interface (no liburing, no C). It takes the same arguments
and variables, and needs Linux 6.4 or later with io_uring enabled; the
integration lane skips it where the kernel refuses a ring. Each worker
keeps one accept outstanding on the shared listening socket only while it
has room, and each connection receives into its own buffer, so memory is
fixed at start-up as in the epoll server. `uring_selftest` exercises the
binding alone (accept, receive, send) as an echo server on the port given
as its argument; `tests/integration/echo_check.py` drives it.

## Adding a unit test program

Add the main to `tests/unit/unit_tests.gpr`; `run_all.sh` picks it up from
there. End the program with a line the normaliser understands, preferably
`=== Name: N passed, M failed ===` (`tests/support/count_results.py` lists
the older shapes it still accepts). A program that needs arguments gets a
`case` arm in the unit section of `run_all.sh`.
