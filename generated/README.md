# Generated parser/builder code

Output of `rflx generate -d generated/ specs/*.rflx` against AdaCore's
[RecordFlux](https://github.com/AdaCore/RecordFlux) (Apache-2.0; see
`../NOTICE`).

Generated with **RecordFlux 0.26.0**. Keep this directory in sync with
`../specs/` — see "Checking for drift" below.

After regeneration, re-apply these patches:

1. **`rflx-rflx_generic_types.ads`**: delete the `with
   Ada.Unchecked_Deallocation;` line and the `Free` instantiation. We
   provide `RFLX_Free` in `src/sparktls-handshake-server_msgs.adb` (and
   similar) instead, in a `SPARK_Mode => Off` body.

   **The old rationale for this was wrong** and is worth re-testing.
   It used to read "`Unchecked_Deallocation` only takes `access all`, so
   it stops compiling once `Bytes_Ptr` is pool-specific". That is not
   true: a pristine 0.26.0 generation contains *both* `type Bytes_Ptr is
   access Bytes` and `procedure Free is new Ada.Unchecked_Deallocation
   (Object => Bytes, Name => Bytes_Ptr)`, and passes `gnatprove
   --mode=check` over 106 units with zero errors. Our own
   `Free_Byte_Seq` in `src/sparktls.adb` also instantiates
   `Unchecked_Deallocation` inside a `SPARK_Mode => On` body. So this
   patch may be unnecessary; dropping it would let us delete the
   `SPARK_Mode => Off` `RFLX_Free` wrappers, which are real gaps in the
   verification story. Not yet tested for *proof* impact (only
   legality/flow), so it stays applied until someone measures it.

2. **`rflx-tls_handshake-server_hello.ads`**: add a `Buffer /= null and then`
   guard before each of the 8 `Buffer.all (RFLX_Types.To_Index ...)` slices in
   the context `Dynamic_Predicate` (around lines 1720, 1729, 1738, 1747, 1829,
   1836, 1843, 1850 — the HelloRetryRequest sentinel comparisons).

   Apply with:

   ```sh
   python3 - <<'EOF'
   import re
   p = 'generated/rflx-tls_handshake-server_hello.ads'
   s = open(p, encoding='utf8').read()
   # NB: exclude "Ctx.Buffer.all" (~line 2195) — that is a Bytes-valued
   # expression in a function body, not a boolean conjunct; guarding it is a
   # type error and will not compile.
   pat = re.compile(r'(?<!Ctx\.)\bBuffer\.all \(RFLX_Types\.To_Index')
   assert len(pat.findall(s)) == 8
   open(p, 'w', encoding='utf8').write(
       pat.sub('Buffer /= null and then Buffer.all (RFLX_Types.To_Index', s))
   EOF
   ```

   **Why.** RecordFlux 0.26.0 emits those dereferences with no null guard.
   After `Take_Buffer` — a legitimate, intended use — `Buffer` is null and the
   predicate is not merely false but *unevaluable*. Consequences:

   * Any build with assertions on (`-gnata`, i.e. `tests/run_all.sh --checked`)
     dies with `access check failed` at `server_hello.ads:1729` on the first
     real ServerHello. Reproduce with `bin/examples/tls_fetch https://github.com/`
     built `--checked`. Release builds are unaffected: predicates are not
     evaluated.
   * GNATprove cannot discharge the 8 pointer-dereference checks, and the
     failure cascades into the predicate checks at every use of the type.

   **Measured effect** (chungus, level 1, same tree before and after):
   `server_hello` went from **74 unproved to 28**. All 8 pointer-dereference
   checks were eliminated; predicate checks fell 26 -> 15 and preconditions
   27 -> 4. Reproduced qualitatively on the primary box (the exact counts
   there were taken under contention and are not citable).

   **Not fixed by this patch:** 8 `range check might fail` remain on the same
   slices. Those need the buffer-bounds invariant relating
   `Cursors (F_Random).First/.Last` to `Buffer.all'Range`, which non-nullness
   alone does not give. Level 3 does not help (74 -> 70 unguarded).

   This is a workaround for an upstream defect. Report it to AdaCore and drop
   the patch once fixed; `rflx generate` will silently discard it otherwise,
   and the proofs will regress with no obvious cause.

### Formerly patch 1 — `Bytes_Ptr` — NO LONGER NEEDED

This directory used to document changing `type Bytes_Ptr is access all
Bytes;` to `type Bytes_Ptr is access Bytes;`. **RecordFlux 0.26.0 emits
the pool-specific form natively.** Diffing our
`rflx-rflx_builtin_types.ads` against a pristine regeneration shows the
only difference is an explanatory comment; the declaration is identical.
Do not re-apply anything here.

### Checking for drift

`generated/` had silently drifted from `specs/` (found 2026-08-14).
`rflx-tls_handshake.ads` and `rflx-tls_handshake-client_hello.{ads,adb}`
were missing the `Get_Legacy_Compression_Methods_Length` value-tracking
conjuncts that the current spec produces. Cause: commit `c09330a`
widened `Legacy_Compression_Methods_Length` from `range 1 .. 1` to
`range 1 .. 255` (needed so the server parses TLS 1.2 ClientHellos
offering multiple compression methods) but edited the generated type and
its `Valid_` predicate **by hand instead of regenerating**. Widening the
range made the value non-static, so RecordFlux would have emitted ~13
value-tracking conjuncts — a hand-edit cannot know that. Their absence
left `Field_Size (Ctx, F_Legacy_Compression_Methods)` underdetermined and
blocked four proofs in `SPARKTLS.Handshake.Client_Msgs`.

Never hand-edit generated code to track a spec change. To check for
drift:

```sh
rflx generate -d /tmp/rflx_check ../specs/*.rflx
diff <(grep -v "Generated by RecordFlux" <file>) \
     <(grep -v "Generated by RecordFlux" /tmp/rflx_check/<file>)
```

(ignore the `Generated by RecordFlux ... on <date>` header line)

### Known upstream defect (RecordFlux 0.26.0)

The generated context `Dynamic_Predicate` dereferences `Buffer.all`
without a null guard — e.g. `rflx-tls_handshake-server_hello.ads` lines
1720/1729/1738/1747/1829/1836/1843/1850, comparing the Random field
against the HelloRetryRequest sentinel. After `Take_Buffer` (legitimate
use) `Buffer` is null, so the predicate is not evaluable. Consequences:

* Any build with assertions on (`-gnata`, i.e. `run_all.sh --checked`)
  dies with `access check failed` on the first real ServerHello. Release
  builds are unaffected — predicates are not evaluated.
* GNATprove cannot discharge the corresponding `predicate check might
  fail` VCs, so proofs over these contexts rest on an assumption that
  cannot be established.

Not yet reported upstream. A local null guard would fix both but means
patching 8 sites in generated code — decide deliberately.
