# Generated parser/builder code

Output of `rflx generate -n -d generated/ specs/*.rflx` against AdaCore's
[RecordFlux](https://github.com/AdaCore/RecordFlux) (Apache-2.0; see
`../NOTICE`).

Generated with **RecordFlux 0.26.0**. Keep this directory in sync with
`../specs/` — see "Checking for drift" below.

Every message unit is **pristine `rflx generate` output** — never hand-edit
one, not even to track a spec change: change the spec and regenerate (see
"Checking for drift" below).

**One library file carries two hand-maintained edits (since 2026-09-05),
both in `rflx-rflx_builtin_types.ads`:**

1. It declares `subtype Byte is Interfaces.Unsigned_8;` where RecordFlux
emits `type Byte is mod 2**8;`. This makes RecordFlux's byte the same type
as SPARKNaCl's, so `Byte_Seq` and `Bytes` convert with a checked Ada array
conversion instead of an element copy (the generic's `Custom_Byte is (<>)`
formal exists for this).

2. It adds `pragma No_Strict_Aliasing (Bytes_Ptr);` after the `Bytes_Ptr`
declaration. The SPARK-Off primitives `SPARKTLS.RFLX_Borrow` and
`SPARKTLS.AEAD_InPlace` fabricate a `Bytes_Ptr` to inline storage via an
`Unchecked_Conversion` from a fat-pointer record; the pragma turns type-based
alias analysis off for this one access type so that pun cannot be miscompiled
at `-O3`, while the rest of the library keeps strict aliasing. `No_Strict_Aliasing`
takes a local name, so it must live in this file (the type's declaration unit).

Consequences:

- **Always regenerate with `-n` (`--no-library`).** It emits only the
  message units; the 15 `rflx-rflx_*` library files are left alone. A
  regeneration without `-n` silently restores RecordFlux's `Byte` (and
  reintroduces the copies) and drops the `No_Strict_Aliasing` pragma; re-apply
  both.
- **On a RecordFlux upgrade**, regenerate the library once (without `-n`)
  into a scratch directory, diff the `rflx-rflx_*` files, re-apply the
  one-line change, and check that `RFLX_Generic_Types` still requires
  `Index'First = 1` (the conversions rely on it).
- **Zero-copy conversions are written inline, in parameter positions.**
  Measured on GNAT with `-gnatG` (2026-09-05): `Byte_Seq (X)` / `Bytes (X)`
  written directly as an `in`, `in out` or `out` actual (or in an object
  renaming) is a view -- no temporary, no copy. A *function* returning the
  same conversion copies its whole result through the secondary stack, so
  `SPARKTLS.RFLX_Bridge` deliberately has no `View_As_*` helpers; its
  `To_RFLX` / `To_NaCl` are the sliding copies and are named as such.
- **Mind the direction.** `Bytes -> Byte_Seq` is always in range (`Index`
  starts at 1, `N32` at 0). `Byte_Seq -> Bytes` carries the conversion's own
  bounds check: a 0-based slice fails it. Under proof that is a VC at the
  site; under `-gnatp` it is an unchecked assumption. Keep such sites to
  genuine 0->1 seams and never suppress the check without proving it.

Two patches this file used to require are gone:

- **`rflx-rflx_generic_types.ads` `Free` deletion — not applied.** The
  generated `Free` instantiation and its `with Ada.Unchecked_Deallocation`
  are shipped as-is; `src/` provides its own `RFLX_Free` (a
  `SPARK_Mode => Off` wrapper) that the code actually calls. Switching
  those call sites to the generated `Free` would let us drop the Off-mode
  wrappers and close a small verification gap — a future cleanup, not a
  patch.
- **`server_hello.ads` sentinel `Buffer /= null` guards — moot.** The
  per-transport ServerHello (no HelloRetryRequest fork) no longer emits
  the sentinel slices those guards protected.

The historical notes below record why each was once needed.

### REJECTED — adding postconditions to expression functions (2026-08-16)

**Do not do this. It was measured and it makes proofs strictly worse.**

The idea was to "republish" facts that looked hidden, by giving RecordFlux's
query functions explicit postconditions:

* `Field_First` in `rflx-tls_handshake-client_hello.ads`, whose generated
  contract is literally `Post => True` (with a `pragma Warnings (Off,
  "postcondition does not mention function result")` around it), while the
  adjacent `Field_Size` and `Field_Last` both publish `rem Byte'Size = 0`.
  Patch added the missing symmetric case, `Field_First'Result rem
  RFLX_Types.Byte'Size = 1` (1 not 0: bit indices are 1-based, so a
  byte-aligned *start* is `rem 8 = 1`).
* `Available_Space` in the same file, and `Available_Space` / `Size` in both
  `rflx-rflx_message_sequence.ads` and `rflx-rflx_scalar_sequence.ads`,
  restating their private-part definitions.

**The premise was wrong.** These functions are declared in the public part and
*completed as expression functions in the private part*. It is true that Ada
visibility hides the completion from clients — but GNATprove does not work at
that level. It already uses the expression function's definition when proving
client code, so callers effectively had the exact value all along.

Adding an explicit `Post` therefore does not add information. It **replaces**
the strongest available contract with whatever you wrote. Writing an
alignment-only postcondition on `Field_First` bought `rem 8 = 1` and destroyed
knowledge of the *value* — which is worth far more, because `Available_Space`,
`Field_Last` and the whole size-accounting chain unfold through it.

**Measured on `SPARKTLS.Handshake.Client_Msgs` (level 1, `-u`, same tree):**

| tree | findings |
|---|---|
| pristine `generated/` | **2** — 1021 (alignment conjunct), 1023 |
| + `Field_First` and `Available_Space` posts | 3 — 1004 (new), 1021 (space conjunct), 1023 |
| + `Field_First` post only | 3 — same |

1021 never closed; it *moved* to the `Available_Space >= Field_Size` conjunct,
which had been proving fine, and 1004 broke outright. Reverted in full;
`generated/` is pristine except this file.

If the byte-alignment of `Field_First` is needed at a call site, derive it
there from the postconditions RecordFlux *does* emit (`Field_Size` and
`Field_Last` are both `rem 8 = 0`) rather than overriding a generated
contract.

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

**This is now fixed locally by patch 2 above** — the 8 sites carry a
`Buffer /= null` guard plus slice bounds, which closed all 16 native
runtime checks in the unit and unblocked the `--checked` build. The
description above is retained because it documents the upstream defect
itself, which is still **not reported to AdaCore**. Report it and drop
patch 2 once fixed.

A second, much weaker candidate defect: `Field_First` is generated with
`Post => True` while the adjacent `Field_Size` and `Field_Last` publish
`rem Byte'Size = 0`. That asymmetry looks like an omission and may be
worth mentioning upstream — but note that attempting to fix it locally
made proofs *worse*, for the reasons in "REJECTED — adding
postconditions to expression functions" above. Do not patch it here.
