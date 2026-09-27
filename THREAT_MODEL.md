# Threat Model

What SparkTLS defends against below the protocol: timing, caches,
speculation, power and memory faults. What the code does, what your
platform must do, and what nobody here claims. Protocol-level attacks are in
`ATTACK_COVERAGE.md`.

Covers `sparktls` and the crypto it ships with: `sparktlscrypto`,
`sparkmlkem` and SPARKNaCl. The target is x86_64 Linux.

## Assumptions

- The attacker controls the network and may run unprivileged code on the
  same machine, including on the sibling hyperthread, or in a neighbouring
  VM.
- The attacker cannot run code inside your process. Anything that can read
  your memory can read your keys.
- The kernel, hypervisor and firmware are trusted and patched.
- Your process is the only user of its keys. Private keys live in its memory
  unless you use an external signer (`Config.Sign`).

## What the proofs buy

SPARK proves the library free of out-of-bounds access, overflow and
uninitialised reads. A Heartbleed-class leak cannot happen here. The proofs
say nothing about timing, power or hardware faults; the rest of this
document does.

Not covered by proof: the inline-assembly tiers (`SPARK_Mode => Off`), which
are checked by differential fuzzing against their proven SPARK twins, and
two conventions held by review rather than proof: RecordFlux buffers are not
touched while borrowed, and the session cache is initialised before use.

## Constant time

Every operation on secret data is branch-free and address-fixed:

- No branch or memory index depends on a secret. Tables (P-256 and
  Curve25519 fixed base) are read in full and selected with masks.
- Software AES computes its S-box arithmetically. No lookup tables.
- The assembly tiers use only instructions on Intel's data-operand-
  independent timing (DOIT) list. No division, no variable shifts on
  secrets.

This is checked, not asserted. See [How it is checked](#how-it-is-checked).

## Microarchitectural classes

| Class | What the code does | What the platform must do |
|---|---|---|
| Cache and TLB timing | Secret-independent addresses. | Nothing. |
| Branch timing, SMT port contention (PortSmash) | Secret-independent branches and instruction stream. | Nothing required. Disable SMT or avoid untrusted co-tenants for depth. |
| Data-dependent instruction latency | DOIT-listed instructions only in assembly. | Intel Ice Lake and later: enable DOITM. The library does not. |
| Speculative execution (Spectre, MDS, Retbleed, Inception) | Nothing. No speculation barriers in the library. | Current microcode and kernel mitigations. SMT off where MDS-class leaks matter. |
| Vector register leaks (Zenbleed, Downfall) | AES, GHASH and ChaCha20 keys pass through vector registers. No gather instructions. | Microcode fixes for Zenbleed (AMD Zen 2) and Downfall (Intel). |
| Power and frequency (Hertzbleed, Platypus) | RSA: exponent blinding. P-256, P-384 ECDSA and ECDH: scalar blinding and projective randomisation. X25519 and ML-KEM keys are single-use. Ed25519: not blinded. | Restrict RAPL energy counters to root (default on patched kernels). |
| Data-memory-dependent prefetchers (GoFetch, Augury) | Blinding randomises RSA and ECDSA intermediates. Ed25519: not blinded. | Intel: DOITM also disables the DMP on Raptor Lake. Apple silicon is untested. |
| Rowhammer, RAMBleed | Fault checks: RSA verifies after signing; ECDSA re-checks [k]G is on the curve. Ed25519 and ECDSA nonces are deterministic, but every message TLS signs carries our own fresh randoms, so a fault never pairs with a repeat. Keys rest in memory in the clear. | ECC memory. Target-row refresh. Or keep keys out of process with `Config.Sign`. |

## Secrets at rest in memory

- **Session keys** are zeroed when the session closes, fails
  (`Enter_Error_State`) or is dropped.
- **Handshake secrets** (ECDHE and ML-KEM private keys, the key schedule,
  the transcript) are zeroed when the handshake ends, successfully or not.
- **Stack temporaries** holding secrets are zeroed with
  `SPARKNaCl.Sanitize`, which the compiler cannot elide.
- **Identity private keys** live as long as your application holds them.
  To keep them out of the process entirely, sign in an HSM, TPM or separate
  process through `Config.Sign`.

Your job: `mlock` key pages, exclude them from core dumps
(`MADV_DONTDUMP`), disable core dumps in production, and encrypt swap.

## Randomness

All randomness comes from `SPARKTLS.RBG`: an HMAC_DRBG seeded from the
SPARKEntropy jitter source, never the OS. After `fork` or a VM snapshot
restore, call `RBG.Reseed`, or two processes will share a random stream.

## Residual risks

- **Ed25519 signing** is not blinded. Its nonce hash mixes the secret key
  prefix with the transcript, a known target for power analysis with a
  probe on the device (out of scope). Signatures stay deterministic, as
  FIPS 186-5 requires; TLS never signs the same message twice, which is
  what the deterministic-nonce fault attack needs.
- **Identity keys in the clear.** Encrypting them in memory between uses
  (OpenSSH-style key shielding) was deferred in favour of the external
  signer, which keeps the key out of the process altogether.
- **No speculation hardening.** The library relies entirely on the platform.

## Out of scope

- Code running in your process, or a compromised kernel or hypervisor.
- Physical access: probing, EM or power measurement with lab equipment,
  cold boot, fault injection by glitching.
- Confidential-computing threat models (SEV-SNP, TDX) where the host is
  hostile.
- Platforms other than x86_64 Linux. Other builds may work; they are not
  evaluated.

## How it is checked

| Check | What it catches | Where |
|---|---|---|
| ctgrind (Valgrind memcheck with secrets poisoned) | Any branch or index on a secret, in the compiled binary. A planted-leak canary must fail. | `ci/timing.sh ctgrind` in sparktls, sparktlscrypto, sparkmlkem |
| dudect | Timing differences in the optimised build, including tiers Valgrind cannot run. Canary as above. | `ci/timing.sh dudect`, same crates |
| Instruction allowlist | Any non-DOIT mnemonic in an assembly tier. | `ci/mnemonics.sh` (sparktlscrypto) |
| Differential fuzzing | Assembly tiers disagreeing with their proven SPARK twins, including carry edge cases. | `ci/fuzz.sh` (sparktlscrypto) |
| Stack residue scan | Secret fragments left on the stack after a primitive returns. | `ci/check.sh` (sparktlscrypto, sparkmlkem) |

To run on proven SPARK only, with no assembly tiers, build sparktlscrypto
with `SPARKTLSCRYPTO_ASM=disabled`.
