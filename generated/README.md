# Generated parser/builder code

Output of `rflx generate -d generated/ specs/*.rflx` against AdaCore's
[RecordFlux](https://github.com/AdaCore/RecordFlux) (Apache-2.0; see
`../NOTICE`).

After regeneration, re-apply two small patches:

1. **`rflx-rflx_builtin_types.ads`**: change `type Bytes_Ptr is access
   all Bytes;` to `type Bytes_Ptr is access Bytes;` so SPARK ownership
   tracking works for our heap allocations.

2. **`rflx-rflx_generic_types.ads`**: delete the `with
   Ada.Unchecked_Deallocation;` line and the `Free` instantiation —
   `Unchecked_Deallocation` only takes `access all`, so it stops
   compiling once `Bytes_Ptr` is pool-specific. We provide `RFLX_Free`
   in `src/sparktls-handshake-server_msgs.adb` (and similar) instead,
   in a `SPARK_Mode => Off` body.
