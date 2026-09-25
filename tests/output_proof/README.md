# Scoped ciphertext output checks

SPARKTLS.Send_Ciphertext offers the currently queued native byte span to a
synchronous callback. The callback may accept any prefix, including zero, and
must not retain the span or access the session through another alias. Only the
accepted prefix advances the cursor. An exception leaves the cursor unchanged.
The library rejects an over-reported count even with contracts disabled.

The GNATprove fixture instantiates the generic with an arbitrary global limit,
so its min(limit, offered) return covers every accepted prefix. Generic bodies
alone are not analyzed by GNATprove; prove this instantiation instead:

    ci/prove.sh -P tests/output_proof/output_proof.gpr -u send_ciphertext_proof.adb

This proves accounting/range/frame obligations under the callback contract.
Socket behavior and callback lifetime discipline remain the application's
responsibility; the example uses a synchronous write(2).

Build tests/unit/checked_output.gpr with SPARKTLS and SPARKTLSCRYPTO contracts
and runtime checks enabled, then run test_send_ciphertext. It compares every
offered byte with Drain_Ciphertext on an independent reference session across
zero progress, partial accepts, exceptions, buffer reuse, both roles, all cipher
suites and key updates queued after a partial send. Existing prepared-write,
AEAD-cap and TLS 1.2 checks run alongside it. Real slow-reader tests must also
exercise partial write(2) returns and EAGAIN and verify the full payload.
