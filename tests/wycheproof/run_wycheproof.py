#!/usr/bin/env python3
"""Run Wycheproof test vectors against bin/tests/wycheproof_runner.

Usage:
    run_wycheproof.py <wycheproof_dir> [vector_set ...]

vector_set is the JSON filename without extension (e.g.
'rsa_signature_2048_sha256_test'). When omitted, runs the curated
default set we care about for SPARKTLS.

Exit code 0 if all required vectors pass; 1 otherwise. 'acceptable'
results count as pass either way (Wycheproof flags them as legal but
optional behaviour).
"""

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Vector sets we care about, mapped to runner command + arg builders.
# Each entry: (json_file, runner_cmd, build_args(group, test) -> list[str])

def rsa_args(sha_len):
    def build(group, test):
        pk = group['publicKey']
        modulus = pk['modulus']
        # Wycheproof JSON sometimes uses 'publicExponent' (hex), sometimes int.
        e = pk.get('publicExponent', '010001')
        if isinstance(e, int):
            e = format(e, 'x')
        # Hash msg with the right SHA. We do this in Python to keep the
        # runner small. SPARKTLSCrypto SHAs are validated separately.
        import hashlib
        h = {32: 'sha256', 48: 'sha384', 64: 'sha512'}[sha_len]
        msg_bytes = bytes.fromhex(test['msg'])
        digest = hashlib.new(h, msg_bytes).hexdigest()
        return [modulus, e, digest, test['sig']]
    return build


def ecdsa_args(sha_len):
    def build(group, test):
        pk = group['publicKey']
        msg = test['msg']
        return [pk['wx'], pk['wy'], msg if msg else '_', test['sig']]
    return build


def ed25519_args(group, test):
    pk = group.get('publicKey', {})
    pk_hex = pk.get('pk') or group.get('key', {}).get('pk', '')
    msg = test['msg']
    return [pk_hex, msg if msg else '_', test['sig']]


def _empty_to_sentinel(s):
    """Replace empty hex fields with '_' so space-separated parsing
    doesn't collapse adjacent fields."""
    return s if s else '_'


def aes_gcm_args(group, test):
    # Filter to TLS-spec parameters: 96-bit IV, 128-bit tag, 128/256-bit
    # key. Wycheproof exercises the full NIST GCM spec (varying IV/tag
    # sizes) but TLS_*_GCM_* uses only the canonical 96/128 sizes.
    if group.get('ivSize') != 96 or group.get('tagSize') != 128:
        return None
    if group.get('keySize') not in (128, 256):
        return None
    return [_empty_to_sentinel(test.get('key', '')),
            _empty_to_sentinel(test.get('iv', '')),
            _empty_to_sentinel(test.get('aad', '')),
            _empty_to_sentinel(test.get('ct', '')),
            _empty_to_sentinel(test.get('tag', ''))]


def chacha_poly_args(group, test):
    # ChaCha20-Poly1305 in TLS uses 256-bit key, 96-bit nonce, 128-bit tag
    # (RFC 7539 / RFC 8439). Filter to that.
    if group.get('keySize') != 256 or group.get('ivSize') != 96 \
       or group.get('tagSize') != 128:
        return None
    return [_empty_to_sentinel(test.get('key', '')),
            _empty_to_sentinel(test.get('iv', '')),
            _empty_to_sentinel(test.get('aad', '')),
            _empty_to_sentinel(test.get('msg', '')),  # plaintext
            _empty_to_sentinel(test.get('ct', '')),
            _empty_to_sentinel(test.get('tag', ''))]


SET_SPECS = {
    'rsa_signature_2048_sha256_test':
        ('rsa_pkcs1_sha256', rsa_args(32)),
    'rsa_signature_2048_sha384_test':
        ('rsa_pkcs1_sha384', rsa_args(48)),
    'rsa_signature_2048_sha512_test':
        ('rsa_pkcs1_sha512', rsa_args(64)),
    'rsa_signature_3072_sha256_test':
        ('rsa_pkcs1_sha256', rsa_args(32)),
    'rsa_signature_4096_sha512_test':
        ('rsa_pkcs1_sha512', rsa_args(64)),
    'rsa_pss_2048_sha256_mgf1_32_test':
        ('rsa_pss_sha256', rsa_args(32)),
    'rsa_pss_2048_sha384_mgf1_48_test':
        ('rsa_pss_sha384', rsa_args(48)),
    'rsa_pss_3072_sha256_mgf1_32_test':
        ('rsa_pss_sha256', rsa_args(32)),
    'rsa_pss_4096_sha512_mgf1_64_test':
        ('rsa_pss_sha512', rsa_args(64)),
    'ecdsa_secp256r1_sha256_test':
        ('ecdsa_p256_sha256', ecdsa_args(32)),
    'ecdsa_secp384r1_sha384_test':
        ('ecdsa_p384_sha384', ecdsa_args(48)),
    'ed25519_test':
        ('ed25519', ed25519_args),
    'aes_gcm_test':
        ('aes_gcm_decrypt', aes_gcm_args),
    'chacha20_poly1305_test':
        ('chacha_poly_kat', chacha_poly_args),
}


def run_set(json_path, runner_path):
    with open(json_path) as f:
        data = json.load(f)
    fname = json_path.stem
    if fname not in SET_SPECS:
        return None
    cmd, build_args = SET_SPECS[fname]

    # Build the full command stream.
    lines = []
    expected = []
    tcs = []
    for group in data['testGroups']:
        for test in group['tests']:
            try:
                args = build_args(group, test)
            except (KeyError, TypeError):
                continue
            if args is None:
                continue  # group filtered out
            lines.append(f"{cmd} {' '.join(args)}\n")
            expected.append(test['result'])  # valid|invalid|acceptable
            tcs.append(test['tcId'])
    if not lines:
        return None

    # Pipe all commands to the runner in one shot.
    proc = subprocess.run(
        [str(runner_path)],
        input=''.join(lines),
        capture_output=True,
        text=True,
        timeout=300)
    if proc.returncode != 0:
        print(f"  runner exit {proc.returncode}: {proc.stderr[:200]}",
              file=sys.stderr)
    actual_lines = proc.stdout.strip().split('\n')

    pass_count = 0
    fail_count = 0
    fail_examples = []
    for tc, exp, act in zip(tcs, expected, actual_lines):
        if exp == 'acceptable':
            # Either reply is fine.
            pass_count += 1
        elif exp == 'valid' and act == 'valid':
            pass_count += 1
        elif exp == 'invalid' and act == 'invalid':
            pass_count += 1
        else:
            fail_count += 1
            if len(fail_examples) < 5:
                fail_examples.append(f"tcId={tc} expected={exp} got={act}")
    return (fname, pass_count, fail_count, fail_examples)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    wp_dir = Path(sys.argv[1])
    requested = sys.argv[2:] if len(sys.argv) > 2 else list(SET_SPECS.keys())

    runner = (Path(__file__).resolve().parent / '..' / '..'
              / 'bin' / 'tests' / 'wycheproof_runner').resolve()
    if not runner.exists():
        print(f"runner not found: {runner}", file=sys.stderr)
        return 2

    vectors_dir = wp_dir / 'testvectors_v1'
    if not vectors_dir.is_dir():
        print(f"testvectors_v1 not found in {wp_dir}", file=sys.stderr)
        return 2

    total_pass = 0
    total_fail = 0
    sets_run = 0
    sets_with_fail = 0

    for s in requested:
        path = vectors_dir / f'{s}.json'
        if not path.exists():
            print(f"  SKIP {s}: not found")
            continue
        result = run_set(path, runner)
        if result is None:
            print(f"  SKIP {s}: no spec")
            continue
        fname, p, f, examples = result
        sets_run += 1
        total_pass += p
        total_fail += f
        status = 'PASS' if f == 0 else 'FAIL'
        print(f"  {status} {fname}: {p}/{p+f} passed, {f} failed")
        if examples:
            sets_with_fail += 1
            for e in examples:
                print(f"      {e}")

    print()
    total = total_pass + total_fail
    print(f"=== Wycheproof: {total_pass}/{total} passed,",
          f"{total_fail} failed across {sets_run} vector sets ===")
    return 0 if total_fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
