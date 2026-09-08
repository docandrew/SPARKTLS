#!/usr/bin/env python3
"""Run NIST CAVP test vectors against bin/tests/wycheproof_runner.

Currently supports: ECDSA SigVer for P-256/SHA-256 and P-384/SHA-384.
The .rsp format is whitespace-separated key=value lines, with section
headers like '[P-256,SHA-256]' and results 'P' (valid) or 'F' (invalid).

CAVP ECDSA SigVer feeds raw Msg bytes (not hash) — we hash on the
Python side so the runner stays SHA-agnostic.
"""

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path


def parse_rsp(path):
    """Yield (section_label, dict_of_fields) tuples per test case."""
    section = None
    fields = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                if fields:
                    yield section, fields
                    fields = {}
                continue
            if line.startswith('[') and line.endswith(']'):
                if fields:
                    yield section, fields
                    fields = {}
                section = line[1:-1]
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                fields[k.strip()] = v.strip()
        if fields:
            yield section, fields


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    rsp_path = Path(sys.argv[1])
    if not rsp_path.exists():
        print(f"Not found: {rsp_path}", file=sys.stderr)
        return 2
    runner = (Path(__file__).resolve().parent / '..' / '..'
              / 'bin' / 'tests' / 'wycheproof_runner').resolve()
    if not runner.exists():
        print(f"runner not found: {runner}", file=sys.stderr)
        return 2

    # Map (curve, sha) → runner command.
    SUPPORTED = {
        ('P-256', 'SHA-256'): 'ecdsa_p256_sha256',
        ('P-384', 'SHA-384'): 'ecdsa_p384_sha384',
    }

    lines = []
    expected = []
    sections_seen = {}
    for section, fields in parse_rsp(rsp_path):
        if not section:
            continue
        m = re.match(r'(P-\d+),(SHA-\d+)', section)
        if not m:
            continue
        curve, sha = m.group(1), m.group(2)
        if (curve, sha) not in SUPPORTED:
            continue
        cmd = SUPPORTED[(curve, sha)]
        if 'Msg' not in fields:
            continue
        sections_seen[section] = sections_seen.get(section, 0) + 1
        # CAVP gives raw Msg; runner expects hex. CAVP also already
        # hex-encodes Msg, so no encoding needed. But our runner takes
        # hex and the runner internally hashes; it does so based on
        # the command chosen. We're passing raw Msg as hex; runner
        # SHA-256 (or SHA-384) hashes internally. Good.
        # Encode signature R and S as DER for runner.
        r_hex = fields['R'].lstrip('0') or '00'
        s_hex = fields['S'].lstrip('0') or '00'
        # Pad to even length and add leading 00 if high bit set.
        for h in [r_hex, s_hex]:
            pass  # placeholder
        def to_int_bytes(h):
            if len(h) % 2: h = '0' + h
            b = bytes.fromhex(h)
            if b and b[0] & 0x80: b = b'\x00' + b
            return b
        r_b = to_int_bytes(fields['R'])
        s_b = to_int_bytes(fields['S'])
        body = b'\x02' + bytes([len(r_b)]) + r_b + b'\x02' + bytes([len(s_b)]) + s_b
        if len(body) < 128:
            der = b'\x30' + bytes([len(body)]) + body
        else:
            der = b'\x30\x81' + bytes([len(body)]) + body
        sig_hex = der.hex()
        lines.append(f"{cmd} {fields['Qx']} {fields['Qy']} {fields['Msg']} {sig_hex}\n")
        expected.append(fields['Result'].split()[0])  # 'P' or 'F'

    if not lines:
        print("No supported test vectors found")
        return 0

    proc = subprocess.run([str(runner)], input=''.join(lines),
                          capture_output=True, text=True, timeout=600)
    actual = proc.stdout.strip().split('\n')

    pass_count = 0
    fail_count = 0
    fails = []
    for i, (exp, act) in enumerate(zip(expected, actual)):
        ok = (exp == 'P' and act == 'valid') or (exp == 'F' and act == 'invalid')
        if ok:
            pass_count += 1
        else:
            fail_count += 1
            if len(fails) < 5:
                fails.append(f"  test #{i+1}: expected={exp} got={act}")

    print(f"=== CAVP {rsp_path.name}: {pass_count}/{pass_count+fail_count} passed,",
          f"{fail_count} failed ===")
    print(f"  Sections covered: {dict(sections_seen)}")
    if fails:
        for f in fails:
            print(f)

    return 0 if fail_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
