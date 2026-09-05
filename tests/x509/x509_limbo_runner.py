#!/usr/bin/env python3
"""
x509-limbo test runner for SPARKTLS/SPARKx509.

Reads the x509-limbo test vectors (limbo.json), writes each test case
to temporary PEM files, invokes the Ada validator binary, and compares
the result against the expected outcome.

Usage:
    python3 x509_limbo_runner.py <limbo.json> <validator_binary>

The validator binary interface:
    x509_validate <peer.pem> <trust.pem> [<intermediates.pem>] \
                  [--hostname <name>] [--time <unix_timestamp>]
    Exit code: 0 = valid, 1 = invalid, 2 = error
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

def parse_time(time_str):
    """Convert ISO 8601 time to Unix timestamp."""
    if not time_str:
        return None
    try:
        dt = datetime.fromisoformat(time_str)
        return int(dt.timestamp())
    except (ValueError, OverflowError):
        return None

def write_pem_file(pem_list, path):
    """Write one or more PEM certificates to a file."""
    with open(path, 'w') as f:
        for pem in pem_list:
            f.write(pem.strip() + '\n')

def run_test(tc, validator, tmpdir):
    """Run a single test case. Returns (passed, reason)."""
    tc_id = tc['id']
    expected = tc['expected_result']  # 'SUCCESS' or 'FAILURE'
    features = tc.get('features', [])

    # Skip CRL tests (we don't support revocation checking)
    if 'has-crl' in features:
        return None, 'skip:crl'

    # Skip CLIENT validation (we only do SERVER)
    if tc.get('validation_kind') != 'SERVER':
        return None, 'skip:client'

    # Write peer cert
    peer_path = os.path.join(tmpdir, 'peer.pem')
    peer_cert = tc.get('peer_certificate', '')
    if not peer_cert:
        return None, 'skip:no-peer'
    write_pem_file([peer_cert], peer_path)

    # Write trusted roots
    trust_path = os.path.join(tmpdir, 'trust.pem')
    trusted = tc.get('trusted_certs', [])
    if not trusted:
        return None, 'skip:no-trust'
    write_pem_file(trusted, trust_path)

    # Write intermediates (may be empty)
    intermediates = tc.get('untrusted_intermediates', [])
    int_path = os.path.join(tmpdir, 'intermediates.pem')
    if intermediates:
        write_pem_file(intermediates, int_path)

    # Build command
    cmd = [validator, peer_path, trust_path]
    if intermediates:
        cmd.append(int_path)

    # Hostname
    peer_name = tc.get('expected_peer_name')
    if peer_name and peer_name.get('kind') == 'DNS':
        cmd.extend(['--hostname', peer_name['value']])

    # Validation time
    vtime = parse_time(tc.get('validation_time'))
    if vtime is not None:
        cmd.extend(['--time', str(vtime)])

    # Run validator
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        actual = 'SUCCESS' if result.returncode == 0 else 'FAILURE'
    except subprocess.TimeoutExpired:
        return False, 'timeout'
    except Exception as e:
        return False, f'error:{e}'

    passed = (actual == expected)
    return passed, f'expected={expected} actual={actual}'

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <limbo.json> <validator_binary>")
        sys.exit(2)

    limbo_path = sys.argv[1]
    validator = sys.argv[2]

    if not os.path.exists(validator):
        print(f"Error: validator binary not found: {validator}")
        sys.exit(2)

    with open(limbo_path) as f:
        data = json.load(f)

    testcases = data['testcases']
    total = 0
    passed = 0
    failed = 0
    skipped = 0
    failures = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for i, tc in enumerate(testcases):
            result, reason = run_test(tc, validator, tmpdir)

            if result is None:
                skipped += 1
                continue

            total += 1
            if result:
                passed += 1
            else:
                failed += 1
                failures.append((tc['id'], reason))
                if failed <= 20:
                    print(f"  FAIL: {tc['id']} ({reason})")

            # Progress
            if (i + 1) % 500 == 0:
                print(f"  ... {i+1}/{len(testcases)} "
                      f"(pass={passed} fail={failed} skip={skipped})")

    print()
    print(f"=== x509-limbo: {passed}/{total} passed, "
          f"{failed} failed, {skipped} skipped ===")

    if failed > 20:
        print(f"  (showing first 20 failures of {failed})")

    sys.exit(0 if failed == 0 else 1)

if __name__ == '__main__':
    main()
