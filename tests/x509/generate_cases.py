#!/usr/bin/env python3
"""
Convert x509-limbo test vectors (limbo.json) into a directory-per-test
layout for the SPARKTLS Ada validator.

Each test becomes:
    generated/<test-id>/
        peer.pem            -- leaf certificate
        trust.pem           -- trusted root(s)
        intermediates.pem   -- intermediate certs (if any)
        expect.txt          -- "SUCCESS" or "FAILURE"
        meta.txt            -- hostname, time, features, description

Tests we skip:
    - has-crl (we don't support CRL revocation)
    - CLIENT validation kind (we only do SERVER)
"""

import json
import os
import sys
from datetime import datetime

def parse_time(time_str):
    """Convert ISO 8601 to Unix timestamp."""
    if not time_str:
        return ""
    try:
        dt = datetime.fromisoformat(time_str)
        return str(int(dt.timestamp()))
    except (ValueError, OverflowError):
        return ""

def safe_dirname(test_id):
    """Convert test ID to a safe directory name."""
    return test_id.replace("::", "--").replace("/", "-").replace(" ", "_")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <limbo.json> <output_dir>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    total = 0
    skipped = 0
    generated = 0

    for tc in data['testcases']:
        total += 1
        features = tc.get('features', [])

        # Skip unsupported test types
        if 'has-crl' in features:
            skipped += 1
            continue
        if tc.get('validation_kind') != 'SERVER':
            skipped += 1
            continue
        if not tc.get('peer_certificate'):
            skipped += 1
            continue
        if not tc.get('trusted_certs'):
            skipped += 1
            continue

        tc_dir = os.path.join(out_dir, safe_dirname(tc['id']))
        os.makedirs(tc_dir, exist_ok=True)

        # Peer certificate
        with open(os.path.join(tc_dir, 'peer.pem'), 'w') as f:
            f.write(tc['peer_certificate'].strip() + '\n')

        # Trusted roots
        with open(os.path.join(tc_dir, 'trust.pem'), 'w') as f:
            for cert in tc['trusted_certs']:
                f.write(cert.strip() + '\n')

        # Intermediates (may be empty)
        intermediates = tc.get('untrusted_intermediates', [])
        if intermediates:
            with open(os.path.join(tc_dir, 'intermediates.pem'), 'w') as f:
                for cert in intermediates:
                    f.write(cert.strip() + '\n')

        # Expected result
        with open(os.path.join(tc_dir, 'expect.txt'), 'w') as f:
            f.write(tc['expected_result'] + '\n')

        # Metadata
        peer_name = tc.get('expected_peer_name') or {}
        hostname = peer_name.get('value', '') if peer_name.get('kind') in ('DNS', 'IP') else ''
        vtime = parse_time(tc.get('validation_time'))

        with open(os.path.join(tc_dir, 'meta.txt'), 'w') as f:
            f.write(f"hostname={hostname}\n")
            f.write(f"time={vtime}\n")
            f.write(f"features={','.join(features)}\n")
            f.write(f"description={tc.get('description', '')}\n")

        generated += 1

    # Write manifest
    with open(os.path.join(out_dir, 'manifest.txt'), 'w') as f:
        f.write(f"total={total}\n")
        f.write(f"generated={generated}\n")
        f.write(f"skipped={skipped}\n")

    print(f"Generated {generated} test cases ({skipped} skipped, {total} total)")

if __name__ == '__main__':
    main()
