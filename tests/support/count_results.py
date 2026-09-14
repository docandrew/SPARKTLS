#!/usr/bin/env python3
"""Normalise a test program's output into "passed failed skipped".

Usage: some_test | count_results.py [--rc N]

The unit-test programs grew up at different times and print their totals in
different shapes. This is the one place that knows them all, so run_all.sh
can treat every program alike. Recognised, in order of preference:

  "N passed, M failed"            (also "N/T passed, M failed", "N total, N passed, M failed")
  "Total checks: N passed M failed 0"   (test_exporter)
  "Total checks: N  Failures: M"        (fiat / 25519 KATs)
  "Total: T  Pass: N  Fail: M"          (test_clock)
  "Pass: N / T"                          (test_aes_ni, test_ghash_ni)
  bare PASS / FAIL lines                 (one check per line)

A "SKIP" line counts as skipped. A non-zero exit status with no reported
failure counts as one failure: the program died before it could report.
"""
import re, sys

def count(text, rc=0):
    p = f = None
    lines = text.splitlines()
    for line in reversed(lines):
        m = re.search(r'(\d+)(?:\s*/\s*\d+)?\s+passed,\s*(\d+)\s+failed', line)
        if m: p, f = int(m.group(1)), int(m.group(2)); break
        m = re.search(r'Total checks:\s*\d+\s+passed\s+(\d+)\s+failed\s+(\d+)', line)
        if m: p, f = int(m.group(1)), int(m.group(2)); break
        m = re.search(r'Total checks:\s*(\d+)\s+Failures:\s*(\d+)', line)
        if m: p, f = int(m.group(1)) - int(m.group(2)), int(m.group(2)); break
        m = re.search(r'Pass:\s*(\d+)\s+Fail:\s*(\d+)', line)
        if m: p, f = int(m.group(1)), int(m.group(2)); break
        m = re.search(r'Pass:\s*(\d+)\s*/\s*(\d+)', line)
        if m: p, f = int(m.group(1)), int(m.group(2)) - int(m.group(1)); break
    if p is None:
        p = sum(1 for l in lines if re.match(r'\s*PASS\b', l))
        f = sum(1 for l in lines if re.match(r'\s*FAIL\b', l))
    s = sum(1 for l in lines if re.match(r'\s*SKIP\b', l))
    if rc != 0 and f == 0:
        f = 1
    return p, f, s

if __name__ == "__main__":
    rc = 0
    if len(sys.argv) > 2 and sys.argv[1] == "--rc":
        rc = int(sys.argv[2])
    p, f, s = count(sys.stdin.read(), rc)
    print(p, f, s)
