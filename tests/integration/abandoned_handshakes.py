#!/usr/bin/env python3
"""Open N TLS 1.2 handshakes, read the ServerHello, and drop each one.

Usage: abandoned_handshakes.py PORT [N]

Models a scanner or a browser's speculative connection: the peer goes
away after our first flight. Every such session must release its
SPARKTLS.HS_Pool slot (Max_Inflight = 16), or the server stops answering
anyone. The runner follows this with a normal connection that must work.
Exit status 1 if any of the N handshakes did not get a ServerHello.
"""
import os, socket, struct, sys

def client_hello():
    suites = b'\xc0\x2f'                               # ECDHE-RSA-AES128-GCM-SHA256
    exts = struct.pack('>HH', 0x000a, 4) + b'\x00\x02\x00\x1d'   # supported_groups: x25519
    exts += struct.pack('>HH', 0x000b, 2) + b'\x01\x00'          # ec_point_formats
    exts += struct.pack('>HH', 0x000d, 4) + b'\x00\x02\x08\x04'  # rsa_pss_rsae_sha256
    body = (b'\x03\x03' + os.urandom(32) + b'\x00' + struct.pack('>H', len(suites)) + suites
            + b'\x01\x00' + struct.pack('>H', len(exts)) + exts)
    hs = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('>H', len(hs)) + hs

port = int(sys.argv[1]); n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
ok = 0
for _ in range(n):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(('127.0.0.1', port)); s.sendall(client_hello())
        r = s.recv(8)
        ok += 1 if r[:1] == b'\x16' else 0
    except OSError:
        pass
    s.close()
print("%d/%d abandoned handshakes got a ServerHello" % (ok, n))
sys.exit(0 if ok == n else 1)
