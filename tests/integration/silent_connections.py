#!/usr/bin/env python3
"""Hold N connections open that send a few ClientHello bytes and then nothing.

Usage: silent_connections.py PORT [N] [SECONDS]

Models the hanging client an event-driven server has to defend against: the
library learns nothing until bytes arrive, so only the application's
handshake deadline can free the connection and its handshake slot.
"""
import socket, sys, time

port = int(sys.argv[1]); n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
secs = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
held = []
for _ in range(n):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(('127.0.0.1', port)); s.sendall(b'\x16\x03\x01\x00\x40\x01')
        held.append(s)
    except OSError:
        pass
time.sleep(secs)
print("%d connections held silent for %.0f s" % (len(held), secs))
