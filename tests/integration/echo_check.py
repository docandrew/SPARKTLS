#!/usr/bin/env python3
"""Send N random bytes to an echo server in random-sized pieces and check
that the same bytes come back.

Usage: echo_check.py PORT [N]
Exit status 0 if the echo is identical, 1 otherwise.
"""
import os, random, socket, sys, threading

port = int(sys.argv[1]); n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000000
data = os.urandom(n)
s = socket.create_connection(('127.0.0.1', port)); s.settimeout(10)
got = bytearray()
def reader():
    while len(got) < len(data):
        chunk = s.recv(65536)
        if not chunk:
            break
        got.extend(chunk)
t = threading.Thread(target=reader); t.start()
i = 0
while i < len(data):
    k = random.randint(1, 20000); s.sendall(data[i:i + k]); i += k
t.join(); s.close()
print("sent %d, echoed %d, identical=%s" % (len(data), len(got), bytes(got) == data))
sys.exit(0 if bytes(got) == data else 1)
