#!/usr/bin/env python3
"""DoS cap regression test (ROADMAP §2.13).

Builds a malicious ClientHello with N cipher_suite entries and verifies
the SPARKTLS server:
  (a) doesn't crash, hang, or exhaust memory parsing it
  (b) reaches a deterministic outcome quickly (negotiates a suite from
      the leading window, or sends handshake_failure if no acceptable
      suite is in that window)

The cipher_suites field is packed with 1000 entries: a known-acceptable
suite (TLS_AES_128_GCM_SHA256 = 0x1301) placed at position 1, then 999
garbage values. Without the iteration cap the server walks all 1000;
with the cap (default 256) it walks the leading 256 and still finds the
acceptable suite at position 1.

Usage: python3 dos_ch_flood.py <host> <port>

Exit 0 = server responded with a ServerHello (handshake started).
Exit 1 = server crashed/hung or sent no response.
"""

import socket
import struct
import sys
import time


def build_malicious_ch(num_suites: int = 1000) -> bytes:
    # ClientHello body fields
    version = b"\x03\x03"  # legacy_version = TLS 1.2
    random = b"\x00" * 32
    session_id_len = b"\x00"

    # Cipher suites: TLS_AES_128_GCM_SHA256 first, then garbage.
    # 0x1301 = TLS_AES_128_GCM_SHA256 (RFC 8446 §B.4)
    # Garbage suites are 0xCAFE, 0xCAFF, 0xCB00, ... (deliberately
    # invalid). The first valid entry must be in the leading window
    # that survives the iteration cap.
    suites = b"\x13\x01"  # the only suite we'd actually negotiate
    for i in range(num_suites - 1):
        # Walk through 0xCAFE+i values; these are private-use space
        # so legitimate code wouldn't recognize them.
        v = (0xCAFE + i) & 0xFFFF
        suites += struct.pack(">H", v)
    cipher_suites = struct.pack(">H", len(suites)) + suites

    comp_methods = b"\x01\x00"  # length=1, null compression

    # Extensions (minimal: just supported_versions for TLS 1.3 +
    # supported_groups + key_share + signature_algorithms).
    # supported_versions ext (tag=0x002b)
    sv_data = b"\x02\x03\x04"  # list_len=2, TLS 1.3
    sv_ext = b"\x00\x2b" + struct.pack(">H", len(sv_data)) + sv_data
    # supported_groups ext (tag=0x000a): just x25519 = 0x001d
    sg_data = b"\x00\x02\x00\x1d"
    sg_ext = b"\x00\x0a" + struct.pack(">H", len(sg_data)) + sg_data
    # signature_algorithms ext (tag=0x000d): ecdsa_secp256r1_sha256 +
    # rsa_pss_rsae_sha256
    sa_data = b"\x00\x04\x04\x03\x08\x04"
    sa_ext = b"\x00\x0d" + struct.pack(">H", len(sa_data)) + sa_data
    # key_share ext (tag=0x0033): x25519 with 32 zero bytes (garbage
    # but well-formed; we just need the server to ATTEMPT to parse,
    # not to complete the handshake).
    ks_entry = b"\x00\x1d\x00\x20" + b"\x00" * 32  # group, len, key
    ks_data = struct.pack(">H", len(ks_entry)) + ks_entry
    ks_ext = b"\x00\x33" + struct.pack(">H", len(ks_data)) + ks_data

    exts = sv_ext + sg_ext + sa_ext + ks_ext
    exts_section = struct.pack(">H", len(exts)) + exts

    body = (
        version + random + session_id_len +
        cipher_suites + comp_methods + exts_section
    )
    # Handshake header: type=1 (ClientHello), 3-byte length
    hs_msg = b"\x01" + len(body).to_bytes(3, "big") + body
    # TLS record header: type=22 (handshake), version=0x0301, length
    record = b"\x16\x03\x01" + struct.pack(">H", len(hs_msg)) + hs_msg
    return record


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <host> <port>", file=sys.stderr)
        return 2

    host, port = sys.argv[1], int(sys.argv[2])

    ch = build_malicious_ch(num_suites=1000)
    print(f"sending CH with 1000 cipher_suites ({len(ch)} bytes)")

    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"connect failed: {e}", file=sys.stderr)
        return 1

    try:
        sock.sendall(ch)
        sock.settimeout(5)
        resp = sock.recv(16384)
    except (OSError, socket.timeout) as e:
        print(f"send/recv failed: {e}", file=sys.stderr)
        sock.close()
        return 1
    finally:
        sock.close()

    dt = time.time() - t0
    print(f"response: {len(resp)} bytes in {dt:.3f}s")

    if len(resp) == 0:
        print("FAIL: empty response (server hung up without alert/SH)")
        return 1

    # Either a ServerHello (type=22 handshake) or a fatal alert
    # (type=21). Both are acceptable: they prove the server parsed
    # the CH and reached a deterministic decision. An empty response
    # or a timeout would indicate parser hang / pathological cost.
    if resp[0] == 22:
        print("PASS: server responded with handshake record")
    elif resp[0] == 21:
        # Alert: bytes 5+ = level(1), description(1).
        if len(resp) >= 7:
            print(f"PASS: server sent alert level={resp[5]} desc={resp[6]} "
                  f"(handshake cleanly rejected)")
        else:
            print("PASS: server sent (truncated) alert record")
    else:
        print(f"FAIL: unexpected response type {resp[0]}")
        return 1

    if dt > 2.0:
        print(f"FAIL: response took {dt:.3f}s (>2s suggests no DoS cap)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
