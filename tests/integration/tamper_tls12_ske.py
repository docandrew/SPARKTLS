#!/usr/bin/env python3
"""TCP proxy that tampers with one TLS 1.2 ServerKeyExchange message.

The integration test uses this between SPARKTLS's client and OpenSSL's
TLS 1.2 server to confirm that ServerKeyExchange signatures are enforced.
It understands enough TLS record and handshake framing to mutate a single
server-to-client ServerKeyExchange body, then transparently forwards the
rest of the connection.
"""

from __future__ import annotations

import argparse
import selectors
import socket
import struct
import sys
import time


CONTENT_HANDSHAKE = 22
HS_SERVER_KEY_EXCHANGE = 12
TLS_HEADER_LEN = 5
HS_HEADER_LEN = 4


def exact_recv(sock: socket.socket, nbytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def tamper_ske_record(record: bytes, mode: str) -> tuple[bytes, bool]:
    if len(record) < TLS_HEADER_LEN:
        return record, False
    content_type = record[0]
    rec_len = struct.unpack("!H", record[3:5])[0]
    if content_type != CONTENT_HANDSHAKE or len(record) != TLS_HEADER_LEN + rec_len:
        return record, False

    out = bytearray(record)
    pos = TLS_HEADER_LEN
    end = len(record)
    while pos + HS_HEADER_LEN <= end:
        msg_type = out[pos]
        msg_len = int.from_bytes(out[pos + 1 : pos + 4], "big")
        body_start = pos + HS_HEADER_LEN
        body_end = body_start + msg_len
        if body_end > end:
            return record, False

        if msg_type == HS_SERVER_KEY_EXCHANGE:
            if mode == "signature":
                if msg_len == 0:
                    return record, False
                out[body_end - 1] ^= 0x01
                return bytes(out), True

            if mode == "point":
                # RFC 8422 ServerECDHParams:
                # curve_type[1] named_curve[2] point_len[1] point[point_len]
                if msg_len < 5:
                    return record, False
                point_len = out[body_start + 3]
                if point_len == 0 or 4 + point_len > msg_len:
                    return record, False
                out[body_start + 4] ^= 0x01
                return bytes(out), True

            raise ValueError(f"unknown tamper mode: {mode}")

        pos = body_end

    return record, False


def forward_client_to_server(src: socket.socket, dst: socket.socket) -> bool:
    data = src.recv(16384)
    if not data:
        return False
    dst.sendall(data)
    return True


def forward_server_record(
    src: socket.socket, dst: socket.socket, mode: str, already_tampered: bool
) -> bool:
    header = exact_recv(src, TLS_HEADER_LEN)
    rec_len = struct.unpack("!H", header[3:5])[0]
    body = exact_recv(src, rec_len)
    record = header + body
    if not already_tampered:
        record, did_tamper = tamper_ske_record(record, mode)
    else:
        did_tamper = False
    dst.sendall(record)
    return did_tamper


def run_proxy(listen_port: int, target_port: int, mode: str, timeout: float) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        print("READY", flush=True)
        listener.settimeout(timeout)
        try:
            client, _ = listener.accept()
        except socket.timeout:
            print("timeout waiting for client", file=sys.stderr)
            return 2

    tampered = False
    deadline = time.monotonic() + timeout
    with client:
        with socket.create_connection(("127.0.0.1", target_port), timeout=timeout) as server:
            client.setblocking(False)
            server.setblocking(False)
            sel = selectors.DefaultSelector()
            sel.register(client, selectors.EVENT_READ, "client")
            sel.register(server, selectors.EVENT_READ, "server")
            while time.monotonic() < deadline:
                events = sel.select(0.25)
                if not events:
                    continue
                for key, _ in events:
                    try:
                        if key.data == "client":
                            if not forward_client_to_server(client, server):
                                return 0 if tampered else 3
                        else:
                            server.setblocking(True)
                            try:
                                did = forward_server_record(
                                    server, client, mode, tampered
                                )
                                tampered = tampered or did
                            finally:
                                server.setblocking(False)
                    except (ConnectionError, EOFError, OSError):
                        return 0 if tampered else 3
            print("timeout forwarding connection", file=sys.stderr)
            return 0 if tampered else 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--mode", choices=("signature", "point"), required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    return run_proxy(args.listen_port, args.target_port, args.mode, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
