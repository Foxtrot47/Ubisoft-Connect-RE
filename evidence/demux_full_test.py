#!/usr/bin/env python3
"""Complete demux download flow — live test."""
import re
import socket
import ssl
import struct

from pathlib import Path

# protobuf helpers
def _varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        o.append(b | (0x80 if n else 0))
        if not n:
            return bytes(o)


def _fld(f, wt, p=b""):
    return _varint((f << 3) | wt) + p


def _ld(f, p):
    return _fld(f, 2, _varint(len(p)) + p)


def _frame(b):
    return len(b).to_bytes(4, "big") + b


def _rdv(buf, i):
    v = 0
    sh = 0
    while True:
        c = buf[i]
        i += 1
        v |= (c & 0x7F) << sh
        sh += 7
        if not (c & 0x80):
            return v, i


def download_auth(pid, jwe, sid):
    inner = (_fld(1, 0, _varint(2)) + _ld(28, _fld(1, 0, _varint(pid)))
             + _ld(30, jwe) + _ld(31, sid))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def service(name, counter=5):
    return _frame(_ld(1, _fld(1, 0, _varint(counter)) + _ld(3, _ld(2, name))))


def jws_auth(jws, uuid):
    inner = _fld(1, 0, _varint(1)) + _ld(2, _ld(5, jws) + _ld(6, uuid))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, inner))))))


def metadata_request(pid, manifest_id):
    path = f"manifests/{manifest_id}.metadata".encode()
    innermost = _fld(1, 0, _varint(pid)) + _ld(2, path)
    body = _fld(1, 0, _varint(2)) + _ld(3, _ld(1, innermost))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, body))))))


def parse_jws(resp):
    # search for the JWS (eyJ0eXAi...) in the protobuf response
    i = resp.find(b"eyJ0eXAi")
    m = re.match(rb"[A-Za-z0-9_\-\.]+", resp[i:])
    return m.group(0).rstrip(b".")


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError
        buf += c
    return buf


def recv_frame(sock):
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n)


def main():
    pid = 1875
    mid = "F0A9A1AE51FAAD88C7FBFCA20409864690E74F8A"
    jwe = Path("cur_jwe.txt").read_bytes()
    sid = Path("cur_sid.txt").read_bytes()
    uuid = b"5af8ea68-c4ba-4d8c-b7b1-ac4fd45deb9b"

    ctx = ssl.create_default_context()
    raw = socket.create_connection(("dmx.upc.ubisoft.com", 443), timeout=30)
    sock = ctx.wrap_socket(raw, server_hostname="dmx.upc.ubisoft.com")
    sock.settimeout(30)
    print("[*] connected")

    # 0. hello
    sock.sendall(_frame(_ld(1, _fld(1, 0, b"\x02") + _ld(5, _ld(1, b"174.2") + b"\x10\x00"))))
    r = recv_frame(sock)
    print(f"[*] hello response: {len(r)}B")

    # 1. download_auth -> JWS
    sock.sendall(download_auth(pid, jwe, sid))
    r = recv_frame(sock)
    jws = parse_jws(r)
    print(f"[*] JWS received: {len(jws)}B  {jws[:40]}")
    Path("fresh_jws.txt").write_bytes(jws)

    # 2. service download_service -> ack
    sock.sendall(service(b"download_service"))
    r = recv_frame(sock)
    print(f"[*] service ack: {len(r)}B")

    # 3. jws_auth -> ack
    sock.sendall(jws_auth(jws, uuid))
    r = recv_frame(sock)
    print(f"[*] jws_auth ack: {len(r)}B")

    # 4. metadata request -> signed .metadata URL
    sock.sendall(metadata_request(pid, mid))
    r = recv_frame(sock)
    print(f"[*] metadata response: {len(r)}B")
    m = re.search(rb"https?://[^\x00-\x20]+", r)
    if m:
        url = m.group(0).decode()
        print(f"[*] signed URL: {url}")
        Path("fresh_metadata_url.txt").write_text(url)
    else:
        print("   (no URL found in response)")


if __name__ == "__main__":
    main()
