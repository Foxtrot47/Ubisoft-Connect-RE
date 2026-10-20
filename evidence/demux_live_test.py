#!/usr/bin/env python3
"""Live demux handshake test — reproduce the client's message sequence to get a
fresh signed manifest URL, then download the manifest."""

import socket
import ssl
import struct

from pathlib import Path

# --- protobuf helpers ------------------------------------------------------ #
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


def _hello(ver=b"174.2"):
    inner = _ld(5, _ld(1, ver) + b"\x10\x00")
    return _frame(_ld(1, _fld(1, 0, b"\x02") + inner))


def _service(name):
    return _frame(_ld(1, _fld(1, 0, b"\x05") + _ld(3, _ld(2, name))))


def _session_auth(jwe, sid, locale=b"en-US"):
    inner = (_fld(1, 0, _varint(2)) + _ld(22, _fld(1, 0, _varint(1)) + _fld(4, 0, _varint(0))
             + _ld(5, jwe) + _ld(6, locale) + _fld(7, 0, _varint(0)) + _ld(8, sid)))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(1)) + _ld(2, _frame(_ld(1, inner))))))


def _download_auth(pid, jwe, sid):
    inner = (_fld(1, 0, _varint(2)) + _ld(28, _fld(1, 0, _varint(pid)))
             + _ld(30, jwe) + _ld(31, sid))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def _jws_auth(jws, uuid):
    inner = _fld(1, 0, _varint(1)) + _ld(2, _ld(5, jws) + _ld(6, uuid))
    return _frame(_ld(2, _ld(1, _fld(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, inner))))))


def _slice_req(pid, paths, counter=0):
    slices = b"".join(_ld(2, p.encode()) for p in paths)
    inner = _fld(1, 0, _varint(pid)) + slices
    body = _ld(1, _fld(1, 0, _varint(counter)) + _ld(3, inner))
    return _frame(_ld(2, body))


# --- socket helpers -------------------------------------------------------- #
def _send(sock, data):
    sock.sendall(data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError
        buf += c
    return buf


def _recv_frame(sock):
    hdr = _recv_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    return _recv_exact(sock, n)


def main():
    jwe = Path("auth_f30.bin").read_bytes()
    sid = b"a52f414b-559d-4145-87e4-c70021b30300"
    jws = Path("demux_jws.txt").read_bytes()
    uuid = b"5af8ea68-c4ba-4d8c-b7b1-ac4fd45deb9b"
    pid = 1875

    ctx = ssl.create_default_context()
    raw = socket.create_connection(("dmx.upc.ubisoft.com", 443), timeout=30)
    sock = ctx.wrap_socket(raw, server_hostname="dmx.upc.ubisoft.com")
    sock.settimeout(20)
    print("[*] connected to demux")

    # handshake — exact order from capture (download happens on a 2nd connection):
    #   hello -> download_auth -> service:download_service -> jws_auth
    seq = [
        ("hello", _hello()),
        ("download_auth", _download_auth(pid, jwe, sid)),
        ("service:download_service", _service(b"download_service")),
        ("jws_auth", _jws_auth(jws, uuid)),
    ]
    for name, msg in seq:
        _send(sock, msg)
        print(f"[>] sent {name} ({len(msg)}B)")

    # read responses
    print("[*] reading responses...")
    try:
        for k in range(6):
            r = _recv_frame(sock)
            print(f"[<] frame {k}: {len(r)}B")
            print("   ", r[:200])
    except Exception as e:
        print(f"[!] recv: {e}")


if __name__ == "__main__":
    main()
