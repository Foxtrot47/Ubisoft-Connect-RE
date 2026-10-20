#!/usr/bin/env python3
"""Probe the demux `denuvo_service` with a request token.

    python probe_denuvo.py <request_token_file> [sid]

Opens an authenticated demux session, subscribes denuvo_service, sends the
captured activation request shape and prints every reply frame. Used to verify
that we can mint tokens by relaying the request token the game sends on
uplay_aux_ipc_pipe_ instead of replaying a captured token.

The request shape was captured from upc.exe (see evidence/):
    {2:{1:{1:2, 2[fr]{1:{1:2, 14:{1:pid,2:0,3:pid}, 30:<requestToken>, 31:sid}}}}}
"""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ubisoft_gui import (  # noqa: E402
    Ubisoft, _frame, _field, _ld, _varint, demux_open_session)

PID = 2688
CAPTURED_SID = "e8cab3a2-a2f0-4f8d-bf43-976d9cdaea35"


def denuvo_request(pid: int, request_token: bytes, sid: bytes) -> bytes:
    info = _field(1, 0, _varint(pid)) + _field(2, 0, _varint(0)) + _field(3, 0, _varint(pid))
    inner = (_field(1, 0, _varint(2)) + _ld(14, info)
             + _ld(30, request_token) + _ld(31, sid))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def main():
    token = Path(sys.argv[1]).read_bytes()
    if token.endswith(b"\n"):
        token = token[:-1]
    sid = (sys.argv[2] if len(sys.argv) > 2 else CAPTURED_SID).encode()
    c = Ubisoft()
    if not c.load():
        sys.exit("no saved session")
    sock, recs = demux_open_session(c.ticket.encode(), c.session_id.encode(),
                                    read_seconds=6)
    print(f"session open, {len(recs)} catalog records, token {len(token)}B, sid {sid!r}")
    sock.sendall(denuvo_request(PID, token, sid))
    end = time.time() + 20
    sock.settimeout(3)
    while time.time() < end:
        try:
            hdr = sock.recv(4)
        except TimeoutError:
            continue
        except OSError as e:
            print("recv error", e)
            break
        if not hdr:
            print("closed")
            break
        while len(hdr) < 4:
            hdr += sock.recv(4 - len(hdr))
        n = struct.unpack(">I", hdr)[0]
        body = b""
        deadline = time.time() + 20
        while len(body) < n and time.time() < deadline:
            try:
                body += sock.recv(n - len(body))
            except TimeoutError:
                continue
        print(f"frame {n}B {body[:32].hex()}")
        Path(f"resp_{n}.bin").write_bytes(body)
        i = body.find(b"eyJlbmMi")
        print("  idx", i, "dots", body.count(b"."))
        if i >= 0:
            j = body.find(b".", body.find(b".", i) + 1)
            tok = body[i:j + 1]
            Path("denuvo_token_fresh.bin").write_bytes(tok)
            print(f"  TOKEN {len(tok)}B -> denuvo_token_fresh.bin")
    sock.close()


if __name__ == "__main__":
    main()
