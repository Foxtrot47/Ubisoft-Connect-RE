#!/usr/bin/env python3
"""Ubisoft Connect — single-file Tkinter client (full flow).

Sign-in (password / 2FA / remember-me) -> library -> activation -> download.

Reverse-engineered from the Ubisoft Connect desktop client (build 174.2.0.13389).
See ../REPORT.md for the full protocol reference.

Usage:  python ubisoft_gui.py
"""

from __future__ import annotations

import base64
import json
import queue
import re
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from urllib.parse import quote

import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# --------------------------------------------------------------------------- #
# Constants (recovered from live traffic)
# --------------------------------------------------------------------------- #
BASE = "https://public-ubiservices.ubi.com"
APP_ID = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6"
AUTH_APP_ID = "94145723-2736-4afe-9862-3de89184ee32"
USER_AGENT = "Massgate_174.2.0.13389"
PLATFORM = "uplay"
DEMUX_HOST = "dmx.upc.ubisoft.com"
BUILD_NUMBER = 13389  # client build; used as the config-service branch id
JWS_UUID = b"5af8ea68-c4ba-4d8c-b7b1-ac4fd45deb9b"

SESSION_FILE = Path.home() / ".ubisoft_poc_session.json"

PID_MARKER = bytes([0x98, 0x01])  # protobuf field 19 (productId), varint

MANIFEST_TAG_PREF = [
    "UbisoftConnect_QC", "UbsioftConnect_QC",  # 2nd is a real typo in the data
    "Live", "live", "DisableOverlayQC", "disableoverlayqc",
]


# --------------------------------------------------------------------------- #
# protobuf helpers
# --------------------------------------------------------------------------- #
def _varint(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        o.append(b | (0x80 if n else 0))
        if not n:
            return bytes(o)


def _field(f, wt, p=b"") -> bytes:
    return _varint((f << 3) | wt) + p


def _ld(f, p) -> bytes:
    return _field(f, 2, _varint(len(p)) + p)


def _frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def _js_basic_auth(email: str, password: str) -> str:
    enc = quote(f"{email}:{password}", safe="-_.!~*'()")
    raw = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), enc)
    return base64.b64encode(raw.encode("latin-1")).decode("ascii")


# --------------------------------------------------------------------------- #
# demux messages (all byte-exact vs captured traffic)
# --------------------------------------------------------------------------- #
def demux_hello(version="174.2") -> bytes:
    """hello on the download connection: {1:{1:2, 5:{1:'174.2', 2:0}}}"""
    inner = _ld(5, _ld(1, version.encode()) + b"\x10\x00")
    return _frame(_ld(1, _field(1, 0, b"\x02") + inner))


def demux_hello_catalog(version="174.2") -> bytes:
    """hello on the catalog connection: {1:{1:0, ...}}"""
    inner = _ld(5, _ld(1, version.encode()) + b"\x10\x00")
    return _frame(_ld(1, _field(1, 0, b"\x00") + inner))


def demux_service(name: bytes, counter: int = 5) -> bytes:
    """{1:{1:<counter>, 3:{2:<name>}}}"""
    return _frame(_ld(1, _field(1, 0, _varint(counter)) + _ld(3, _ld(2, name))))


demux_service_field3 = demux_service


def demux_utility_service(counter: int = 1) -> bytes:
    """{1:{1:1, 6:{1:'utility_service', 2:{1:{1:''}}}}}"""
    return _frame(_ld(1, _field(1, 0, _varint(counter))
                      + _ld(6, _ld(1, b"utility_service") + _ld(2, _ld(1, _ld(1, b""))))))


def demux_build_message(build: int = BUILD_NUMBER) -> bytes:
    """{2:{4:{1:<build>}}}"""
    return _frame(_ld(2, _ld(4, _field(1, 0, _varint(build)))))


def demux_auth_simple(ticket: bytes) -> bytes:
    """{1:{1:2, 2:{1:{3:<JWE>}}}}"""
    return _frame(_ld(1, _field(1, 0, _varint(2)) + _ld(2, _ld(1, _ld(3, ticket)))))


def demux_session_auth(ticket: bytes, sid: bytes, locale=b"en-US") -> bytes:
    """{2:{1:{1:1, 2[fr]{1:{1:2, 22:{1:1,4:0,5:JWE,6:locale,7:0,8:sid}}}}}}"""
    inner = (_field(1, 0, _varint(2)) + _ld(22, _field(1, 0, _varint(1)) + _field(4, 0, _varint(0))
             + _ld(5, ticket) + _ld(6, locale) + _field(7, 0, _varint(0)) + _ld(8, sid)))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(1)) + _ld(2, _frame(_ld(1, inner))))))


def demux_download_auth(pid: int, ticket: bytes, sid: bytes) -> bytes:
    """{2:{1:{1:2, 2[fr]{1:{1:2, 28:{1:pid}, 30:JWE, 31:sid}}}}}"""
    inner = (_field(1, 0, _varint(2)) + _ld(28, _field(1, 0, _varint(pid)))
             + _ld(30, ticket) + _ld(31, sid))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def demux_denuvo_request(pid: int, request_token: bytes, sid: bytes) -> bytes:
    """Denuvo activation on the `denuvo_service` channel.

    Captured from upc.exe for product 2688 (2026-10-21):
        {2:{1:{1:2, 2[fr]{1:{1:2, 14:{1:pid,2:0,3:pid}, 30:requestToken, 31:sid}}}}}
    `request_token` and `sid` are produced by the game (Denuvo -> dbdata) and
    relayed unchanged; `sid` is the `sid` in the request token's JWE header.
    """
    info = (_field(1, 0, _varint(pid)) + _field(2, 0, _varint(0))
            + _field(3, 0, _varint(pid)))
    inner = (_field(1, 0, _varint(2)) + _ld(14, info)
             + _ld(30, request_token) + _ld(31, sid))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def demux_jws_auth(jws: bytes, uuid: bytes = JWS_UUID) -> bytes:
    """{2:{1:{1:4, 2[fr]{1:{1:1, 2:{5:JWS, 6:uuid}}}}}"""
    inner = _field(1, 0, _varint(1)) + _ld(2, _ld(5, jws) + _ld(6, uuid))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, inner))))))


def demux_metadata_request(pid: int, manifest_id: str) -> bytes:
    """{2:{1:{1:4, 2[fr]{1:{1:2, 3:{1:{1:pid, 2:'manifests/{id}.metadata'}}}}}}}"""
    path = f"manifests/{manifest_id}.metadata".encode()
    innermost = _field(1, 0, _varint(pid)) + _ld(2, path)
    body = _field(1, 0, _varint(2)) + _ld(3, _ld(1, innermost))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, body))))))


def demux_slice_request(pid: int, paths, counter: int = 0) -> bytes:
    slices = b"".join(_ld(2, p.encode()) for p in paths)
    inner = _field(1, 0, _varint(pid)) + slices
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(counter)) + _ld(3, inner))))


def demux_config_request(name: bytes = b"client_configuration_service",
                         build: int = BUILD_NUMBER) -> bytes:
    """{1:{1:4, 6:{1:'client_configuration_service', 2:{1:{1:0, 3:{1:{1:<build>}}}}}}}"""
    inner = _field(1, 0, _varint(0)) + _ld(3, _ld(1, _field(1, 0, _varint(build))))
    sub = _ld(1, name) + _ld(2, _ld(1, inner))
    return _frame(_ld(1, _field(1, 0, _varint(4)) + _ld(6, sub)))


# --------------------------------------------------------------------------- #
# demux service channels (mg.protocol.demux: Upstream/Downstream/Push/DataMessage)
# --------------------------------------------------------------------------- #
def demux_authenticate(sock, ticket: bytes, request_id: int) -> None:
    """Demux authenticate (AuthenticateReq) with the session ticket."""
    token = _ld(1, _ld(3, ticket))
    req = _ld(2, token + _ld(2, b"uplay_pc") + _ld(4, b"\x08\x00"))
    sock.sendall(_frame(_ld(1, _field(1, 0, _varint(request_id)) + req)))
    rsp = _demux_await_response(sock, request_id)
    auth_rsp = next((v for f, v in _fields(rsp) if f == 2), b"")
    ok = next((v for f, v in _fields(auth_rsp) if f == 1), 0)
    if not ok:
        raise RuntimeError("demux authenticate failed")


DEMUX_API_VERSION = 13389


def demux_open_janus(ticket: bytes) -> tuple:
    """Open a demux socket the way the real client does.

    First message is a `clientVersion` push, then an `authenticateReq` with
    requestId 0. The legacy catalog handshake is not used here.
    """
    sock = _demux_connect()
    sock.settimeout(10)
    sock.sendall(_frame(_ld(2, _ld(4, _field(1, 0, _varint(DEMUX_API_VERSION))))))
    demux_authenticate(sock, ticket, 0)
    return sock, 1


def demux_service_request(sock, service: bytes, msg: bytes, request_id: int,
                         timeout: float = 30.0) -> bytes:
    """Connection-less service call (Req.serviceRequest).

    `serviceRequest` (id 6) carries {service, data}; `data` is the service
    Upstream message without a length prefix. The reply is the service
    Downstream message in `serviceRsp.data`.
    """
    req = _ld(6, _ld(1, service) + _ld(2, msg))
    sock.sendall(_frame(_ld(1, _field(1, 0, _varint(request_id)) + req)))
    rsp = _demux_await_response(sock, request_id, timeout=timeout)
    srsp = next((v for f, v in _fields(rsp) if f == 6), b"")
    return next((v for f, v in _fields(srsp) if f == 2), b"")


def demux_open_connection(sock, service: bytes, request_id: int) -> int:
    """Open a service connection; returns the connectionId from the reply."""
    req = _frame(_ld(1, _field(1, 0, _varint(request_id)) + _ld(3, _ld(2, service))))
    sock.sendall(req)
    rsp = _demux_await_response(sock, request_id)
    open_rsp = next((v for f, v in _fields(rsp) if f == 3), b"")  # Rsp.openConnectionRsp
    conn = next((v for f, v in _fields(open_rsp) if f == 1), None)
    if conn is None:
        raise RuntimeError(f"openConnection({service!r}) failed")
    return conn


def demux_push(sock, connection_id: int, request_id: int, msg: bytes) -> None:
    """Send a length-prefixed service request on an open connection."""
    inner = _frame(_ld(1, _field(1, 0, _varint(request_id)) + msg))
    push = _frame(_ld(2, _ld(1, _field(1, 0, _varint(connection_id)) + _ld(2, inner))))
    sock.sendall(push)


def _demux_await_response(sock, request_id: int, connection_id: int | None = None,
                          timeout: float = 20.0) -> bytes:
    """Read frames until the response carrying `request_id` arrives.

    Responses to requests sent on a service connection arrive as a pushed
    DataMessage for that connection (`Downstream.push -> Push.data -> data`),
    whose payload is a length-prefixed inner `Downstream.response`.
    """
    end = time.time() + timeout
    while time.time() < end:
        try:
            hdr = _read_exact(sock, 4)
            n = struct.unpack(">I", hdr)[0]
            body = _read_exact(sock, n)
        except (TimeoutError, EOFError):
            continue
        if body[:1] == b"\x0a":            # bare Downstream.response on the socket
            rsp = next((v for f, v in _fields(body) if f == 1), None)
            rid = next((v for f, v in _fields(rsp) if f == 1), None) if rsp else None
            if rid == request_id:
                return rsp
            continue
        # outer push?
        push = next((v for f, v in _fields(body) if f == 2), None)
        if push is not None and connection_id is None:
            continue                       # keep-alive / connection push, not an Rsp
        if push is not None and connection_id is not None:
            data_msg = next((v for f, v in _fields(push) if f == 1), b"")
            cid = next((v for f, v in _fields(data_msg) if f == 1), None)
            if cid != connection_id:
                continue
            raw = next((v for f, v in _fields(data_msg) if f == 2), b"")
            body = raw[4:] if len(raw) >= 4 else b""
            if not body.startswith(b"\x0a"):
                continue
        rsp = next((v for f, v in _fields(body) if f == 1), None)   # Downstream.response
        if not rsp:
            continue
        # Proto3 service replies omit request_id when its value is zero.
        default_id = 0 if connection_id is not None else None
        rid = next((v for f, v in _fields(rsp) if f == 1), default_id)
        if rid == request_id:
            return rsp
    raise TimeoutError(f"no demux response for request {request_id}")


def _fields(buf: bytes):
    i = 0
    while i < len(buf):
        tag, i = _rd_varint(buf, i)
        f, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _rd_varint(buf, i)
            yield f, v
        elif wt == 2:
            n, i = _rd_varint(buf, i)
            yield f, buf[i:i + n]
            i += n
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            return


def _demux_initialize_ownership(sock, request_id: int) -> tuple:
    """Open and initialize an ownership service connection."""
    conn = demux_open_connection(sock, b"ownership_service", request_id)
    request_id = 0
    init = _ld(2, _field(2, 0, _varint(1)) + _field(3, 0, _varint(7))
               + _field(5, 0, _varint(0)))
    demux_push(sock, conn, request_id, init)
    init_rsp = _demux_await_response(sock, request_id, conn)
    ok = next((v for f, v in _fields(next((v for f, v in _fields(init_rsp) if f == 2), b"")) if f == 1), 0)
    if not ok:
        raise RuntimeError("ownership initialize failed")
    return conn, init_rsp


def demux_ownership_token(sock, product_id: int, request_id: int,
                          ticket: bytes = b"", session_id: bytes = b"") -> str:
    """OwnershipTokenRsp.token for a product, on a fresh ownership connection."""
    conn, _ = _demux_initialize_ownership(sock, request_id)
    request_id = 1
    req = _ld(28, _field(1, 0, _varint(product_id)))
    if ticket:
        req += _ld(30, ticket)
    if session_id:
        req += _ld(31, session_id)
    demux_push(sock, conn, request_id, req)
    rsp = _demux_await_response(sock, request_id, conn)
    tok_rsp = next((v for f, v in _fields(rsp) if f == 27), b"")
    if not next((v for f, v in _fields(tok_rsp) if f == 1), 0):
        raise RuntimeError("ownershipTokenRsp.success = false")
    token = next((v for f, v in _fields(tok_rsp) if f == 2), None)
    if not token:
        raise RuntimeError("ownershipTokenRsp has no token")
    return token.decode()


def ownership_session_products(initialize_response: bytes) -> list[int]:
    """Owned/released games and add-ons, matching the official session f5 list.

    Verified against the current account's capture: all 125 IDs and their order.
    Other product/state combinations have not been validated for session f5.
    """
    initialize = dict(_fields(dict(_fields(initialize_response)).get(2, b"")))
    products = []
    for field, raw in _fields(initialize.get(2, b"")):
        if field != 1 or not isinstance(raw, bytes):
            continue
        game = dict(_fields(raw))
        if (game.get(20) == 1 and game.get(8, 0) in (0, 1)
                and game.get(13, 0) in (0, 3)):
            products.append(game[1])
    return products


def demux_pc_session(sock, product_id: int, request_id: int,
                     ticket: bytes, session_id: bytes) -> tuple[bytes, list[int]]:
    """Get the session f8 ticket and live ownership catalog's session products."""
    conn, initialize_response = _demux_initialize_ownership(sock, request_id)
    # f3 is present in the newer official capture, in addition to uplayId/platform.
    info = (_field(1, 0, _varint(product_id)) + _field(2, 0, _varint(0))
            + _field(3, 0, _varint(product_id)))
    req = _ld(14, info) + _ld(30, ticket) + _ld(31, session_id)
    demux_push(sock, conn, 1, req)
    rsp = _demux_await_response(sock, 1, conn)
    result = dict(_fields(next((v for f, v in _fields(rsp) if f == 13), b"")))
    if not result.get(1):
        raise RuntimeError(f"GetUplayPCTicket failed (code={result.get(3)})")
    token = result.get(2)
    if not isinstance(token, bytes) or not token:
        raise RuntimeError("GetUplayPCTicket has no ticket")
    return token, ownership_session_products(initialize_response)


def demux_pc_ticket(sock, product_id: int, request_id: int,
                    ticket: bytes, session_id: bytes) -> bytes:
    """GetUplayPCTicket: the session f8 ticket, NOT the aux activation answer."""
    return demux_pc_session(sock, product_id, request_id, ticket, session_id)[0]


def demux_game_token(sock, ownership_token: str, request_token: bytes, request_id: int) -> bytes:
    """GetGameTokenReq -> GetGameTokenRsp.gameToken (the Denuvo activation blob)."""
    conn = demux_open_connection(sock, b"denuvo_service", request_id)
    request_id = 1  # Matches the official client's first GetGameToken request.
    req = _ld(2, _ld(1, ownership_token.encode()) + _ld(2, request_token))
    demux_push(sock, conn, request_id, req)
    rsp = _demux_await_response(sock, request_id, conn, timeout=45)
    # proto3 omits the default enum value: absent result means Success (0).
    result = next((v for f, v in _fields(rsp) if f == 2), 0)
    if result != 0:
        raise RuntimeError(f"GetGameToken result={result}")
    gr = next((v for f, v in _fields(rsp) if f == 3), b"")
    token = next((v for f, v in _fields(gr) if f == 1), None)
    if not token:
        raise RuntimeError("GetGameTokenRsp has no gameToken")
    return token


# two fixed branch-ack frames the client sends during catalog setup
ACK7 = bytes.fromhex("0000001812160a14080212100000000c0a0a08011206100118072800")
ACK8 = bytes.fromhex("0000001212100a0e0801120a000000060a0408016a00")


def demux_game_active(pid: int, name: bytes) -> bytes:
    """Announce the starting title to the service channel.

    Captured from upc.exe right after a launch (2026-10-21):
        {2:{1:{1:1, 2[fr]{1:{1:3, 13:{1:{1:pid, 3:{<name>}}}}}}}}
    `name` is the store title, e.g. b"WATCH_DOGS\\xc2\\xae 2" for 2688.
    """
    ident = _field(1, 0, _varint(pid)) + _ld(3, name)
    inner = _field(1, 0, _varint(3)) + _ld(13, ident)
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(1)) + _ld(2, _frame(_ld(1, inner))))))


def demux_game_start(pid: int) -> bytes:
    """{2:{6:{1:pid}}} -- captured alongside the announce above."""
    return _frame(_ld(2, _ld(6, _field(1, 0, _varint(pid)))))


def parse_jws_response(resp: bytes) -> bytes:
    i = resp.find(b"eyJ0eXAi")
    m = re.match(rb"[A-Za-z0-9_\-\.]+", resp[i:])
    return m.group(0).rstrip(b".")


def _rd_varint(buf: bytes, i: int):
    v = 0
    sh = 0
    while True:
        c = buf[i]
        i += 1
        v |= (c & 0x7F) << sh
        sh += 7
        if not (c & 0x80):
            return v, i


def _tag_name(raw: bytes) -> str:
    t = raw.decode("ascii", "replace")
    m = re.search(r"([A-Za-z][A-Za-z0-9 _]{2,40})", t)
    return m.group(1).strip() if m else ""


def parse_qc_records(stream: bytes) -> dict:
    """Extract {productId: {branchTag: manifestId}} from the config catalog."""
    out = {}

    def parse_at(b, i):
        rec = {}
        try:
            for _ in range(80):
                tag, i = _rd_varint(b, i)
                f, wt = tag >> 3, tag & 7
                if wt == 0:
                    v, i = _rd_varint(b, i)
                    rec.setdefault(f, v)
                elif wt == 2:
                    ln, i = _rd_varint(b, i)
                    v = b[i:i + ln]
                    i += ln
                    rec.setdefault(f, v)
                elif wt == 1:
                    i += 8
                elif wt == 5:
                    i += 4
                else:
                    return None
                if 21 in rec and 19 in rec and 26 in rec:
                    return rec
        except (IndexError, KeyError):
            return None
        return None

    for m in re.finditer(PID_MARKER, stream):
        rec = parse_at(stream, m.start())
        if not rec:
            continue
        pid, h, qc = rec.get(19), rec.get(21), rec.get(26) or b""
        if not isinstance(pid, int) or pid <= 0:
            continue
        if not isinstance(h, bytes) or not re.fullmatch(rb"[0-9A-F]{40}", h):
            continue
        out.setdefault(pid, {})[_tag_name(qc)] = h.decode()
    return out


def resolve_manifest(records: dict, pid: int):
    """Pick the download manifest for a product -> (manifestId, tag)."""
    tags = records.get(pid) or {}
    for p in MANIFEST_TAG_PREF:
        if p in tags:
            return tags[p], p
    if tags:
        k = sorted(tags)[0]
        return tags[k], k
    return None, None


# --------------------------------------------------------------------------- #
# demux sockets / CDN download
# --------------------------------------------------------------------------- #
def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError("demux connection closed")
        buf += c
    return buf


def _recv_frame(sock):
    (n,) = struct.unpack(">I", _read_exact(sock, 4))
    return _read_exact(sock, n)


def _demux_connect():
    ctx = ssl.create_default_context()
    raw = socket.create_connection((DEMUX_HOST, 443), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=DEMUX_HOST)


def _drain(sock, wait):
    """Read whole frames for `wait` seconds and return them concatenated.

    Frame-aligned: it never stops in the middle of a frame, so whatever the
    caller reads next starts on a length prefix. The demux answers the catalog
    handshake with hundreds of KB, and a raw recv drain leaves the stream
    misaligned.
    """
    end = time.time() + wait
    buf = b""
    while time.time() < end:
        try:
            hdr = _read_exact(sock, 4)
            n = int.from_bytes(hdr, "big")
            if n <= 0 or n > (1 << 22):
                continue
            buf += hdr + _read_exact(sock, n)
        except (OSError, EOFError, TimeoutError):
            break
        if len(buf) > (1 << 21):
            break
    return buf


def demux_open_session(ticket: bytes, sid: bytes, read_seconds: float = 18.0):
    """Open an authenticated demux connection and return (socket, catalog_records).

    The demux rejects download_auth on a fresh socket: the catalog handshake has
    to happen on the same connection first.
    """
    sock = _demux_connect()
    sock.settimeout(4)

    sock.sendall(_frame(_ld(2, _ld(4, _field(1, 0, _varint(DEMUX_API_VERSION))))))
    sock.sendall(demux_hello_catalog())
    _drain(sock, 2)
    sock.sendall(demux_utility_service())
    _drain(sock, 2)
    sock.sendall(demux_build_message())
    sock.sendall(demux_auth_simple(ticket))
    _drain(sock, 2)
    sock.sendall(demux_service(b"friends_service", 0))
    sock.sendall(demux_service(b"ownership_service", 1))
    _drain(sock, 3)
    sock.sendall(demux_session_auth(ticket, sid))
    sock.sendall(ACK7)
    sock.sendall(ACK8)
    sock.sendall(demux_service(b"denuvo_service", 3))
    sock.sendall(demux_config_request())

    catalog = _drain(sock, read_seconds)
    return sock, parse_qc_records(catalog)


def fetch_manifest_map(ticket: bytes, session_id: bytes, read_seconds: float = 20.0) -> dict:
    """Fetch {productId: {tag: manifestId}} from the demux catalog."""
    sock, recs = demux_open_session(ticket, session_id, read_seconds)
    try:
        sock.close()
    except OSError:
        pass
    return recs


def download_file(url, dest, progress=None):
    """Fetch a signed CDN URL byte-exactly.

    Must NOT go through requests/urllib: they re-encode the percent-escaped
    `_tkn_` ACL (%2f -> %2F) and the Akamai HMAC check then returns 403.
    """
    from urllib.parse import urlsplit

    sp = urlsplit(url)
    host = sp.netloc
    path = sp.path + (("?" + sp.query) if sp.query else "")

    s = socket.create_connection((host, 80), timeout=60)
    try:
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: {USER_AGENT}\r\n"
               f"Connection: close\r\n\r\n")
        s.sendall(req.encode("ascii"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(65536)
            if not d:
                raise RuntimeError("CDN closed before headers")
            buf += d
        head, _, body = buf.partition(b"\r\n\r\n")

        status = int(head.split(b"\r\n")[0].split(b" ")[1])
        if status != 200:
            raise RuntimeError(f"CDN HTTP {status}: {body[:200]!r}")

        hdrs = {}
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            hdrs[k.strip().lower()] = v.strip()

        chunked = b"chunked" in hdrs.get(b"transfer-encoding", b"").lower()
        total = 0 if chunked else int(hdrs.get(b"content-length", b"0") or 0)

        chunks = [body]
        done = len(body)
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
            done += len(d)
            if progress:
                progress(done, total)
    finally:
        s.close()

    data = b"".join(chunks)
    if chunked:
        out, i = b"", 0
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j < 0:
                break
            try:
                size = int(data[i:j].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += data[j + 2:j + 2 + size]
            i = j + 2 + size + 2
        data = out

    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_bytes(data)
    return len(data)


# --------------------------------------------------------------------------- #
# local "configurations" parsing -> game / addon names
# --------------------------------------------------------------------------- #
def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _yaml_val(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _is_placeholder(name) -> bool:
    if not name:
        return True
    if re.fullmatch(r"l\d+", name):
        return True
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", name))


def _load_config_index(path=None) -> dict:
    """Parse the local 'configurations' file -> {"spaces": {...}, "addons": {...}}."""
    import os

    if path is None:
        root = os.environ.get("LOCALAPPDATA", "")
        path = Path(root) / "Ubisoft Game Launcher" / "cache" / "configuration" / "configurations"
    try:
        cfg = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"spaces": {}, "addons": {}}

    blocks, cur = [], None
    for ln in cfg.split("\n"):
        if ln.startswith("root:"):
            if cur is not None:
                blocks.append(cur)
            cur = []
        if cur is not None:
            cur.append(ln)
    if cur is not None:
        blocks.append(cur)

    spaces, addons = {}, {}
    for block in blocks:
        space_id = name = game_id = shortcut = None
        localized = {}
        in_loc = False
        loc_indent = 0
        pending_addon = None
        block_addons = []
        for ln in block:
            st = ln.strip()
            if not st:
                continue
            ind = _indent_of(ln)

            if st.startswith("localizations:"):
                in_loc, loc_indent = True, ind
                continue
            if in_loc:
                if ind <= loc_indent:
                    in_loc = False
                else:
                    m = re.match(r"\s*(l\d+):\s*(.*)$", ln)
                    if m and ind == loc_indent + 4:
                        localized.setdefault(m.group(1), _yaml_val(m.group(2)))
                    continue

            m = re.match(r"\s*-\s*id:\s*(\d+)\s*$", ln)
            if m:
                pending_addon = int(m.group(1))
                continue
            m = re.match(r"\s*name:\s*(.*)$", ln)
            if m and pending_addon is not None and ind > 2:
                addons.setdefault(pending_addon, _yaml_val(m.group(1)))
                block_addons.append(pending_addon)
                pending_addon = None
                continue

            m = re.match(r"\s*space_id:\s*([0-9a-f-]{36})", ln)
            if m:
                space_id = space_id or m.group(1).lower()
                continue
            m = re.match(r"\s{2}name:\s*(.*)$", ln)
            if m and name is None:
                name = _yaml_val(m.group(1))
                continue
            m = re.match(r"\s*game_identifier:\s*(.*)$", ln)
            if m and game_id is None:
                game_id = _yaml_val(m.group(1))
                continue
            m = re.match(r"\s*shortcut_name:\s*(.*)$", ln)
            if m and shortcut is None:
                shortcut = _yaml_val(m.group(1))
                continue

        for aid in block_addons:
            v = addons.get(aid)
            if re.fullmatch(r"l\d+", v or ""):
                addons[aid] = localized.get(v) or v

        if not space_id:
            continue
        nm = name
        if nm and re.fullmatch(r"l\d+", nm):
            nm = localized.get(nm)
        if _is_placeholder(nm):
            nm = None
        spaces.setdefault(space_id, nm or game_id or shortcut or "")

    return {"spaces": spaces, "addons": addons}


def _load_config_names(path=None) -> dict:
    return _load_config_index(path)["spaces"]



# --------------------------------------------------------------------------- #
# manifest -> chunks -> slices_v3  (real game file download)
# --------------------------------------------------------------------------- #
SLICE_ALPHABET = "0123456789abcdefghijklmnopqrstuv"


def slice_shard(sha1_hex: str) -> str:
    """CDN shard bucket = base32hex(first byte % 32).

    Verified against 10 captured URLs (e.g. 73AF6807... -> 'j', EDE115E6... -> 'd').
    """
    return SLICE_ALPHABET[int(sha1_hex[:2], 16) % 32]


def slice_path(sha1_hex: str) -> str:
    h = sha1_hex.upper()
    return "slices_v3/%s/%s" % (slice_shard(h), h)


def _pb_fields(b):
    """Yield (field, wiretype, value) for one protobuf message."""
    i, n = 0, len(b)
    while i < n:
        v = 0
        sh = 0
        while True:
            c = b[i]
            i += 1
            v |= (c & 0x7F) << sh
            sh += 7
            if not (c & 0x80):
                break
        f, wt = v >> 3, v & 7
        if wt == 0:
            val = 0
            sh = 0
            while True:
                c = b[i]
                i += 1
                val |= (c & 0x7F) << sh
                sh += 7
                if not (c & 0x80):
                    break
            yield f, wt, val
        elif wt == 2:
            ln = 0
            sh = 0
            while True:
                c = b[i]
                i += 1
                ln |= (c & 0x7F) << sh
                sh += 7
                if not (c & 0x80):
                    break
            yield f, wt, b[i:i + ln]
            i += ln
        elif wt == 1:
            yield f, wt, b[i:i + 8]
            i += 8
        elif wt == 5:
            yield f, wt, b[i:i + 4]
            i += 4
        else:
            return


def parse_manifest(raw: bytes):
    """Parse a .manifest file -> [{'path', 'size', 'chunks': [{'len','hash'}]}].

    Container: u32 version, u32 sig_len, u32 body_len, signature, zlib(body).
    body f4 = download units; each f3 = file entry:
        f1 path, f2 size, f4 content-sha1 (20B), f7 = {f1:slice_size, f2:len, f3:hash}
    The f7 hash is the slices_v3 object name (verified against captured URLs).
    """
    import struct as _struct
    import zlib as _zlib

    ver, l1, l2 = _struct.unpack("<III", raw[:12])
    body = _zlib.decompress(raw[12 + l1:12 + l1 + l2])

    files = []
    for f, wt, unit in _pb_fields(body):
        if f != 4 or wt != 2:
            continue
        for f2, wt2, entry in _pb_fields(unit):
            if f2 != 3 or wt2 != 2:
                continue
            path = size = None
            chunks = []
            for f3, wt3, v3 in _pb_fields(entry):
                if f3 == 1 and wt3 == 2:
                    path = v3.decode("utf-8", "replace")
                elif f3 == 2 and wt3 == 0:
                    size = v3
                elif f3 == 7 and wt3 == 2:
                    sd = {a: c for a, w, c in _pb_fields(v3)}
                    h = sd.get(3)
                    if isinstance(h, bytes) and len(h) == 20:
                        chunks.append({"len": sd.get(2, 0), "hash": h.hex()})
            if path:
                files.append({"path": path, "size": size, "chunks": chunks})
    return files


def demux_path_request(pid: int, path: str, counter: int = 4) -> bytes:
    """Request a signed URL for a manifest/slice path."""
    inner = _field(1, 0, _varint(pid)) + _ld(2, path.encode())
    body = _field(1, 0, _varint(2)) + _ld(3, _ld(1, inner))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(counter)) + _ld(2, _frame(_ld(1, body))))))


def demux_fetch(pid: int, paths, counter: int = 4) -> list:
    """Build a path request for several paths at once (one f2 entry per path)."""
    inner = _field(1, 0, _varint(pid)) + b"".join(_ld(2, p.encode()) for p in paths)
    body = _field(1, 0, _varint(2)) + _ld(3, _ld(1, inner))
    return [_frame(_ld(2, _ld(1, _field(1, 0, _varint(counter)) + _ld(2, _frame(_ld(1, body))))))]


def signed_urls_from(resp: bytes) -> list:
    return [m.group(0).decode("ascii")
            for m in re.finditer(rb"http://[A-Za-z0-9._~:/?#@!$&()*+,;=%\-]+", resp)]


def download_game_slices(pid: int, raw_manifest: bytes, dest_root, sock,
                         log=print, only=None, max_files=None):
    """Download every file in a .manifest using an open authenticated demux socket.

    Signed URLs are matched to the requested chunk **by hash**, never by position:
    the demux may emit extra/unsolicited frames, so a naive request->response
    pairing hands back another slice's URL (silent corruption).
    """
    import hashlib

    files = parse_manifest(raw_manifest)
    log("manifest: %d files, %d slices"
        % (len(files), sum(len(f["chunks"]) for f in files)))
    if only:
        files = [f for f in files if only in f["path"]]
    if max_files:
        files = files[:max_files]

    root = Path(dest_root)
    url_cache = {}

    def absorb(resp):
        for u in signed_urls_from(resp):
            name = u.split("?")[0].rsplit("/", 1)[-1].upper()
            url_cache.setdefault(name, u)

    def signed_url_for(sha1):
        key = sha1.upper()
        if key in url_cache:
            return url_cache[key]
        sock.sendall(demux_path_request(pid, slice_path(sha1)))
        for _ in range(8):
            try:
                absorb(_recv_frame(sock))
            except (EOFError, OSError):
                break
            if key in url_cache:
                return url_cache[key]
        return None

    done = 0
    total = sum(len(f["chunks"]) for f in files)
    failures = 0
    for fi, ent in enumerate(files, 1):
        out = bytearray()
        for ch in ent["chunks"]:
            url = signed_url_for(ch["hash"])
            if not url:
                log("  no signed url for %s (skipped)" % ch["hash"][:12])
                failures += 1
                continue
            tmp = root / ".slices" / ch["hash"].upper()
            blob = None
            for attempt in range(3):
                download_file(url, tmp)
                blob = tmp.read_bytes()
                if hashlib.sha1(blob).hexdigest() == ch["hash"].lower():
                    break
                url_cache.pop(ch["hash"].upper(), None)
                url = signed_url_for(ch["hash"]) or url
                blob = None
            if blob is None:
                log("  SHA1 mismatch persisted for %s" % ch["hash"][:12])
                failures += 1
                continue
            if blob[:4] == bytes([0x28, 0xB5, 0x2F, 0xFD]):
                try:
                    import zstandard as _zstd
                    blob = _zstd.ZstdDecompressor().decompress(
                        blob, max_output_size=1 << 28)
                except Exception as exc:
                    log("  zstd failed for %s: %s" % (ch["hash"][:12], exc))
            out += blob
            done += 1
            try:
                tmp.unlink()
            except OSError:
                pass
        target = root / ent["path"].replace("\\", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(out))
        log("[%d/%d] %s (%d bytes, %d slices)"
            % (fi, len(files), ent["path"], len(out), len(ent["chunks"])))
    if failures:
        log("%d slice(s) failed" % failures)
    return done, total



# --------------------------------------------------------------------------- #
# launch: install dir -> executable -> spawn -> playsession -> cloud saves
# --------------------------------------------------------------------------- #
def _reg_read(key_path: str, value: str):
    import winreg

    hive = key_path.split("\\", 1)[0].upper()
    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKEY_LOCAL_MACHINE" else winreg.HKEY_CURRENT_USER
    sub = key_path.split("\\", 1)[1]
    try:
        k = winreg.OpenKey(root, sub)
    except OSError:
        return None
    try:
        v, _ = winreg.QueryValueEx(k, value)
        return v
    except OSError:
        return None
    finally:
        winreg.CloseKey(k)


def install_dir(product_id: int):
    """InstallDir for a product, from the launcher's own registry keys."""
    for base in (r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs\%d",
                 r"HKEY_LOCAL_MACHINE\SOFTWARE\Ubisoft\Launcher\Installs\%d"):
        v = _reg_read(base % product_id, "InstallDir")
        if v:
            return Path(v.replace("/", "\\"))
    return None


def _load_launch_specs(path=None):
    """spaceId -> {'exe': rel, 'args': str, 'register': key} from the config file."""
    import os

    if path is None:
        root = os.environ.get("LOCALAPPDATA", "")
        path = Path(root) / "Ubisoft Game Launcher" / "cache" / "configuration" / "configurations"
    try:
        cfg = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    blocks, cur = [], None
    for ln in cfg.split("\n"):
        if ln.startswith("root:"):
            if cur is not None:
                blocks.append(cur)
            cur = []
        if cur is not None:
            cur.append(ln)
    if cur is not None:
        blocks.append(cur)

    out = {}
    for block in blocks:
        space = exe = args = reg = None
        in_online = False
        in_trial = False
        for ln in block:
            ind = len(ln) - len(ln.lstrip(" "))
            if ln.strip() == "online:":
                in_online = True
                continue
            if ln.strip() == "offline:":
                in_online = False
                continue
            if ln.strip() == "trial:":
                in_trial = True
                continue
            m = re.match(r"\s*space_id:\s*([0-9a-f-]{36})", ln)
            if m and space is None:
                space = m.group(1).lower()
                continue
            if not in_online:
                continue
            m = re.match(r"\s*relative:\s*'?([^'\s]+)'?\s*$", ln)
            if m and exe is None:
                exe = m.group(1).replace("\\", "\\").lstrip("\\")
                continue
            m = re.match(r"\s*arguments:\s*(.*)$", ln)
            if m and exe is not None and args is None and not in_trial:
                args = m.group(1).strip().strip("'")
                continue
            m = re.match(r"\s*register:\s*(.+)$", ln)
            if m and in_online and reg is None and "Install" in m.group(1):
                reg = m.group(1).strip()
                continue
        if space and exe:
            out.setdefault(space, {"exe": exe, "args": args or "", "register": reg})
    return out


def launch_spec(client, product_id: int):
    """(exe_path, args_list, cwd) for a product id, or (None, None, None)."""
    space = None
    for e in client.library():
        if e.get("productId") == product_id and e.get("spaceId"):
            space = e["spaceId"].lower()
            break
    specs = _load_launch_specs()
    spec = specs.get(space or "")
    root = install_dir(product_id)
    if not spec or not root:
        return None, None, None
    exe = root / spec["exe"]
    args = [a for a in (spec["args"] or "").split(" ") if a]
    return exe, args, root


def playsession_start(client, product_id: int):
    """PUT the play session (this is what marks the account as 'in game')."""
    return client._check(client.s.put(
        f"{BASE}/v1/profiles/{client.profile_id}/global/ubiconnect/playsession/api/sessions",
        headers=client._h(), json={"productId": product_id}, timeout=30))


def playsession_delete(client, product_id: int):
    return client._check(client.s.delete(
        f"{BASE}/v1/profiles/{client.profile_id}/global/ubiconnect/playsession/api/sessions",
        headers=client._h(), params={"productId": product_id}, timeout=30))


def cloud_save_entity(client, product_id: int):
    """Cloud save metadata: slots with md5/size, plus `revision` (conflict key)."""
    data = client.get(f"/v1/profiles/{client.profile_id}/entities",
                      name=f"upcCloudSaveUplayId_{product_id}")
    if isinstance(data, list):
        return data[0] if data else None
    items = data.get("entities") if isinstance(data, dict) else None
    return items[0] if items else (data if data.get("name") else None)


def launch_game(client, product_id: int, refrsh_seconds: int = 330, log=print):
    """Launch a game the way the client does: playsession -> spawn -> refresh -> delete.

    Returns the subprocess. Requires the official Ubisoft Connect client to be
    running so the game's uplay_r1_loader can obtain its ticket over the pipe.
    """
    import subprocess
    import threading
    import time

    exe, args, cwd = launch_spec(client, product_id)
    if not exe or not exe.exists():
        raise RuntimeError("cannot resolve executable for product %s (%s)" % (product_id, exe))

    ent = None
    try:
        ent = cloud_save_entity(client, product_id)
        slots = (ent or {}).get("obj", {}).get("slots", [])
        log("cloud save: revision=%s, %d slot(s)" % ((ent or {}).get("revision"), len(slots)))
    except Exception as exc:
        log("cloud save query failed: %s" % exc)

    try:
        playsession_start(client, product_id)
        log("play session started")
    except Exception as exc:
        log("play session start failed: %s" % exc)

    log("spawn: %s %s (cwd=%s)" % (exe, " ".join(args), cwd))
    proc = subprocess.Popen([str(exe)] + args, cwd=str(cwd))

    stop = threading.Event()

    def heartbeat():
        while not stop.wait(refrsh_seconds):
            try:
                playsession_start(client, product_id)
                log("play session refreshed")
            except Exception as exc:
                log("play session refresh failed: %s" % exc)

    threading.Thread(target=heartbeat, daemon=True).start()

    def finish():
        stop.set()
        try:
            playsession_delete(client, product_id)
            log("play session deleted")
        except Exception as exc:
            log("play session delete failed: %s" % exc)

    proc._finish = finish
    return proc


# --------------------------------------------------------------------------- #
# Ubisoft services client
# --------------------------------------------------------------------------- #
class Ubisoft:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": USER_AGENT})
        self.ticket = None
        self.session_id = None
        self.session_key = None
        self.profile_id = None
        self.user_id = None
        self.name_on_platform = None
        self.remember_me_ticket = None

    def login(self, email, password, remember_me=True):
        r = self.s.post(f"{BASE}/v3/profiles/sessions",
                        headers={"Authorization": "Basic " + _js_basic_auth(email, password),
                                 "Ubi-AppId": APP_ID, "Ubi-RequestedPlatformType": PLATFORM},
                        json={"rememberMe": remember_me, "enforceTwoFactorSession": False},
                        timeout=60)
        data = self._check(r)
        if data.get("twoFactorAuthenticationTicket"):
            return {"needs_2fa": True, "ticket": data["twoFactorAuthenticationTicket"]}
        self._adopt(data)
        return data

    def login_2fa(self, two_factor_ticket, code):
        r = self.s.post(f"{BASE}/v3/profiles/sessions",
                        headers={"Authorization": f"ubi_2fa_v1 t={two_factor_ticket}",
                                 "Ubi-AppId": APP_ID, "Ubi-RequestedPlatformType": PLATFORM,
                                 "Ubi-2FA-Code": code},
                        json={"twoFactorCode": code}, timeout=60)
        data = self._check(r)
        self._adopt(data)
        return data

    def login_remember_me(self, ticket):
        r = self.s.post(f"{BASE}/v3/profiles/sessions",
                        headers={"Authorization": f"ubi_v1 t={ticket}",
                                 "Ubi-AppId": APP_ID, "Ubi-RequestedPlatformType": PLATFORM},
                        json={}, timeout=60)
        data = self._check(r)
        self._adopt(data)
        return data

    def _adopt(self, data):
        self.session_origin = "poc-login"
        self.ticket = data.get("ticket") or self.ticket
        self.session_id = data.get("sessionId")
        self.session_key = data.get("sessionKey")
        self.profile_id = data.get("profileId")
        self.user_id = data.get("userId")
        self.name_on_platform = data.get("nameOnPlatform")
        self.remember_me_ticket = data.get("rememberMeTicket")

    def _check(self, r):
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {data}")
        return data

    def _h(self):
        h = {"Authorization": f"Ubi_v1 t={self.ticket}", "Ubi-AppId": APP_ID,
             "Ubi-RequestedPlatformType": PLATFORM}
        if self.session_id:
            h["Ubi-SessionId"] = self.session_id
        return h

    def get(self, path, **params):
        return self._check(self.s.get(f"{BASE}{path}", headers=self._h(), params=params, timeout=60))

    def post(self, path, body):
        return self._check(self.s.post(f"{BASE}{path}", headers=self._h(), json=body, timeout=60))

    def me(self):
        return self.get("/v3/users/me")

    def library(self):
        data = self.get("/v1/profiles/me/global/ubiconnect/entitlement/api/entitlements")
        for k in ("items", "entitlements", "products", "games", "results"):
            if isinstance(data.get(k), list):
                return data[k]
        return data if isinstance(data, list) else []

    def activate(self, code, benefit_ids=None):
        pid = self.profile_id
        if benefit_ids is None:
            info = self.get(f"/v1/profiles/{pid}/redeemBenefits/selectableBenefits/{code}")
            benefit_ids = [b.get("benefitId") for b in (info.get("selectableBenefits") or [])
                           if b.get("benefitId")]
        body = {"code": code}
        if benefit_ids:
            body["benefitIds"] = benefit_ids
        return self.post(f"/v1/profiles/{pid}/redeemBenefits/code", body)

    def save(self):
        SESSION_FILE.write_text(json.dumps({
            "ticket": self.ticket, "sessionId": self.session_id, "sessionKey": self.session_key,
            "profileId": self.profile_id, "userId": self.user_id,
            "rememberMeTicket": self.remember_me_ticket,
            "source": getattr(self, "session_origin", "unknown"),
        }, indent=2))

    def load(self):
        if not SESSION_FILE.exists():
            return False
        d = json.loads(SESSION_FILE.read_text())
        self.ticket = d.get("ticket")
        self.session_id = d.get("sessionId")
        self.session_key = d.get("sessionKey")
        self.profile_id = d.get("profileId")
        self.user_id = d.get("userId")
        self.remember_me_ticket = d.get("rememberMeTicket")
        self.session_origin = d.get("source", "unknown")
        return bool(self.ticket and self.session_id)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
class UbisoftApp:
    def __init__(self, root):
        self.root = root
        self.client = Ubisoft()
        self.q = queue.Queue()
        self._twofa_ticket = None
        self._frames = {}

        root.title("Ubisoft Connect — PoC client")
        root.geometry("980x640")
        self._build_login()
        self._poll()

    # ---------------------------------------------------------------- utils
    def _poll(self):
        try:
            while True:
                fn = self.q.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _log(self, msg, tag="LOG"):
        def _fn():
            w = self._frames.get("log")
            if w:
                w.configure(state="normal")
                w.insert("end", f"[{tag}] {msg}\n")
                w.see("end")
                w.configure(state="disabled")
        self.q.put(_fn)

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()
        self._frames.clear()

    # ---------------------------------------------------------------- login
    def _build_login(self):
        self._clear()
        f = ttk.Frame(self.root, padding=40)
        f.pack(expand=True)

        ttk.Label(f, text="Ubisoft Connect", font=("Segoe UI", 22, "bold")).pack(pady=(0, 20))
        ttk.Label(f, text="Email").pack(anchor="w")
        email = ttk.Entry(f, width=40)
        email.pack(pady=(0, 10))
        ttk.Label(f, text="Password").pack(anchor="w")
        pw = ttk.Entry(f, width=40, show="*")
        pw.pack(pady=(0, 10))
        ttk.Label(f, text="2FA code (only if prompted)").pack(anchor="w")
        twofa = ttk.Entry(f, width=40)
        twofa.pack(pady=(0, 20))

        status = ttk.Label(f, text="", foreground="#a00")
        status.pack(pady=(0, 10))
        self._frames["status"] = status

        def do_login():
            self._do_login(email.get(), pw.get(), twofa.get().strip(), status)

        ttk.Button(f, text="Sign in", command=do_login).pack(pady=(0, 10))
        ttk.Label(f, text="Credentials are used only for this session and are never stored.\n"
                          "The session ticket is saved locally in ~/.ubisoft_poc_session.json",
                  foreground="#666").pack()

    def _do_login(self, email, password, twofa, status):
        if not email or not password:
            status.configure(text="Email and password required")
            return
        status.configure(text="Signing in...")
        self.root.update()

        def work():
            try:
                if twofa and self._twofa_ticket:
                    self.client.login_2fa(self._twofa_ticket, twofa)
                    self._twofa_ticket = None
                elif self.client.remember_me_ticket:
                    self.client.login_remember_me(self.client.remember_me_ticket)
                else:
                    out = self.client.login(email, password)
                    if out.get("needs_2fa"):
                        self._twofa_ticket = out["ticket"]
                        self.q.put(lambda: status.configure(
                            text="2FA required — enter your code and click Sign in again"))
                        return
                self.client.save()
                self.q.put(self._build_main)
            except Exception as e:
                self.q.put(lambda: status.configure(text=f"Error: {e}"))

        threading.Thread(target=work, daemon=True).start()

    # ----------------------------------------------------------------- main
    def _build_main(self):
        self._clear()
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)
        for name, fn in (("Library", self._tab_library), ("Activate", self._tab_activate),
                         ("Download", self._tab_download), ("Account", self._tab_account),
                         ("Log", self._tab_log)):
            f = ttk.Frame(nb, padding=15)
            nb.add(f, text=name)
            self._frames[name] = f
            fn(f)
        self._refresh_library()

    # -------------------------------------------------------------- library
    def _tab_library(self, f):
        ttk.Label(f, text="Owned games / DLC", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(f, text="Double-click a game: loads productId and resolves the manifest ID.",
                  foreground="#666").pack(anchor="w", pady=(2, 0))
        cols = ("name", "type", "productId", "spaceId")
        tree = ttk.Treeview(f, columns=cols, show="headings", height=20)
        for c, w in zip(cols, (330, 80, 90, 350)):
            tree.heading(c, text=c)
            tree.column(c, width=w)
        tree.pack(fill="both", expand=True, pady=(8, 0))
        row = ttk.Frame(f)
        row.pack(pady=10)
        ttk.Button(row, text="Refresh", command=self._refresh_library).pack(side="left", padx=4)

        def do_launch():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Launch", "Select a game first")
                return
            vals = tree.item(sel[0], "values")
            if not str(vals[2]).isdigit():
                messagebox.showinfo("Launch", "That row has no productId")
                return
            pid = int(vals[2])
            self._log(f"Launching {vals[0]} (productId={pid}) ...")
            threading.Thread(target=self._do_launch, args=(pid,), daemon=True).start()

        ttk.Button(row, text="Launch", command=do_launch).pack(side="left", padx=4)
        ttk.Button(row, text="Stop", command=self._do_stop).pack(side="left", padx=4)
        self._frames["tree"] = tree

        def on_double(_evt):
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0], "values")
            pid, name = vals[2], vals[0]
            entry = self._frames.get("dl_pid")
            if entry is not None and str(pid).isdigit():
                entry.delete(0, "end")
                entry.insert(0, str(pid))
                self._log(f"Selected for download: {name} (productId={pid})")
                resolver = self._frames.get("dl_resolve")
                if resolver is not None:
                    resolver()

        tree.bind("<Double-1>", on_double)

    def _refresh_library(self):
        tree = self._frames.get("tree")
        if not tree:
            return
        for i in tree.get_children():
            tree.delete(i)

        def work():
            try:
                items = self.client.library()
                idx = _load_config_index()
                spaces, addons = idx["spaces"], idx["addons"]

                def fill():
                    rows = []
                    for it in items:
                        sid = (it.get("spaceId") or "").lower()
                        pid = it.get("productId")
                        nm = spaces.get(sid) if sid else None
                        if not nm and isinstance(pid, int):
                            nm = addons.get(pid)
                        if not nm and not sid:
                            continue
                        if not nm:
                            nm = f"Unknown ({it.get('type') or 'item'} {pid})"
                        rows.append((nm, it.get("type") or "",
                                     pid if pid is not None else "",
                                     it.get("spaceId") or ""))
                    rows.sort(key=lambda r: (r[1] != "game", str(r[0]).lower()))
                    for r in rows:
                        tree.insert("", "end", values=r)

                self.q.put(fill)
            except Exception as e:
                err = str(e)
                self.q.put(lambda: messagebox.showerror("Library", err))

        threading.Thread(target=work, daemon=True).start()

    def _do_launch(self, pid):
        try:
            proc = launch_game(self.client, pid, log=self._log)
            self._launch_proc = proc
            try:
                proc.wait()
            except Exception:
                pass
            finish = getattr(proc, "_finish", None)
            if finish:
                finish()
            self._log(f"game exited (code {proc.returncode})")
        except Exception as e:
            self._log(f"launch error: {e}", "ERR")

    def _do_stop(self):
        proc = getattr(self, "_launch_proc", None)
        if not proc:
            self._log("no game launched from here")
            return
        try:
            proc.terminate()
            self._log("terminated game process")
        except Exception as e:
            self._log(f"stop error: {e}", "ERR")

    # ------------------------------------------------------------- activate
    def _tab_activate(self, f):
        ttk.Label(f, text="Activate a CD key / activation code",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(f, text="Key (e.g. XXXX-XXXX-XXXX-XXXX)").pack(anchor="w", pady=(15, 0))
        key = ttk.Entry(f, width=40)
        key.pack(pady=(0, 10))
        result = scrolledtext.ScrolledText(f, height=14, width=90, state="disabled")
        result.pack(pady=10)

        def do():
            k = key.get().strip()
            if not k:
                return
            result.configure(state="normal")
            result.insert("end", f"Activating {k} ...\n")
            result.configure(state="disabled")

            def work():
                try:
                    r = self.client.activate(k)

                    def show():
                        result.configure(state="normal")
                        result.insert("end", json.dumps(r, indent=2) + "\n")
                        result.see("end")
                        result.configure(state="disabled")
                    self.q.put(show)
                except Exception as e:
                    def err():
                        result.configure(state="normal")
                        result.insert("end", f"Error: {e}\n")
                        result.configure(state="disabled")
                    self.q.put(err)

            threading.Thread(target=work, daemon=True).start()

        ttk.Button(f, text="Activate", command=do).pack()

    # ------------------------------------------------------------- download
    def _tab_download(self, f):
        ttk.Label(f, text="Download a game", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=15)

        ttk.Label(row, text="Product ID").pack(side="left")
        pid = ttk.Entry(row, width=12)
        pid.pack(side="left", padx=5)
        self._frames["dl_pid"] = pid

        ttk.Label(row, text="Manifest ID (SHA1)").pack(side="left", padx=(15, 0))
        mid = ttk.Entry(row, width=42)
        mid.pack(side="left", padx=5)
        self._frames["dl_mid"] = mid

        def resolve():
            try:
                want = int(pid.get().strip())
            except ValueError:
                messagebox.showerror("Resolve", "Enter a numeric Product ID first")
                return
            self._log(f"Resolving manifestId for product {want} via demux catalog...")

            def work():
                try:
                    recs = fetch_manifest_map(self.client.ticket.encode(),
                                              self.client.session_id.encode())
                    self._log(f"catalog: {len(recs)} products")
                    mval, tag = resolve_manifest(recs, want)
                    if not mval:
                        msg = (f"No manifest for product {want}\n"
                               f"(catalog products: {sorted(recs)})")
                        self.q.put(lambda: messagebox.showinfo("Resolve", msg))
                        return

                    def fill():
                        mid.delete(0, "end")
                        mid.insert(0, mval)
                        self._log(f"manifestId[{want}] = {mval}  (branch: {tag})")

                    self.q.put(fill)
                except Exception as e:
                    err = str(e)
                    self.q.put(lambda: self._log(f"resolve error: {err}", "ERR"))

            threading.Thread(target=work, daemon=True).start()

        ttk.Button(row, text="Resolve", command=resolve).pack(side="left", padx=(6, 0))
        self._frames["dl_resolve"] = resolve

        ttk.Label(f, text="productId comes from entitlements; manifestId from the demux config "
                          "catalog (branch tag UbisoftConnect_QC / Live).",
                  foreground="#666").pack(anchor="w")

        progress = ttk.Progressbar(f, length=700, mode="determinate")
        progress.pack(pady=15)
        self._frames["progress"] = progress

        def do():
            try:
                p = int(pid.get().strip())
            except ValueError:
                messagebox.showerror("Download", "Product ID must be an integer")
                return
            m = mid.get().strip()
            if not m:
                messagebox.showerror("Download", "Manifest ID required")
                return
            progress.configure(value=0, maximum=100)
            threading.Thread(target=self._do_download, args=(p, m), daemon=True).start()

        ttk.Button(f, text="Download", command=do).pack()

        def do_files():
            try:
                p = int(pid.get().strip())
            except ValueError:
                messagebox.showerror("Files", "Product ID must be an integer")
                return
            m = mid.get().strip()
            if not m:
                messagebox.showerror("Files", "Manifest ID required")
                return
            progress.configure(value=0, maximum=100)
            threading.Thread(target=self._do_download_files,
                             args=(p, m), daemon=True).start()

        ttk.Button(f, text="Download game files", command=do_files).pack(pady=(10, 0))
        ttk.Label(f, text="Downloads the .manifest, then every file's slices "
                          "(zstd-compressed), verifies SHA1 and writes the real files.",
                  foreground="#666").pack(anchor="w", pady=(6, 0))

    def _do_download_files(self, pid, mid):
        self._log(f"Downloading game files: product={pid} manifest={mid}")
        try:
            ticket = self.client.ticket.encode()
            sid = self.client.session_id.encode()

            sock, recs = demux_open_session(ticket, sid, read_seconds=15)
            sock.settimeout(15)
            sock.sendall(demux_download_auth(pid, ticket, sid))
            jws = parse_jws_response(_recv_frame(sock))
            sock.sendall(demux_service(b"download_service", 5))
            _recv_frame(sock)
            sock.sendall(demux_jws_auth(jws))
            _recv_frame(sock)
            self._log("session ready")

            sock.sendall(demux_path_request(pid, f"manifests/{mid}.manifest"))
            urls = signed_urls_from(_recv_frame(sock))
            if not urls:
                self._log("no signed manifest URL", "ERR")
                return
            tmp = f"downloads/{mid}.manifest"
            download_file(urls[0], tmp)
            raw = Path(tmp).read_bytes()
            self._log(f"manifest: {len(raw)} bytes")

            files = parse_manifest(raw)
            total = sum(len(f["chunks"]) for f in files)
            self._log(f"{len(files)} files, {total} slices")

            done = [0]

            def log(msg):
                self._log(msg)

            orig = log

            def progress_log(msg):
                orig(msg)
                if msg.startswith("["):
                    try:
                        cur = int(msg[1:msg.index("/")])
                        self.q.put(lambda: self._frames["progress"].configure(
                            value=100.0 * cur / max(len(files), 1)))
                    except (ValueError, IndexError):
                        pass

            download_game_slices(pid, raw, "downloads/game", sock, log=progress_log)
            self._log("game files complete")
        except Exception as e:
            self._log(f"files error: {e}", "ERR")

    def _do_download(self, pid, mid):
        self._log(f"Starting download: product={pid} manifest={mid}")
        try:
            ticket = self.client.ticket.encode()
            sid = self.client.session_id.encode()

            self._log("demux: establishing session (catalog handshake)...")
            sock, recs = demux_open_session(ticket, sid, read_seconds=18)
            self._log(f"session ready (catalog {len(recs)} products)")
            sock.settimeout(10)

            sock.sendall(demux_download_auth(pid, ticket, sid))
            jws = parse_jws_response(_recv_frame(sock))
            self._log(f"ownership JWS: {len(jws)}B")

            sock.sendall(demux_service(b"download_service", 5))
            _recv_frame(sock)
            sock.sendall(demux_jws_auth(jws))
            _recv_frame(sock)
            self._log("download_service + jws_auth ok")

            sock.sendall(demux_metadata_request(pid, mid))
            resp = _recv_frame(sock)
            m = re.search(rb"http://[A-Za-z0-9._~:/?#@!$&()*+,;=%\-]+", resp)
            if not m:
                self._log("no signed URL in metadata response", "ERR")
                return
            url = m.group(0).decode("ascii")
            self._log("signed .metadata URL acquired")

            dest = f"downloads/{mid}.metadata"
            done = download_file(
                url, dest,
                lambda d, t: self.q.put(lambda: self._frames["progress"].configure(
                    value=(100 * d / t) if t else 0)))
            self._log(f".metadata downloaded: {done} bytes -> {dest}")
            self._log("Download flow complete (manifest + slices follow the same pattern).")
        except Exception as e:
            self._log(f"download error: {e}", "ERR")

    # -------------------------------------------------------------- account
    def _tab_account(self, f):
        c = self.client
        rows = [("userId", c.user_id), ("profileId", c.profile_id),
                ("nameOnPlatform", c.name_on_platform), ("sessionId", c.session_id),
                ("ticket (JWE)", (c.ticket or "")[:40] + "…")]
        for i, (k, v) in enumerate(rows):
            ttk.Label(f, text=k, font=("Segoe UI", 10, "bold")).grid(row=i, column=0,
                                                                    sticky="w", pady=3)
            ttk.Label(f, text=str(v), foreground="#444").grid(row=i, column=1,
                                                              sticky="w", padx=15)

    # ------------------------------------------------------------------ log
    def _tab_log(self, f):
        w = scrolledtext.ScrolledText(f, width=110, height=32, state="disabled")
        w.pack(fill="both", expand=True)
        self._frames["log"] = w


def main():
    root = tk.Tk()
    app = UbisoftApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
