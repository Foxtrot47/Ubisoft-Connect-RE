"""Demux cloudsave_service client.

CloudSaveClient uses a live ownership token and dynamically assigned connection
IDs. URL methods are 1=PUT, 2=GET, 3=DELETE. See docs/07-cloud-saves.md.
The older fixed-channel helpers remain below for historical capture comparison;
they omit ownership authorization and are not the verified transport path.
"""

from __future__ import annotations

import re
import struct
from urllib.parse import urlsplit

import ubisoft_gui as g

CLOUDSAVE_SERVICE = b"cloudsave_service"
SERVICE_COUNTER = 6  # observed in the capture: {1:{1:6, 3:{2:"cloudsave_service"}}}


def service_select(counter: int = SERVICE_COUNTER) -> bytes:
    return g._frame(g._ld(1, g._field(1, 0, g._varint(counter))
                          + g._ld(3, g._ld(2, CLOUDSAVE_SERVICE))))


def build_request(product_id: int, op: int, slots, counter: int = 1) -> bytes:
    """slots: list of (name, size|None, md5_b64|None)."""
    slot_msgs = b""
    for name, size, md5 in slots:
        inner = g._ld(1, name.encode())
        if size is not None or md5 is not None:
            body = b""
            if size is not None:
                body += g._field(1, 0, g._varint(size))
            if md5 is not None:
                body += g._ld(2, md5.encode())
            inner += g._ld(2, body)
        slot_msgs += g._ld(4, inner)

    body = g._field(2, 0, g._varint(product_id)) + g._field(3, 0, g._varint(op)) + slot_msgs
    framed = g._frame(g._ld(1, g._field(1, 0, g._varint(1)) + g._ld(2, body)))
    return g._frame(g._ld(2, g._ld(1, g._field(1, 0, g._varint(5)) + g._ld(2, framed))))


def open_socket(ticket: bytes, sid: bytes):
    """Authenticated demux socket with cloudsave_service subscribed."""
    sock, records = g.demux_open_session(ticket, sid, read_seconds=12)
    sock.sendall(service_select())
    g._drain(sock, 2)
    return sock, records


def request(sock, message: bytes, wait: float = 5.0):
    sock.sendall(message)
    return g._drain(sock, wait)


def urls(resp: bytes):
    return [m.group(0).decode("ascii")
            for m in re.finditer(rb"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%\-]+", resp)]


def cloudsave_url_request(product_id: int, method: int, slots, ownership_token: str):
    """Modern service payload; demux_push supplies connection/request framing.

    Method 1=PUT, 2=GET, 3=DELETE. DELETE is used only to clean up test objects.
    Unlike the historical builder above, this includes the required ownership token.
    """
    if method not in (1, 2, 3) or not ownership_token or product_id <= 0:
        raise ValueError("Invalid cloud URL request")
    body = (g._ld(1, ownership_token.encode())
            + g._field(2, 0, g._varint(product_id))
            + g._field(3, 0, g._varint(method)))
    seen = set()
    for name, size, md5 in slots:
        if not re.fullmatch(r"[0-9]+", name) or name in seen:
            raise ValueError("Invalid or duplicate cloud slot")
        seen.add(name)
        item = g._ld(1, name.encode())
        if method == 1:
            import base64
            if not isinstance(size, int) or not 0 <= size <= 16 * 1024 * 1024:
                raise ValueError("Invalid cloud object size")
            if not isinstance(md5, str) or len(base64.b64decode(md5, validate=True)) != 16:
                raise ValueError("Invalid cloud MD5")
            item += g._ld(2, g._field(1, 0, g._varint(size)) + g._ld(2, md5.encode()))
        elif size is not None or md5 is not None:
            raise ValueError("Unexpected write arguments")
        body += g._ld(4, item)
    if not seen:
        raise ValueError("No cloud slots supplied")
    return g._ld(2, body)


def parse_cloudsave_urls(response, profile_id, product_id, slots):
    """Validate destinations without exposing presigned URLs in diagnostics."""
    body = dict(g._fields(response)).get(2, b"")
    status = dict(g._fields(body)).get(1, 0)
    if status != 1:  # This enum's default is Unknown, not Success.
        raise RuntimeError(f"Cloud URL request rejected (status={status})")
    result = {}
    for field, raw in g._fields(body):
        if field != 2:
            continue
        url = dict(g._fields(raw)).get(2, b"").decode("ascii")
        parsed = urlsplit(url)
        name = parsed.path.rsplit("/", 1)[-1].removesuffix(".savegame")
        if (parsed.scheme != "https" or parsed.hostname not in (
                "ubisoft-uplay-savegames.s3.us-east-1.amazonaws.com",
                "ubisoft-uplay-savegames.s3.amazonaws.com")
                or parsed.username or parsed.password or parsed.fragment
                or parsed.port not in (None, 443)
                or name not in slots or name in result
                or parsed.path != f"/{profile_id}/{product_id}/{name}.savegame"):
            raise RuntimeError("Unexpected cloud object destination")
        result[name] = url
    if set(result) != set(slots):
        raise RuntimeError("Incomplete cloud URL response")
    return result


class CloudSaveClient:
    """Authenticated, dynamically addressed cloudsave_service connection."""
    def __init__(self, ticket, session_id, profile_id, product_id):
        self.ticket, self.session_id = ticket, session_id
        self.profile_id, self.product_id = profile_id, product_id
        self.sock = None
        self.request_id = 1

    def __enter__(self):
        self.sock, outer_id = g.demux_open_janus(self.ticket)
        try:
            self.token = g.demux_ownership_token(self.sock, self.product_id, outer_id,
                                                self.ticket, self.session_id)
            self.connection_id = g.demux_open_connection(self.sock, CLOUDSAVE_SERVICE, outer_id + 1)
            return self
        except BaseException:
            self.sock.close()
            raise

    def __exit__(self, *args):
        self.sock.close()

    def urls(self, method, slots):
        slots = list(slots)
        payload = cloudsave_url_request(self.product_id, method, slots, self.token)
        rid = self.request_id
        self.request_id += 1
        g.demux_push(self.sock, self.connection_id, rid, payload)
        response = g._demux_await_response(self.sock, rid, self.connection_id)
        return parse_cloudsave_urls(response, self.profile_id, self.product_id,
                                   [name for name, _, _ in slots])


if __name__ == "__main__":
    print("Import CloudSaveClient for authenticated cloud transfers.\n"
          "For a temporary-slot round trip: python tooling/cloudsave_roundtrip.py --help\n"
          "Historical unauthenticated opcode probing is no longer run.")
