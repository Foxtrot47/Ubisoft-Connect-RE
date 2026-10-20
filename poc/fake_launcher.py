#!/usr/bin/env python3
"""Fake Ubisoft launcher — serves the pipes the game expects and spawns it.

Reconstructed from live captures of `upc.exe` (see docs/06-launch.md):

    terminal_1_game_start_ipc_pipe_        launch request/response
    terminal_1_uplay_api_process_ipc_pipe_ game announces itself
    terminal_1_uplay_ipc_pipe_             session push (carries the ticket)
    terminal_1_uplay_aux_ipc_pipe_         Denuvo activation (cached gameToken)
    + observe-only overlay/protocol/orbit/crash/service pipes

The session ticket is a real JWE obtained through our own login; the activation
answer is the launcher's own cached `gameToken`. Game binaries and Ubisoft's DLLs
stay untouched — we impersonate the launcher service.

The game is spawned with an inheritable wait event, exactly as `upc.exe` does;
`UbisoftGameLauncher.exe` needs it or it times out and the job kills the game.

Usage:
    python fake_launcher.py 2688                # serve + spawn
    python fake_launcher.py 2688 --no-launch    # serve only
    python fake_launcher.py 2688 --eac          # add -eac_launcher (skip EAC)
    python fake_launcher.py 2688 --fresh-activation  # server-issued aux answer

--fresh-activation bypasses disk/evidence activation answers, but session pushes
and follow-up messages still depend on captured templates. This is not yet a
verified fresh-machine launch mode.

UPLAY_PASSWORD fills the cleartext credential field of the session push.
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import time
from pathlib import Path

import win32api
import win32con
import win32event
import win32file
import win32pipe
import win32process
import win32ts
import pywintypes

sys.path.insert(0, str(Path(__file__).parent))
from ubisoft_gui import (  # noqa: E402
    cloud_save_entity, demux_denuvo_request, demux_game_active, demux_game_start,
    demux_open_janus, demux_ownership_token, demux_game_token, demux_pc_session,
    playsession_delete, playsession_start)

PIPE_PREFIX = rf"\\.\pipe\terminal_{win32ts.ProcessIdToSessionId(os.getpid())}_"
BUFSIZE = 65536

# Reply to the 11B probe the game sends on uplay_aux_ipc_pipe_.
# initRsp addonsToValidate triple. Captured verbatim; the game echoes it back in
# later requests, so it looks like a validation list rather than a version.
AUX_VERSION_TRIPLE = (3367, 3368, 3962)

# Store titles the launcher announces to the service on launch (captured for 2688).
PRODUCT_NAMES = {2688: "WATCH_DOGS® 2".encode()}


# Sent proactively on uplay_service_ipc_pipe_: the hardware-score cache path.
HWSCORE_PATH = b"C:/ProgramData/Ubisoft/Ubisoft Game Launcher/cache//statistics/hwscore"


def hwscore_message(path: bytes = HWSCORE_PATH) -> bytes:
    return frame(ld(3, vint(1, 1) + ld(3, ld(1, path))))


# --------------------------------------------------------------------------- #
# Captured launcher state we replay (see docs/06-launch.md)
# --------------------------------------------------------------------------- #
GAME_TOKEN_FILE = (Path(__file__).resolve().parent.parent
                   / "evidence" / "wd2_game_token.bin")


def captured_game_token(user_id: str | bytes | None = None) -> bytes | None:
    r"""The launcher's cached activation answer for this machine.

    `upc.exe` keeps it in
    %LOCALAPPDATA%\Ubisoft Game Launcher\cache\activations\<userId>
    and serves it byte-for-byte on every launch (verified: two launches produce
    an identical 1576-byte value). Replaying it is therefore not stale data.

    The live launcher cache is preferred; a copy in evidence/ keeps the PoC
    working on a clean machine state.
    """
    cache = (Path(os.environ.get("LOCALAPPDATA", "")) / "Ubisoft Game Launcher"
             / "cache" / "activations")
    for path in (cache / user_id if user_id else None, GAME_TOKEN_FILE):
        if path is None:
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        # Cache file: {1:productId, 2:{1:0, 3:<base64 blob>, 5:""}}
        inner = find_field(blob, 2)
        tok = find_field(inner or b"", 3)
        if tok:
            return tok
    return None


FOLLOWUPS_FILE = (Path(__file__).resolve().parent.parent
                  / "evidence" / "wd2_uplay_followups.bin")


def captured_uplay_followups() -> list[bytes]:
    """Launcher->game messages upc.exe sends right after the first session push.

    Captured from a working launch: an addon list, repeated friend pushes,
    per-addon acks and the large session-detail frame. The file is a sequence
    of 4-byte length prefixed *writes*; each captured write is re-framed with a
    fresh prefix because that is the shape the game accepted (the large frame
    was split over 64 KB writes).
    """
    try:
        blob = FOLLOWUPS_FILE.read_bytes()
    except OSError:
        return []
    out, i = [], 0
    while i + 4 <= len(blob):
        n = int.from_bytes(blob[i:i + 4], "big")
        i += 4
        out.append(blob[i:i + n])
        i += n
    return out


def request_sid(request_token: bytes) -> str | None:
    """The `sid` from a denuvo request token's JWE header (relayed as f31)."""
    import base64
    import json
    try:
        header = request_token.split(b".")[0]
        header += b"=" * (-len(header) % 4)
        data = json.loads(base64.urlsafe_b64decode(header))
    except (ValueError, TypeError):
        return None
    sid = data.get("sid")
    return sid if isinstance(sid, str) and sid else None


def demux_token(body: bytes) -> bytes | None:
    """Pull the activation token out of a `denuvo_service` reply frame.

    The reply nests a length-prefixed inner frame, which plain protobuf parsing
    cannot cross (`{2:{1:{1:2, 2[fr]{1:{1:2, 13:{1:1, 2:<JWE>}}}}}}`), so take
    the JWE run directly. Its own header starts with `eyJlbmMi`.
    """
    m = re.search(rb"eyJlbmMi[A-Za-z0-9_\-.]+(?:\.|$)", body)
    if not m:
        return None
    tok = m.group(0).rstrip(b".")
    return tok if tok.count(b".") == 2 else None


DENUVO_TOKEN_FILE = (Path(__file__).resolve().parent.parent
                     / "evidence" / "denuvo_token.bin")

SESSION_PUSH_FILE = (Path(__file__).resolve().parent.parent
                     / "evidence" / "wd2_session_push.bin")


def default_session_push() -> bytes | None:
    """Official 1326B session push, used as the message template.

    Our generated push reproduces every field but the game crashes inside
    Disrupt_64.dll (Denuvo) with it; the captured shape works. Only f8 (the
    ticket) is replaced at send time.
    """
    try:
        return SESSION_PUSH_FILE.read_bytes()
    except OSError:
        return None


def denuvo_token() -> bytes | None:
    """The 620-byte 3-part JWE the launcher puts in the session push at f8.

    Minted per launch and delivered by the demux stream as f13{f1:1 f2:<token>}.
    Until we can mint it ourselves we replay the one captured from a working
    launch (our own account), which is why it lives in evidence/.
    """
    try:
        tok = DENUVO_TOKEN_FILE.read_bytes()
    except OSError:
        return None
    return tok if tok.count(b".") == 2 and len(tok) > 200 else None


def parse_cache_record(body: bytes):
    """Decode an HTTP cache record reported on uplay_service_ipc_pipe_.

    Captured shape (1084B, 2026-10-21):
        f1{ f1:"GET" }
        f2{ f1:<status> f2:<reason> f3:1 f4{f1:name f2:value}* f6:<id>
            f7:<trace> f8:<url> f10:4 f11:"h2" f12:1 f13:<content-type> f14:"GET" }
        f3{ <id> }
    upc.exe sends no reply for these -- it just absorbs them.
    """
    def varint(b, i):
        r = s = 0
        while True:
            x = b[i]; i += 1
            r |= (x & 0x7f) << s
            if not x & 0x80:
                return r, i
            s += 7

    def fields(b):
        i, out = 0, []
        while i < len(b):
            k, i = varint(b, i)
            f, wt = k >> 3, k & 7
            if wt == 0:
                v, i = varint(b, i); out.append((f, v))
            elif wt == 2:
                n, i = varint(b, i); out.append((f, b[i:i + n])); i += n
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
        return out

    try:
        top = dict(fields(body))
        inner = dict(fields(top.get(2, b"")))
        method = ""
        m = dict(fields(top.get(1, b"")))
        if isinstance(m.get(1), bytes):
            method = m[1].decode("utf-8", "replace")
        url = inner.get(8, b"")
        ctype = inner.get(13, b"")
        hdrs = [v for f, v in fields(inner.get(2, b"")) if False]
        # headers are repeated f4 inside f2's payload; reparse to count them
        raw_f2 = top.get(2, b"")
        headers = []
        for f, v in fields(raw_f2):
            if f == 4 and isinstance(v, bytes):
                pair = dict(fields(v))
                nm = pair.get(1, b""); val = pair.get(2, b"")
                if isinstance(nm, bytes) and isinstance(val, bytes):
                    headers.append((nm.decode("utf-8", "replace"),
                                    val.decode("utf-8", "replace")))
        return {
            "method": method or (inner.get(14, b"").decode("utf-8", "replace") if isinstance(inner.get(14), bytes) else ""),
            "status": inner.get(1),
            "url": url.decode("utf-8", "replace") if isinstance(url, bytes) else "",
            "content_type": ctype.decode("utf-8", "replace") if isinstance(ctype, bytes) else "",
            "headers": headers,
        }
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# protobuf helpers (4-byte big-endian frame prefix, as observed on the wire)
# --------------------------------------------------------------------------- #
def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def fld(f: int, wt: int, payload: bytes = b"") -> bytes:
    return varint((f << 3) | wt) + payload


def ld(f: int, payload: bytes) -> bytes:
    return fld(f, 2, varint(len(payload)) + payload)


def vint(f: int, value: int) -> bytes:
    return fld(f, 0, varint(value))


def f32(field: int, value: float) -> bytes:
    """Single-precision float field (wire type 5), as seen in f16.f3."""
    import struct
    return fld(field, 5, struct.pack("<f", value))


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def rd_varint(buf: bytes, i: int):
    v = 0
    sh = 0
    while True:
        c = buf[i]
        i += 1
        v |= (c & 0x7F) << sh
        sh += 7
        if not (c & 0x80):
            return v, i


def parse_fields(buf: bytes):
    """Yield (field, value) for one protobuf message (bytes for wt=2)."""
    i = 0
    while i < len(buf):
        tag, i = rd_varint(buf, i)
        f, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = rd_varint(buf, i)
            yield f, v
        elif wt == 2:
            ln, i = rd_varint(buf, i)
            yield f, buf[i:i + ln]
            i += ln
        elif wt == 1:
            yield f, buf[i:i + 8]
            i += 8
        elif wt == 5:
            yield f, buf[i:i + 4]
            i += 4
        else:
            return


def find_field(buf: bytes, want: int, max_depth: int = 4):
    """Depth-first search for a length-delimited field, descending into messages."""
    for f, v in parse_fields(buf):
        if not isinstance(v, bytes):
            continue
        if f == want:
            return v
        if max_depth > 1:
            got = find_field(v, want, max_depth - 1)
            if got is not None:
                return got
    return None


# --------------------------------------------------------------------------- #
# launcher
# --------------------------------------------------------------------------- #
class FakeLauncher:
    def __init__(self, client, product_id: int, log=print, replay=None,
                 fresh_activation: bool = False, session_template: bytes | None = None,
                 session_followups: list[bytes] | None = None,
                 independent_session: bool = False, launch_spec_override=None):
        if independent_session and (not fresh_activation or replay is not None
                                    or session_template is not None or session_followups is not None):
            raise ValueError("independent session requires live activation and forbids all replay inputs")
        self.independent_session = independent_session
        self.launch_spec_override = launch_spec_override
        if fresh_activation and os.environ.get("UPLAY_AUX_REPLAY"):
            raise ValueError("fresh activation cannot be combined with UPLAY_AUX_REPLAY")
        self.fresh_activation = fresh_activation
        self._activation_request = None
        self._activation_answer = None
        self.client = client
        self.pid = product_id
        self.log = log
        if fresh_activation and replay:
            raise ValueError("fresh activation cannot replay a session capture")
        self.replay = session_template if session_template is not None else (
            None if fresh_activation else (
                Path(replay).read_bytes() if replay else default_session_push()))
        self.session_followups = session_followups
        self._ps_thread = None
        self._ps_started = False
        self._stop = threading.Event()
        self.threads = []
        self.session_pushes = 0
        self.demux_sock = None
        self.demux_ready = threading.Event()
        self.fresh_token: bytes | None = None
        self._token_q: queue.Queue[bytes] = queue.Queue()
        self.wait_event = None
        self.child_pid = None
        self.child_exit_code = None
        self.active_game_pid = None
        self.active_game_exit_code = None
        self.game_exit_codes = {}
        self._session_owned_ids = None

    # -- pipe plumbing ------------------------------------------------------ #
    def _serve(self, name: str, handler):
        full = PIPE_PREFIX + name
        while not self._stop.is_set():
            try:
                h = win32pipe.CreateNamedPipe(
                    full,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    BUFSIZE, BUFSIZE, 0, None)
            except pywintypes.error as e:
                self.log(f"[pipe] create {name} failed: {e}")
                return
            try:
                win32pipe.ConnectNamedPipe(h, None)
                self.log(f"[pipe] client connected on {name}")
                handler(h)
            except pywintypes.error as e:
                if e.winerror not in (109, 232, 233):  # broken/no process
                    self.log(f"[pipe] {name} error: {e}")
            finally:
                try:
                    win32file.CloseHandle(h)
                except pywintypes.error:
                    pass

    def _read(self, h, timeout_s: float = 30.0) -> bytes:
        """Read one framed message (4-byte big-endian length prefix)."""
        buf = b""
        deadline = time.time() + timeout_s
        while len(buf) < 4 and time.time() < deadline:
            try:
                _, data = win32file.ReadFile(h, BUFSIZE)
            except pywintypes.error:
                return b""
            if data:
                buf += data
        if len(buf) < 4:
            return b""
        need = int.from_bytes(buf[:4], "big")
        while len(buf) < 4 + need and time.time() < deadline:
            try:
                _, data = win32file.ReadFile(h, BUFSIZE)
            except pywintypes.error:
                break
            if not data:
                break
            buf += data
        return buf

    def _read_raw(self, h, timeout_s: float = 600.0) -> bytes:
        """Read once from a pipe that does not use the 4-byte length prefix."""
        while not self._stop.is_set():
            try:
                _, data = win32file.ReadFile(h, BUFSIZE)
            except pywintypes.error:
                return b""
            if data:
                return data
        return b""

    def _write(self, h, body: bytes):
        win32file.WriteFile(h, frame(body))

    # -- session message ---------------------------------------------------- #
    def _owned_ids(self):
        if self.fresh_activation:
            if self._session_owned_ids is None:
                raise RuntimeError("fresh session ownership catalog is not ready")
            return self._session_owned_ids
        try:
            lib = self.client.library()
        except Exception:
            return [self.pid]
        ids = sorted({e.get("productId") for e in lib if isinstance(e.get("productId"), int)})
        return ids or [self.pid]

    def _session_message(self) -> bytes:
        if self.independent_session and self.replay is not None:
            raise RuntimeError("independent session cannot replay a captured message")
        if self.replay is not None:
            return self._replayed_session()
        return self._generated_session()

    def _replayed_session(self) -> bytes:
        """Captured session push with the live ticket and a usable save root.

        The captured frame is `{1:{...}}`; f8 (ticket) and f17 (savegames root)
        inside the inner message are the only fields substituted. f17 matters
        because the captured value points into the Connect install directory,
        which does not exist when the client is absent or renamed.
        """
        body = self.replay[4:]
        inner = next((v for f, v in parse_fields(body) if f == 1), b"")
        out = bytearray()
        for f, v in parse_fields(inner):
            if f == 8:
                out += ld(8, self._ticket_field())
            elif f == 17:
                out += ld(17, ld(1, self._savegames_dir().replace("\\", "/").encode()))
            elif isinstance(v, bytes):
                out += ld(f, v)
            elif isinstance(v, int):
                out += vint(f, v)
        return ld(1, bytes(out))

    def _generated_session(self) -> bytes:
        """Build the profile/session message without reading capture templates."""
        try:
            me = self.client.me()
        except Exception as e:
            self.log(f"[session] profile lookup failed ({e}); using saved ids")
            me = {}
        profile = (
            ld(1, str(me.get("userId") or self.client.user_id).encode())
            + ld(2, str(me.get("username") or "").encode())
            + ld(3, str(me.get("nameOnPlatform") or "").encode())
            + ld(4, str(me.get("email") or "").encode())
            + ld(5, b"" if self.fresh_activation else os.environ.get("UPLAY_PASSWORD", "").encode())
            + ld(6, str(me.get("country") or "IN").encode())
        )
        # Field set reproduced from a *working* launch capture (2688, 2026-10-21).
        # Everything below f8 was missing or wrong in our earlier push.
        body = (
            vint(1, 1)
            + ld(2, profile)
            + vint(3, 1)
            + vint(4, self.pid)
            + b"".join(vint(5, i) for i in self._owned_ids())
            + ld(6, vint(1, self.pid) + ld(2, b""))
            + vint(7, 0)
            + ld(8, self._ticket_field())
            + ld(11, vint(1, 0))
            + vint(12, 0)
            + ld(15, vint(1, 1) + vint(2, 3))
            + ld(16, vint(1, 6211) + vint(2, 22395) + f32(3, 1.0))
            + ld(17, ld(1, self._savegames_dir().encode()))
            + ld(18, b"")
            + ld(19, vint(1, 1) + vint(2, 1))
            + ld(21, vint(2, 1))
            + ld(22, ld(1, self._game_application_id().encode()))
            + ld(23, b"")
        )
        return ld(1, body)

    def _ticket_field(self) -> bytes:
        """f8: the denuvo token minted for this launch, else the login ticket."""
        if self.fresh_activation:
            if not self.fresh_token:
                raise RuntimeError("fresh session PC ticket is not ready")
            return self.fresh_token
        tok = self.fresh_token or denuvo_token()
        if tok:
            src = "minted" if self.fresh_token else "captured"
            self.log(f"[session] using {src} denuvo token ({len(tok)}B, 3-part JWE)")
            return tok
        self.log("[session] no denuvo token â falling back to login ticket")
        return self.client.ticket.encode()

    def _game_application_id(self) -> str:
        """InitRsp.ubiServices.appId, resolved from live entitlement metadata."""
        import uuid
        value = getattr(self.client, "game_app_id", None)
        if not value:
            for product in self.client.library():
                if product.get("productId") == self.pid:
                    value = product.get("applicationId")
                    break
        if not value:
            raise RuntimeError("game application ID unavailable; refusing to invent one")
        return str(uuid.UUID(value))

    def _install_dir(self, exe: str, cwd: str = "") -> str:
        """Working directory the real launcher hands back for the game.

        upc.exe reads HKLM\\SOFTWARE\\Ubisoft\\Launcher\\Installs\\<pid>\\InstallDir
        and returns that (forward slashes, trailing separator). Falls back to the
        request's cwd, then to the exe's parent.
        """
        if self.independent_session:
            if self.launch_spec_override is None:
                raise RuntimeError("independent session requires an explicit game path")
            return str(self.launch_spec_override[2])
        if cwd:
            return cwd
        try:
            import winreg
            key = rf"SOFTWARE\\Ubisoft\\Launcher\\Installs\\{self.pid}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as k:
                v = winreg.QueryValueEx(k, "InstallDir")[0]
            if v:
                return v
        except OSError:
            pass
        return str(Path(exe).parent)

    def _handle_service(self, h):
        """uplay_service_ipc_pipe_: the launcher's HTTP cache sink.

        upc.exe writes the hwscore path notice on connect, then reads cached
        response records from clients without replying. Implemented to match.
        """
        if self.independent_session:
            path = Path(self._savegames_dir()).parents[1] / "statistics" / "hwscore"
            msg = hwscore_message(path.as_posix().encode())
        else:
            msg = hwscore_message()
        self._write(h, msg)
        self.log(f"[service] sent hwscore path notice ({len(msg)}B)")
        while not self._stop.is_set():
            # NOTE: this pipe is NOT length-prefixed; messages start straight at
            # the first protobuf tag (captured records begin with 0x0a).
            req = self._read_raw(h)
            if not req:
                self.log("[service] idle/closed")
                return
            rec = parse_cache_record(req)
            if rec:
                self.log(f"[service] cache record {rec['status']} {rec['method']} "
                         f"{rec['url'][:90]} ({len(rec['headers'])} headers, "
                         f"{rec['content_type']})")
            else:
                self.log(f"[service] {len(req)}B undecoded {req[:48].hex()}")

    def _handle_unknown(self, h, name):
        """Serve a pipe we do not fully emulate, from captured evidence."""
        if name == "uplay_aux_ipc_pipe_":
            self._handle_aux(h)
            return
        req = self._read(h)
        self.log(f"[unknown:{name}] {len(req)}B {req[:64].hex()}")
        if name == "uplay_service_ipc_pipe_":
            self._handle_service(h)
        self._hold_open(h, f"unknown:{name}")

    def _handle_aux(self, h):
        """uplay_aux_ipc_pipe_: the Denuvo activation channel.

        Protocol (descriptor in uplay_aux_r164.dll, `UplayAuxDll.proto`):
            Req { requestId, initReq{uplayId}, activateReq{getCachedOrFreshTokenReq{
                  requestToken, secureDlcEnabled}} }
            Rsp { requestId, initRsp{result, uplayPID, addonsToValidate},
                  activateRsp{getCachedOrFreshTokenRsp{result, errorCode, gameToken}} }

        The game (Denuvo -> dbdata) mints the `requestToken`; we relay it to the
        demux `denuvo_service` and hand back the token it returns. The captured
        response is only a fallback while no demux connection exists.
        """
        while not self._stop.is_set():
            req = self._read(h, timeout_s=600.0)
            if not req:
                self.log("[aux] idle/closed")
                return
            rid = 0
            activate = None
            for f, v in parse_fields(req[4:]):
                if f == 1 and isinstance(v, int):
                    rid = v
                elif f == 3 and isinstance(v, bytes):
                    activate = v
            self.log(f"[aux] req {len(req)}B rid={rid} "
                     f"{'activate' if activate is not None else 'init'}")
            if activate is None:
                # initReq -> initRsp{result:1 ok, uplayPID, addonsToValidate}
                self._write_aux(h, rid, 2, vint(1, 1) + vint(2, os.getpid())
                                + b"".join(vint(3, v) for v in AUX_VERSION_TRIPLE))
                continue
            token = self._activate(activate)
            if token is None:
                # Nothing to send; the game retries with the same requestId.
                continue
            self._write_aux(h, rid, 3, ld(2, vint(2, 1) + vint(3, 0)
                                          + ld(4, token) + ld(5, b"")))

    def _write_aux(self, h, rid: int, field: int, body: bytes):
        self._write(h, vint(1, rid) + ld(field, body))

    def _activate(self, activate: bytes) -> bytes | None:
        """Answer an ActivateReq; returns the gameToken or None on failure."""
        request_token = None
        for f, v in parse_fields(activate):
            if f == 1:
                self.log("[aux] invalidateCachedTokenReq")
            elif f == 2 and isinstance(v, bytes):
                for f2, v2 in parse_fields(v):
                    if f2 == 2 and isinstance(v2, bytes):
                        request_token = v2
                    elif f2 == 3:
                        self.log(f"[aux] secureDlcEnabled={v2}")
        if not request_token:
            return None
        if self.fresh_activation:
            return self._fresh_game_token(request_token)
        (Path(__file__).parent / "denuvo_request_game.bin").write_bytes(request_token)
        self.log(f"[aux] requestToken {len(request_token)}B "
                 f"header={request_token[:24]!r}")
        sid = request_sid(request_token) or self.client.session_id
        if not sid:
            self.log("[aux] no session id")
            return None
        self.log(f"[aux] requestToken {len(request_token)}B sid={sid}")
        if not os.environ.get("UPLAY_AUX_REPLAY"):
            # Refresh the session token for the session push in the background;
            # the aux reply itself uses the launcher's cached activation blob.
            threading.Thread(target=self._mint_session_token,
                             args=(request_token, sid.encode()),
                             daemon=True).start()
        fallback = captured_game_token(self.client.user_id)
        if fallback:
            self.log(f"[aux] gameToken from cache ({len(fallback)}B)")
            return fallback
        return None

    def _fresh_game_token(self, request_token: bytes) -> bytes | None:
        """Issue the aux answer online; never fall back to a disk/evidence token.

        Repeated identical challenges reuse only this instance's successful answer,
        avoiding duplicate activation requests after an IPC retry.
        """
        if request_token == self._activation_request and self._activation_answer:
            return self._activation_answer
        for attempt in range(2):
            sock = None
            try:
                sock, rid = demux_open_janus(self.client.ticket.encode())
                ownership = demux_ownership_token(sock, self.pid, rid,
                    self.client.ticket.encode(), self.client.session_id.encode())
                token = demux_game_token(sock, ownership, request_token, rid + 10)
                self._activation_request, self._activation_answer = request_token, token
                self.log(f"[aux] server-issued gameToken ({len(token)}B)")
                return token
            except (OSError, EOFError) as error:
                self.log(f"[aux] issuance transport failure: {type(error).__name__}")
                if attempt == 0 and not self._stop.wait(3):
                    continue
                return None
            except RuntimeError as error:
                self.log(f"[aux] issuance rejected: {error}")
                return None
            finally:
                if sock is not None:
                    sock.close()
        return None

    def _mint_session_token(self, request_token: bytes, sid: bytes):
        token = self._demux_activate(request_token, sid)
        if token:
            self.fresh_token = token
            self.log(f"[aux] session token minted ({len(token)}B)")

    def _demux_activate(self, request_token: bytes, sid: bytes) -> bytes | None:
        """Relay the request token to `denuvo_service` and wait for the reply."""
        if not self.demux_sock:
            return None
        try:
            self.demux_sock.sendall(
                demux_denuvo_request(self.pid, request_token, sid))
        except OSError as e:
            self.log(f"[demux] activation send failed: {e}")
            return None
        deadline = time.time() + 25
        while time.time() < deadline and not self._stop.is_set():
            try:
                return self._token_q.get(timeout=1)
            except queue.Empty:
                continue
        return None

    # -- demux ---------------------------------------------------------------- #
    def _prepare_fresh_session(self):
        sock = None
        try:
            sock, rid = demux_open_janus(self.client.ticket.encode())
            self.fresh_token, self._session_owned_ids = demux_pc_session(sock, self.pid, rid,
                self.client.ticket.encode(), self.client.session_id.encode())
            self.log(f"[session] live PC ticket ready ({len(self.fresh_token)}B), "
                     f"{len(self._session_owned_ids)} catalog products")
        except (OSError, EOFError, RuntimeError) as error:
            self.log(f"[session] live PC ticket failed: {type(error).__name__}")
        finally:
            if sock is not None:
                sock.close()
            self.demux_ready.set()

    def _demux_session(self):
        """Hold an authenticated demux connection with `denuvo_service` subscribed.

        Mirrors what upc.exe does for the lifetime of a launch. `denuvo_service`
        is the channel WD2's Denuvo layer appears to wait on before it lets EAC
        initialise, so the game is launched only after this is up.
        """
        if self.fresh_activation:
            self._prepare_fresh_session()
            return
        from ubisoft_gui import demux_open_session

        ticket = (self.client.ticket or "").encode()
        sid = (self.client.session_id or "").encode()
        if not ticket or not sid:
            self.log("[demux] no ticket/session_id â skipping demux")
            self.demux_ready.set()
            return
        try:
            sock, recs = demux_open_session(ticket, sid, read_seconds=10)
        except Exception as e:
            self.log(f"[demux] open failed: {e}")
            self.demux_ready.set()
            return
        self.demux_sock = sock
        self.log(f"[demux] session open, denuvo_service subscribed "
                 f"({len(recs)} catalog records)")
        self.log("[demux] ready â launch the game now")
        self.demux_ready.set()

        # Keep the connection alive; the server pushes service traffic on it.
        # The catalog drain leaves the stream mid-frame, so frames are cut out
        # of a buffer and re-aligned whenever a length prefix is implausible.
        buf = b""
        while not self._stop.is_set():
            try:
                sock.settimeout(5)
                data = sock.recv(65536)
            except TimeoutError:
                continue
            except OSError as e:
                self.log(f"[demux] recv error: {e}")
                break
            if not data:
                self.log("[demux] server closed the connection")
                break
            buf += data
            while True:
                while len(buf) >= 4:
                    n = int.from_bytes(buf[:4], "big")
                    if 0 < n <= 0x400000 and (len(buf) < 5 or buf[4] >> 3):
                        break
                    buf = buf[1:]
                if len(buf) < 4:
                    break
                n = int.from_bytes(buf[:4], "big")
                if len(buf) < 4 + n:
                    break
                body, buf = buf[4:4 + n], buf[4 + n:]
                token = demux_token(body)
                if token:
                    self._token_q.put(token)
                    self.log(f"[demux] activation response, token {len(token)}B")
                else:
                    self.log(f"[demux] recv {len(body)}B {body[:32].hex()}")

    def _savegames_dir(self) -> Path:
        r"""Writable savegames root, reported to the game in f17.

        The real launcher uses <install>\savegames\<userId>; we must not depend on
        that path existing (and Program Files is not writable), so use our own root.
        Override with UPLAY_SAVE_ROOT.
        """
        import os

        root = os.environ.get("UPLAY_SAVE_ROOT")
        base = Path(root) if root else (Path(__file__).resolve().parent.parent / "savegames")
        # The game string-concatenates "<f17>1.save", so this must end with the
        # product folder AND a trailing separator (real client layout:
        # savegames\<userId>\<productId>\).
        d = base / str(self.client.user_id) / str(self.pid)
        d.mkdir(parents=True, exist_ok=True)
        return str(d) + "/"

    # -- handlers ----------------------------------------------------------- #
    def _reply_exe_path(self, exe: str, workdir: str) -> str:
        """Executable path in the exact form upc.exe returns.

        Captured from the real launcher for product 2688:
            E:/Games/WATCH_DOGS2//bin/WatchDogs2.exe
        i.e. <install root>/ + "/" + <relative path with forward slashes>.
        """
        root = workdir.replace("\\", "/")          # keep the trailing separator
        rel = exe.replace("\\", "/")
        base = root.rstrip("/")
        if base and rel.lower().startswith(base.lower() + "/"):
            rel = rel[len(base) + 1:]
        return (root + "/" + rel) if root else rel

    def _handle_game_start(self, h):
        req = self._read(h)
        self.log(f"[game_start] raw {len(req)}B head={req[:48].hex()}")
        if len(req) <= 4:
            return
        exe = cwd = ""
        b = find_field(req[4:], 10)
        if b is not None:
            exe = b.decode("utf-8", "replace")
        b = find_field(req[4:], 22)
        if b is not None:
            cwd = b.decode("utf-8", "replace")
        self.log(f"[game_start] exe={exe!r} cwd={cwd!r}")
        # exact shape observed on the wire:
        #   f2{ f1{ f1:1 f2:0 f3:exe f4:cwd f8:2
        #          f9{ f1{f1:1 f2:113 f3:0 f4:1 f5:0}
        #              f1{f1:3 f2:123 f3:0 f4:0 f5:0} } } }
        progress = (ld(1, vint(1, 1) + vint(2, 113) + vint(3, 0) + vint(4, 1) + vint(5, 0))
                    + ld(1, vint(1, 3) + vint(2, 123) + vint(3, 0) + vint(4, 0) + vint(5, 0)))
        # f4 is the game's *install root* (from Installs\<pid>\InstallDir), not the
        # exe's directory; f8 is 3, not 2. Both verified against a real upc.exe
        # capture for product 2688 (2026-10-21).
        workdir = self._install_dir(exe, cwd)
        # Reproduce the real launcher's string exactly: it concatenates the install
        # root with a leading slash plus the relative exe path, which yields a
        # doubled separator -- "E:/Games/WATCH_DOGS2//bin/WatchDogs2.exe".
        reply_exe = self._reply_exe_path(exe, workdir)
        body = ld(2, ld(1,
                        vint(1, 1) + vint(2, 0)
                        + ld(3, reply_exe.encode())
                        + ld(4, workdir.replace("\\", "/").encode())
                        + vint(8, 3)
                        + ld(9, progress)))
        self._write(h, body)
        self.log("[game_start] launch parameters returned")
        self._demux_announce()

    def _demux_announce(self):
        """Tell the service which title is starting (captured launch frames)."""
        if not self.demux_sock:
            return
        try:
            self.demux_sock.sendall(demux_game_active(self.pid, PRODUCT_NAMES.get(self.pid, b"")))
            self.demux_sock.sendall(demux_game_start(self.pid))
            self.log("[demux] game announced")
        except OSError as e:
            self.log(f"[demux] announce failed: {e}")

    def launch(self, extra_args=(), before_resume=None):
        """Spawn the game the way upc.exe does, with an inherited wait event.

        The starter hands the event's handle to UbisoftGameLauncher.exe, which
        waits on it after spawning the real game and only then exits. Without a
        signaled event it times out and the job object takes the game down.
        """
        if self.launch_spec_override is not None:
            exe, args, cwd = self.launch_spec_override
        elif self.independent_session:
            raise RuntimeError("independent session requires an explicit game path")
        else:
            from ubisoft_gui import launch_spec
            exe, args, cwd = launch_spec(self.client, self.pid)
        if not exe or not exe.exists():
            self.log(f"[launch] cannot resolve executable ({exe})")
            return
        self.wait_event = win32event.CreateEvent(None, 0, 0, None)
        win32api.SetHandleInformation(self.wait_event, win32con.HANDLE_FLAG_INHERIT,
                                      win32con.HANDLE_FLAG_INHERIT)
        cmd = f'"{exe}"'
        for a in list(args) + list(extra_args):
            cmd += f" {a}"
        si = win32process.STARTUPINFO()
        si.dwFlags |= win32process.STARTF_USESHOWWINDOW
        flags = win32process.CREATE_SUSPENDED if before_resume else 0
        process, thread, pid, _ = win32process.CreateProcess(
            None, cmd, None, None, True, flags, None, str(cwd), si)
        self.child_pid = pid
        threading.Thread(target=self._watch_child, args=(process,), daemon=True).start()
        try:
            if before_resume:
                try:
                    before_resume(pid)
                finally:
                    win32process.ResumeThread(thread)
        finally:
            win32api.CloseHandle(thread)
        self.log(f"[launch] spawned pid={pid} cwd={cwd}")

    def _watch_child(self, process, active_pid=None):
        try:
            while not self._stop.is_set():
                if win32event.WaitForSingleObject(process, 1000) == win32event.WAIT_OBJECT_0:
                    code = win32process.GetExitCodeProcess(process) & 0xFFFFFFFF
                    if active_pid is None:
                        self.child_exit_code = code
                        label = "startup process"
                    else:
                        self.game_exit_codes[active_pid] = code
                        if self.active_game_pid == active_pid:
                            self.active_game_exit_code = code
                        label = f"real game pid={active_pid}"
                    self.log(f"[launch] {label} exited with code 0x{code:08x}")
                    return
        finally:
            win32api.CloseHandle(process)

    def _watch_active_game(self, pid):
        try:
            # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION; no injection or
            # memory access, only a retained handle for the real exit status.
            handle = win32api.OpenProcess(0x00100000 | 0x1000, False, pid)
        except pywintypes.error as error:
            self.log(f"[launch] cannot monitor real game pid={pid}: winerror={error.winerror}")
            return
        threading.Thread(target=self._watch_child, args=(handle, pid), daemon=True).start()

    def _signal_launch(self):
        if self.wait_event is not None:
            win32event.SetEvent(self.wait_event)
            self.wait_event = None
            self.log("[launch] wait event signaled")

    def _handle_api_process(self, h):
        req = self._read(h)
        product_id = game_pid = None
        for f, v in parse_fields(req[4:]):
            if f == 2 and isinstance(v, bytes):
                for f2, v2 in parse_fields(v):
                    if f2 == 1:
                        product_id = v2
                    elif f2 == 2:
                        game_pid = v2
        self.log(f"[api_process] productId={product_id} gamePid={game_pid}")
        if (product_id == self.pid and isinstance(game_pid, int) and game_pid > 0
                and game_pid != self.active_game_pid):
            self.active_game_pid = game_pid
            self.active_game_exit_code = None
            self._watch_active_game(game_pid)
        # Real upc.exe replies f13{f1:1 f3:1 f4:3 f6:0} (f4 was 2 before the fix).
        self._write(h, ld(13, vint(1, 1) + vint(3, 1) + vint(4, 3) + vint(6, 0)))
        # The game is up and has identified itself: release the starter.
        self._signal_launch()
        # The real launcher keeps this connection open; the game asks for avatars
        # on it later. Closing here costs nothing visible but can wedge the game.
        self._hold_open(h, "api_process")

    def _push_followups(self, h):
        if self.independent_session and self.session_followups is not None:
            raise RuntimeError("independent session cannot replay captured follow-ups")
        if self.fresh_activation:
            if self.session_followups is None:
                self.log("[uplay_ipc] fresh mode: no captured follow-ups replayed")
                return
            for chunk in self.session_followups:
                try:
                    # These are exact WriteFile chunks from one framed stream.
                    # Do not reframe individual fragments of a large message.
                    win32file.WriteFile(h, chunk)
                except pywintypes.error as error:
                    self.log(f"[uplay_ipc] compatibility follow-up failed: {error}")
                    return
                time.sleep(0.05)
            self.log(f"[uplay_ipc] compatibility stream: {len(self.session_followups)} captured chunks")
            return
        frames = captured_uplay_followups()
        for chunk in frames:
            try:
                self._write(h, chunk[4:] if len(chunk) > 4 else chunk)
            except pywintypes.error as e:
                self.log(f"[uplay_ipc] follow-up push failed: {e}")
                return
            time.sleep(0.05)
        self.log(f"[uplay_ipc] replayed {len(frames)} follow-up push(es)")

    def _hold_open(self, h, name: str, timeout_s: float = 600.0):
        """Drain further traffic on a connection we must not close."""
        while not self._stop.is_set():
            req = self._read(h, timeout_s=timeout_s)
            if not req:
                self.log(f"[{name}] idle/closed")
                return
            self.log(f"[{name}] extra {len(req)}B {req[:32].hex()}")

    def _handle_uplay(self, h):
        """Serve the session channel for the life of the connection.

        The real launcher keeps this pipe open and answers every request on it
        (capture for 2688: read 13B -> push profile, read 12B -> push again, ...).
        Closing after the first push leaves the game holding a broken pipe, which
        is exactly the kind of thing that wedges it before EAC initialises.
        """
        first = True
        while not self._stop.is_set():
            req = self._read(h, timeout_s=600.0)
            if not req:
                self.log("[uplay_ipc] idle/closed")
                return
            self.log(f"[uplay_ipc] request {len(req)}B {req[:24].hex()}")
            request_fields = dict(parse_fields(req[4:]))
            if 13 in request_fields:
                # Req.installerReq, NOT another session request. The runtime's
                # own descriptor maps 13 -> InstallerReq, 10 -> InstallerRsp.
                installer = dict(parse_fields(request_fields[13]))
                if 1 in installer:
                    language = getattr(self.client, "game_language", "en-US")
                    reply = ld(10, ld(1, vint(1, 1) + ld(2, b"") + ld(3, language.encode())))
                    self._write(h, reply)
                    self.log(f"[uplay_ipc] generated installer initialization (language={language}, no chunk catalog)")
                else:
                    self.log("[uplay_ipc] unsupported installer operation")
                continue
            if 1 not in request_fields:
                self.log(f"[uplay_ipc] unsupported request fields {sorted(request_fields)}")
                continue
            msg = self._session_message()
            self._write(h, msg)
            self.session_pushes += 1
            self.log(f"[uplay_ipc] session pushed ({len(msg) + 4}B), ticket "
                     f"{len(self.client.ticket)}B, {self.session_pushes} push(es)")
            if first:
                first = False
                self._push_followups(h)
                self._ensure_playsession()

    # -- cloud saves -------------------------------------------------------- #
    def _local_save(self) -> Path:
        return (Path(self._savegames_dir()) / "1.save")

    def _local_hash(self):
        """The save hash the game writes at offset 8..40 of the save file."""
        f = self._local_save()
        if not f.exists():
            return None, 0
        b = f.read_bytes()
        h = b[8:40].decode("ascii", "replace").strip("\x00") if len(b) >= 40 else ""
        return (h or None), len(b)

    def log_cloud_state(self):
        """Compare the cloud save entity with the local file; never overwrite silently.

        Both directions of transfer need a signed URL from the demux
        `cloudsave_service`, which we can observe in captures but cannot yet
        trigger ourselves -- so this only reports, it does not sync.
        """
        try:
            ent = cloud_save_entity(self.client, self.pid)
        except Exception as e:
            self.log(f"[cloudsave] entity lookup failed: {e}")
            return
        if not ent:
            self.log("[cloudsave] no cloud save for this product")
            return
        slot = (ent.get("obj") or {}).get("slots", [{}])[0]
        local_hash, local_size = self._local_hash()
        cloud_hash = slot.get("hash")
        if local_hash and local_hash == cloud_hash:
            state = "in sync"
        elif not cloud_hash:
            state = "LOCAL ONLY (no cloud slot)"
        elif local_size == 0:
            state = "CLOUD ONLY (no local save)"
        elif local_hash is None:
            state = "local save present but header hash is empty"
        else:
            state = "DIVERGED"
        self.log(f"[cloudsave] revision={ent.get('revision')} cloud={cloud_hash} "
                 f"({slot.get('size')}B, {slot.get('lastModified')})")
        self.log(f"[cloudsave] local={local_hash} ({local_size}B) -> {state}")
        if state == "DIVERGED":
            self.log("[cloudsave] WARNING: not syncing (signed-URL trigger not "
                     "reproducible); launch once with the official client to reconcile")

    # -- play session ------------------------------------------------------- #
    def _ensure_playsession(self):
        """Mark the account as in-game and keep the session alive (330 s refresh)."""
        if self._ps_started:
            return
        self._ps_started = True
        try:
            playsession_start(self.client, self.pid)
            self.log("[playsession] started")
        except Exception as e:
            self.log(f"[playsession] start failed: {e}")

        def beat():
            while not self._stop.wait(330):
                try:
                    playsession_start(self.client, self.pid)
                    self.log("[playsession] refreshed")
                except Exception as e:
                    self.log(f"[playsession] refresh failed: {e}")

        self._ps_thread = threading.Thread(target=beat, daemon=True)
        self._ps_thread.start()

    # -- lifecycle ---------------------------------------------------------- #
    def start(self):
        served = (
            ("game_start_ipc_pipe_", self._handle_game_start),
            ("uplay_api_process_ipc_pipe_", self._handle_api_process),
            ("uplay_ipc_pipe_", self._handle_uplay),
        )
        # Pipes the real upc.exe creates but we do not emulate yet. Creating them
        # keeps the game from failing with "cannot find the pipe"; any traffic is
        # logged so we can implement them from evidence.
        observed_only = (
            "upc_api_process_ipc_pipe_standard",
            "uplay_aux_ipc_pipe_",
            "uplay_protocol_ipc_pipe_",
            "uplay_service_ipc_pipe_",
            "uplay_overlay_ipc_pipe_",
            "orbit_ipc_pipe_",
            "uplay_crash_reporter_ipc_pipe_",
        )
        for name, handler in served:
            t = threading.Thread(target=self._serve, args=(name, handler), daemon=True)
            t.start()
            self.threads.append(t)
        for name in observed_only:
            t = threading.Thread(
                target=self._serve,
                args=(name, lambda h, n=name: self._handle_unknown(h, n)),
                daemon=True,
            )
            t.start()
            self.threads.append(t)
        self.log(f"[*] fake launcher serving {len(served)} pipes "
                 f"(+{len(observed_only)} observe-only)")
        threading.Thread(target=self._demux_session, daemon=True).start()
        threading.Thread(target=self.log_cloud_state, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._ps_started:
            try:
                playsession_delete(self.client, self.pid)
                self.log("[playsession] deleted")
            except Exception as e:
                self.log(f"[playsession] delete failed: {e}")
        self.log("[*] fake launcher stopped")


def main():
    sys.path.insert(0, str(Path(__file__).parent))
    from ubisoft_gui import Ubisoft

    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 609
    c = Ubisoft()
    if not c.load():
        sys.exit("no saved session â sign in with the GUI once (python ubisoft_gui.py)")
    c.app_id = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6"
    try:
        me = c.me()
        print(f"session OK â {me.get('nameOnPlatform')} ({c.user_id})")
    except Exception as e:
        print(f"warning: saved session is not usable ({e})")
        print("continuing with saved ids; the demux token will be replayed")
    print(f"product {pid}")

    replay = None
    if "--replay" in sys.argv:
        replay = sys.argv[sys.argv.index("--replay") + 1]
    launcher = FakeLauncher(c, pid, replay=replay,
                            fresh_activation="--fresh-activation" in sys.argv)
    launcher.start()
    if "--no-launch" not in sys.argv:
        launcher.demux_ready.wait(60)
        if launcher.fresh_activation and not launcher.fresh_token:
            launcher.stop()
            sys.exit("fresh session setup failed; game not launched")
        time.sleep(1)
        launcher.launch(["-eac_launcher"] if "--eac" in sys.argv else [])
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        launcher.stop()


if __name__ == "__main__":
    main()
