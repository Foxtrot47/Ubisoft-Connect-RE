#!/usr/bin/env python3
"""Ubisoft Connect — minimal proof-of-concept client.

Reverse-engineered from the Ubisoft Connect desktop client (build 174.2.0.13389).
Implements the four core actions against the public Ubisoft services API:

    sign-in     POST /v3/profiles/sessions   (password / remember-me / 2FA)
    library     GET  .../entitlement/api/entitlements
    activation  POST /v1/profiles/{pid}/redeemBenefits/code
    download    demux (dmx.upc.ubisoft.com) -> CDN manifest + slices

Usage:
    python ubisoft_poc.py login EMAIL          # interactive password, saves session
    python ubisoft_poc.py library              # list owned games / DLC
    python ubisoft_poc.py activate KEY         # redeem a CD key / activation code
    python ubisoft_poc.py download URL [DEST]  # fetch a (signed) CDN file

See REPORT.md (project root) for the full protocol reference.
"""

from __future__ import annotations

import base64
import getpass
import json
import re
import socket
import ssl
import struct
import sys
from pathlib import Path
from urllib.parse import quote

import requests

# --------------------------------------------------------------------------- #
# Constants recovered from live traffic
# --------------------------------------------------------------------------- #
BASE = "https://public-ubiservices.ubi.com"
APP_ID = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6"       # Connect shell Ubi-AppId
AUTH_APP_ID = "94145723-2736-4afe-9862-3de89184ee32"  # remember-me ticket aid
USER_AGENT = "Massgate_174.2.0.13389"
PLATFORM = "uplay"

DOWNLOAD_CDN = "http://uplaypc-s-ubisoft.cdn.ubi.com"
DEMUX_HOST = "dmx.upc.ubisoft.com"

SESSION_FILE = Path.home() / ".ubisoft_poc_session.json"


# --------------------------------------------------------------------------- #
# protobuf helpers (wire format used by the demux service)
# --------------------------------------------------------------------------- #
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(field_no: int, wire_type: int, payload: bytes = b"") -> bytes:
    return _varint((field_no << 3) | wire_type) + payload


def _ld(field_no: int, payload: bytes) -> bytes:  # length-delimited
    return _field(field_no, 2, _varint(len(payload)) + payload)


def _frame(body: bytes) -> bytes:  # 4-byte big-endian length prefix
    return len(body).to_bytes(4, "big") + body


def _js_basic_auth(email: str, password: str) -> str:
    """Reproduce the client's Basic header: btoa(unescape(encodeURIComponent(email:password)))."""
    enc = quote(f"{email}:{password}", safe="-_.!~*'()")
    raw = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), enc)
    return base64.b64encode(raw.encode("latin-1")).decode("ascii")


def demux_hello(version: str = "174.2") -> bytes:
    """{1:{1:2, 5:{1:'174.2', 2:0}}}"""
    inner = _ld(5, _ld(1, version.encode()) + b"\x10\x00")
    return _frame(_ld(1, _field(1, 0, b"\x02") + inner))


def demux_service_request(service: str = "download_service") -> bytes:
    """{1:{1:5, 3:{2:'download_service'}}}"""
    return _frame(_ld(1, _field(1, 0, b"\x05") + _ld(3, _ld(2, service.encode()))))


def demux_slice_request(product_id: int, slice_paths: list[str], counter: int = 0) -> bytes:
    """{1:{1:<n>, 3:{1:<productId>, 2:['slices_v3/...', ...]}}}"""
    slices = b"".join(_ld(2, p.encode()) for p in slice_paths)
    inner = _field(1, 0, _varint(product_id)) + slices
    body = _ld(1, _field(1, 0, _varint(counter)) + _ld(3, inner))
    return _frame(_ld(2, body))


def demux_session_auth(ticket: bytes, session_id: bytes, locale: bytes = b"en-US") -> bytes:
    """Session auth (connection 1): {f2:{f1:{f1:1, f2[framed]{f1:{f1:2, f22:{f1:1,
    f4:0, f5:JWE, f6:locale, f7:0, f8:sessionId}}}}}}  (byte-exact vs capture)"""
    inner = (_field(1, 0, _varint(2)) + _ld(22, _field(1, 0, _varint(1)) + _field(4, 0, _varint(0))
             + _ld(5, ticket) + _ld(6, locale) + _field(7, 0, _varint(0)) + _ld(8, session_id)))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(1)) + _ld(2, _frame(_ld(1, inner))))))


def demux_download_auth(product_id: int, ticket: bytes, session_id: bytes) -> bytes:
    """Download auth (connection 2): {f2:{f1:{f1:2, f2[framed]{f1:{f1:2,
    f28:{f1:productId}, f30:JWE, f31:sessionId}}}}}  (byte-exact vs capture)"""
    inner = (_field(1, 0, _varint(2)) + _ld(28, _field(1, 0, _varint(product_id)))
             + _ld(30, ticket) + _ld(31, session_id))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(2)) + _ld(2, _frame(_ld(1, inner))))))


def demux_jws_auth(jws: bytes, uuid: bytes) -> bytes:
    """Ownership JWS auth: {f2:{f1:{f1:4, f2[framed]{f1:{f1:1, f2:{f5:JWS, f6:uuid}}}}}}"""
    inner = _field(1, 0, _varint(1)) + _ld(2, _ld(5, jws) + _ld(6, uuid))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, inner))))))


def manifest_url(product_id: int, manifest_id: str, token: str | None = None) -> str:
    base = f"{DOWNLOAD_CDN}/uplaypc/downloads/{product_id}/manifests/{manifest_id}.manifest"
    return base if token is None else f"{base}?_tkn_={token}"


def slice_url(product_id: int, sha1: str, token: str | None = None) -> str:
    shard = sha1[0].lower()
    base = f"{DOWNLOAD_CDN}/uplaypc/downloads/{product_id}/slices_v3/{shard}/{sha1}"
    return base if token is None else f"{base}?_tkn_={token}"



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
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.ticket = None
        self.session_id = None
        self.session_key = None
        self.profile_id = None
        self.user_id = None
        self.remember_me_ticket = None

    # -- auth --------------------------------------------------------------- #
    def login(self, email: str, password: str, remember_me: bool = True) -> dict:
        r = self.session.post(
            f"{BASE}/v3/profiles/sessions",
            headers={
                "Authorization": "Basic " + _js_basic_auth(email, password),
                "Ubi-AppId": APP_ID,
                "Ubi-RequestedPlatformType": PLATFORM,
            },
            json={"rememberMe": remember_me, "enforceTwoFactorSession": False},
            timeout=60,
        )
        data = self._check(r)
        if data.get("twoFactorAuthenticationTicket"):
            return {"needs_2fa": True, "ticket": data["twoFactorAuthenticationTicket"]}
        self._adopt(data)
        return data

    def login_2fa(self, two_factor_ticket: str, code: str) -> dict:
        r = self.session.post(
            f"{BASE}/v3/profiles/sessions",
            headers={
                "Authorization": f"ubi_2fa_v1 t={two_factor_ticket}",
                "Ubi-AppId": APP_ID,
                "Ubi-RequestedPlatformType": PLATFORM,
                "Ubi-2FA-Code": code,
            },
            json={"twoFactorCode": code},
            timeout=60,
        )
        data = self._check(r)
        self._adopt(data)
        return data

    def login_remember_me(self, ticket: str) -> dict:
        r = self.session.post(
            f"{BASE}/v3/profiles/sessions",
            headers={
                "Authorization": f"ubi_v1 t={ticket}",
                "Ubi-AppId": APP_ID,
                "Ubi-RequestedPlatformType": PLATFORM,
            },
            json={},
            timeout=60,
        )
        data = self._check(r)
        self._adopt(data)
        return data

    def _adopt(self, data: dict) -> None:
        self.ticket = data.get("ticket") or self.ticket
        self.session_id = data.get("sessionId")
        self.session_key = data.get("sessionKey")
        self.profile_id = data.get("profileId")
        self.user_id = data.get("userId")
        self.remember_me_ticket = data.get("rememberMeTicket")

    def _check(self, r: requests.Response) -> dict:
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {data}")
        return data

    # -- authenticated requests -------------------------------------------- #
    def _headers(self) -> dict:
        h = {
            "Authorization": f"Ubi_v1 t={self.ticket}",
            "Ubi-AppId": APP_ID,
            "Ubi-RequestedPlatformType": PLATFORM,
        }
        if self.session_id:
            h["Ubi-SessionId"] = self.session_id
        return h

    def get(self, path: str, **params) -> dict:
        r = self.session.get(f"{BASE}{path}", headers=self._headers(), params=params, timeout=60)
        return self._check(r)

    def post(self, path: str, json_body: dict) -> dict:
        r = self.session.post(f"{BASE}{path}", headers=self._headers(), json=json_body, timeout=60)
        return self._check(r)

    # -- actions ------------------------------------------------------------ #
    def me(self) -> dict:
        return self.get("/v3/users/me")

    def library(self) -> list[dict]:
        data = self.get("/v1/profiles/me/global/ubiconnect/entitlement/api/entitlements")
        for key in ("items", "entitlements", "products", "games", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        return data if isinstance(data, list) else []

    def activate(self, code: str, benefit_ids: list[str] | None = None) -> dict:
        pid = self.profile_id
        if benefit_ids is None:
            info = self.get(f"/v1/profiles/{pid}/redeemBenefits/selectableBenefits/{code}")
            benefit_ids = [
                b.get("benefitId") for b in (info.get("selectableBenefits") or []) if b.get("benefitId")
            ]
        body = {"code": code}
        if benefit_ids:
            body["benefitIds"] = benefit_ids
        return self.post(f"/v1/profiles/{pid}/redeemBenefits/code", body)

    # -- persistence -------------------------------------------------------- #
    def save(self) -> None:
        SESSION_FILE.write_text(json.dumps({
            "ticket": self.ticket, "sessionId": self.session_id, "sessionKey": self.session_key,
            "profileId": self.profile_id, "userId": self.user_id,
            "rememberMeTicket": self.remember_me_ticket,
        }, indent=2))

    def load(self) -> bool:
        if not SESSION_FILE.exists():
            return False
        d = json.loads(SESSION_FILE.read_text())
        for k, v in d.items():
            setattr(self, _snake(k), v)
        return bool(self.ticket and self.session_id)


def _snake(s: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


# --------------------------------------------------------------------------- #
# Download (demux -> CDN). The demux AUTH message field layout is partially
# recovered; the framing + CDN layer are fully implemented.
# --------------------------------------------------------------------------- #
def download_file(url, dest, progress=None):
    """Fetch a signed CDN URL byte-exactly.

    NOTE: must NOT be routed through requests/urllib, which re-encode the
    percent-escaped `_tkn_` ACL (`%2f` -> `%2F`) and break the Akamai HMAC.
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

        status_line = head.split(b"\r\n")[0]
        status = int(status_line.split(b" ")[1])
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


def demux_connect() -> "ssl.SSLSocket":
    """Open a TLS connection to the demux service (standard TLS on 443)."""
    ctx = ssl.create_default_context()
    raw = socket.create_connection((DEMUX_HOST, 443), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=DEMUX_HOST)


def demux_recv_frame(sock: "ssl.SSLSocket") -> bytes:
    hdr = _read_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    return _read_exact(sock, n)


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("demux closed connection")
        buf += chunk
    return buf


JWS_UUID = b"5af8ea68-c4ba-4d8c-b7b1-ac4fd45deb9b"  # stable device/install id (captured)


def demux_metadata_request(product_id: int, manifest_id: str) -> bytes:
    """Manifest .metadata request: {2:{1:{1:4, 2[fr]{1:{1:2,
    3:{1:{1:productId, 2:'manifests/{id}.metadata'}}}}}}}  (byte-exact)"""
    path = f"manifests/{manifest_id}.metadata".encode()
    innermost = _field(1, 0, _varint(product_id)) + _ld(2, path)
    body = _field(1, 0, _varint(2)) + _ld(3, _ld(1, innermost))
    return _frame(_ld(2, _ld(1, _field(1, 0, _varint(4)) + _ld(2, _frame(_ld(1, body))))))


def parse_jws_response(resp: bytes) -> bytes:
    """Extract the ownership JWS from the demux download_auth response."""
    i = resp.find(b"eyJ0eXAi")
    m = re.match(rb"[A-Za-z0-9_\-\.]+", resp[i:])
    return m.group(0).rstrip(b".")


BUILD_NUMBER = 13389  # client build number; used as the config-service branch id

# branch tags that denote a download manifest, in preference order
MANIFEST_TAG_PREF = [
    "UbisoftConnect_QC", "UbsioftConnect_QC",   # (the second is a real typo in the data)
    "Live", "live", "DisableOverlayQC", "disableoverlayqc",
]


def demux_config_request(name: bytes = b"client_configuration_service",
                         build: int = BUILD_NUMBER) -> bytes:
    """Subscribe to the config catalog (carries per-game branch manifest hashes)."""
    inner = _field(1, 0, _varint(0)) + _ld(3, _ld(1, _field(1, 0, _varint(build))))
    sub = _ld(1, name) + _ld(2, _ld(1, inner))
    return _frame(_ld(1, _field(1, 0, _varint(4)) + _ld(6, sub)))


def demux_service_field3(name: bytes, counter: int) -> bytes:
    """Simple service subscribe: {1:{1:<counter>, 3:{2:<name>}}}."""
    return _frame(_ld(1, _field(1, 0, _varint(counter)) + _ld(3, _ld(2, name))))


def demux_utility_service(counter: int = 1) -> bytes:
    """utility_service subscribe: {1:{1:1, 6:{1:"utility_service", 2:{1:{1:""}}}}}."""
    return _frame(_ld(1, _field(1, 0, _varint(counter))
                      + _ld(6, _ld(1, b"utility_service") + _ld(2, _ld(1, _ld(1, b""))))))


def demux_build_message(build: int = BUILD_NUMBER) -> bytes:
    """{2:{4:{1:<build>}}} — sent right after the utility subscribe."""
    return _frame(_ld(2, _ld(4, _field(1, 0, _varint(build)))))


def demux_auth_simple(ticket: bytes) -> bytes:
    """{1:{1:2, 2:{1:{3:<JWE>}}}} — auth variant used on the catalog connection."""
    return _frame(_ld(1, _field(1, 0, _varint(2)) + _ld(2, _ld(1, _ld(3, ticket)))))


# the two branch-ack messages the client sends verbatim during catalog setup
ACK7 = bytes.fromhex(
    "0000001812160a14080212100000000c0a0a08011206100118072800")
ACK8 = bytes.fromhex(
    "0000001212100a0e0801120a000000060a0408016a00")


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


PID_MARKER = bytes([0x98, 0x01])  # protobuf field 19, varint


def parse_qc_records(stream: bytes) -> dict:
    """Extract {productId: {branchTag: manifestId}} from the config catalog.

    Record layout: f19=productId, f21=40-byte ASCII SHA1, f26=branch tag,
    f30=spaceId, f31=appId.
    """
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
    """Pick the download manifest for a product: (manifestId, tag) or (None, None)."""
    tags = records.get(pid) or {}
    for p in MANIFEST_TAG_PREF:
        if p in tags:
            return tags[p], p
    if tags:
        k = sorted(tags)[0]
        return tags[k], k
    return None, None


def fetch_manifest_map(ticket: bytes, session_id: bytes, read_seconds: float = 25.0) -> dict:
    """Replay the client's catalog-connection sequence and parse the manifest map.

    hello -> utility_service -> build -> auth -> friends -> ownership
          -> session_auth -> ack7 -> ack8 -> denuvo -> client_configuration_service
    """
    import time

    sock = demux_connect()
    sock.settimeout(4)

    def drain(wait):
        end = time.time() + wait
        buf = b""
        while time.time() < end:
            try:
                d = sock.recv(65536)
                if not d:
                    break
                buf += d
                if len(buf) > (1 << 21):
                    break
            except OSError:
                break
        return buf

    sock.sendall(demux_hello())
    drain(2.0)
    sock.sendall(demux_utility_service())
    drain(2.0)
    sock.sendall(demux_build_message())
    sock.sendall(demux_auth_simple(ticket))
    drain(2.0)
    sock.sendall(demux_service_field3(b"friends_service", 0))
    sock.sendall(demux_service_field3(b"ownership_service", 1))
    drain(3.0)
    sock.sendall(demux_session_auth(ticket, session_id))
    sock.sendall(ACK7)
    sock.sendall(ACK8)
    sock.sendall(demux_service_field3(b"denuvo_service", 3))
    sock.sendall(demux_config_request())

    buf = drain(read_seconds)
    try:
        sock.close()
    except OSError:
        pass
    return parse_qc_records(buf)


def demux_download(product_id: int, ticket: bytes, session_id: bytes,
                   manifest_id: str, dest_dir: str) -> str:
    """Full download: demux handshake -> fresh ownership JWS -> signed CDN URLs.

    Sequence (captured byte-exact):
      hello -> download_auth(pid,JWE,sid) -> [JWS] -> service:download_service
             -> jws_auth(JWS) -> metadata_request(pid,manifestId) -> [.metadata URL]
    """
    sock = demux_connect()
    sock.sendall(demux_hello())
    demux_recv_frame(sock)  # hello response (ignore)

    sock.sendall(demux_download_auth(product_id, ticket, session_id))
    jws = parse_jws_response(demux_recv_frame(sock))
    print(f"[demux] ownership JWS: {len(jws)}B")

    sock.sendall(demux_service_request(b"download_service"))
    demux_recv_frame(sock)  # ack

    sock.sendall(demux_jws_auth(jws, JWS_UUID))
    demux_recv_frame(sock)  # ack

    sock.sendall(demux_metadata_request(product_id, manifest_id))
    resp = demux_recv_frame(sock)
    m = re.search(rb"https?://[^\x00-\x20]+", resp)
    if not m:
        raise RuntimeError("no signed URL in demux metadata response")
    url = m.group(0).decode()
    print(f"[demux] signed .metadata URL: {url[:90]}...")
    dest = f"{dest_dir}/{manifest_id}.metadata"
    download_file(url, dest)
    return dest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    c = Ubisoft()

    if cmd == "login":
        email = sys.argv[2]
        password = getpass.getpass("Password: ")
        try:
            out = c.login(email, password)
        except RuntimeError as e:
            print(f"login failed: {e}", file=sys.stderr)
            sys.exit(1)
        if out.get("needs_2fa"):
            code = input("2FA code: ").strip()
            c.login_2fa(out["ticket"], code)
        c.save()
        print(f"logged in: userId={c.user_id} profileId={c.profile_id}")

    elif cmd == "library":
        if not c.load():
            sys.exit("not logged in — run: python ubisoft_poc.py login EMAIL")
        for item in c.library():
            sid = item.get("spaceId") or item.get("space_id")
            print(f"{sid}  {item.get('name') or '(unnamed)'}  type={item.get('type')}")

    elif cmd == "activate":
        if not c.load():
            sys.exit("not logged in")
        print(json.dumps(c.activate(sys.argv[2]), indent=2))

    elif cmd == "download":
        url = sys.argv[2]
        dest = sys.argv[3] if len(sys.argv) > 3 else url.split("/")[-1].split("?")[0]
        download_file(url, dest)

    else:
        print(__doc__)


if __name__ == "__main__":
    main()
