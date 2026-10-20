"""Probe WD2 issuance using session/challenge inputs from a private capture.

Never reads the cached game-token answer. By default requests ownership only.
--issue makes ONE game-token request. Output goes in a new private capture
subdirectory; no credentials or token values are printed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "poc"))
import ubisoft_gui as protocol


def capture_inputs(root, pid):
    streams = defaultdict(bytearray)
    challenges = []
    with (root / "payloads.bin").open("rb") as payloads, (root / "events.jsonl").open(encoding="utf-8") as events:
        for line in events:
            try:
                event = json.loads(line)
            except ValueError:
                continue  # Live JSONL may end in a partially written record.
            if event.get("pid") != pid or event["kind"] not in ("encrypt-input", "pipe-read-output"):
                continue
            size = event["size"]
            if not 0 <= size <= 1024 * 1024:
                raise ValueError("Capture event exceeds safe analysis size")
            payloads.seek(event["offset"])
            data = payloads.read(size)
            if len(data) != size:
                raise ValueError("Capture payload is incomplete")
            if event["kind"] == "encrypt-input":
                stream = streams[event["key_handle"]]
                if len(stream) + size > 16 * 1024 * 1024:
                    raise ValueError("Capture stream exceeds safe analysis size")
                stream.extend(data)
            elif "uplay_aux_ipc_pipe_" in event.get("name", ""):
                challenges.extend(re.findall(rb"[A-Za-z0-9_+/=-]{340}", data))
    ticket = session_id = None
    for stream in streams.values():
        for request in service_requests(stream):
            if not all(field in request for field in (28, 30, 31)):
                continue
            if dict(protocol._fields(request[28])).get(1) == 2688:
                ticket, session_id = request[30], request[31]
    challenges = list(dict.fromkeys(challenges))
    if ticket is None or session_id is None or len(challenges) != 1:
        raise ValueError("Expected one WD2 challenge and matching ownership-session inputs")
    return ticket, session_id, challenges[0]


def service_requests(stream):
    offset = 0
    while offset + 5 <= len(stream):
        length = int.from_bytes(stream[offset:offset + 4], "big")
        if not 0 < length <= len(stream) - offset - 4 or stream[offset + 4] != 18:
            offset += 1
            continue
        try:
            envelope = dict(protocol._fields(bytes(stream[offset + 4:offset + 4 + length])))
            push = dict(protocol._fields(envelope[2]))
            data = dict(protocol._fields(push[1]))[2]
            if len(data) < 4 or int.from_bytes(data[:4], "big") != len(data) - 4:
                raise ValueError("Not a service frame")
            yield dict(protocol._fields(dict(protocol._fields(data[4:]))[1]))
            offset += length + 4
        except (KeyError, ValueError, TypeError, IndexError):
            offset += 1


class WireRecording:
    def __init__(self, sock, directory):
        self.sock = sock
        self.outgoing = (directory / "sent.bin").open("xb", buffering=0)
        self.incoming = (directory / "received.bin").open("xb", buffering=0)

    def sendall(self, data):
        self.outgoing.write(data)
        self.sock.sendall(data)

    def recv(self, size):
        data = self.sock.recv(size)
        self.incoming.write(data)
        return data

    def close(self):
        self.sock.close()
        self.outgoing.close()
        self.incoming.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--issue", action="store_true")
    args = parser.parse_args()
    ticket, session_id, challenge = capture_inputs(args.capture, args.pid)
    directory = args.capture / ("live-probe-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    directory.mkdir(exist_ok=False)
    report = {"success": False, "game_token_requested": False, "request_bytes": len(challenge)}
    sock = None
    start = time.monotonic()
    try:
        sock, request_id = protocol.demux_open_janus(ticket)
        sock = WireRecording(sock, directory)
        ownership = protocol.demux_ownership_token(sock, 2688, request_id, ticket, session_id)
        report["ownership_bytes"] = len(ownership.encode())
        print("Live ownership succeeded.", flush=True)
        if args.issue:
            report["game_token_requested"] = True
            token = protocol.demux_game_token(sock, ownership, challenge, request_id + 10)
            with (directory / "game_token.bin").open("xb") as output:
                output.write(token)
            report.update(game_token_bytes=len(token), game_token_sha256=hashlib.sha256(token).hexdigest())
        report["success"] = True
    except Exception as error:
        # These protocol helpers report status codes, not credential values.
        report.update(error_type=type(error).__name__, error=str(error))
    finally:
        if sock is not None:
            sock.close()
        report["elapsed_seconds"] = round(time.monotonic() - start, 2)
        report["limitation"] = "Uses an already captured game challenge, not a new game-generated challenge."
        (directory / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Private output:", directory)
    if not report["success"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
