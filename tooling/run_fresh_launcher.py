"""Controlled WD2 launch with current capture-derived auth, not activation answers.

Uses official copied runtime binaries. Fresh mode generates session messages and
requests both session/activation tickets online. Does not save a PoC login file.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "poc"))
from fake_launcher import FakeLauncher, PIPE_PREFIX, parse_fields
from ubisoft_gui import Ubisoft, launch_spec
from probe_captured_activation import capture_inputs


def captured_session_stream(root, pid, user_id):
    template = None
    followups = []
    total = 0
    with (root / "events.jsonl").open(encoding="utf-8") as events, (root / "payloads.bin").open("rb") as payloads:
        for line in events:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if (event.get("pid") != pid or event["kind"] != "pipe-write-input"
                    or not event.get("name", "").endswith("_uplay_ipc_pipe_")):
                continue
            total += event["size"]
            if total > 2 * 1024 * 1024:
                raise ValueError("Session compatibility stream exceeds safe size")
            payloads.seek(event["offset"])
            chunk = payloads.read(event["size"])
            if len(chunk) != event["size"]:
                raise ValueError("Session compatibility stream is incomplete")
            if template is None:
                inner = dict(parse_fields(chunk[4:])).get(1, b"")
                profile = dict(parse_fields(dict(parse_fields(inner)).get(2, b"")))
                if profile.get(1) != user_id.encode():
                    raise ValueError("Session compatibility capture belongs to a different account")
                template = chunk
            else:
                followups.append(chunk)
    if template is None:
        raise ValueError("No official session capture found")
    return template, followups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--skip-eac", action="store_true", help="Pass -eac_launcher to WD2")
    parser.add_argument("--session-compatibility", action="store_true",
                        help="Replay this account's captured session shape/follow-ups, with live tickets")
    parser.add_argument("--pause-for-observer", action="store_true",
                        help="Start suspended; wait up to 60s for a RESUME file")
    args = parser.parse_args()
    ticket, session_id, previous_challenge = capture_inputs(args.capture, args.pid)
    client = Ubisoft()
    client.ticket, client.session_id = ticket.decode(), session_id.decode()
    me = client.me()
    profiles = client.get("/v3/profiles", platformType="uplay", idOnPlatform=me["userId"])
    mine = [p for p in profiles.get("profiles", []) if p.get("userId") == me["userId"]]
    if len(mine) != 1:
        raise SystemExit("Cannot resolve the current account profile; not launching.")
    client.user_id, client.profile_id = me["userId"], mine[0]["profileId"]
    client.name_on_platform = me.get("nameOnPlatform")
    library = client.library()
    if not any(p.get("productId") == 2688 for p in library):
        raise SystemExit("WD2 ownership not found; not launching.")
    # Reuse validated metadata during the IPC handshake, avoiding redundant HTTP
    # lookups while the game waits for each synchronous session response.
    client.me = lambda: me
    client.library = lambda: library
    exe, _, _ = launch_spec(client, 2688)
    if not exe or not exe.is_file():
        raise SystemExit("Cannot resolve the installed WD2 executable; not launching.")
    run = args.capture / ("fresh-launch-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    run.mkdir(exist_ok=False)
    print(f"Run directory: {run}", flush=True)
    template, followups = captured_session_stream(args.capture, args.pid, client.user_id) if args.session_compatibility else (None, None)
    launcher = FakeLauncher(client, 2688, fresh_activation=True,
                            session_template=template, session_followups=followups)
    phase = "preparing"
    def status():
        challenge = launcher._activation_request
        answer = launcher._activation_answer
        data = {"launcher_pid": os.getpid(), "phase": phase,
                "pipe_prefix": PIPE_PREFIX, "game_pid": launcher.child_pid,
                "active_game_pid": launcher.active_game_pid,
                "game_pid_note": "game_pid is the startup process; active_game_pid comes from game IPC",
                "session_product_count": len(launcher._session_owned_ids or []),
                "child_exit_code": launcher.child_exit_code,
                "live_pc_ticket_bytes": len(launcher.fresh_token or b""),
                "live_game_token_bytes": len(answer or b""),
                "challenge_sha256": hashlib.sha256(challenge).hexdigest() if challenge else None,
                "challenge_matches_previous_capture": challenge == previous_challenge if challenge else None,
                "session_pushes": launcher.session_pushes,
                "session_capture_replayed": launcher.replay is not None,
                "followup_capture_replayed": launcher.session_followups is not None,
                "activation_disk_cache_used": False,
                "eac_skip_requested": args.skip_eac}
        temporary = run / "status.tmp"
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temporary.replace(run / "status.json")
    try:
        launcher.start()
        status()
        if not launcher.demux_ready.wait(60) or not launcher.fresh_token:
            raise RuntimeError("Live PC ticket setup failed; game not launched")
        # Allow named-pipe listener threads to enter ConnectNamedPipe.
        time.sleep(1)
        def wait_for_observer(pid):
            nonlocal phase
            phase = "awaiting-observer"
            status()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if (run / "RESUME").exists():
                    return
                time.sleep(0.1)
            raise RuntimeError("Observer wait timed out")
        launcher.launch(["-eac_launcher"] if args.skip_eac else [],
                        before_resume=wait_for_observer if args.pause_for_observer else None)
        if not launcher.child_pid:
            raise RuntimeError("Game process was not created")
        phase = "launched"
        while not (run / "STOP").exists():
            status()
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    except Exception as error:
        phase = "failed"
        print(f"Launch failed: {type(error).__name__}", flush=True)
        raise
    finally:
        launcher.stop()
        status()


if __name__ == "__main__":
    main()
