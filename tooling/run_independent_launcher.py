"""Launch WD2 from PoC login + generated IPC, without captured client state.

No capture-reading modules are imported. Supply the installed executable directly,
so Connect's configuration cache is not needed. Official runtime files remain a
native dependency; Python's audit guard is not an OS-wide file-access sandbox.
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

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'poc'))
from fake_launcher import FakeLauncher
from ubisoft_gui import Ubisoft


def input_guard(roots, violations):
    roots = [os.path.normcase(os.path.realpath(p)) for p in roots]
    def guard(event, args):
        if event not in ('open', 'os.listdir', 'os.scandir') or not args:
            return
        if not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        path = os.path.normcase(os.path.realpath(os.fsdecode(args[0])))
        if any(path == root or path.startswith(root + os.sep) for root in roots):
            violations.append(event)
            raise RuntimeError('Independent run forbids official-state/capture file access')
    return guard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-exe', required=True, type=Path)
    parser.add_argument('--skip-eac', action='store_true')
    parser.add_argument('--wait-login', type=int, default=0)
    args = parser.parse_args()
    exe = args.game_exe.resolve()
    if not exe.is_file() or exe.name.lower() != 'watchdogs2.exe' or exe.parent.name.lower() != 'bin':
        raise SystemExit('Supply the installed WD2 bin/WatchDogs2.exe')
    run = REPO / 'tooling' / 'independent-runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    run.mkdir(parents=True)
    # Keep this test's saves separate; never replace existing progress.
    os.environ['UPLAY_SAVE_ROOT'] = str(run / 'savegames')
    forbidden = [REPO / 'evidence', REPO / 'tooling/captures']
    for variable, suffix in [('LOCALAPPDATA', 'Ubisoft Game Launcher'),
                             ('APPDATA', 'Ubisoft Game Launcher'),
                             ('PROGRAMDATA', 'Ubisoft/Ubisoft Game Launcher'),
                             ('ProgramFiles(x86)', 'Ubisoft/Ubisoft Game Launcher'),
                             ('ProgramFiles', 'Ubisoft/Ubisoft Game Launcher')]:
        if os.environ.get(variable):
            forbidden.append(Path(os.environ[variable]) / suffix)
    violations = []
    sys.addaudithook(input_guard(forbidden, violations))
    client = Ubisoft()
    launcher = None
    phase = 'awaiting-poc-login'
    def status():
        challenge = launcher._activation_request if launcher else None
        data = {'phase': phase, 'launcher_pid': os.getpid(), 'authentication_source': 'poc-session-file',
                'independent_session': True, 'session_capture_replayed': False,
                'followup_capture_replayed': False, 'activation_disk_cache_used': False,
                'official_configuration_cache_used': False,
                'blocked_python_file_accesses': len(violations),
                'bootstrap_pid': launcher.child_pid if launcher else None,
                'bootstrap_exit_code': launcher.child_exit_code if launcher else None,
                'active_game_pid': launcher.active_game_pid if launcher else None,
                'active_game_exit_code': launcher.active_game_exit_code if launcher else None,
                'active_game_exit_hex': (f'0x{launcher.active_game_exit_code:08x}'
                                         if launcher and launcher.active_game_exit_code is not None else None),
                'live_pc_ticket_bytes': len(launcher.fresh_token or b'') if launcher else 0,
                'live_game_token_bytes': len(launcher._activation_answer or b'') if launcher else 0,
                'session_product_count': len(launcher._session_owned_ids or []) if launcher else 0,
                'session_pushes': launcher.session_pushes if launcher else 0,
                'challenge_sha256': hashlib.sha256(challenge).hexdigest() if challenge else None,
                'eac_skip_requested': args.skip_eac, 'save_root': os.environ['UPLAY_SAVE_ROOT']}
        tmp = run / 'status.tmp'
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(run / 'status.json')
    print('Independent run directory:', run, flush=True)
    try:
        deadline = time.monotonic() + args.wait_login
        while True:
            status()
            try:
                if client.load():
                    break
            except (OSError, ValueError):
                pass
            if (run / 'STOP').exists() or time.monotonic() >= deadline:
                raise RuntimeError('Sign in through tooling/login_poc.py first')
            time.sleep(1)
        phase = 'validating-login'
        status()
        me = client.me()
        profiles = client.get('/v3/profiles', platformType='uplay', idOnPlatform=me['userId'])
        mine = [p for p in profiles.get('profiles', []) if p.get('userId') == me['userId']]
        if len(mine) != 1:
            raise RuntimeError('Cannot resolve PoC account profile')
        client.user_id, client.profile_id = me['userId'], mine[0]['profileId']
        library = client.library()
        if not any(p.get('productId') == 2688 for p in library):
            raise RuntimeError('WD2 entitlement not found')
        client.me = lambda: me
        client.library = lambda: library
        launcher = FakeLauncher(client, 2688, fresh_activation=True, independent_session=True,
                                launch_spec_override=(exe, [], exe.parent.parent))
        phase = 'preparing'
        launcher.start()
        status()
        if not launcher.demux_ready.wait(60) or not launcher.fresh_token:
            raise RuntimeError('Live PC ticket unavailable; game not launched')
        time.sleep(1)
        launcher.launch(['-eac_launcher'] if args.skip_eac else [])
        if not launcher.child_pid:
            raise RuntimeError('Startup process was not created')
        phase = 'launched'
        while not (run / 'STOP').exists():
            if launcher.active_game_exit_code is not None:
                phase = 'game-exited'
            status()
            time.sleep(2)
        phase = 'stopped'
    except KeyboardInterrupt:
        phase = 'stopped'
    except Exception as error:
        phase = 'failed'
        print('Independent launch failed:', type(error).__name__, flush=True)
        return 1
    finally:
        if launcher:
            launcher.stop()
        status()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
