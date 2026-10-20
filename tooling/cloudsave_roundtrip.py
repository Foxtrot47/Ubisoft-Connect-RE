"""Round-trip save snapshots through temporary, unlisted cloud slots.

Never writes real slots or cloud entity metadata. Deletes only objects this run
created, with a matching body and ETag. Credentials/URLs are never printed.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zlib

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'poc'))
from cloudsave import CloudSaveClient
from probe_captured_activation import capture_inputs
from ubisoft_gui import Ubisoft, cloud_save_entity


class RoundtripError(RuntimeError):
    pass


def transfer(method, url, *, data=None, headers=None):
    with requests.request(method, url, data=data, headers=headers, stream=True,
                          allow_redirects=False, timeout=(10, 30)) as response:
        chunks = []
        total = 0
        for chunk in response.iter_content(65536):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise RoundtripError('Cloud response exceeded size limit')
            chunks.append(chunk)
        return response.status_code, b''.join(chunks), response.headers.get('ETag')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--snapshots', required=True, type=Path)
    args = parser.parse_args()
    run = args.capture / ('cloud-transfer-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    run.mkdir()
    downloaded = run / 'downloaded'
    downloaded.mkdir()
    report = {'mode': 'temporary-cloud-slots', 'real_slots_written': False,
              'metadata_written': False, 'slots': [], 'complete': False}
    exit_code = 1
    try:
        ticket, sid, _ = capture_inputs(args.capture, args.pid)
        client = Ubisoft()
        client.ticket, client.session_id = ticket.decode(), sid.decode()
        client.profile_id = client.me()['userId']
        before = cloud_save_entity(client, 2688)
        (run / 'cloud-before.json').write_text(json.dumps(before, indent=2))
        items = {}
        for name in ('1.save', '2.save'):
            path = args.snapshots / name
            if path.stat().st_size > 16 * 1024 * 1024:
                raise RoundtripError('Snapshot exceeded size limit')
            raw = path.read_bytes()
            slot = str(1_000_000_000 + secrets.randbelow(1_000_000_000))
            while slot in items:
                slot = str(1_000_000_000 + secrets.randbelow(1_000_000_000))
            items[slot] = (name, raw, zlib.compress(raw))
        plain = [(slot, None, None) for slot in items]
        pending = set()
        cleanup = {}
        with CloudSaveClient(ticket, sid, client.profile_id, 2688) as cloud:
            get_urls = cloud.urls(2, plain)
            delete_urls = cloud.urls(3, plain)  # Obtain cleanup capability before any writes.
            for slot in items:
                status, _, _ = transfer('GET', get_urls[slot])
                if status != 404:
                    raise RoundtripError('Temporary slot was not confirmed absent')
            put_urls = cloud.urls(1, [(slot, len(data), base64.b64encode(hashlib.md5(data).digest()).decode())
                                      for slot, (_, _, data) in items.items()])
            try:
                for slot, (name, raw, compressed) in items.items():
                    pending.add(slot)  # A timed-out PUT may nevertheless have committed.
                    headers = {'Content-Length': str(len(compressed)),
                               'Content-MD5': base64.b64encode(hashlib.md5(compressed).digest()).decode(),
                               'If-None-Match': '*'}
                    status, _, _ = transfer('PUT', put_urls[slot], data=compressed, headers=headers)
                    if 400 <= status < 500:
                        pending.remove(slot)
                    if status not in (200, 201, 204):
                        raise RoundtripError(f'Cloud PUT failed (HTTP {status})')
                    status, received, _ = transfer('GET', get_urls[slot])
                    if status != 200:
                        raise RoundtripError(f'Cloud readback failed (HTTP {status})')
                    decoder = zlib.decompressobj()
                    restored = decoder.decompress(received, len(raw) + 1)
                    if not decoder.eof or decoder.unused_data or restored != raw:
                        raise RoundtripError('Downloaded save did not match snapshot')
                    (downloaded / name).write_bytes(restored)
                    report['slots'].append({'name': name, 'temporary_slot': slot,
                        'bytes': len(raw), 'compressed_bytes': len(compressed),
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'download_sha256': hashlib.sha256(restored).hexdigest(), 'byte_match': True})
            finally:
                for slot in pending:
                    try:
                        status, current, etag = transfer('GET', get_urls[slot])
                        if status == 404:
                            cleanup[slot] = True
                            continue
                        if status != 200 or current != items[slot][2] or not etag:
                            raise RoundtripError('Cleanup refused: object identity uncertain')
                        status, _, _ = transfer('DELETE', delete_urls[slot], headers={'If-Match': etag})
                        if status not in (200, 204):
                            raise RoundtripError(f'Test-object cleanup failed (HTTP {status})')
                        status, _, _ = transfer('GET', get_urls[slot])
                        cleanup[slot] = status == 404
                    except Exception as error:
                        cleanup[slot] = False
                        report.setdefault('cleanup_error_types', {})[slot] = type(error).__name__
                report['cleanup_verified'] = cleanup
        after = cloud_save_entity(client, 2688)
        (run / 'cloud-after.json').write_text(json.dumps(after, indent=2))
        report['cloud_metadata_unchanged'] = before == after
        report['complete'] = (len(report['slots']) == 2 and bool(cleanup)
                              and all(cleanup.values()) and before == after)
        exit_code = 0 if report['complete'] else 1
    except Exception as error:
        report['error_type'] = type(error).__name__
        # requests errors can include presigned credentials in their message.
        if isinstance(error, RoundtripError):
            report['error'] = str(error)
    finally:
        (run / 'result.json').write_text(json.dumps(report, indent=2))
        print('Evidence folder:', run)
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
