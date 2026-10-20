#!/usr/bin/env python3
"""Fetch a Denuvo gameToken straight from the demux services.

    python probe_gametoken.py <request_token_file> [productId]

Mimics the launcher (see the contrary/Janus protocol):
  ownership_service: InitializeReq -> OwnershipTokenReq{productId}
  denuvo_service:    GetGameTokenReq{ownershipToken, requestToken} -> gameToken

The demux is flaky (connections get closed at random), so the whole exchange is
retried on a fresh socket. No Ubisoft Connect and no cached activation needed.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ubisoft_gui import (  # noqa: E402
    Ubisoft, demux_game_token, demux_open_janus, demux_ownership_token)


def main():
    token = Path(sys.argv[1]).read_bytes()
    pid = int(sys.argv[2]) if len(sys.argv) > 2 else 2688
    c = Ubisoft()
    if not c.load():
        sys.exit("no saved session")

    last = None
    for attempt in range(1, 7):
        sock = None
        try:
            sock, rid = demux_open_janus(c.ticket.encode())
            t0 = time.time()
            own = demux_ownership_token(sock, pid, rid, c.ticket.encode(), c.session_id.encode())
            print(f"attempt {attempt}: ownership token {len(own)}B in {time.time() - t0:.1f}s")
            t0 = time.time()
            tok = demux_game_token(sock, own, token, rid + 10)
            print(f"gameToken {len(tok)}B in {time.time() - t0:.1f}s")
            print("prefix", tok[:16].hex(), "request prefix", token[:8].hex())
            Path("game_token_live.bin").write_bytes(tok)
            return
        except Exception as e:
            last = e
            print(f"attempt {attempt} failed: {type(e).__name__} {e}")
            try:
                sock.close()
            except Exception:
                pass
            time.sleep(3)
    raise SystemExit(f"all attempts failed: {last}")


if __name__ == "__main__":
    main()
