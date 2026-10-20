# Evidence

Captured artifacts behind the findings. The launch path generates its own session and
activation messages and does not read these files.

## Files

| File | What it is | Supports |
|------|------------|----------|
| `connecturls.json` | Full service URL map returned by `configcache/api/connecturls` | [01](../docs/01-architecture.md), [05](../docs/05-downloads.md) |
| `entitlements.json` | 178 entitlements for one account (productId/spaceId/applicationId) | [03](../docs/03-library.md) |
| `manifest_files_full.json` | Parsed AC Syndicate manifest: 467 files, 23,177 chunks | [05](../docs/05-downloads.md) |
| `manifest_raw.bin` | Decompressed `.manifest` protobuf (1.3 MB) | 05 |
| `metadata_sec2.bin` | `.metadata` section table (zlib-decoded) | 05 |
| `demux_messages.json` | Classified demux frames from a download run | 05 |
| `demux_config_stream.bin` | Config catalog stream (~216 KB) | 03, 05 |
| `live_cfg_stream.bin` | Catalog from a later run (~400 KB) | 05 |
| `demux_metadata_request.bin` | 88-byte `.metadata` request, reproduced byte-exactly | 05 |
| `dl_metadata.bin` | A real `.metadata` file (958 B) | 05 |
| `qc_by_space.json` | QC signature hashes keyed by spaceId | 05 |
| `manifest_tags.json` | Branch tags per productId | 05 |
| `download_urls.sample.txt` | First signed slice URLs (scheme sample; tokens expired) | 05 |
| `samples/…manifest`, `samples/…licenses` | Raw CDN artifacts from a real download | 05 |
| `demux_full_test.py`, `demux_live_test.py` | Early live-replay experiments, kept for provenance | 05 |
| `wd2_session_push.bin` | 1,326-byte session push from a working WD2 launch; template for `f8` substitution | [06](../docs/06-launch.md) |
| `wd2_uplay_followups.bin` | Length-prefixed launcher pushes that follow the session push (addons, friends, acks, session detail) | 06 |
| `wd2_game_token.bin` | Cached Denuvo `gameToken` the launcher serves on `uplay_aux_ipc_pipe_` | 06, [08](../docs/08-open-issues.md) |
| `denuvo_token.bin` | 620-byte PC-session JWE captured from a client launch; the launcher fetches its own from ownership service | 06, [09](../docs/09-fresh-activation.md) |

## Run artifacts

`tooling/captures/20261022T132423.573463Z/` — official first activation:

| Location | Contents |
|----------|----------|
| `events.jsonl` | Event stream for the activation exchange |
| `live-probe-20261022T134314.183915Z/` | First live ownership/Denuvo issuance |
| `fresh-launch-20261022T143346.100748Z/` | Compatibility menu run |
| `cloud-roundtrip-20261022T144926.494495Z/` | Local snapshots, previous cloud backups |
| `cloud-transfer-20261022T145749.393750Z/result.json` | Temporary-slot transfer and cleanup |
| `runtime-registry-before-fresh.json` | Original registry values |

`tooling/independent-runs/` — launcher runs:

| Location | Contents |
|----------|----------|
| `20261022T153617.084378Z/` | Real-process access violation |
| `20261022T155009.643936Z/` | Independent launch, EAC skipped |
| `20261022T182133.554861Z/` | Gameplay with EAC enabled, screenshot, confirmation |
| `isolation-elevated.json` | Preserved-folder mappings |
| `runtime-uplay-schema.json` | Extracted `uplaydll` field inventory |

Raw payload blobs and live tokens stay out of git; see `../.gitignore`.

## Regenerating

Most files come from the installed client's cache; the rest from the tooling:

```bash
python tooling/capture.py upc.exe        # traffic
python tooling/download_capture.py       # demux
```

`entitlements.json` and the catalog streams can be re-fetched with the PoC using a valid
session (see `poc/README.md`).

## Removed on purpose

`auth_f30.bin`, `cur_jwe.txt`, `cur_sid.txt`, `cur_download_auth.bin`, `demux_auth.bin`,
`demux_blob_1025.bin`, `demux_blob_4389.bin`, `demux_jws.txt`, `demux_jws_response.bin`,
`cfg_stream.bin`, and all capture logs: they contained live session tokens or an
account credential.

`wd2_session_push.bin` and `wd2_uplay_followups.bin` still contain the account's
profile fields (userId, username, email), the owned-product list and friend entries.
The captured push carries a literal password in `f2.f5`.
The successful generated-session path supplies this field empty.
