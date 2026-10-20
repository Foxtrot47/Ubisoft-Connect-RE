# 07: Cloud saves

Ubisoft stores only **metadata**; the bytes go to S3 through a **presigned URL** the
demux `cloudsave_service` issues. **Authenticated URL issuance and upload/download
transport are now verified (2026-10-22).** Full metadata-aware synchronization is
not yet implemented; the verified round trip used temporary, unlisted slots.

## Save file format

The save is a container whose header carries its own id:

| Offset | Type | Meaning |
|--------|------|---------|
| 0 | u32 | `548` (0x224) |
| 4 | u32 | 0 |
| 8 | char[32] | **the entity `hash`**, written by the game |
| … | | payload |

Existing official cloud saves have a 32-character marker at offset 8 matching the
entity `hash`. However, saves freshly written during the PoC launch have zeroes
there. The marker finalization algorithm remains unresolved.

## The entity

`GET /v1/profiles/{pid}/entities?name=upcCloudSaveUplayId_{pid}`

```json
{"entityId":"d2a2bbb4-…","profileId":"1ae5ff50-…",
 "spaceId":"e17be87d-…","type":"cloudSave","name":"upcCloudSaveUplayId_609",
 "tags":[],
 "obj":{"slots":[{"id":1,"filename":"1","hash":"c90d6206…","size":34683,
                  "lastModified":"2026-10-20T18:58:21Z"}],
        "timestamp":"1792522701","pc_name":"FOX-RYZEN"},
 "lastModified":"…","revision":2}
```

| Field | Role |
|-------|------|
| `obj.slots[]` | one per save slot: id, filename, hash, size, lastModified |
| `obj.pc_name` | last writing machine |
| `revision` | conflict key, bumped on every write |

## Upload: four steps

```
1  GET  /v1/profiles/{pid}/entities?name=upcCloudSaveUplayId_{pid}
2  PUT  /v1/profiles/entities/{entityId}          (metadata; revision++)
3  demux cloudsave_service                        → presigned PUT URL
4  PUT  https://ubisoft-uplay-savegames.s3.us-east-1.amazonaws.com/
          {profileId}/{pid}/{slot}.savegame?X-Amz-…
```

### Step 2 body

Validated against the live API; each omitted field is rejected in turn
(`obj` → `name` → `revision`):

```json
{"revision": 2,
 "name": "upcCloudSaveUplayId_609",
 "type": "cloudSave",
 "spaceId": "e17be87d-2996-4f3b-97c4-19bb2dae2933",
 "tags": [],
 "obj": {"slots": [{"id":1,"filename":"1","hash":"…32 hex…","size":34683,
                    "lastModified":"2026-10-20T19:08:18Z"}],
         "timestamp": "1792523298",
         "pc_name": "FOX-RYZEN"}}
```

`DELETE /v1/profiles/entities/{id}` removes an entity.

### Step 3 request

```
f2 { f1 { f1: 5,
      f2[fr] { f1 { f1: 1,
                    f2 { f2: <productId>, f3: 1,
                         f4 { f1: "<slot>",
                              f2 { f1: <compressed size>,
                                   f2: "<base64 md5 of compressed body>" } } } } } } }
```

`f3: 1` = upload. The reply carries the signed URL plus the expected
`Content-Length` and `Content-MD5`. The request also needs the **ownership token in
inner f1**, and connection IDs come from the server rather than being reused.

### Step 4 encoding

| Thing | Value |
|-------|-------|
| body | `zlib(save)`: 34,683 B → 11,367 B |
| `Content-MD5` | `base64(md5(zlib(save)))` |
| object key | `{profileId}/{productId}/{slot}.savegame` |
| URL TTL | `X-Amz-Expires=3600` |
| signed headers | `content-length;content-md5;host` |

## Verified authenticated flow and round trip

1. Open/authenticate demux with the current session ticket.
2. Initialize `ownership_service`; request its product-specific ownership token.
3. Open `cloudsave_service`, retaining the returned connection ID.
4. Send service `Req.cloudsave_url_req` (f2): ownership token f1, product ID f2,
   method f3, repeated items f4. Methods are **1 PUT, 2 GET, 3 DELETE**.
5. Parse `Rsp.cloudsave_url_rsp` (f2), requiring `status == 1` (Ok), and consume
   its `http_reqs` URLs. Validate bucket, profile, product and slot before I/O.
6. PUT uses `zlib(save)` with its compressed length and base64 MD5. GET restores
   the original bytes after bounded decompression.

Implemented by `poc/cloudsave.py:CloudSaveClient`. Ownership tokens and presigned
URLs remain in memory; they are not printed.

`tooling/cloudsave_roundtrip.py` verified the current WD2 snapshots using temporary
numeric cloud slots, not real slots 1/2. It required GET 404 before each conditional
PUT, downloaded/decompressed the objects, compared bytes/SHA-256, and cleaned up
only matching test objects using conditional DELETE. Final GETs returned 404;
the cloud entity metadata remained unchanged.

| File | Original bytes | Compressed bytes | Readback |
|------|---------------:|-----------------:|----------|
| `1.save` | 3,467 | 1,212 | byte-identical |
| `2.save` | 28,806 | 6,033 | byte-identical |

Private result: `tooling/captures/20261022T132423.573463Z/cloud-transfer-20261022T145749.393750Z/result.json`.
The previous real cloud saves were separately downloaded/backed up before this test.
The round-trip wrapper currently sources authentication from the private capture;
`CloudSaveClient` itself accepts caller-supplied normal authentication. Integrating
PoC-login auth into the test/product workflow remains separate work. The cloud test
must not be described as using the later strict launch's independent login.

**This proves cloud transport, not permanent sync of the new progress.** Real-slot
publication, header finalization, metadata revision conflicts and automatic
upload/download policy remain separate work.

## Download sequence

```
GET  /v1/profiles/{pid}/entities?name=upcCloudSaveUplayId_{pid}
demux  download_auth(productId) → JWS
demux  service:cloudsave_service  {1:{1:5, 3:{2:"cloudsave_service"}}}
demux  jws_auth(JWS)              → 408-byte reply containing the URL
GET  {profileId}/{pid}/{slot}.savegame?X-Amz-…&X-Amz-SignedHeaders=host
     → 200 → written to savegames\<userId>\<pid>\<slot>.save
```

The signed headers distinguish direction: **`host` = download**,
`content-length;content-md5;host` = upload.

Captured result: local file restored at 34,683 B with the header hash matching the cloud
slot.

## Transport contract

- URL requests need the product ownership token in `f1`; without it the demux returns
  an 8–28 byte ack instead of a signed URL.
- Methods are 1 PUT, 2 GET, 3 DELETE; URL response status 1 is Ok.
- Connection IDs are returned dynamically — never reuse a captured one.
- PUT sends zlib-compressed bytes with the compressed `Content-Length` and a base64
  `Content-MD5`.
- Temporary slots answer GET with 404 before creation; conditional PUT and DELETE are
  supported; cleanup leaves entity metadata untouched.

Local save bytes 8..40 are zero, while official cloud saves carry 32-character markers
matching entity metadata.

## Observed conflict behavior

During an earlier official-client test, missing local data and a failed download
were followed by an upload that replaced the cloud copy. Entity revision changed
from 2 to 3, and the older cloud save was lost.

`fake_launcher.py` reports local/cloud state without transferring on divergence.
The later temporary-slot round trip did not change real slots or entity metadata.

## Next

→ [08: Open issues](08-open-issues.md)
