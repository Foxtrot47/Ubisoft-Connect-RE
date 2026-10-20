# 05 — Downloads

Three layers: the web UI asks the native layer, the native layer asks the **demux**
service, and the files come from a plain-HTTP CDN.

## 1. Web → native

The `game-download-manager` micro-frontend drives the native downloader:

```
pcGameManagement.v1.startDownload(spaceIdOrGame, options)
pcGameManagement.v1.resumeDownload(id)      .pauseDownloadQueue()
pcGameManagement.v1.setDownloadPriority(id, priority)
pcGameManagement.v1.clearDownload(id)       .uninstallGame(game)
```

Status enum: `Pending · Download · ResumeFiles · AllocatingDiskSpace · Paused ·
Completed · Failure · NetworkError · Cancelled`.

## 2. Demux protocol

`dmx.upc.ubisoft.com:443` is a custom TLS service using **4-byte big-endian length
prefix + protobuf**. Two connections are used.

**Connection 1 — establish the session:**

```
hello(f1=0)
utility_service   {1:{1:1, 6:{1:"utility_service", 2:{1:{1:""}}}}}
build             {2:{4:{1:13389}}}
auth_simple       {1:{1:2, 2:{1:{3:<JWE>}}}}
friends_service   {1:{1:0, 3:{2:"friends_service"}}}
ownership_service {1:{1:1, 3:{2:"ownership_service"}}}
session_auth      {2:{1:{1:1, 2[fr]{1:{1:2, 22:{1:5:JWE,6:"en-US",8:sid,…}}}}}}
ack7 / ack8       (two fixed frames)
denuvo_service    {1:{1:3, 3:{2:"denuvo_service"}}}
client_configuration_service  {1:{1:4, 6:{1:"client_configuration_service",
                               2:{1:{1:0, 3:{1:{1:13389}}}}}}}
→ catalog stream (~400 KB)
```

**Connection 2 — download:**

```
hello → download_auth(pid,JWE,sid) → [ownership JWS]
      → service:download_service  → [ack]
      → jws_auth(JWS)             → [ack]
      → metadata_request(pid,manifestId) → [signed .metadata URL]
```

`download_auth` is **required** to obtain the ownership JWS, and it is rejected on a
socket that has not completed the session handshake first.

### Manifest ID

`manifestId` is not in the local config and not in entitlements. It is the per-game QC
signature from the config catalog record:

| Field | Meaning |
|-------|---------|
| `f19` | `productId` |
| `f21` | **manifestId** — 40-byte ASCII SHA1 |
| `f26` | branch tag, e.g. `UbisoftConnect_QC` |
| `f30` / `f31` | `spaceId` / `applicationId` |

Preference order: `UbisoftConnect_QC`, `UbsioftConnect_QC` (**a real typo in the data**),
`Live`, `live`, `DisableOverlayQC`, then alphabetical.

## 3. CDN layout

```
http://uplaypc-s-ubisoft.cdn.ubi.com/uplaypc/downloads/{productId}/
    manifests/{manifestId}.metadata
    manifests/{manifestId}.manifest
    manifests/{manifestId}.licenses
    slices_v3/{shard}/{SHA1}
```

Every URL is signed:

```
?_tkn_=exp={epoch}~acl={url-encoded-path}~data={userId}~hmac={sha256}
```

**Two traps:**

1. **Fetch with a raw socket.** `requests` re-encodes the ACL (`%2f` → `%2F`) and the
   Akamai HMAC then fails with `403`.
2. **The shard is not the first hex digit.** It is:

```python
shard = "0123456789abcdefghijklmnopqrstuv"[int(sha1[:2],16) % 32]
```

(e.g. `73AF6807…` → `j`, `EDE115E6…` → `d`).

## 4. File reconstruction

`.metadata` and `.manifest` share a container:

```
u32 version(1) | u32 sig_len | u32 body_len | signature | zlib(body)
```

The `.manifest` body has `f4` = download units; each unit's `f3` = one file:

| Field | Meaning |
|-------|---------|
| `f1` | path |
| `f2` | uncompressed size |
| `f4` (repeated, 20 B) | content SHA1 — **verification only** |
| `f7` (repeated) | `{f1: slice_size, f2: compressed_len, f3: <20-byte hash>}` |

The **`f7.f3` hash is the CDN object name** (verified: all 23,163 chunk hashes match
captured slice URLs; the `f4` hashes never do).

Slices are **zstd frames** (magic `28 B5 2F FD`). Decompressed length equals the file
size; `f2` is the compressed length.

### Pipeline

```
signed .manifest URL
  → parse units/files/chunks
  → per chunk: sign slices_v3/{shard}/{HASH} via demux
  → GET slice (raw socket) → SHA1 check → zstd decode
  → concatenate → write file at its path
```

### Trap: never pair signed URLs by position

The demux emits extra frames, so "send one request, read one frame" eventually returns
**another slice's URL**. Key each URL by the hash in its path:

```python
name = url.split("?")[0].rsplit("/", 1)[-1].upper()
url_cache[name] = url
```

Verified result (Assassin's Creed Syndicate, product 1875): 467 files / 23,177 slices,
individual files reproduced at exact manifest size with zero hash mismatches.

## Next

→ [06 — Launch](06-launch.md)
