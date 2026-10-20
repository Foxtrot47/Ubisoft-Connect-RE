# 01 — Architecture

The client is a **hybrid native + web application**. Understanding this split explains
why some traffic is visible to native hooks and some is not.

## Components

| Binary | Role |
|--------|------|
| `upc.exe` (17 MB) | Main shell: UI container, download orchestration, pipe **server** |
| `UplayWebCore.exe` | CEF renderer hosting the web UI |
| `UbisoftGameLauncher.exe` | 32-bit **game starter**; the game re-execs into it, it talks to the launcher |
| `UplayService.exe` (11 MB) | Elevated helper for install/patch |
| `uplay_r1.dll` / `uplay_r164.dll` | The Uplay IPC client (game side links the loader) |
| `uplay_r1_loader.dll` | Shipped with each game; `LoadLibraryW("uplay_r1.dll")` + `UPLAY_*` exports |
| `overlay*.dll`, `shareplay/*` | In-game overlay and SharePlay |

The UI itself is a **SystemJS micro-frontend app** served from `connect.cdn.ubisoft.com`
and rendered inside CEF. Native↔web uses a JS bridge (e.g. `pcGameManagement.v1.*`).

## Backend hosts

| Host | Purpose |
|------|---------|
| `public-ubiservices.ubi.com` | Main REST API (prod) |
| `uat-public-ubiservices.ubi.com` | UAT / Dev / Cert |
| `public-ws-ubiservices.ubi.com` | WebSocket notifications |
| `delegation-ubiservices.ubi.com` | Delegated auth (SSO) |
| `dmx.upc.ubisoft.com` | **Demux**: manifests, signed URLs, ownership, catalog |
| `ubisoft-uplay-savegames.s3.us-east-1.amazonaws.com` | Cloud save objects |
| `uplaypc-s-ubisoft.cdn.ubi.com` | Game content (manifests + slices) |
| `static3.cdn.ubi.com`, `ubiservices.cdn.ubi.com` | Assets, client patches |
| `connect.cdn.ubisoft.com` | Web micro-frontends |
| `channel-service.upc.ubi.com` | Channels |
| `store.ubi.com`, `ecom.ubi.com`, `shop-prod.ubi.com` | Commerce |

Environment → base URL:

```
Local/Dev/Uat/Cert → https://uat-public-ubiservices.ubi.com
Prod              → https://public-ubiservices.ubi.com
```

## Application IDs

| UUID | Meaning |
|------|---------|
| `f68a4bb5-608a-4ff2-8123-be8ef797e0a6` | Connect shell `Ubi-AppId` (the real one) |
| `94145723-2736-4afe-9862-3de89184ee32` | Auth / remember-me ticket app |
| `20adeb9c-6dad-404e-af1e-b12b4594e86e` | `configcache` app |
| `af82f1ef-36d4-48a4-a0c3-962d6c3841ab` | game-download-manager micro-app |
| `035ebe81-61ab-4bae-bade-5ffda0aa3754` | key-redemption micro-app |

## Request headers

| Header | Use |
|--------|-----|
| `Authorization` | `Ubi_v1 t=<JWE>` · `ubi_v1 t=<rm ticket>` · `ubi_2fa_v1 t=…` · `Basic b64(email:password)` |
| `Ubi-AppId` | Application UUID |
| `Ubi-SessionId` | Session UUID |
| `Ubi-RequestedPlatformType` | `uplay` |
| `Ubi-LocaleCode`, `Ubi-Populations`, `Ubi-AppBuildId` | Locale / targeting |
| `Ubi-2FA-Code`, `Ubi-RememberDeviceTicket` | 2FA |

Client identity: `User-Agent: Massgate_174.2.0.13389`.

## Two things that shape every capture

**The binaries are packed.** `upc.exe` and `UplayService.exe` have `.text`/`.rdata`
with `rawsize = 0`; the real code lives in custom `.ubx0/.ubx1/.ubx2` sections and is
unpacked at runtime. Static string/endpoint extraction yields nothing.
`UbisoftGameLauncher*.exe` is *not* packed.

**The API uses a custom TLS stack.** Traffic is not WinHTTP/WinINet — it is
`SSLSocket.cpp` over CNG. Hooking `BCryptEncrypt`/`BCryptDecrypt` therefore exposes
**plaintext requests and responses**, which is how most of this document was produced.

## Next

→ [02 — Authentication](02-auth.md)
