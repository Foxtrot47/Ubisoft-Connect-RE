# 03 — Library and game metadata

The library is not one call. It is a **join** of an API response and a local
configuration file.

## The ownership list

```http
GET /v1/profiles/me/global/ubiconnect/entitlement/api/entitlements
Authorization: Ubi_v1 t=<ticket>
Ubi-SessionId: <sessionId>
Ubi-AppId: fc097858-… (shell)
```

Each entry looks like:

```json
{"productId": 1875, "availability": "playable", "accessLevel": "owned",
 "source": "activation", "type": "game",
 "spaceId": "9676c860-e256-4d60-b39a-26d114b125c3",
 "applicationId": "8ae62d8c-0a53-438e-bbea-a4f8f1f9feeb",
 "playable": true, "downloadable": true, "grantedAt": "2021-01-16T11:50:54Z"}
```

Measured on one account: **178 entitlements** — 25 `game`, 104 `addon`, 37 `package`,
12 `bundle`.

This is the **only** place the numeric `productId` exists.

## Supporting calls

| Endpoint | Purpose |
|----------|---------|
| `GET /v3/users/me` | identity (id, name, avatar) |
| `GET /v1/profiles/me/gamesplayed?applicationPlatformTypes=PC` | recently played |
| `GET /v1/mdm/products?productIds=…` | product metadata |
| `GET /v1/profiles/me/populations?spaceIds=…` | space populations |
| `GET /v1/profiles/{pid}/global/ubiconnect/economy/api/ubiplussubscriptions` | Ubisoft+ |

## The local configuration file

`%LOCALAPPDATA%\Ubisoft Game Launcher\cache\configuration\configurations` (~312 KB).

Per game it carries: `space_id`, `app_id`, `game_code`, `sort_string`, install
executables, registry install dir, `installer.game_identifier`, addon list, asset image
hashes, and launch flags (`denuvo: yes`, `cloud_saves: yes`).

### Parsing pitfalls

`root.name` comes in four flavours:

| Form | Example | Handling |
|------|---------|----------|
| quoted | `name: "Assassin's Creed II"` | strip quotes |
| bare | `name: Assassin's Creed® Syndicate` | as-is |
| localization key | `name: l1` | resolve via `localizations.default.l1` |
| template token | `name: GAMENAME`, `NAME` | fall back to `installer.game_identifier`, then `shortcut_name` |

DLC names live in the block's `addons:` list, keyed by `productId`; those names can also
be `lN` keys.

## How each field is sourced

| Field | Source |
|-------|--------|
| `productId` | entitlements |
| `spaceId`, `applicationId` | entitlements |
| owned / playable / downloadable / grantedAt | entitlements |
| display name | configurations `root.name` (+ fallbacks above) |
| DLC / addon names | configurations `addons:` |
| images | configurations hashes → `static3.cdn.ubi.com/orbit/uplay_launcher_3_0/assets/{hash}.{ext}` |
| launch exe, working dir | configurations `start_game.*`, registry `Installs\{pid}\InstallDir` |
| `manifestId` | demux config catalog (see [05](05-downloads.md#manifest-id)) |

## Result on one account

23 spaces + 93 addon names resolved → 42 renderable rows. The only unnamed row was an
old giveaway whose `spaceId` is absent from the local file.

## Session product list

The launch session's `f5` product IDs come from ownership initialization, filtered:

- `owned` f20 = 1
- `product_type` f8 (default 0) in {0, 1}
- `state` f13 (default 0) in {0, 3}
- `product_id` f1 emitted in catalog order

On the test account this matches the official session exactly: 125 IDs, same order.
The broader entitlement API returns 176, which is not what the game expects in `f5`.

## Next

→ [04 — Activation](04-activation.md)
