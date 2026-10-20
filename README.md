# Ubisoft Connect reverse engineering and PoC

A working replacement for Ubisoft Connect PC build `174.2.0.13389`: sign-in,
library, downloads, launch IPC, Denuvo activation and cloud saves.

Watch Dogs 2 (product 2688) reaches gameplay and joins a multiplayer session from
this launcher, with the official client isolated and EasyAntiCheat attached.

## Status

| Component | Result |
|-----------|--------|
| Authentication | PoC login, live session tickets |
| Entitlements | Live product metadata and ownership catalog (125 products) |
| Downloads | Manifest/slice reconstruction, byte-verified |
| Launch | WD2 gameplay confirmed, EAC enabled, no client running |
| Activation | Live 620 B PC ticket and live 1576 B Denuvo answer |
| Multiplayer | Session joined, multiplayer UI and season/leaderboard observed |
| Saves | Saving confirmed; cloud transfer byte-exact, permanent sync pending |
| Runtime | Ten copied DLL/starter files, ~12.3 MB |

Confirmed 2026-10-22 in run `20261022T182133.554861Z` without `-eac_launcher`.

## Known gaps

Cloud saves use temporary slots — transfer is byte-exact, permanent sync is not
wired up. Activation is re-issued on every launch rather than cached. Achievement,
friends and overlay pipes exist but are not served.

## Documentation

| Document | Contents |
|----------|----------|
| [01 Architecture](docs/01-architecture.md) | Components, hosts, headers, binary layout |
| [02 Authentication](docs/02-auth.md) | Login, 2FA, remember-me |
| [03 Library](docs/03-library.md) | Entitlements and game metadata |
| [04 Key activation](docs/04-activation.md) | Key inspection and redemption |
| [05 Downloads](docs/05-downloads.md) | Demux, manifests, slices, file reconstruction |
| [06 Launch](docs/06-launch.md) | Spawn chain and IPC protocol |
| [07 Cloud saves](docs/07-cloud-saves.md) | Authenticated URL issuance and transfer |
| [08 Open issues](docs/08-open-issues.md) | Unresolved behavior |
| [09 Live activation](docs/09-fresh-activation.md) | Independent launch and activation protocol |
| [10 Denuvo activation](docs/10-denuvo.md) | Aux channel, token roles, live issuance |
| [Runtime field inventory](docs/protocol/uplaydll-field-inventory.json) | 238 message definitions from the runtime descriptor |

`poc/` holds the implementation, `tooling/` the capture and test harnesses,
`runtime/` the copied native dependencies.
