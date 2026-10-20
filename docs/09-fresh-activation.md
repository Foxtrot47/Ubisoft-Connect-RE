# 09: Live activation and independent launch

Watch Dogs 2 launches from this launcher with fresh server-issued activation and no
captured input of any kind. Two runs are confirmed: `20261022T155009.643936Z` with EAC
skipped, and `20261022T182133.554861Z` with EAC enabled.

## EAC-enabled gameplay

Run `tooling/independent-runs/20261022T182133.554861Z/`, launched without
`--skip-eac` (`eac_skip_requested: false`). The launcher fetched a 620-byte PC
ticket and a 1576-byte activation answer, replayed nothing, and the game loaded with
no disabled-EAC warning.

The screenshot (`gameplay-multiplayer-ui.png`) shows the player in the game world,
Public Party with empty slots, and the multiplayer season/leaderboard screen. A
multiplayer session was joined and the game saved.

The process sequence differed from the skipped run: PID 10808 exited 0, then PID 8500
registered and loaded gameplay. `phase: game-exited` went stale when the later PID
registered, so both exit statuses are tracked separately and normalized to unsigned
32-bit.

The preceding attempt `20261022T181945.066274Z` stopped before creating a process:
saved login and remember-me refresh both returned HTTP 401. A fresh PoC login made
the retry succeed.

## Strict baseline, EAC skipped

Run `tooling/independent-runs/20261022T155009.643936Z/` reached gameplay with:

- PoC dialog login and `~/.ubisoft_poc_session.json` — no captured auth.
- Explicit game path — not Connect's cached configuration.
- Live 620-byte PC ticket; session product IDs from the live ownership catalog.
- Generated session/profile and typed installer reply.
- Live 1576-byte Denuvo answer to the game's own challenge.
- No replay of captured sessions or follow-ups, no activation cache read.
- A dedicated empty save root; existing progress left alone.
- Copied runtime DLLs/starters, EAC skipped via `-eac_launcher`.

Official install, LocalAppData cache and ProgramData state were renamed aside. The
mapping is in `tooling/independent-runs/isolation-elevated.json` and restoration is
outstanding. This run proves operation with those folders isolated, not operation on
a machine where Connect was never installed.

## Generated IPC instead of template replay

Field meanings come from the descriptor embedded in `runtime/uplay_r164.dll`:

| Item | Meaning |
|---|---|
| `InitRsp.f22.f1` | `UbiServices.appId`, from the selected live entitlement's `applicationId` |
| `Req.f13` | `InstallerReq` |
| `Rsp.f10.f1` | `InstallerRsp.initInstallerRsp` |

The installer reply carries success, an empty optional chunk catalog and `en-US` —
enough for an installed title, not a full progressive-install implementation. The
account password field stays empty; nothing needs it.

Schema detail lives in [the field inventory](protocol/uplaydll-field-inventory.json);
the runner does not load it as runtime state.

Session fields: `f8` is the PC ticket, not the aux activation answer. `f17` is the
writable save directory and ends in a slash. `f5` product IDs come from ownership
initialization filtered on owned=1, product_type in (0,1), state in (0,3), in catalog
order — 125 IDs for this account, where the broader entitlement API had returned 176.

## Live issuance

Token roles and the aux-pipe schema are in
[10: Denuvo activation](10-denuvo.md).

Transport is TLS to `dmx.upc.ubisoft.com:443` with four-byte big-endian frame lengths.
Client API 13389 authenticates; 10931 is rejected.

1. Authenticate demux with the login ticket (`clientId: uplay_pc`).
2. Open and initialize `ownership_service`.
3. Request the product ownership token — request operation f28, response f27.
4. Open `denuvo_service`; send request operation f2 with the ownership token in f1
   and the untouched game challenge in f2.
5. Read response operation f3, `gameToken` in f1; return it on the aux pipe.

For WD2 the challenge is 340 bytes of encoded text decoding to 253 bytes — the
service expects the 340 encoded bytes. Observed sizes: ownership token 957 bytes,
activation answer 1576 bytes (1180 decoded), official cache wrapper 1592 bytes.
These are three distinct objects.

`GetUplayPCTicket` (request f14 / response f13) produces the 620-byte session ticket.
Ownership's `GetGameToken` (request f21 / response f20) is not the Denuvo-service
operation — keeping them apart matters.

Wire details that must be right:

- Ownership init scalars f2/f3/f5 and productId f1 use wire type 0.
- Denuvo uses proto3 omission, so 0 means Success. Others: 1 NotOwned, 2 Failure,
  3 ExceededActivations, 4 TimeOut, 5 ServerError.
- Omitted requestId in a service response means 0.
- The first Denuvo request ID is 1; connection-open IDs are server-assigned.
- Ownership registration replay is unnecessary for a successful exchange.

Schema references, corroborated against live API-13389 traffic:

- https://unpkg.com/ubisoft-demux@1.10931.1/dist/proto/proto_ownership/ownership.proto
- https://unpkg.com/ubisoft-demux@1.10931.1/dist/proto/proto_denuvo_service/denuvo_service.proto

## Caching

`tooling/run_independent_launcher.py` forces live issuance. An answer is reused only
in memory for an identical challenge within one launcher process; a changed challenge
triggers a new issuance. Retries stop at two attempts, three seconds apart, and do
not retry business errors. Sockets close on both paths. A timed-out request may
still have been processed server-side.

Cache-first operation with force-fresh diagnostics is the recorded policy.
Persistent storage, invalidation and expiry are unimplemented, and the effect of
repeated issuance on activation or rate quotas is unknown. Turning off
`fresh_activation` selects a legacy path that falls back to captured artifacts — it
is not an independent cache. PC ticket refresh and Denuvo activation caching are
separate policies.

## Capture cross-check

The official first activation shows the challenge and its answer byte-identical across
the aux pipe, the CNG plaintext stream and the resulting cache entry — so the launcher
transports the blob unchanged. See `tooling/ACTIVATION-VERIFIED.md`.

## Regression

44 PoC tests plus 4 input-guard tests pass. They cover wire encoding, proto3 defaults,
live-ticket routing, absence of a fresh-mode disk fallback, replay rejection, dynamic
IDs, cloud authorization and URL validation, application-ID selection, typed installer
responses, exit-code normalization and real-PID tracking. They do not exercise the
game, EAC or cloud sync.
