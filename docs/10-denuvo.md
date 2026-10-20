# 11: Denuvo activation

How the Denuvo gate inside a Ubisoft title gets satisfied, and which token is which.
Launch mechanics live in [06](06-launch.md); the full independent-launch sequence is
in [09](09-fresh-activation.md).

## Where Denuvo sits

```
game process
 ├─ CPU thread   → Disrupt_64.dll, obfuscated Denuvo VM handlers
 └─ Denuvo       → dbdata.dll
      └─ uplay_aux_r164.dll  →  UPLAY_GetActivate   (this DLL's only export)
           └─ \\.\pipe\terminal_<session>_uplay_aux_ipc_pipe_
```

Denuvo never asks the game for a licence file. It asks the launcher, over the aux
pipe, for a `gameToken` bound to a challenge the game generates at startup. If the
answer never arrives, the aux provider sits in a `SleepEx` retry loop and the VM
thread spins — the symptom that looks like a hang.

The aux pipe is therefore the activation channel, not a handshake probe. `upc.exe`
answers it from a local cache; we answer it by live issuance.

## Aux protocol

Defined by the descriptor at `0x1800f37f1` inside `uplay_aux_r164.dll`
(`mg.protocol.uplayauxdll`):

```
Req { requestId,
      initReq     { uplayId },
      activateReq { getCachedOrFreshTokenReq { requestToken,
                                               secureDlcEnabled } } }

Rsp { requestId,
      initRsp { result, uplayPID, addonsToValidate },
      activateRsp { getCachedOrFreshTokenRsp { result, errorCode,
                                               gameToken, ownershipList } } }
```

The game sends `activateReq` with a per-launch challenge — 253 decoded bytes wrapped in
a `06 00` container, 340 bytes encoded. The service expects the **340 encoded bytes
untouched**, not the decoded form. The answer is a 1576-byte `gameToken`.

Two routing rules matter:

- The aux answer goes to the aux pipe. It is **not** the session ticket.
- Session `f8` is the PC ticket (620 bytes) from `GetUplayPCTicket`. Putting the aux
  answer there, or the PC ticket on the aux pipe, breaks the launch.

## Four objects, four roles

| Object | Size | Produced by | Goes to |
|---|---|---|---|
| Ownership token | 957 B | `ownership_service`, request f28 → response f27 | input to the next step |
| PC ticket | 620 B | `ownership_service`, request f14 → response f13 | session push `f8` |
| Activation answer (`gameToken`) | 1576 B | `denuvo_service`, request f2 → response f3.f1 | aux pipe |
| Official cache wrapper | 1592 B | `upc.exe`, disk | its own cache only |

They are not interchangeable. `ownership_service`'s `GetGameToken` (request f21 →
response f20) is a third, separate operation — not the Denuvo one.

## Live issuance

Transport is TLS to `dmx.upc.ubisoft.com:443`, framed with four-byte big-endian
lengths. Demux client API 13389 authenticates; 10931 is answered as outdated.

1. Authenticate demux with the login ticket: `clientId: uplay_pc`.
2. Open and initialize `ownership_service`.
3. Ask for the product ownership token — request operation f28, response f27.
4. Open `denuvo_service`; send request operation f2 with the ownership token in `f1`
   and the game challenge in `f2`.
5. Read response operation f3, `gameToken` in `f1`; return it on the aux pipe.

Wire details that silently break the exchange:

- Ownership init scalars `f2`/`f3`/`f5` and productId `f1` are wire type 0;
  length-delimited encoding is rejected.
- proto3 omission means 0, so an absent result is Success.
- Omitted `requestId` in a service response is 0.
- The first Denuvo request uses ID 1; connection IDs are server-assigned.
- Ownership registration replay is unnecessary for a successful exchange.

| Denuvo result | Meaning |
|---|---|
| 0 | Success |
| 1 | NotOwned |
| 2 | Failure |
| 3 | ExceededActivations |
| 4 | TimeOut |
| 5 | ServerError |

A first standalone issuance took 5.95 s. Retries stop at two attempts three seconds
apart; business errors are not retried.

## Caching

`upc.exe` keeps the answer at
`%LOCALAPPDATA%\Ubisoft Game Launcher\cache\activations\<userId>` and serves it
verbatim, so it can run offline after a first activation.

`fake_launcher.py` re-issues per launch instead: an answer is reused only in memory
for an identical challenge inside one launcher process, and a changed challenge
triggers a new request. Nothing is persisted, so no client cache is needed — but the
effect of repeated issuance on activation quotas is unmeasured, and cache-first
operation (with force-fresh diagnostics) remains the intended policy.

The PC ticket and the Denuvo answer have independent lifetimes: the ticket is a
session credential, the answer is bound to that launch's challenge.

## Why the launcher's own service is not the path

`UplayService.exe` looked like the component that would vouch for a launch. It does
not work that way: it opens `\\.\pipe\terminal_<session>_uplay_service_icp_pipe_` as a
*client*, and no Ubisoft component serves that pipe. Serving it ourselves gets a
connection, then `GetNamedPipeServerProcessId` + `OpenProcess` ×3 and an exit from the
service with code 6, sending zero bytes — peer identification by lineage, not a
`WinVerifyTrust` signature check.

The working path needs none of it: Denuvo talks to the launcher over the aux pipe
directly, so activation happens without that component ever running.

## Evidence

| Source | Contents |
|---|---|
| `tooling/ACTIVATION-CAPTURE.md` | collector design, coverage limits, capture self-test |
| `tooling/ACTIVATION-VERIFIED.md` | challenge/answer byte-matched across aux, CNG plaintext and cache |
| `tooling/captures/20261022T132423.573463Z/` | official first-activation exchange (payload blob held locally) |
| `tooling/independent-runs/20261022T182133.554861Z/` | live issuance with EAC enabled, gameplay confirmed |

Public schema references, corroborated against live API-13389 traffic:

- https://unpkg.com/ubisoft-demux@1.10931.1/dist/proto/proto_ownership/ownership.proto
- https://unpkg.com/ubisoft-demux@1.10931.1/dist/proto/proto_denuvo_service/denuvo_service.proto
