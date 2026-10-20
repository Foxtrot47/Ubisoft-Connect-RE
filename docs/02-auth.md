# 02 — Authentication

Every sign-in path funnels through one endpoint:

```
POST /v3/profiles/sessions
```

## Password login

```http
POST /v3/profiles/sessions HTTP/1.1
Host: public-ubiservices.ubi.com
Ubi-AppId: f68a4bb5-608a-4ff2-8123-be8ef797e0a6
Ubi-RequestedPlatformType: uplay
Authorization: Basic base64(email:password)
Content-Type: application/json

{"rememberMe": true, "enforceTwoFactorSession": false}
```

The header is built in the shipped JS as:

```js
btoa(unescape(encodeURIComponent(`${email}:${password}`)))
```

For ASCII credentials that is `base64(email + ":" + password)`. The PoC reproduces the
full JS semantics, including non-ASCII input.

## Session response

| Field | Notes |
|-------|-------|
| `ticket` | **JWE** — used as `Authorization: Ubi_v1 t=<ticket>` |
| `sessionId` | sent as `Ubi-SessionId` |
| `sessionKey` | symmetric key material |
| `profileId`, `userId` | equal in practice |
| `nameOnPlatform` | display name |
| `spaceId` | Connect space |
| `expiration` | ~3 h lifetime |
| `rememberMeTicket` | only when `rememberMe: true` |
| `twoFactorAuthenticationTicket` | only when 2FA is required |
| `clientIp`, `clientIpCountry`, `serverTime`, `maskedPhone`, `environment` | metadata |

## Login variants (same endpoint)

| Variant | Authorization |
|---------|---------------|
| Password | `Basic base64(email:password)` |
| 2FA completion | `ubi_2fa_v1 t=<twoFactorAuthenticationTicket>` + `Ubi-2FA-Code` |
| Remember-me | `ubi_v1 t=<rememberMeTicket>` |
| Steam / console ticket | platform ticket + `platformType` in the body |
| SSO (Google/Facebook/Apple) | external code exchanged at the same endpoint |

Related: `GET /v3/profiles/me/2fa`, `GET /v3/profiles/me/2facode`,
`GET|POST /v1/profiles/{pid}/tokens[/{id}]`.

## The ticket is a JWE

Decoded header of a live ticket:

```json
{"ver":"1","aid":"f68a4bb5-…","env":"Prod","sid":"<sessionId>",
 "typ":"JWE","enc":"A128CBC","int":"HS256","kid":"<keyId>"}
```

It is opaque to us — we simply pass it through. A fresh one is what lets a third-party
launcher hand a game its session (see [06 — Launch](06-launch.md)).

## Two caveats

**The web login form is Datadome-protected.** `disableDatadome: false` comes back from
`/v2/applications/{appId}/parameters?parameterGroups=auth-parameters`. The raw
`/v3/profiles/sessions` call is what the form makes underneath, but scripted traffic may
be challenged.

**Remember-me tickets die.** Observed: after a failed renewal, the stored
`rememberMeTicket` returned `401 Ticket is invalid`. Re-authenticate with a password
instead of assuming the ticket is reusable.

## Next

→ [03 — Library](03-library.md)
