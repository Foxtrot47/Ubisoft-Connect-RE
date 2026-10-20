# 04 — Activation (CD key / code redemption)

Two calls. Both carry the **key-redemption** app id, not the shell one.

## 1. Inspect a key

```http
GET /v1/profiles/{profileId}/redeemBenefits/selectableBenefits/{code}
Authorization: Ubi_v1 t=<ticket>
Ubi-AppId: 035ebe81-61ab-4bae-bade-5ffda0aa3754
```

Returns `selectableBenefits` — the platforms/editions the key can be redeemed for.

## 2. Redeem

```http
POST /v1/profiles/{profileId}/redeemBenefits/code
Authorization: Ubi_v1 t=<ticket>
Content-Type: application/json

{"code": "<key>", "benefitIds": ["<benefitId>"]}
```

`benefitIds` is optional; omit it to let the server choose.

## Response states

Success returns `benefits`. Failures are distinguishable by error code; strings
recovered from the shipped bundle include:

```
CodeAlreadyRedeemedByOtherAccount   CodeAlreadyRedeemed
Banned                              NoBenefitSelectable
SomethingWrong                      RequirementsNotMet
```

The UI surfaces these as: invalid key, blocked (too many attempts), wrong account,
subscription required.

## Notes

- Redemption is rate-limited per account (`error.keyBlocked` after repeated failures).
- A key can unlock several platforms; the client shows a platform picker before
  submitting, which is just the `benefitIds` choice above.

## Next

→ [05 — Downloads](05-downloads.md)
