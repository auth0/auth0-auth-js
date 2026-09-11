# Docs Update Rules — @auth0/auth0-server-js

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, client setup, store configuration, interactive login/logout, DB connections | ✅ |
| `EXAMPLES.md` | Configuration (store/cookies/secret rotation/PrivateKeyJwt/mTLS), MCD, login/logout, backchannel, passkeys, token exchange, userinfo, session transfer, passwordless, session expiry, refresh-token revocation, backchannel logout, per-request options | ✅ |
| `MFA.md` | MFA setup, handling MFA-required, list/enroll/challenge/verify authenticators, session persistence, error handling | ✅ |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| `ServerClient` public method (added / removed / renamed) | `README.md` usage, `EXAMPLES.md` affected samples |
| Store base classes, concrete stores, or `CookieHandler` | `README.md` store-configuration section, `EXAMPLES.md` configuration |
| Configuration options (secret/rotation, cookies, PrivateKeyJwt, mTLS, store identifier) | `README.md` + `EXAMPLES.md` configuration |
| MFA sub-client behaviour or flow | `MFA.md` |
| A new flow (backchannel, passkeys, session transfer, passwordless, session expiry) | `README.md` + `EXAMPLES.md` (add an example) |
| Install / package name / peer requirements | `README.md` install section |

Update the doc **in the same PR** as the code — do not defer.
