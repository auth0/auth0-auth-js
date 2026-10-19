# Docs Update Rules — @auth0/auth0-auth-js

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, client setup, authorization/logout URLs, token exchange, ROPG, MFA, passkeys, DB connections, passwordless | ✅ |
| `EXAMPLES.md` | Configuration, auth URLs, tokens, logout, userinfo, passwordless, MFA, passkeys, custom token exchange, DB connections, HTTP req/resp | ✅ |
| `examples/` | Markdown usage docs linked from `EXAMPLES.md` (not runnable `.ts` apps) | ✅ |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| `AuthClient` or a sub-client public method (added / removed / renamed) | `README.md` usage, `EXAMPLES.md` affected samples, the linked `examples/*.md` |
| Configuration options (`AuthClientOptions`, telemetry, client-auth options) | `README.md` configuration section |
| A new grant / flow (token exchange, passwordless, DB connection, etc.) | `README.md` + `EXAMPLES.md` (add an example) |
| Install / package name / peer requirements | `README.md` install section |

Update the doc **in the same PR** as the code — do not defer.
