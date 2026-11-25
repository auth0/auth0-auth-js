# Docs Update Rules — @auth0/auth0-api-js

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, client setup, access-token verification, DPoP verification, RFC 9728 metadata, token exchange | ✅ |
| `EXAMPLES.md` | Token on behalf of a user, access token for a connection, multiple custom domains, discovery cache, DPoP authentication | ✅ |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| `ApiClient` public method (added / removed / renamed) | `README.md` usage, `EXAMPLES.md` affected samples |
| Configuration options (`audience`, `domains`/resolver, `discoveryCache`, `dpop` mode) | `README.md` configuration section |
| DPoP behaviour, verification rules, or WWW-Authenticate challenges | `README.md` DPoP section, `EXAMPLES.md` DPoP examples |
| Token-exchange / delegation surface (`act` helpers, exchange profiles) | `README.md` + `EXAMPLES.md` |
| Install / package name / peer requirements | `README.md` install section |

Update the doc **in the same PR** as the code — do not defer.
