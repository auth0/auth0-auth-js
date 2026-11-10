# Docs Update Rules — @auth0/auth0-api-js

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, client setup, access-token verification, DPoP verification, RFC 9728 metadata, token exchange, Poppy (Personal Agent) request verification heads-up | ✅ |
| `EXAMPLES.md` | Token on behalf of a user, access token for a connection, multiple custom domains, discovery cache, DPoP authentication, Personal Agent Protocol (Poppy) | ✅ |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| `ApiClient` public method (added / removed / renamed) | `README.md` usage, `EXAMPLES.md` affected samples |
| Configuration options (`audience`, `domains`/resolver, `discoveryCache`, `dpop` mode) | `README.md` configuration section |
| DPoP behaviour, verification rules, or WWW-Authenticate challenges | `README.md` DPoP section, `EXAMPLES.md` DPoP examples |
| Token-exchange / delegation surface (`act` helpers, exchange profiles) | `README.md` + `EXAMPLES.md` |
| Install / package name / peer requirements | `README.md` install section |
| `verifyPoppyRequest`, the `poppy` option (`PoppyOptions`, `PoppyAgentMetadataOptions`) or a default in `src/poppy/constants.ts` | `README.md` section 8; `EXAMPLES.md` Poppy "Configure the client" and the `PoppyOptions` table |
| The order of the Poppy checks, or an `InvalidSessionReason` value | `EXAMPLES.md` Poppy "What the SDK does for you" and the `InvalidSessionReason` table |
| A Poppy error, or the status, headers or body from `toHttpErrorResponse` | `EXAMPLES.md` Poppy "Turn errors into responses" and "Routes that need the account" |
| `PoppySessionStore`, `PoppySessionRecord` or `PoppySession` | `EXAMPLES.md` Poppy "Session records" and the `PoppySession` table |
| Agent metadata fetch rules, limits or caches (`agent-metadata.ts`, `url-rules.ts`) | `EXAMPLES.md` Poppy "How agent metadata is fetched" and the `PoppyOptions` table |
| `@auth0/auth0-api-js/testing` (`createTestAgent`, its options or defects) | `EXAMPLES.md` Poppy "Test your routes with `@auth0/auth0-api-js/testing`" |

Update the doc **in the same PR** as the code — do not defer.

After you change a `ts` snippet in `README.md` or in the Poppy section of `EXAMPLES.md`, compile it against the built package (`tsc --noEmit`, `strict`, `moduleResolution: bundler`) before you publish the docs, and run the `Map` store and the test-agent examples. Several snippets import each other by the file name in their first-line comment (`auth0.ts`, `express-route.ts`, `fetch-handler.ts`, `with-error-responses.ts`, `memory-store.ts`), so save each under that name when you compile.
