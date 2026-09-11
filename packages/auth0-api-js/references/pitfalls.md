# Common Pitfalls — @auth0/auth0-api-js

- **Four runtimes.** Code must work on Node, Bun, Deno, and Cloudflare Workers (each has its own CI workflow). Prefer Web-standard APIs (`fetch`, `crypto.subtle`, `crypto.createHash` guarded) over Node-only built-ins; a change that passes `npm test` can still fail the Workers/Bun/Deno tiers.
- **ESM `.js` import extensions are mandatory** on relative imports even though sources are `.ts`.
- **`audience` is required.** The `ApiClient` constructor throws `MissingRequiredArgumentError` without it — verification is not optional.
- **DPoP is `ES256`-only.** Don't add algorithms to `ALLOWED_DPOP_ALGORITHMS`; the proof `typ` must be `dpop+jwt`, and the JWK thumbprint must match the token's `cnf.jkt`.
- **JWKS errors are intentionally generic** (`'JWKS request failed'`) to avoid leaking upstream detail — don't "improve" them to surface the raw error.
- **Depends on `auth0-auth-js`.** Token-exchange flows delegate to its `AuthClient`; a change there can shift behaviour here.
- **`.version` vs `package.json` version.** The release workflow reads `.version`; keep both in sync.
