# AI Agent Guidelines for @auth0/auth0-api-js

## Project Structure

```
packages/auth0-api-js/
├── src/
│   ├── index.ts                       # Public entry (barrel) — ApiClient, errors, types, helpers
│   ├── api-client.ts                  # ApiClient: access-token verification + token exchange (core)
│   ├── dpop-api.ts                    # DPoP (RFC 9449) proof verification, WWW-Authenticate challenges
│   ├── token.ts                       # getToken(): extract bearer token from request (RFC 6750/9449)
│   ├── act.ts                         # RFC 8693 delegation: getCurrentActor, getDelegationChain
│   ├── protected-resource-metadata.ts # RFC 9728 metadata builder
│   ├── errors.ts                      # Error classes (AuthError base + standalone validators)
│   ├── types.ts                       # Public types (no runtime code)
│   ├── lru-cache.ts                   # TTL+size LRU with in-flight dedup (discovery + JWKS)
│   └── test-utils/tokens.ts           # Test-only token/JWK helpers (not exported)
├── eslint.config.mjs · .prettierrc · tsup.config.ts
└── vitest.config.ts · vitest.config.workers.ts · wrangler.toml
```

`ApiClient` public methods: `verifyAccessToken`, `getAccessTokenForConnection`, `getTokenByExchangeProfile`, `getTokenOnBehalfOf`. `index.ts` also re-exports `MissingClientAuthError` / `TokenExchangeError` from `@auth0/auth0-auth-js`.

---

## Boundaries

### ✅ Always Do

- Run the unit suite (`npm test`) before committing.
- Make surgical changes — touch only what the request requires; don't refactor adjacent code that isn't broken.
- Follow existing code style and naming (single quotes, `printWidth` 120, `.js` extensions on relative imports, `#private` members).
- Add unit tests for new functionality (`src/*.spec.ts`, co-located).
- Throw errors from the existing hierarchy: `AuthError` subclasses (carry `code`, `statusCode`, `headers`, typed `cause`), or the standalone `MissingRequiredArgumentError` / `InvalidConfigurationError` for validation.
- Keep `.version` and the `package.json` `version` field in sync — the release workflow reads `.version`.
- Update `README.md` and `EXAMPLES.md` in the same PR when changing the public API, configuration options, or supported integration patterns.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never break backward compatibility on your own initiative.
- Modifying public API signatures on `ApiClient` or the exported helpers.
- Adding new dependencies.
- Modifying security-related code: JWT verification, JWKS fetching/caching, DPoP proof validation (`dpop-api.ts`), audience/issuer/algorithm rules.
- Changes to CI (`.github/workflows/*`) or the release actions.

### 🚫 Never Do

- Commit secrets, API keys, or tokens.
- Log access tokens or JWK private material.
- Modify auto-generated / build output (`dist/`) or hand-edit lock files.
- Remove or skip failing tests without fixing them.
- Accept symmetric `HS*` algorithms, widen the DPoP algorithm set beyond `ES256`, or make `audience` optional.

---

## Security Considerations

- **This is an API-side verifier** — it validates inbound access tokens; it holds no user session and (by design) sends no telemetry.
- **JWT verification** (`api-client.ts`): decode header/payload unverified → reject `HS*` symmetric algs → resolve issuer/domain → discover metadata → fetch JWKS → `jose.jwtVerify` with required `audience` (constructor, mandatory), `issuer` (from discovery), `algorithms` (default `['RS256']`), and required `iat`/`exp` claims.
- **JWKS caching:** `createRemoteJWKSet` per URI, cached in an `LruCache` (default TTL 600s, 100 entries; configurable via `discoveryCache`). The JWKS fetch wrapper deliberately masks upstream error detail (`'JWKS request failed'`).
- **DPoP (RFC 9449):** modes `allowed` (default) / `required` / `disabled`. Proof restricted to `ES256`, `typ` `dpop+jwt`; validates `jti`/`iat`/`htm`/`htu`/`ath`, the `iat` window, `htu` URL normalization, the `ath` = base64url(sha256(token)) binding, and the JWK thumbprint against `cnf.jkt`; rejects private-key material.
- **Multi-domain:** issuer allowlist matched against the unverified `iss` before discovery; `normalizeDomain` enforces HTTPS and rejects credentials/query/path.
- **Token logging:** none — errors surface messages, not token contents.

---

> The sections below are **reference** — each keeps a one-line anchor here and offloads its body to `references/*.md`, read on demand.

## Commands

```bash
npm run build        # tsup — dual ESM/CJS to dist/
npm test             # vitest run — unit tier (no credentials)
npm run lint         # eslint "./**/*.ts*"
npm run test:workers # vitest run --config vitest.config.workers.ts
```

See [references/commands.md](references/commands.md) for the full list (coverage, watch, clean). Read when you need to run, build, or test something.

## Testing

- **Framework:** Vitest 3 (provider `v8`); mocking via MSW 2.
- **Location:** co-located `src/*.spec.ts`.
- The default `npm test` suite is unit-only — no credentials required (it excludes `*.workers.spec.ts`, which run under the Cloudflare Workers pool). No live-tenant tier in this package.

See [references/testing.md](references/testing.md) for MSW setup, `test.each` conventions, and the workers config. Read when writing or debugging tests.

## Code Style

- **CI-enforced:** ESLint flat config = `@eslint/js` recommended + `typescript-eslint` recommended (lint fails CI). Prettier: single quotes, `printWidth` 120, `arrowParens: always`, `trailingComma: es5`.
- **Dominant convention:** PascalCase types/classes, camelCase members, `#private` fields, `SCREAMING_SNAKE` consts, `.js` import extensions; classes for stateful config (`ApiClient`, `LruCache`), functions for pure helpers (`getToken`, `verifyDpopProof`); heavy JSDoc with `@example`.

See [references/code-style.md](references/code-style.md) for good/bad examples and patterns. Read when writing non-trivial new code.

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for runtime-compatibility, ESM, and DPoP/verification gotchas. Read when a change spans runtimes or touches verification.

## Docs Update Rules

> A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping. The "update README.md / EXAMPLES.md in the same PR" rule is in Boundaries → Always Do.
