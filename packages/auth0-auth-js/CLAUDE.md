# AI Agent Guidelines for @auth0/auth0-auth-js

## Project Structure

```
packages/auth0-auth-js/
├── src/
│   ├── index.ts                 # Public entry (barrel) — exports AuthClient + sub-clients, errors, types
│   ├── auth-client.ts           # AuthClient: OAuth/OIDC flows, token grants, client auth (main class)
│   ├── errors.ts                # Error hierarchy: ApiError base + OAuth2Error helpers
│   ├── types.ts                 # Public option/response types
│   ├── telemetry.ts             # Auth0-Client header fetch wrapper + opt-out
│   ├── request-fetch.ts         # Per-request fetch composition + response capture
│   ├── cache-provider.ts        # OIDC discovery + JWKS caching
│   ├── lru-cache.ts             # LRU cache backing the discovery/JWKS cache
│   ├── utils.ts                 # Header filtering, org-claim validation
│   ├── mfa/                     # MfaClient sub-client (list/enroll/challenge/verify)
│   ├── passkey/                 # PasskeyClient sub-client (WebAuthn)
│   ├── passwordless/            # PasswordlessClient sub-client (OTP / magic-link)
│   ├── database/                # DatabaseClient sub-client (sign-up, change-password)
│   ├── anonymous-session/       # AnonymousSessionClient sub-client
│   └── test-utils/              # Test-only token/JWK helpers (not exported)
├── examples/                    # Markdown usage docs (linked from EXAMPLES.md) — no .ts fixtures
├── test/                        # load-env.ts (integration), examples-typecheck.ts fixture
├── eslint.config.mjs · .prettierrc · tsup.config.ts
└── vitest.config.ts · vitest.config.workers.ts · vitest.config.integration.ts
```

`AuthClient` exposes sub-clients as instance fields: `mfa`, `passkey`, `passwordless`, `database`, `anonymous`.

---

## Boundaries

### ✅ Always Do

- Run the unit suite (`npm test`) before committing.
- Make surgical changes — touch only what the request requires; don't refactor or reformat adjacent code that isn't broken.
- Follow existing code style and naming (single quotes, `printWidth` 120, `.js` extensions on relative imports, `#private` class members).
- Add unit tests for new functionality (`src/*.spec.ts`, co-located).
- Throw errors from the existing hierarchy — `ApiError` subclasses with a snake_case `.code`; use `toOAuth2Error`/`extractHttpMetadata` to carry OAuth context.
- Keep `.version` and the `package.json` `version` field in sync — the release workflow reads `.version`, the telemetry payload reads `package.json`.
- Update `README.md` and `EXAMPLES.md` in the same PR when changing the public API, configuration options, or supported integration patterns.
- When adding a **new outbound request path to Auth0**, route its fetch through the existing telemetry wrapper in `src/telemetry.ts` so it carries the `Auth0-Client` header, and preserve the `{ enabled: false }` opt-out — don't hand-roll a separate HTTP client.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never break backward compatibility on your own initiative.
- Modifying public API signatures on `AuthClient` or any exported sub-client.
- Adding new dependencies.
- Modifying security-related code: PKCE, client auth (`#getClientAuth`), JWKS/JWT verification, the `PARAM_DENYLIST`, header filtering.
- Changes to CI (`.github/workflows/*`) or the release actions.
- Running the live integration tests (`npm run test:integration`) — they hit a real Auth0 tenant using `.env.validation` creds, are slow, and can mutate real resources.

### 🚫 Never Do

- Commit secrets, API keys, or tokens.
- Log tokens, client secrets, or `Set-Cookie` values — `filterSensitiveHeaders` exists precisely to strip these.
- Remove the telemetry opt-out or send `Auth0-Client` unconditionally.
- Modify auto-generated / build output (`dist/`) or hand-edit lock files.
- Remove or skip failing tests without fixing them.
- Weaken PKCE (always `S256`) or the `HS*` symmetric-algorithm rejection.

---

## Security Considerations

- **PKCE:** authorization URLs always use `S256` (`randomPKCECodeVerifier` + `calculatePKCECodeChallenge`); the code verifier is returned to the caller for the later token exchange. Do not add a non-PKCE path.
- **State / nonce:** magic-link exchange validates `state` against `expectedState`; logout-token verification **rejects** any `nonce` claim.
- **JWT/JWKS:** verified via `jose` (`createRemoteJWKSet`, `jwtVerify`); discovery + JWKS cached via `cache-provider.ts`. OIDC discovery/grants go through `openid-client`.
- **Client auth:** three methods in priority order — mTLS (needs a custom fetch), `private_key_jwt` (`importPKCS8`, default `RS256`), `client_secret_post`; missing all throws `MissingClientAuthError`.
- **Injection / DoS guards:** `PARAM_DENYLIST` (frozen Set) blocks security-critical OAuth params from `extras`; `MAX_ARRAY_VALUES_PER_KEY = 20`.
- **Secret leakage:** `Set-Cookie` stripped from error/response headers; auth-bearing discovery config is never shared with the optional-auth path.
- **Secrets:** provided at runtime by the caller; nothing is persisted or logged by this package.

---

> The sections below are **reference** — each keeps a one-line anchor here and offloads its body to `references/*.md`, read on demand.

## Commands

Core commands (run from this package dir):

```bash
npm run build        # tsup — dual ESM/CJS to dist/
npm test             # vitest run — unit tier (no credentials)
npm run lint         # eslint "./**/*.ts*"
npm run typecheck    # tsc --noEmit --project tsconfig.test.json
```

See [references/commands.md](references/commands.md) for the full command list (workers/integration tiers, coverage, watch, clean, examples type-check). Read when you need to run, build, or test something specific.

## Testing

- **Framework:** Vitest 3 (`@vitest/coverage-v8`, provider `v8`); mocking via MSW 2.
- **Location:** co-located `src/**/*.spec.ts`.
- The default `npm test` suite is unit-only — no credentials required (it excludes `*.workers.spec.ts` and `*.live.integration.spec.ts`). A separate **live integration tier** (`npm run test:integration`) hits a real tenant — see Boundaries.

See [references/testing.md](references/testing.md) for the three test tiers, MSW setup, conventions, and config files. Read when writing or debugging tests.

## Code Style

- **CI-enforced:** ESLint flat config = `@eslint/js` recommended + `typescript-eslint` recommended (lint fails CI). Prettier: single quotes, `printWidth` 120, `arrowParens: always`, `trailingComma: es5`.
- **Dominant convention:** PascalCase types/classes, camelCase members, `#private` fields, `SCREAMING_SNAKE` module consts, `.js` extensions on relative imports; thin public async methods delegating to `#private` implementations; heavy JSDoc.

See [references/code-style.md](references/code-style.md) for good/bad examples and patterns. Read when writing non-trivial new code.

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for runtime-compatibility and ESM gotchas (4 packaged runtimes, `.js` import extensions, build-time telemetry constants). Read when a change spans runtimes or touches the build.

## Docs Update Rules

> A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping. The "update README.md / EXAMPLES.md in the same PR" rule is in Boundaries → Always Do.
