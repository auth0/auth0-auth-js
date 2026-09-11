# AI Agent Guidelines for @auth0/auth0-server-js

## Project Structure

```
packages/auth0-server-js/
├── src/
│   ├── index.ts                     # Public entry (barrel) — ServerClient, stores, cookie types, errors
│   ├── server-client.ts             # ServerClient<TStoreOptions>: main façade (delegates OAuth to AuthClient)
│   ├── errors.ts                    # Error classes + TokenExchangeErrorCode consts
│   ├── types.ts                     # Public types; re-exports many from auth0-auth-js
│   ├── telemetry.ts                 # Builds TelemetryConfig, passes to AuthClient (opt-out honoured)
│   ├── utils.ts                     # compareScopes, ensureOpenIdScope
│   ├── encryption/index.ts          # jose JWE encrypt/decrypt, HKDF key derivation, secret rotation
│   ├── state/utils.ts               # IPSIE session_expiry extraction + enforcement
│   ├── store/                       # Store abstractions (see Security) — abstract + cookie/stateful/stateless
│   ├── mfa/                         # ServerMfaClient<TStoreOptions>
│   ├── passkey/                     # ServerPasskeyClient<TStoreOptions>
│   ├── database/                    # ServerDatabaseClient<TStoreOptions> (sign-up, change-password)
│   └── test-utils/                  # Default stores, encryption + token helpers (test-only)
├── eslint.config.mjs · .prettierrc · tsup.config.ts
└── vitest.config.ts · vitest.config.workers.ts · wrangler.toml
```

`ServerClient<TStoreOptions = unknown>` is the façade; it holds a transaction store, a state/session store, and an `AuthClient` from `auth0-auth-js`, plus MFA/passkey/database sub-clients. Concrete stores exported: `CookieTransactionStore`, `StatefulStateStore`, `StatelessStateStore`, plus the `AbstractStateStore` / `AbstractTransactionStore` bases and the `CookieHandler` interface.

---

## Boundaries

### ✅ Always Do

- Run the unit suite (`npm test`) before committing.
- Make surgical changes — touch only what the request requires; don't refactor adjacent code that isn't broken.
- Follow existing code style and naming (single quotes, `printWidth` 120, `.js` extensions, `#private` members, `TStoreOptions` generic threading).
- Add unit tests for new functionality (`src/**/*.spec.ts`, co-located).
- Throw errors from the existing set — an `Error` subclass with a snake_case `.code` and `this.name` set (`MissingSessionError`, `SessionExpiredError`, etc.); reuse `TokenExchangeError` from auth0-auth-js and stamp a `TokenExchangeErrorCode`.
- Keep `.version` and the `package.json` `version` field in sync — the release workflow reads `.version`, the telemetry payload reads `package.json`.
- Update `README.md`, `EXAMPLES.md`, and `MFA.md` in the same PR when changing the public API, configuration options, or supported integration patterns.
- When adding a **new outbound request path to Auth0**, route it through `AuthClient` (which carries the `Auth0-Client` header) and pass the `TelemetryConfig` from `src/telemetry.ts` — don't hand-roll a separate HTTP client, and preserve the `{ enabled: false }` opt-out.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never break backward compatibility on your own initiative.
- Modifying public API signatures on `ServerClient`, the store base classes, or `CookieHandler`.
- Adding new dependencies.
- Modifying security-related code: session encryption (`encryption/`), the store abstractions, cookie options, secret rotation, or IPSIE `session_expiry` handling.
- Changing the encrypted session/cookie format (a storage-format change breaks existing sessions).
- Changes to CI (`.github/workflows/*`) or the release actions.

### 🚫 Never Do

- Commit secrets, API keys, or tokens.
- Log tokens, session data, or the encryption secret.
- Modify auto-generated / build output (`dist/`) or hand-edit lock files.
- Remove or skip failing tests without fixing them.
- Weaken cookie defaults (`httpOnly` / `secure` / `sameSite: 'lax'`), drop session-id regeneration on login (session fixation), or store session data unencrypted.

---

## Security Considerations

- **Session storage is encrypted at rest.** `encryption/index.ts` uses `jose` JWE (`enc = A256CBC-HS512`, `alg = dir`); the per-record key is HKDF-derived (SHA-256, 512-bit) salted with `${salt}${kid}`, `kid` a per-encryption `randomUUID` stored in the JWE header. Tokens carry an expiry; decrypt allows a 15s clock tolerance.
- **Secret rotation:** `secret` may be `string | string[]`; the newest encrypts, all are tried on decrypt (only for JWE decryption failures — other errors rethrow). Empty array throws `InvalidConfigurationError`.
- **Store strategies:** `StatelessStateStore` encrypts the whole session into cookies chunked at 3072 bytes; `StatefulStateStore` keeps only a session id in a cookie (data in an injected `SessionStore`) and **regenerates the session id on login to prevent fixation**. On decryption failure the base store returns `undefined` (treats as expired/invalid).
- **Cookies:** framework-agnostic `CookieHandler`; defaults `httpOnly: true`, `secure: true`, `sameSite: 'lax'`, `path: '/'`.
- **PKCE / state / nonce:** delegated to `AuthClient`; this package only persists the resulting transaction data (`codeVerifier`, etc.). Session ids use `crypto.getRandomValues`.
- **IPSIE `session_expiry`** (`state/utils.ts`): reads the ID-token `session_expiry` claim, fail-open on missing/malformed, rejects millisecond timestamps, applies a 30s leeway; triggers `SessionExpiredError`.
- **Token logging:** none — no logger in `src/`.

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
- **Location:** co-located `src/**/*.spec.ts`.
- The default `npm test` suite is unit-only — no credentials required (it excludes `*.workers.spec.ts`, which run under the Cloudflare Workers pool). Store tests use a `TestCookieHandler` and default in-memory stores from `src/test-utils/`; no live-tenant tier.

See [references/testing.md](references/testing.md) for MSW setup, the cookie-handler test double, and the workers config. Read when writing or debugging tests.

## Code Style

- **CI-enforced:** ESLint flat config = `@eslint/js` recommended + `typescript-eslint` recommended (lint fails CI; `no-explicit-any` is active). Prettier: single quotes, `printWidth` 120, `arrowParens: always`, `trailingComma: es5`.
- **Dominant convention:** PascalCase types/classes, camelCase members, `#private` fields, `SCREAMING_SNAKE` consts; the `TStoreOptions` generic threads through `ServerClient`, every store, and `CookieHandler`; deep store inheritance; pure helpers are free functions; `import type` for type-only imports; `.js` extensions.

See [references/code-style.md](references/code-style.md) for good/bad examples and patterns. Read when writing non-trivial new code.

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for runtime-compatibility, ESM, store-format, and generics gotchas. Read when a change spans runtimes or touches the stores/encryption.

## Docs Update Rules

> A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping. The "update README.md / EXAMPLES.md in the same PR" rule is in Boundaries → Always Do.
