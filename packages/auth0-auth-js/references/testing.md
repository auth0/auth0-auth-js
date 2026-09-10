# Testing — @auth0/auth0-auth-js

## Three test tiers

| Tier | Command | Config | Files | Credentials |
|------|---------|--------|-------|-------------|
| Unit (default) | `npm test` | `vitest.config.ts` | `src/**/*.spec.ts` (excludes workers + live-integration) | none |
| Cloudflare Workers | `npm run test:workers` | `vitest.config.workers.ts` | `src/**/*.workers.spec.ts` | none (uses `wrangler.toml`) |
| Live integration | `npm run test:integration` | `vitest.config.integration.ts` | `src/**/*.live.integration.spec.ts` | **real tenant** — Ask First |

The live tier loads `.env.validation` from the repo root (or `AUTH0_ENV_FILE`) via `test/load-env.ts`, uses a 20s timeout, and retries twice. It hits a real Auth0 tenant and can mutate resources — do not run without approval.

## Conventions

- **Framework:** Vitest 3. Import from `vitest`: `import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest'`.
- **Naming:** `describe(...)` groups with `test(...)` blocks (this package uses `test`, not `it`); test titles are behaviour sentences.
- **Assertions:** `expect(...)` (`.toBe`, `.toBeDefined`, `.toThrow(ErrorClass)`, `resolves`/`rejects`).

## Mocking (MSW)

- `setupServer` from `msw/node` with `http` / `HttpResponse` / `delay` handlers, mocking the Auth0 `.well-known/openid-configuration`, JWKS, token, backchannel, and userinfo endpoints.
- Lifecycle: `beforeAll(() => server.listen())`, `afterEach(() => server.resetHandlers())`, `afterAll(() => server.close())`; `server.use(...)` overrides handlers per test.
- Token/JWKS fixtures come from `src/test-utils/tokens.ts` (`generateToken`, `jwks`); openid-client `Configuration` is built inline.

## Build-time constants in tests

The telemetry name/version constants (`__AUTH0_AUTH_JS_PACKAGE_NAME__`, `__AUTH0_AUTH_JS_PACKAGE_VERSION__`) are injected via each vitest config's `define` block (read from `package.json`), mirroring `tsup.config.ts`. Tests that touch telemetry rely on these being defined.
