# Testing — @auth0/auth0-server-js

## Tiers

| Tier | Command | Config | Files | Credentials |
|------|---------|--------|-------|-------------|
| Unit (default) | `npm test` | `vitest.config.ts` | `src/**/*.spec.ts` (excludes workers) | none |
| Cloudflare Workers | `npm run test:workers` | `vitest.config.workers.ts` | `src/**/*.workers.spec.ts` | none (uses `wrangler.toml`) |

No live-tenant tier. `src/per-request-options.integration.spec.ts` runs under the default unit config using MSW (no real credentials).

## Conventions

- **Framework:** Vitest 3. `import { expect, test, describe, vi, beforeAll, afterEach, ... } from 'vitest'`.
- **Naming:** predominantly flat `test('...', async () => {...})` with `describe(...)` for grouping; descriptive `-`-separated titles (e.g. `'get - should throw when no storeOptions provided'`).
- **Assertions:** `expect(...)` — `.toStrictEqual`, `objectContaining`, `rejects.toThrowError(...)`.

## Mocking (MSW + cookie double)

- `setupServer` from `msw/node` with `http` / `HttpResponse`, mocking the Auth0 `.well-known`, token, backchannel, and userinfo endpoints.
- Store tests use a `TestCookieHandler` implementing `CookieHandler`, plus `DefaultStateStore` / `DefaultTransactionStore` and encryption/token helpers from `src/test-utils/`; `vi.fn()` spies on the cookie handler.
- Lifecycle: `beforeAll`/`afterEach`/`afterAll` for MSW start/reset/close.

## Build-time constants

Telemetry constants (`__AUTH0_SERVER_JS_PACKAGE_NAME__` / `__AUTH0_SERVER_JS_PACKAGE_VERSION__`) are injected via `vitest.config.ts`'s `define` (mirroring `tsup.config.ts`, both reading `package.json`).
