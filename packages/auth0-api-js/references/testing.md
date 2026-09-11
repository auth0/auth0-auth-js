# Testing — @auth0/auth0-api-js

## Tiers

| Tier | Command | Config | Files | Credentials |
|------|---------|--------|-------|-------------|
| Unit (default) | `npm test` | `vitest.config.ts` | `src/*.spec.ts` (excludes workers) | none |
| Cloudflare Workers | `npm run test:workers` | `vitest.config.workers.ts` | `src/**/*.workers.spec.ts` | none (uses `wrangler.toml`) |

No live-tenant tier in this package.

## Conventions

- **Framework:** Vitest 3. `import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'`.
- **Naming:** `describe(...)` groups with `test(...)`; heavy `test.each([...])` parameterized cases; titles are behaviour sentences (e.g. `"verifyAccessToken - should verify an access token successfully"`).
- **Assertions:** `expect(...)` — `.toBe`, `.toBeDefined`, `expect(() => ...).toThrow(InvalidRequestError)`, `resolves`/`rejects`.

## Mocking (MSW)

- `setupServer` from `msw/node` with `http` / `HttpResponse`, mocking the Auth0 `.well-known/openid-configuration` and `.well-known/jwks.json`.
- Lifecycle: `beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))`, `afterEach(() => server.resetHandlers())`, `afterAll(() => server.close())`; `server.use(...)` per test.
- Token/JWK fixtures from `src/test-utils/tokens.ts`.
