# Commands — @auth0/auth0-server-js

Run from `packages/auth0-server-js` (or add `-w @auth0/auth0-server-js` from the repo root).

```bash
# Build (dual ESM/CJS via tsup → dist/)
npm run build
npm run build:watch          # rebuild on change

# Clean build output
npm run clean                # rm -rf ./dist

# Unit tests (safe — no credentials; excludes workers specs)
npm test                     # vitest run
npm run test:ci              # vitest --watch false --coverage (CI command)

# Cloudflare Workers runtime tier
npm run test:workers         # vitest run --config vitest.config.workers.ts

# Lint
npm run lint                 # eslint "./**/*.ts*"
```

CI (`.github/workflows/test.yml`) builds this package after `auth0-auth-js`, then runs `test:ci` on Node 20 and 22 and `lint` on Node 24. The Bun, Deno, and Workers workflows build `auth0-auth-js` first, then this package.
