# Commands — @auth0/auth0-auth-js

Run from `packages/auth0-auth-js` (or add `-w @auth0/auth0-auth-js` from the repo root).

```bash
# Build (dual ESM/CJS via tsup → dist/)
npm run build
npm run build:watch          # rebuild on change

# Clean build output
npm run clean                # rm -rf ./dist

# Unit tests (safe — no credentials; excludes workers + live-integration specs)
npm test                     # vitest run
npm run test:ci              # vitest --watch false --coverage (CI command)

# Cloudflare Workers runtime tier
npm run test:workers         # vitest run --config vitest.config.workers.ts

# Live integration tier (Ask First — hits a real tenant)
npm run test:integration     # vitest run --config vitest.config.integration.ts

# Lint
npm run lint                 # eslint "./**/*.ts*"

# Type-check
npm run typecheck            # tsc --noEmit --project tsconfig.test.json
npm run type-check:examples  # tsc -p tsconfig.examples.json (the examples fixture)
```

CI (`.github/workflows/test.yml`) runs `build`, `typecheck`, `type-check:examples`, then `test:ci` on Node 20 and 22; `lint` on Node 24. Separate workflows run the Bun, Deno, and Workers runtime tiers.
