# Common Pitfalls — @auth0/auth0-auth-js

- **Four runtimes, not one.** Code must work on Node, Bun, Deno, and Cloudflare Workers (each has its own CI workflow). Prefer Web-standard APIs (`fetch`, `crypto.subtle`, `Headers`, `btoa`) over Node-only built-ins. A change that passes `npm test` can still fail the Workers/Bun/Deno tiers.
- **ESM `.js` import extensions are mandatory.** Relative imports must end in `.js` even though the source is `.ts` — omitting the extension breaks the ESM build and the Workers tier.
- **Telemetry constants are build-time injected.** `__AUTH0_AUTH_JS_PACKAGE_NAME__` / `__AUTH0_AUTH_JS_PACKAGE_VERSION__` come from tsup `define` (and vitest `define` in tests). They don't exist at plain `tsc` time — don't reference them outside code that ships through tsup/vitest.
- **`.version` and `package.json` version drift.** Two sources of truth: the release workflow reads `.version`, the telemetry payload reads `package.json`. Bump both together.
- **Dependents downstream.** `auth0-api-js` and `auth0-server-js` consume this package. A signature or behaviour change here can break them — build and test them when you change the public surface.
