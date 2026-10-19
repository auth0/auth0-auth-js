# Common Pitfalls — @auth0/auth0-server-js

- **Four runtimes.** Code must work on Node, Bun, Deno, and Cloudflare Workers (each has its own CI workflow). Encryption uses `crypto.subtle` (Web Crypto) precisely so it runs everywhere — prefer Web-standard APIs over Node-only built-ins. A change that passes `npm test` can still fail the Workers/Bun/Deno tiers.
- **ESM `.js` import extensions are mandatory** on relative imports even though sources are `.ts`.
- **Changing the encrypted session/cookie format breaks live sessions.** The JWE payload shape, chunk size (3072 bytes), and HKDF salt are a storage contract — a change invalidates every existing cookie. Treat as a breaking change (Ask First).
- **Thread `TStoreOptions` through.** New store or client methods must carry the generic, not `any` — `no-explicit-any` is enforced.
- **Decrypt is fail-safe, not fail-silent.** Only swallow JWE decryption failures (via `isDecryptionError`); rethrow everything else so real bugs surface.
- **Depends on `auth0-auth-js`.** OAuth/OIDC and telemetry are delegated to its `AuthClient`; a change there can shift behaviour here.
- **`.version` vs `package.json` version.** The release workflow reads `.version`; keep both in sync.
