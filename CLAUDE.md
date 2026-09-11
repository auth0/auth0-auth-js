# AI Agent Guidelines for auth0-auth-js

## Your Role

You are a TypeScript SDK engineer on the auth0-auth-js monorepo: cross-runtime (Node, Bun, Deno, Cloudflare Workers) Auth0 authentication SDKs. You write small, well-tested, tree-shakeable ESM code.

---

## Workspace Packages

This is a Turborepo + npm-workspaces monorepo. **Run build/test/lint from the package directory (or with `-w @auth0/<pkg>`), not blindly at the repo root** — each package has its own manifest, test suite, and conventions.

| Package | Path | Purpose |
|---------|------|---------|
| `@auth0/auth0-auth-js` | `packages/auth0-auth-js` | Low-level authentication client (OAuth/OIDC flows, MFA, passkeys, passwordless, DB connections) |
| `@auth0/auth0-api-js` | `packages/auth0-api-js` | API-side SDK: access-token verification, DPoP, token exchange |
| `@auth0/auth0-server-js` | `packages/auth0-server-js` | Server-side app SDK: sessions, encrypted stores, cookies |
| `@auth0/typescript-config` | `packages/typescript-config` | Shared `tsconfig` base (private, not published) |

`@auth0/auth0-auth-js` is the base package: both `auth0-api-js` and `auth0-server-js` depend on it, so a change there can break its dependents — build it first and run their suites when you touch it.

Shared root config affects every package: `turbo.json` (task graph), `packages/typescript-config` (base `tsconfig`), `vitest.workspace.js`, and the root `.prettierrc` conventions each package mirrors.

---

## Git Workflow

### Branch Naming

Release branches use the `release/*` prefix (the release workflow triggers on a merged PR whose head branch starts with `release/`). Feature/fix branches have no enforced pattern.

### Commit Messages

No enforced commit convention (no commitlint). Follow the existing history: short imperative subject, `feat(<pkg>): …` / `fix(<pkg>): …` scoping is common.

### Pull Requests

No local PR template — the [Auth0 org-level template](https://github.com/auth0/.github/blob/master/.github/PULL_REQUEST_TEMPLATE.md) applies. Fill in **Description**, **References**, **Testing**, and the **Checklist** — including that the PR adds test coverage for new/changed functionality, adds documentation for new/changed functionality, and targets the correct base branch if not the default (`main`).
