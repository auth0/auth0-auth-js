# Code Style — @auth0/auth0-auth-js

## Naming & structure

- PascalCase for classes and types (`AuthClient`, `OAuth2Error`); camelCase for methods and variables.
- ECMAScript `#private` fields and methods (`#configuration`, `#customFetch`, `#buildAuthorizationUrl`).
- `SCREAMING_SNAKE` for module-level constants (`DEFAULT_SCOPES`, `PARAM_DENYLIST`, `MAX_ARRAY_VALUES_PER_KEY`).
- Relative imports carry `.js` extensions (ESM / NodeNext): `from './errors.js'`.
- `import type { ... }` for type-only imports.
- Explicit return types on public/async methods; some inference on private helpers.

## Patterns

- **Class-based core, function-based helpers.** Stateful/config-holding logic is a class (`AuthClient`, sub-clients); pure helpers are exported functions (`filterSensitiveHeaders`, `toOAuth2Error`).
- **Thin public methods delegate to `#private` implementations**; discovery is resolved first via `await this.#discover()`.
- **Heavy JSDoc** on every export: `@param`, `@returns`, `@throws`, `@deprecated`, `@internal`, `@example` fences, `{@link ...}` cross-refs.
- **Defensive header handling** — copy and strip sensitive headers rather than mutating shared objects.

## ✅ Good (from `src/utils.ts`)

```typescript
export function filterSensitiveHeaders(source: Headers): Headers {
  try {
    const filtered = new Headers(source);
    filtered.delete('set-cookie');
    return filtered;
  } catch {
    return new Headers();
  }
}
```

## ❌ Bad

```typescript
// Mutates the caller's Headers, leaks set-cookie, no return type, double quotes
export function filterSensitiveHeaders(source) {
    source.delete("set-cookie")
    return source
}
```
