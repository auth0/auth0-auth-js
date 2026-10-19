# Code Style — @auth0/auth0-server-js

## Naming & structure

- PascalCase classes/types (`ServerClient`, `AbstractSessionStore`); camelCase members; `#private` fields on concrete stores.
- `SCREAMING_SNAKE` module consts (`ENC`, `ALG`, `HKDF_INFO`, `MAX_PLAUSIBLE_UNIX_SECONDS`, `SESSION_EXPIRY_LEEWAY`); snake_case error `.code` strings.
- `import type { ... }` for type-only imports; `.js` extensions on all relative imports.
- Explicit return types on abstract/store methods (`Promise<void>`, `Promise<TData | undefined>`); some inference on private helpers.

## Patterns

- **Generics everywhere:** `TStoreOptions = unknown` threads through `ServerClient`, all stores, and `CookieHandler`; base is `AbstractStore<TData extends JWTPayload, TStoreOptions>`.
- **Deep inheritance for stores:** `AbstractStore` → `AbstractStateStore` → `AbstractSessionStore` → concrete (`StatefulStateStore` / `StatelessStateStore`); pure utilities (`encryption`, `state/utils`, `telemetry`, `utils`) are exported free functions.
- **Fail-safe decrypt:** swallow decryption failures (return `undefined`), rethrow everything else.
- **Extensive JSDoc**, including long rationale comments on non-obvious constants.

## ✅ Good (from `src/store/abstract-store.ts`)

```typescript
protected async decrypt<TData>(identifier: string, encryptedStateData: string) {
  try {
    return (await decrypt(encryptedStateData, this.options.secret, identifier)) as TData;
  } catch (e: unknown) {
    // A decryption failure likely means the session expired or the data is invalid — treat as absent.
    if (isDecryptionError(e)) {
      return;
    }
    throw e;
  }
}
```

## ❌ Bad

```typescript
// Swallows ALL errors (hides real bugs), no generic, double quotes
protected async decrypt(identifier, encryptedStateData) {
    try {
        return await decrypt(encryptedStateData, this.options.secret, identifier)
    } catch (e) {
        return undefined
    }
}
```
