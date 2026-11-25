# Code Style — @auth0/auth0-api-js

## Naming & structure

- PascalCase classes/types (`ApiClient`, `ProtectedResourceMetadataBuilder`); camelCase members.
- `#private` fields/methods (`#options`, `#jwksByUri`, `#discoverDomain`); `SCREAMING_SNAKE` module consts (`ALLOWED_DPOP_ALGORITHMS`, `DPOP_ERROR_MESSAGES`).
- Relative imports carry `.js` extensions (ESM).
- Explicit return types on exported/public functions; some inference on private helpers.

## Patterns

- **Class-based state, function-based purity.** Config-holding/stateful logic is a class (`ApiClient`, `LruCache`, `ProtectedResourceMetadataBuilder`); pure/stateless logic is an exported function (`getToken`, `verifyDpopProof`, `getCurrentActor`, `normalizeUrl`).
- **Defensive immutability** — array copies (`[...arr]`) in the metadata builder; `readonly` on private fields.
- **Heavy JSDoc** with `@param`/`@returns`/`@throws`/`@example`/`@see`, including code fences for DPoP.
- **Validate early, throw typed.** Argument/shape checks throw `MissingRequiredArgumentError` / `InvalidRequestError` up front.

## ✅ Good (from `src/act.ts`)

```typescript
export function getCurrentActor(claims: ClaimsWithAct): string | undefined {
  if (!claims || typeof claims !== 'object') {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  if (claims.act === undefined) {
    return undefined;
  }

  const sub = (claims.act as unknown as { sub?: unknown }).sub;
  if (typeof sub !== 'string' || sub.trim().length === 0) {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  return sub;
}
```

## ❌ Bad

```typescript
// No return type, silent on bad input, double quotes, no typed error
export function getCurrentActor(claims) {
    return claims.act ? claims.act.sub : null
}
```
