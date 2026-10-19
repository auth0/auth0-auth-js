# Enterprise Connect — Domain Discovery

> [!NOTE]
> Enterprise Connect is in **Early Access**. To enable it for your tenant, contact Auth0 support.

`isFederatedDomain` checks whether an email domain is managed for enterprise SSO on the given Auth0 tenant by calling Auth0's WebFinger endpoint. It is exported from both `@auth0/auth0-auth-js` and `@auth0/auth0-server-js`.

> [!NOTE]
> This is a **routing hint**, not a security control. Always validate the returned ID token and `org_id` claim after the Auth0 callback.

## Checking Whether a Domain Is Federated

```ts
import { isFederatedDomain } from '@auth0/auth0-auth-js';

const federated = await isFederatedDomain('your-tenant.auth0.com', 'acmecorp.com');
// true  → domain is configured for enterprise SSO; redirect the user to Auth0
// false → domain is not federated; fall back to password or another flow
```

The function never throws. On network errors, rate limits (429), or unexpected status codes it fails closed and returns `false`.

## Cache Behavior

Results are cached in memory with an LRU cache (max 1 000 entries):

| Result | TTL |
|--------|-----|
| Federated (`true`) | 60 seconds |
| Not federated (`false`) from a 404 | 15 seconds — short TTL so newly configured domains appear quickly |
| Errors / non-404 failures | Not cached — retried on the next call |

To pass a custom `fetch` implementation or telemetry config:

```ts
const federated = await isFederatedDomain(
  'your-tenant.auth0.com',
  'acmecorp.com',
  { customFetch: myFetch, telemetry: { clientName: 'my-app', clientVersion: '1.0.0' } }
);
```

## Scheme Normalization

The `auth0Domain` parameter accepts either a bare hostname or a URL with a scheme prefix. Any `https://` or `http://` prefix is stripped automatically, so all three of the following are equivalent:

```ts
await isFederatedDomain('your-tenant.auth0.com', 'acmecorp.com');
await isFederatedDomain('https://your-tenant.auth0.com', 'acmecorp.com');
await isFederatedDomain('http://your-tenant.auth0.com', 'acmecorp.com');
```

The email domain is lowercased before the cache lookup and WebFinger fetch, so `ACMECORP.COM` and `acmecorp.com` resolve to the same result.
