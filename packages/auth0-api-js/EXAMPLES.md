# Examples

- [Get a token on behalf of a user](#get-a-token-on-behalf-of-a-user)
  - [Caching OBO tokens with a TokenStore](#caching-obo-tokens-with-a-tokenstore)
    - [Verification and DPoP](#verification-and-dpop)
    - [Scope matching](#scope-matching)
    - [Narrowed grants](#narrowed-grants)
    - [The store contract](#the-store-contract)
- [Get an access token for a connection](#get-an-access-token-for-a-connection)
- [Client Credentials (Machine-to-Machine)](#client-credentials-machine-to-machine)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
- [Discovery Cache](#discovery-cache)
- [DPoP Authentication](#dpop-authentication)
  - [Access token verifier options](#access-token-verifier-options)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
  - [Customize DPoP validation behavior](#customize-dpop-validation-behavior)
    - [DPoP Behavior Matrix](#dpop-behavior-matrix)
    - [Proof Timing Options](#proof-timing-options)

## Get a token on behalf of a user

Use `getTokenOnBehalfOf()` when your API receives an `Auth0` access token for itself and needs to
exchange it for another `Auth0` access token targeting a downstream API while preserving the same
user identity. This is especially useful for `MCP` servers and other intermediary APIs that need to
call downstream APIs on behalf of the user.

The following example verifies the incoming access token for your API, exchanges it for a token for the downstream API, and then calls the downstream API with the exchanged token.

```ts
import { apiClient } from './auth0.js';

function getBearerToken(authorizationHeader: string | null): string {
  if (!authorizationHeader?.toLowerCase().startsWith('bearer ')) {
    throw new Error('Missing Bearer access token');
  }

  return authorizationHeader.slice('Bearer '.length).trim();
}

export async function handleCalendarRequest(request: Request) {
  const incomingAccessToken = getBearerToken(request.headers.get('authorization'));

  // Verify the incoming token for your API before exchanging it.
  const claims = await apiClient.verifyAccessToken({
    accessToken: incomingAccessToken,
  });

  const obo = await apiClient.getTokenOnBehalfOf(incomingAccessToken, {
    audience: 'https://calendar-api.example.com',
    scope: 'calendar:read calendar:write',
  });

  const downstreamResponse = await fetch('https://calendar-api.example.com/events', {
    headers: {
      authorization: `Bearer ${obo.accessToken}`,
    },
  });

  if (!downstreamResponse.ok) {
    throw new Error(`Calendar API request failed with ${downstreamResponse.status}`);
  }

  return {
    user: claims.sub,
    data: await downstreamResponse.json(),
  };
}
```

The parameters for the `getTokenOnBehalfOf` method are as follows:

- `accessToken`: The incoming Auth0 access token used as the `subject_token`.
- `audience`: The identifier of the downstream API.
- `scope` (optional): The requested scopes for the downstream API.

If the exchange is successful, the method returns an `OnBehalfOfTokenResult` object containing:

- `accessToken`: The exchanged access token issued for the downstream API.
- `expiresAt`: The access token expiration time, represented in seconds since the Unix epoch.
- `scope`: The scope string exactly as the authorization server returned it. It is absent when the server omitted it, which means the grant matched the request. An empty string is different: it means nothing was granted. Do not test it for truthiness, because `if (result.scope)` and `result.scope ||` read an empty grant as a full grant. Compare against `undefined` explicitly, or use `grantedScopes`.
- `grantedScopes`: The scopes the exchange actually granted, normalized, deduplicated and sorted alphabetically. It is always present, on a fresh exchange and on a cache hit. See [Narrowed grants](#narrowed-grants).
- `tokenType`: The returned token type, if returned.
- `issuedTokenType`: The returned RFC 8693 issued token type, if returned.

> [!TIP] Production notes:
> - Pass the raw access token to `getTokenOnBehalfOf()`. Do not pass the full `Authorization` header or include the `Bearer ` prefix.
> - Verify the incoming token for your API before exchanging it so your application rejects invalid or mis-targeted tokens early.
> - The downstream `audience` must match an API identifier configured in your Auth0 tenant.
> - `getTokenOnBehalfOf()` only returns access-token-oriented fields. It does not expose `idToken` or `refreshToken`.

When a downstream API receives an exchanged token, it can verify the token, confirm that the current actor is the expected `MCP` server, and record the full delegation chain for audit logging. The following example uses the verifier helpers for that flow:

```ts
import { getCurrentActor, getDelegationChain } from '@auth0/auth0-api-js';

const claims = await apiClient.verifyAccessToken({ accessToken });
const currentActor = getCurrentActor(claims);
const delegationChain = getDelegationChain(claims);

// Authorize only the current actor.
if (currentActor && currentActor !== 'mcp_server_client_id') {
  throw new Error('Unexpected actor');
}

// Use the full chain for logging or audit only.
auditLogger.info('delegated_request', {
  user: claims.sub,
  currentActor,
  delegationChain,
});
```

Only the outermost `act.sub` should be used for authorization decisions. Use `delegationChain` for logging, audit, or attribution.

`getTokenOnBehalfOf()` forwards the incoming access token as the
[RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) `subject_token` and applies no
DPoP-specific handling of its own during the exchange. When you pass a token store (see below), the SDK also verifies
the subject token before the exchange, and that changes what it can accept.

### Caching OBO tokens with a TokenStore

For high-traffic APIs and MCP servers, you can skip the round trip to Auth0 on most requests by
passing a `TokenStore` in the optional third argument of `getTokenOnBehalfOf()`. The SDK checks the
store before calling Auth0 and writes the result back after a successful exchange.

The third argument is an `OnBehalfOfTokenContext`, an object with two optional members:

- `store`: the `TokenStore` to read from and write to. Omit it to exchange on every call.
- `verified`: the already-verified form of the token being exchanged, as
  `{ accessToken, claims }`. The claims must be the object `verifyAccessToken` returned on the same
  `ApiClient`. See [Verification and DPoP](#verification-and-dpop).

`@auth0/auth0-api-js` defines the `TokenStore` interface but ships no implementation. You supply
the storage backend and its eviction policy.

A token whose key claims have the wrong type is not cached. If `iss`, `client_id`, `azp`, `sub`,
`org_id`, `sid` or `jti` is present with a value that is not a string, the call proceeds as an
ordinary uncached exchange, because the key encoding cannot tell such a value from an absent claim.
A conforming token never triggers this.

```ts
import { ApiClient, type TokenStore, type CachedToken } from '@auth0/auth0-api-js';

// A minimal in-memory store, suitable for a single process with no persistence.
// A deployment with more than one process typically needs a shared store such as Redis.
class InMemoryTokenStore implements TokenStore {
  private readonly cache = new Map<string, CachedToken>();

  async get(key: string): Promise<CachedToken | undefined> {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    // Drop expired entries on read.
    if (Math.floor(Date.now() / 1000) >= entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }
    return entry;
  }

  async set(key: string, value: CachedToken): Promise<void> {
    this.cache.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }
}

const store = new InMemoryTokenStore();

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

export async function handleCalendarRequest(request: Request) {
  const incomingAccessToken = getBearerToken(request.headers.get('authorization'));

  // On a cache hit the SDK returns the cached token without calling Auth0.
  // Because a store is supplied, the SDK verifies the incoming token as a Bearer token first.
  const obo = await apiClient.getTokenOnBehalfOf(
    incomingAccessToken,
    { audience: 'https://calendar-api.example.com', scope: 'calendar:read calendar:write' },
    { store }
  );

  return fetch('https://calendar-api.example.com/events', {
    headers: { authorization: `Bearer ${obo.accessToken}` },
  });
}
```

#### Verification and DPoP

Caching needs the claims of the subject token to build a cache key, so the SDK verifies the token
if, and only if, a store is supplied.

- **No store:** the token is forwarded untouched, exactly as if caching did not exist.
- **Store, no `context.verified`:** the SDK verifies the token internally as a **Bearer** token with
  no request context. That verification cannot satisfy `dpop: { mode: 'required' }`, cannot accept a
  DPoP-bound token, and gives a `domains` resolver no URL and no headers.
- **Store and `context.verified`:** the SDK uses the claims you supply and does not verify again.

If your API uses DPoP or a `domains` resolver, verify once at your ingress, where the authentication
scheme, the DPoP proof and the request headers are available, and hand the result in as
`context.verified`.

The SDK trusts supplied claims only when all of the following hold. Claims this instance never
produced throw an `InvalidConfigurationError`, because that is a bug in the integration. Claims that
are genuine but belong to a different token, or have expired, throw a `VerifyAccessTokenError`
(`invalid_token`, with the same challenge headers `verifyAccessToken` sets), because the problem is
the caller's token:

- `claims` is the exact object that `verifyAccessToken` returned on the **same `ApiClient`
  instance**. The SDK checks object identity against a private registry. A hand-built object, a
  clone, a spread copy, a JSON round trip, claims returned by a different `ApiClient` instance, and
  claims sent across a process or worker boundary are all rejected.
- `accessToken` is identical to the token you are exchanging, and is the token those claims were
  verified from.
- The claims have not expired. An `exp` that is at, or within a few seconds of, the current time is
  rejected.

The restriction exists because the cache key is derived from these claims. If the SDK accepted
claims it had not verified itself, a caller could supply another principal's `sub`, `org_id` or
session and read or overwrite that principal's cached delegated token.

If ingress and the exchange run in different processes, you cannot carry the claims object across.
Call `verifyAccessToken` again on the exchanging side and pass that result. A repeat verification is
cheap because the JWKS is cached. Pass the returned object straight through, as the sample below
does, and do not copy or spread it.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  dpop: { mode: 'required' },
});

// `store` is the store from the previous example.
export async function handleCalendarRequest(request: Request) {
  const authorization = request.headers.get('authorization') ?? '';
  const [scheme, incomingAccessToken] = authorization.split(' ');
  const dpopProof = request.headers.get('dpop');

  if (scheme?.toLowerCase() !== 'dpop' || !incomingAccessToken || !dpopProof) {
    throw new Error('Missing DPoP access token or proof');
  }

  // Verify once on this ApiClient, with everything the verifier needs: scheme, proof, method and URL.
  // The returned object is the one the SDK recognizes, so keep it as it is.
  const claims = await apiClient.verifyAccessToken({
    accessToken: incomingAccessToken,
    scheme: 'dpop',
    dpopProof,
    httpMethod: request.method,
    httpUrl: request.url,
  });

  // Pass `claims` straight through, not a copy or a spread, so the SDK does not verify
  // the token a second time as a Bearer token.
  const obo = await apiClient.getTokenOnBehalfOf(
    incomingAccessToken,
    { audience: 'https://calendar-api.example.com', scope: 'calendar:read' },
    { store, verified: { accessToken: incomingAccessToken, claims } }
  );

  return fetch('https://calendar-api.example.com/events', {
    headers: { authorization: `Bearer ${obo.accessToken}` },
  });
}
```

#### Scope matching

The `scopeMatching` option on `ApiClient` controls when a cached token is reused. Both modes compare
the scopes an exchange was **granted**, never the scopes a previous call asked for, and both cache a
token under the scopes it was granted.

| Mode | Reuses a cached token when | Store required |
| --- | --- | --- |
| `'strict'` (default) | its granted scopes are exactly the requested set | any `TokenStore` |
| `'non_strict'` | its granted scopes cover the requested set; the token with the fewest extra scopes wins | an `IndexedTokenStore` |

A request for no scopes never reuses a cached token under `'non_strict'`, because every cached
token would cover it.

In `'strict'` mode a cached token is found only by looking up the exact scope set of the new request,
and it is stored under the scopes it was **granted**. When Auth0 omits `scope` from the response, the
grant matched the request, so a repeat request hits. When Auth0 narrows or widens the grant, the token
is stored under a set that differs from the one requested, so the same request misses and exchanges
again every time. Request the scopes the client is actually granted to benefit from the cache, or use
`'non_strict'`, which also reuses a token whose granted scopes cover the request.

`'non_strict'` has to search several tokens per user, so it needs a store that also maintains a scope
index. With a plain `TokenStore`, `getTokenOnBehalfOf()` throws an `InvalidConfigurationError`. Cache
keys carry the mode, so changing `scopeMatching` never reads entries written under the other mode.

An `IndexedTokenStore` adds two members to `TokenStore`:

- `addIndexMember(indexKey, member)`: adds a `TokenIndexMember` to the index stored under
  `indexKey`, replacing any existing member with the same `tokenKey`.
- `listIndexMembers(indexKey)`: returns every member of that index, or an empty array when there is
  none.

A `TokenIndexMember` describes one cached token without requiring the token to be fetched:

- `tokenKey`: the `TokenStore` key the token itself is stored under.
- `grantedScopes`: the granted scopes of that token, deduplicated and sorted.
- `expiresAt`: expiration time of that token in Unix epoch seconds.

```ts
import {
  ApiClient,
  type CachedToken,
  type IndexedTokenStore,
  type TokenIndexMember,
} from '@auth0/auth0-api-js';

class InMemoryIndexedTokenStore implements IndexedTokenStore {
  private readonly tokens = new Map<string, CachedToken>();
  private readonly indexes = new Map<string, Map<string, TokenIndexMember>>();

  async get(key: string): Promise<CachedToken | undefined> {
    const entry = this.tokens.get(key);
    if (!entry) return undefined;
    if (Math.floor(Date.now() / 1000) >= entry.expiresAt) {
      this.tokens.delete(key);
      return undefined;
    }
    return entry;
  }

  async set(key: string, value: CachedToken): Promise<void> {
    this.tokens.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.tokens.delete(key);
  }

  async addIndexMember(indexKey: string, member: TokenIndexMember): Promise<void> {
    const members = this.indexes.get(indexKey) ?? new Map<string, TokenIndexMember>();
    members.set(member.tokenKey, member);
    this.indexes.set(indexKey, members);
  }

  async listIndexMembers(indexKey: string): Promise<TokenIndexMember[]> {
    return [...(this.indexes.get(indexKey)?.values() ?? [])];
  }
}

const indexedStore = new InMemoryIndexedTokenStore();

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  scopeMatching: 'non_strict',
});

export async function readCalendar(incomingAccessToken: string) {
  // Granted: calendar:read calendar:write. Cached under both scopes.
  await apiClient.getTokenOnBehalfOf(
    incomingAccessToken,
    { audience: 'https://calendar-api.example.com', scope: 'calendar:read calendar:write' },
    { store: indexedStore }
  );

  // A narrower request is served from the cached token, with no second exchange.
  return apiClient.getTokenOnBehalfOf(
    incomingAccessToken,
    { audience: 'https://calendar-api.example.com', scope: 'calendar:read' },
    { store: indexedStore }
  );
}
```

The index is not pruned by this package. Expired members are skipped when reading, but removing
them from the backing store is part of your eviction policy.

#### Narrowed grants

If Auth0 grants fewer scopes than you requested, `getTokenOnBehalfOf()` does not throw. It caches
the token under the scopes it was actually granted, and returns it with `scope` set to exactly the
value the authorization server sent. When the server sends no `scope`, the field is omitted from the
result, which per RFC 6749 section 5.1 means the grant matched the request.

`scope` has a trap. An empty string means nothing was granted, and it is distinct from the field
being absent, which means the grant matched the request. A truthiness test such as
`if (result.scope)` or `result.scope ||` therefore reads an empty grant as a full grant.

This is a deliberate split of responsibilities. Whether a narrowed grant is acceptable depends on the
request that triggered the exchange, and only the layer that handles that request can turn it into
the right response. `@auth0/auth0-api-js` reports what was granted; it does not decide. Do not
read the absence of an error here as a guarantee that the token carries every scope you asked
for.

Check `grantedScopes` on the result. It is always present, on a fresh exchange and on a cache hit,
and it is normalized, deduplicated and sorted alphabetically. It exists because `scope` alone cannot
answer the question in two cases:

- When the server omits `scope`, `grantedScopes` reports the requested set.
- On a `'non_strict'` cache hit for a narrower request, `grantedScopes` reports the broader scopes
  the cached token actually carries.

```ts
// `apiClient`, `incomingAccessToken` and `store` are as in the previous examples.
const requested = ['calendar:read', 'calendar:write'];

const obo = await apiClient.getTokenOnBehalfOf(
  incomingAccessToken,
  { audience: 'https://calendar-api.example.com', scope: requested.join(' ') },
  { store }
);

const granted = new Set(obo.grantedScopes);
const missing = requested.filter((scope) => !granted.has(scope));

if (missing.length > 0) {
  // Turn the gap into the response your API should give, such as a 403 naming the missing scopes.
  throw new Error(`Missing scopes: ${missing.join(' ')}`);
}
```

#### The store contract

A value in the store is a `CachedToken`:

- `accessToken`: the exchanged access token.
- `expiresAt`: expiration time as Unix epoch **seconds**, not milliseconds. Compare against
  `Math.floor(Date.now() / 1000)`.
- `grantedScopes`: the scopes Auth0 granted for this exchange, deduplicated and sorted
  alphabetically. This may differ from the scopes you requested.
- `scope`: the scope string exactly as the authorization server returned it, if it returned one.
- `tokenType` and `issuedTokenType`: the values the server returned, if any.

Your implementation must follow these rules:

- **Keys are opaque.** They are fixed-length, namespaced strings that contain no claim value in the
  clear. Store and return them unchanged. Do not parse or transform them.
- **Protect tokens at rest.** This package applies no encryption. A store backed by shared or
  persistent storage, such as Redis or a database, holds live access tokens and is responsible for
  protecting them at rest, with encryption and access controls that suit your environment.
- **Return entries with their own properties.** The SDK reads each field of a returned entry once,
  through `Object.hasOwn`. A value whose fields live on a prototype as accessors reads as an empty
  entry and is treated as a miss. Plain objects and `JSON.parse` output are fine. A class instance
  with prototype getters is not.
- **Eviction is yours.** This package never deletes or prunes entries or index members. Expiry, size
  limits and removal of stale index members belong to the implementation.
- **Records are bounded and verified on read.** A record or index member carrying more than 1000
  scopes is rejected as malformed. Under `'non_strict'` matching, at most 20 candidate entries are
  read per lookup, so an oversized index degrades to a miss and not to unbounded store traffic. The
  index is a hint, not an authority: a member that points at a key that does not match its own
  recorded scopes is skipped.
- **Failures never fail a call.** The cache is an optimization, not a dependency. A `get` that
  throws, an entry that is malformed, and an entry within five seconds of expiry are all treated as
  a cache miss. A `set` that throws still returns the freshly exchanged token. A store outage
  therefore costs extra exchanges and does not break requests. The same applies to
  `listIndexMembers` and `addIndexMember`.

**Revocation window**

The session component of the cache key outlives any single access token, so a delegated token minted
earlier in a session is reused for later subject tokens from the same session. If the authorization
server revokes the session, an already cached delegated token stays valid until its own expiry. This
is inherent to caching delegated tokens.

**Responsibility boundary**

`@auth0/auth0-api-js` owns:

- The `TokenStore`, `IndexedTokenStore`, `TokenIndexMember`, `CachedToken` and `TokenSet` types.
- The cache key schema, which partitions entries by the exchanging client, the subject's issuer,
  client, user, organization and session, the downstream audience, and the scope set.
- Cache-aside logic inside `getTokenOnBehalfOf()`, including the `strict` and `non_strict` lookups.
- Recording the scopes each exchange was granted, and caching under them.

Your application, or a layer above this package, owns:

- The store instance, its lifecycle, and its eviction policy, including expiry, size limits and
  removal of stale index members.
- Protecting cached tokens at rest.
- Deciding what a narrowed grant means for the request being served, and rejecting it where that is
  required.

## Client Credentials (Machine-to-Machine)

Use `getClientCredentialsToken()` when your service needs to call a downstream API without a user context. This is the standard OAuth 2.0 client credentials grant for M2M scenarios such as background jobs, daemons, and microservices.

The `ApiClient` must be configured with a `clientId` and either a `clientSecret` or a `clientAssertionSigningKey`. Calling this method without client authentication configured throws a `MissingClientAuthError`.

### Basic usage

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Request a token for the audience configured at construction time.
const tokenSet = await apiClient.getClientCredentialsToken({});

const response = await fetch('https://api.example.com/data', {
  headers: {
    authorization: `Bearer ${tokenSet.accessToken}`,
  },
});
```

### Specifying audience and scope

You can override the audience for a single call and pass a scope:

```ts
const tokenSet = await apiClient.getClientCredentialsToken({
  audience: 'https://api.backend.com',
  scope: 'read:reports write:reports',
});
```

When `audience` is omitted, the SDK uses the `audience` value supplied to the `ApiClient` constructor.

`scope` is forwarded to the token endpoint, with whitespace normalized to single spaces. Pass `null` or leave it out to send no scope. A blank or non-string value throws `InvalidScopeError` before any request is made, because Auth0 would treat it as omitted and issue the full grant. Auth0 does not narrow the issued token to the requested `scope`, so check the granted `scope` on the result (see below) rather than assuming the token carries only what you asked for.

### Reading the result

The `TokenSet` returned by `getClientCredentialsToken()` contains:

- `accessToken`: The issued access token string.
- `expiresAt`: The expiration time as **seconds since the Unix epoch** (not milliseconds).
- `scope` (optional): The scope the authorization server granted, as a space-delimited string returned exactly as given. An absent `scope` means the scopes were granted as requested (RFC 6749 section 5.1). An empty string means nothing was granted.
- `tokenType` (optional): The token type, normalized to lower case by the underlying OAuth client. A bearer token arrives as `bearer`, not `Bearer`.

To work out what was granted, treat an absent `scope` as the requested scope and compare an explicit one against it:

```ts
const requested = 'read:reports write:reports';
const tokenSet = await apiClient.getClientCredentialsToken({
  audience: 'https://api.backend.com',
  scope: requested,
});

const splitScopes = (value: string): string[] => value.split(' ').filter(Boolean);

// Absent means granted as requested. An empty string means nothing was granted.
const granted = new Set(splitScopes(tokenSet.scope ?? requested));
const missing = splitScopes(requested).filter((s) => !granted.has(s));
if (missing.length > 0) {
  // The server granted fewer scopes than were requested. Decide here rather than later.
}
```

### Checking token expiry

```ts
// expiresAt is epoch seconds; Date.now() is milliseconds.
const nowSeconds = Math.floor(Date.now() / 1000);
if (nowSeconds >= tokenSet.expiresAt) {
  // Token has expired, so request a new one.
}
```

### Error handling

```ts
import { ApiClient, InvalidScopeError, MissingClientAuthError, TokenByClientCredentialsError } from '@auth0/auth0-api-js';

try {
  const tokenSet = await apiClient.getClientCredentialsToken({
    audience: 'https://api.example.com',
  });

  await fetch('https://api.example.com/data', {
    headers: { authorization: `Bearer ${tokenSet.accessToken}` },
  });
} catch (err) {
  if (err instanceof MissingClientAuthError) {
    // ApiClient was constructed without client credentials.
  } else if (err instanceof InvalidScopeError) {
    // scope was blank or not a string.
  } else if (err instanceof TokenByClientCredentialsError) {
    // Auth0 rejected the grant (e.g., wrong client secret, unauthorized audience).
  }
  throw err;
}
```

## Get an access token for a connection

The `getAccessTokenForConnection` method allows you to exchange an access token for an access token for a specific connection. To use this method, you will need to instantiate the `ApiClient` with the client credentials:

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

const tokenSet = await apiClient.getAccessTokenForConnection({
  connection: 'my-connection',
  accessToken: 'my-access-token',
  loginHint: 'login-hint', // Optional
});
```

The parameters for the `getAccessTokenForConnection` method are as follows:

- `connection`: The name of the connection to get the token for.
- `accessToken`: The access token used as the subject token to be exchanged.
- `loginHint` (optional): An optional login hint to pass to the connection.

If the exchange is successful, the method will return a `ConnectionTokenSet` object containing the following properties:

- `accessToken`: The access token issued by the connection.
- `scope`: The scope granted by the connection.
- `expiresAt`: The access token expiration time, represented in seconds since the Unix epoch.
- `connection`: The name of the connection the token was requested for.
- `loginHint`: An optional login hint that was passed during the exchange.

For additional details, please refer to the [Token Vault documentation](https://auth0.com/docs/secure/tokens/token-vault).

## Multiple Custom Domains (MCD)

Multiple Custom Domains (MCD) support enables a single API application to accept access tokens issued by multiple domains associated with the same Auth0 tenant, including the canonical domain and its custom domains.

This is commonly required in scenarios such as:
- Multi-brand applications (B2C) where each brand uses a different custom domain but they all share the same API.
- A single API serves multiple frontend applications that use different custom domains.
- A gradual migration from the canonical domain to a custom domain, where both domains need to be supported during the transition period.

In these cases, your API must trust and validate tokens from multiple issuers instead of a single domain.

The SDK supports two approaches for configuring multiple allowed issuer domains:

### Static domains
Use a static allowlist when the set of trusted issuer domains is known in advance and remains the same for all requests.
This approach also works well for domain migration scenarios, where multiple domains, such as the canonical domain and one or more custom domains, need to be accepted during a transition period.
The SDK validates incoming tokens against this predefined list of allowed issuer domains.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  audience: 'https://api.example.com',
  domains: [
    'brand1.auth.example.com',
    'brand2.auth.example.com',
  ],
});

const payload = await apiClient.verifyAccessToken({
  accessToken,
});
```

### Dynamic resolver
Use a dynamic resolver when the set of allowed issuer domains needs to be determined at runtime based on the incoming request.
The SDK provides a `DomainsResolverContext` containing request and token-derived information (`url`, `headers`, and `unverifiedIss`). You can use any combination of these inputs to determine the allowed issuer domains for the request.

In the following example, a single API application is accessed through two domains:
- `https://api.brand1.com/`
- `https://api.brand2.com/`

Each domain should only accept tokens issued by its corresponding Auth0 custom domains.

- `https://api.brand1.com/` should accept tokens issued by:
  - `brand1-en.auth.example.com`
  - `brand1-jp.auth.example.com`

- `https://api.brand2.com/` should accept tokens issued by:
  - `brand2-en.auth.example.com`
  - `brand2-jp.auth.example.com`

To enforce this behavior, you can configure a dynamic domain resolver that determines the allowed issuer domains based on the incoming request.

```ts
import { ApiClient, type DomainsResolver, type DomainsResolverContext } from '@auth0/auth0-api-js';

const domainsResolver: DomainsResolver = async (context: DomainsResolverContext) => {
  const host = context.url ? new URL(context.url).hostname : undefined;

  if (host === 'api.brand1.com') {
    return ['brand1-en.auth.example.com', 'brand1-jp.auth.example.com'];
  }

  if (host === 'api.brand2.com') {
    return ['brand2-en.auth.example.com', 'brand2-jp.auth.example.com'];
  }

  // Fallback to the default custom domain.
  return ['default.auth.example.com'];
};

const apiClient = new ApiClient({
  audience: 'https://api.example.com',
  domains: domainsResolver, // provide the resolver function
  algorithms: ['RS256'], // optional, defaults to RS256
});

const payload = await apiClient.verifyAccessToken({
  accessToken,
  httpUrl: '<REQUEST_URL>', // Get it from the incoming request in your framework.
  headers: '<REQUEST_HEADERS>', // Get it from the incoming request in your framework.
});
```

It is the application's responsibility to decide how to use this information to return the allowed issuer domains. This allows the application to control which issuers the SDK can verify tokens from on a per-request basis. The resolver must return a non-empty array of domain strings.

In MCD, `httpUrl` is optional for bearer token verification. When provided, the SDK passes it to the domains resolver as `context.url`. If it is omitted, `context.url` will be `undefined`. So if your resolver needs the `request URL`, make sure you pass `httpUrl`.

### Security Requirements
When configuring `domains` or a domain resolver for `Multiple Custom Domains` (MCD), you are responsible for ensuring that only trusted issuer domains are returned.

Mis-configuring the domain resolver is a critical security risk. It can cause the SDK to:
- accept access tokens from unintended issuers
- make discovery or JWKS requests to unintended domains

**Single Tenant Limitation:**
The `domains` configuration is intended only for multiple custom domains that belong to the same `Auth0` tenant. It is not a supported mechanism for connecting multiple `Auth0` tenants to a single API.

**Request-Derived Input Warning:**
If your resolver uses request-derived values such as `context.url`, `context.headers`, or `context.unverifiedIss`, do not trust those values directly. Use them only to map known and expected request values to a fixed allowlist of issuer domains that you control.

In particular:
- `context.url` and `context.headers` may be influenced by clients, proxies, or load balancers, depending on your framework and deployment setup
- `context.unverifiedIss` comes from the token before signature verification and must not be trusted by itself

If your deployment relies on reverse proxies or load balancers, ensure that host-related request information is treated as trusted only when it comes from trusted infrastructure. Misconfigured proxy handling can cause the SDK to trust unintended issuer domains.

## Discovery Cache
By default, the SDK caches OIDC discovery metadata and JWKS fetchers in memory using LRU caches with a TTL of `600` seconds and a maximum of `100` entries.
Most applications can keep the defaults, but you may want to adjust `discoveryCache` in the following cases:
- Increase `maxEntries` if one process may verify tokens for more than `100` distinct domains or JWKS URIs during the `TTL` window. This is most common in Multiple Custom Domains (MCD) deployments that work with many custom domains.
- Decrease `maxEntries` if memory usage matters more than avoiding repeated discovery and JWKS setup.
- Increase `ttl` if the same domains are reused frequently and you want to reduce repeated discovery and JWKS setup after cache entries expire.
- Decrease `ttl` if you want the SDK to recreate discovery and JWKS fetchers sooner.
- Set `ttl` to `0` if you want to effectively disable discovery cache.

Rule of thumb:

Set `maxEntries` to cover the number of distinct domains or JWKS URIs a single process is expected to use during the `TTL` window, with some headroom.

If you need different cache behavior, configure `discoveryCache`:

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const cachedApiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  discoveryCache: { ttl: 900, maxEntries: 200 },
});
```

## DPoP Authentication

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the client application is in possession of a certain private key.
By default, DPoP is enabled but not required. This means that the `auth0-api-js` will accept both Bearer and DPoP tokens.

### Access token verifier options
If the request uses `DPoP` authentication, you must provide all required DPoP parameters when calling `verifyAccessToken()`, missing any of them will result in an error.  
The following parameters are required for DPoP validation:
- `accessToken`: The JWT access token to be verified.
- `scheme`: The authentication scheme used in the `Authorization` header. Either `bearer` or `dpop`.
- `dpopProof`: The value of the `DPoP` header from the incoming HTTP request.
- `httpMethod`: The HTTP method of the incoming request (e.g., `GET`, `POST`).
- `httpUrl`: The full URL of the incoming request.

### Accept both Bearer and DPoP tokens (default)
```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  dpop: { mode: 'allowed' }, // accept bearer or `DPoP`
});

// 1. `Bearer` token verification (no `DPoP` proof)
const bearerPayload = await apiClient.verifyAccessToken({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…', // JWT access token
});

// 2. `DPoP-bound` token verification
const dpopPayload = await apiClient.verifyAccessToken({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…', // JWT with cnf.jkt
  scheme: 'dpop',
  dpopProof: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3A...',
  httpMethod: 'GET',
  httpUrl: 'https://api.example.com/resource/123',
});

```
Requests using DPoP must include both `Authorization` and `DPoP` headers:
```http
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6...
DPoP: eyJhbGciOiJkcG9wIiwidHlwIjoi...
```

### Require only DPoP tokens
To enforce stronger protection and reject non-DPoP tokens:
```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  dpop: { mode: 'required' }, // `DPoP` enforced
});

// for each request, validate the `DPoP-bound` token + proof
const payload = await apiClient.verifyAccessToken({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…', 
  scheme: 'dpop',
  dpopProof: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3A…',
  httpMethod: 'POST',
  httpUrl: 'https://api.example.com/resource/123',
});

// use `payload` claims downstream

```

### Require only Bearer tokens
If you want to reject all DPoP tokens and only accept standard Bearer access tokens, you can disable DPoP support explicitly:

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  dpop: { mode: 'disabled' }, // `DPoP` disabled; `Bearer` only
});

// verify a bearer token (`DPoP` proof is ignored even if present)
const payload = await apiClient.verifyAccessToken({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…',
  // `scheme` defaults to bearer.
  // other `DPoP` params are not required.
});

// use `payload` claims downstream
```

### Customize DPoP validation behavior
```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  dpop: {
    mode: 'allowed',
    iatOffset: 120,  // accept proofs up to 2 minutes old
    iatLeeway: 10,   // allow up to 10 seconds of clock skew into the future
  },
});

// later, verify a DPoP-bound request
const payload = await apiClient.verifyAccessToken({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…',
  scheme: 'dpop',
  dpopProof: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3A…',
  httpMethod: 'POST',
  httpUrl: 'https://api.example.com/resource/123',
});

// `payload` contains the verified JWT claims

```
#### DPoP Behavior Matrix

| Mode     |Behavior                                                                                              |
| -----------|-----------------------------------------------------------------------------------------------------|
| `allowed`  | **Default behavior**. Both `Bearer` and `DPoP` tokens are accepted. Proofs are validated if present.     |
| `disabled` | Legacy mode: only `Bearer` scheme is accepted; `DPoP` scheme is rejected. **Warning:** `DPoP`-bound tokens (with `cnf.jkt`) are still accepted as `Bearer` without proof validation, which downgrades token binding. Use only for migration or legacy compatibility. |
| `required` | Invalid configuration. `DPoP` is ignored, so `required: true` has no effect. `DPoP` is ignored entirely. |


#### Proof Timing Options

When `DPoP` is enabled, you can control the accepted timing of DPoP proofs using the following options:

  - `iatOffset`: The maximum age (in seconds) of a DPoP proof. Proofs with `iat` older than this offset (relative to now) will be rejected.
    Default: `300 seconds`(5 minutes)

  - `iatLeeway`: Clock skew tolerance (in seconds) when comparing a proof's `iat` with the current server time.
    Default: `30 seconds`
