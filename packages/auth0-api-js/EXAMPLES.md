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
- [Personal Agent Protocol (Poppy)](#personal-agent-protocol-poppy)
  - [What the SDK does for you](#what-the-sdk-does-for-you)
  - [Configure the client](#configure-the-client)
  - [Verify a request](#verify-a-request)
  - [Turn errors into responses](#turn-errors-into-responses)
  - [Routes that need the account](#routes-that-need-the-account)
  - [Session records](#session-records)
    - [The `PoppySessionStore` contract](#the-poppysessionstore-contract)
    - [A store backed by a Map](#a-store-backed-by-a-map)
    - [A store backed by SQL](#a-store-backed-by-sql)
    - [Ending a Session](#ending-a-session)
    - [The same checks without a store](#the-same-checks-without-a-store)
    - [Moving a guest cart when the User signs in](#moving-a-guest-cart-when-the-user-signs-in)
    - [Refusing an account change](#refusing-an-account-change)
  - [Sessions in a web app's access token](#sessions-in-a-web-apps-access-token)
  - [Registered agents](#registered-agents)
  - [How agent metadata is fetched](#how-agent-metadata-is-fetched)
  - [Test your routes with `@auth0/auth0-api-js/testing`](#test-your-routes-with-auth0auth0-api-jstesting)
  - [Reference](#reference)
    - [`PoppyOptions`](#poppyoptions)
    - [`PoppySession`](#poppysession)
    - [`InvalidSessionReason`](#invalidsessionreason)

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

It is the application's responsibility to decide how to use this information to return the allowed issuer domains. This allows the application to control which issuers the SDK can verify tokens from on a per-request basis. The resolver must return a non-empty array of domain strings: `verifyAccessToken` fails the request with a 401 when it returns an empty array. For the `aud` of a Poppy Session JWT, an empty array refuses the Session JWT instead (see [Configure the client](#configure-the-client)).

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

## Personal Agent Protocol (Poppy)

> [!NOTE]
> Poppy support is in beta. It follows [Poppy 0.3](https://personalagentprotocol.org/docs/0.3/spec), a draft of the protocol that can still change in ways that are not backward compatible, and this API can change with it.

The [Personal Agent Protocol](https://personalagentprotocol.org/docs/0.3/spec) (Poppy) describes how a Personal Agent, software that acts for one User, works with a Company, the organization that runs your API. This section is for the API side: how to verify the requests such an agent sends, and how to answer when a check fails.

A first route needs three steps: [configure the client](#configure-the-client), [verify a request](#verify-a-request) and [turn errors into responses](#turn-errors-into-responses). The other subsections add to that as your API needs them. If Poppy is new to you, start with the next one.

### What the SDK does for you

A Personal Agent sends a signed `Poppy-Session` header with every request to your API ([the Session header](https://personalagentprotocol.org/docs/0.3/spec#session-header)). The header is a JWT. It names a **Session** (`sid`), the **User ID** the agent gave its User for your Company (`sub`), and the one request it was signed for (`htm` and `htu`). A User ID is pseudonymous: it is not an account and holds no personal information ([User IDs](https://personalagentprotocol.org/docs/0.3/spec#user-ids)).

The agent does not sign with the keys it publishes. A key at its `jwks_uri` signs a short-lived **delegation** that vouches for a **delegated key**, and that key signs the Session JWT. The agent uses a delegated key for one User ID only, and it decides when to replace it ([delegated keys](https://personalagentprotocol.org/docs/0.3/spec#delegated-keys)). `verifyPoppyRequest` checks that whole chain, so you never handle a key.

For a request that has the header, the SDK runs these checks in the order of [the specification](https://personalagentprotocol.org/docs/0.3/spec#session-verification). The first check that fails throws.

1. The header holds exactly one well-formed Session JWT.
2. The agent in `iss` is one of your registered agents, if you set `agents`. Nothing is fetched before this check.
3. The delegation is valid, and the Session JWT is signed with the key it vouches for. The SDK fetches the agent's metadata and keys here, and caches them.
4. The claims fit the request: `aud` is your Auth0 issuer, `htm` is the method, `htu` is the URL without query and fragment, and `iat` is within `iatWindow` of now, a minute by default.
5. `ath`, the hash of the access token, is absent when the request has no token, and matches the token when it has one. This runs before the token is verified, so a wrong header costs no call to Auth0.
6. The access token is verified as `verifyAccessToken` verifies it, including your `dpop` mode.
7. The token was issued to the agent in `iss`.
8. With a `sessionStore`, a known Session keeps its User ID and Agent ID, an ended Session is refused, and a new Session is saved.

A request that has an access token and no header to check has the token verified, and the Session in its `act` claim, if it has one, is returned (see [Sessions in a web app's access token](#sessions-in-a-web-apps-access-token)). A `sessionStore` checks and saves that Session like one from the header. While Session checks are on, the token of a registered agent is refused with `missing_session` (see [Registered agents](#registered-agents)). A request with neither returns an empty result, and that is not an error.

**Signed out and signed in.** A Session starts signed out: the request carries only the header, so you know the agent and the pseudonymous User, not the person. It is signed in on every request that also carries an access token, and then you also get the verified `claims`, which hold the account and its scopes ([signing in](https://personalagentprotocol.org/docs/0.3/spec#sign-in)). Sign-in is plain OAuth and does not involve the Session, so one Session can be signed out on one request and signed in on the next. A signed-out request never calls Auth0.

**Opt in, at two levels.** An `ApiClient` without the `poppy` option does exactly what it did before, until you call `verifyPoppyRequest`. After that:

- `poppy: { verifySession: true }` verifies the header of every request that carries one.
- `requireSession: true` on one call makes that route need a verified Session, whatever `verifySession` says.

With neither, the header is ignored: it is not parsed and nothing is fetched.

**What it does not do.** The SDK does not rate limit, so put a rate limit in front of the route, before `verifyPoppyRequest` runs. It does not limit its own requests to agent hosts either, or the number of different agent URLs it fetches: set `agents` to bound them. Answer a request over the limit with 429 and a `Retry-After` header ([sending requests](https://personalagentprotocol.org/docs/0.3/spec#sending-requests)). The SDK keeps no `jti` replay store, so make a route that changes something safe to repeat. A copied header works for the same method, URL and token while its `iat` is within `iatWindow` of your clock in either direction, which is 60 seconds by default. A header whose `iat` is ahead of your clock stays valid until the window has passed after that `iat` ([verification](https://personalagentprotocol.org/docs/0.3/spec#session-verification)). And the SDK saves no Sessions unless you pass a `sessionStore` (see [Session records](#session-records)).

### Configure the client

Everything about Poppy goes in the `poppy` option of the `ApiClient`, and every field of it is optional. `verifyPoppyRequest` also works without the option, with the defaults. The easiest setup is a config file named `auth0-poppy.json`, which the Auth0 CLI can write for your API or you can write by hand. Pass the parsed file as `config`, and the SDK takes your issuer, your public origin and your registered agents from it. These are the fields it reads, and it ignores the rest:

```json
{
  "issuer": "https://your-tenant.auth0.com/",
  "apis": [{ "identifier": "https://api.example.com", "public_origin": "https://api.example.com" }],
  "agents": ["https://agent.example/agent.json"]
}
```

- `issuer` is what the `aud` of every Session JWT must equal, character by character. Auth0 writes it with a lower-case host, no default port and a trailing slash.
- The `apis` entry whose `identifier` is the `audience` of your client gives the `public_origin`.
- `agents` lists the agents you accept (see [Registered agents](#registered-agents)).

You can also skip the file and set `baseUrl` and `agents` yourself. The `aud` of a Session JWT must then equal the issuer of your `domain`, such as `https://your-tenant.auth0.com/`.

The SDK reads no files, so parse the file yourself. In Node:

```ts
// auth0.ts
import { readFileSync } from 'node:fs';
import { ApiClient, type PoppyConfig } from '@auth0/auth0-api-js';

const config: PoppyConfig = JSON.parse(readFileSync(new URL('./auth0-poppy.json', import.meta.url), 'utf8'));

export const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: { config, verifySession: true },
});
```

In a Worker, or with a bundler that imports JSON, import the file instead:

```ts
// auth0.ts
import { ApiClient } from '@auth0/auth0-api-js';
import config from './auth0-poppy.json';

export const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: { config, verifySession: true },
});
```

When you build the client, the SDK checks that the config fits it. It throws an `InvalidConfigurationError` whose message starts with `Invalid poppy configuration:` when the `audience` is not one of the `identifier`s, when the `issuer` is not written as above or is not the issuer of your `domain` (or of one of your `domains`), and when an agent or the origin is not valid. For an `audience` that is not in the file, the message is:

```text
Invalid poppy configuration: "config.apis" has no entry with the identifier "https://api.other.example", the audience of this client. The identifier must equal the audience exactly. The entries have the identifiers "https://api.example.com".
```

**`customFetch`.** If the client has a `customFetch`, the SDK also uses it to fetch agent metadata and keys, unless you set `agentMetadata.fetch`. A `customFetch` that adds credentials or rewrites hosts then sees the agent URLs too, so set `agentMetadata.fetch` if yours does (see [How agent metadata is fetched](#how-agent-metadata-is-fetched)).

**The public origin and `baseUrl`.** The agent signs the URL it called, which is your public URL. Behind a proxy, a load balancer or a CDN, your server sees another one, such as `http://10.0.0.5:8080/cart`, and comparing with it would refuse every request. So the SDK compares the signed URL with your public origin plus the path of the `url` you pass; the query and the fragment are ignored. DPoP proofs of access tokens are compared the same way. The origin comes from `baseUrl`, or else from the `public_origin` in the config. Set `baseUrl` yourself when you pass no config, or when it should differ. It must be an `https:` origin with no path. Without a public origin, `url` must be the absolute URL exactly as the agent called it. The SDK needs the URL only for a request with a `Poppy-Session` header to check, for a DPoP proof and for a `domains` function. A request with only a Bearer access token, and no `domains` function, can pass a path and needs no public origin.

Behind a gateway that strips a path prefix, pass the path the agent called, because only the path of `url` is put on the public origin. With a public origin, `url` can also be only a path. If you use a `domains` function without a `config`, pass a full URL when it reads the host. For the Session's `aud` check it receives `url` exactly as you pass it. When it is called again for the access token, it receives the URL that `htu` is compared with: the public origin and the path. A function that returns an empty array refuses every Session JWT with `claim_mismatch`.

```ts
import type { Request } from 'express';
import { apiClient } from './auth0.js';

// The gateway serves https://api.example.com/api/orders and forwards /orders to this service,
// so `req.originalUrl` has lost the prefix the agent signed.
export function verifyBehindGateway(req: Request) {
  return apiClient.verifyPoppyRequest({
    method: req.method,
    url: `/api${req.originalUrl}`,
    headers: req.headers,
  });
}
```

### Verify a request

Call `verifyPoppyRequest` at the top of every route that depends on the agent, the Session or the account. Pass the method, the URL the agent called and the request headers. The SDK finds `Poppy-Session`, `Authorization` and `DPoP` in `headers` in any letter case. It returns the verified Session as `poppy` and the claims of the verified access token as `claims`, or it throws.

A request with no credentials is not an error: unless the call sets `requireSession`, the result is `{}`, so a route that needs a Session or an account must check `poppy` or `claims` itself. `headers` must be a plain object, such as `req.headers` of Node.js, or `Object.fromEntries(request.headers)` for a Fetch API `Request`. A `Headers` instance, a `Map`, an array or any other iterable would read as a request with no headers, so the SDK refuses it with an `InvalidConfigurationError`.

In Express, build the URL from `req.protocol`, `req.get('host')` and `req.originalUrl`, and pass `req.headers`. Behind a proxy the protocol and host describe the proxy, which is fine when a public origin is set, because then only the path counts. Express 5 sends the rejected promise of an async route to your error handler; with Express 4, call `next(error)` as below.

```ts
// express-route.ts
import express, { type Request } from 'express';
import { apiClient } from './auth0.js';

export const app = express();

// The URL the agent called. Only its path counts when a public origin is configured.
export const urlOf = (req: Request): string => `${req.protocol}://${req.get('host')}${req.originalUrl}`;

// Session state, such as a cart, is keyed by `poppy.key`.
const carts = new Map<string, string[]>();

// This route needs a Session: `requireSession: true` makes `poppy` always set.
app.get('/cart', async (req, res, next) => {
  try {
    const { poppy, claims } = await apiClient.verifyPoppyRequest({
      method: req.method,
      url: urlOf(req),
      headers: req.headers,
      requireSession: true,
    });

    res.json({
      items: carts.get(poppy.key) ?? [],
      signedIn: poppy.state === 'signed_in',
      account: claims?.sub ?? null,
    });
  } catch (error) {
    next(error);
  }
});

// This route works with or without a Session, so `poppy` can be undefined.
app.get('/products', async (req, res, next) => {
  try {
    const { poppy } = await apiClient.verifyPoppyRequest({
      method: req.method,
      url: urlOf(req),
      headers: req.headers,
    });

    res.json({ products: [], session: poppy?.key ?? null });
  } catch (error) {
    next(error);
  }
});
```

With the Fetch API (Workers, Hono and others), pass `request.url` and `Object.fromEntries(request.headers)`. A header that was sent twice arrives as one value joined with a comma. The SDK refuses that for `Poppy-Session` (`malformed_session`) and for `Authorization` (`invalid_request`), which is the safe reading.

```ts
// fetch-handler.ts
import type { ApiClient } from '@auth0/auth0-api-js';

// The client is a parameter, so a test can pass one that talks to a test agent.
export function createHandler(apiClient: ApiClient): (request: Request) => Promise<Response> {
  return async (request) => {
    const { poppy, claims } = await apiClient.verifyPoppyRequest({
      method: request.method,
      url: request.url,
      headers: Object.fromEntries(request.headers),
      requireSession: true,
    });

    return Response.json({
      session: poppy.key,
      signedIn: poppy.state === 'signed_in',
      account: claims?.sub ?? null,
    });
  };
}
```

What the result holds depends on what the request carried:

| The request carries | `poppy` | `claims` |
| --- | --- | --- |
| Nothing | absent (`requireSession` throws `missing_session`) | absent |
| A `Poppy-Session` header only | set, `state: 'signed_out'`, `source: 'header'` | absent |
| A header and an access token | set, `state: 'signed_in'`, `source: 'header'` | set |
| An access token with a Session in its `act` claim, and no header | set, `state: 'signed_in'`, `source: 'token'` | set |
| An access token without a Session, and no header | absent | set |

`claims` are the claims of the verified access token, set whenever the request carried one, with or without a Session. A member the request has none of is left out. With Session checks off, the header is ignored: a request with only a header has an empty result, and a request with a header and a token reads like one with only the token, the last two rows.

`requireSession` is a per-route choice. Pass the literal `true` for a route that needs a Session: a request without one throws `missing_session`, and TypeScript types `poppy` as always set. Leave it out for a route that works either way, and `poppy` is optional. Do not log the `Poppy-Session` header or the access token: both are credentials.

### Turn errors into responses

A failed check throws. `toHttpErrorResponse(error)` turns an error of this SDK into the response the specification asks for ([API errors](https://personalagentprotocol.org/docs/0.3/spec#apis)): the status, the headers and, for Session errors, a JSON body. For any other error it returns `undefined`. Rethrow that one and let your framework answer 500, because the SDK does not know what it is.

In Express, one error handler after your routes does it:

```ts
import type { ErrorRequestHandler } from 'express';
import { toHttpErrorResponse } from '@auth0/auth0-api-js';

// Register it after your routes: `app.use(poppyErrorHandler)`.
export const poppyErrorHandler: ErrorRequestHandler = (error, _req, res, next) => {
  const failure = toHttpErrorResponse(error);
  if (!failure) {
    next(error); // Not an error of this SDK: let Express answer 500.
    return;
  }

  res.status(failure.status).set(failure.headers);
  if (failure.body) {
    res.json(failure.body);
  } else {
    res.end();
  }
};
```

With the Fetch API, wrap the handler once. A header value can be a list, such as the two `www-authenticate` challenges, so append each entry. The Worker is then `export default { fetch: withErrorResponses(createHandler(apiClient)) }`.

```ts
// with-error-responses.ts
import { toHttpErrorResponse, type HttpErrorResponse } from '@auth0/auth0-api-js';

function toResponse({ status, headers, body }: HttpErrorResponse): Response {
  // A header value can be a list, such as the two `www-authenticate` challenges.
  const responseHeaders = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    for (const entry of Array.isArray(value) ? value : [value]) {
      responseHeaders.append(name, entry);
    }
  }
  if (body) {
    responseHeaders.set('content-type', 'application/json');
  }
  return new Response(body ? JSON.stringify(body) : null, { status, headers: responseHeaders });
}

export function withErrorResponses(
  handle: (request: Request) => Promise<Response>
): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      return await handle(request);
    } catch (error) {
      const failure = toHttpErrorResponse(error);
      if (!failure) {
        throw error; // Not an error of this SDK: let the platform answer 500.
      }
      return toResponse(failure);
    }
  };
}
```

| Error | Status | Headers | JSON body (`error`) |
| --- | --- | --- | --- |
| `InvalidSessionError`: a Session check failed, and `reason` says which (see [the reasons](#invalidsessionreason)) | 400 | none | `invalid_session` |
| `SessionEndedError`: the store, or your code, says the Session ended | 400 | none | `session_ended` |
| `PoppyUnavailableError`: an agent's host cannot be reached, answers 429 or 5xx, or is too slow | 503 (the SDK's choice, not in the specification) | `retry-after`: 30 seconds, or what is left of the 30 seconds a failed fetch is remembered | `temporarily_unavailable` |
| `SignInRequiredError`: you throw it for a route that needs the account (see [Routes that need the account](#routes-that-need-the-account)) | 401 | `www-authenticate`, naming the scopes needed | none |
| `VerifyAccessTokenError`, `InvalidDpopProofError` and `InvalidRequestError`: the access token, its DPoP proof or the `Authorization` header failed | 401 or 400 | `www-authenticate` | none |

Access token errors have no JSON body because the specification puts them in the `WWW-Authenticate` header. Every JSON body is `{ "error": "...", "error_description": "..." }`, and `error_description` is the message of the error. These messages never hold the content of a token or of a JWT. The specification says what the agent does with the two Session errors: after `invalid_session` it stops sending that request until it fixes the cause, and after `session_ended` it starts a new Session and sends the request again once. It defines no response for an agent host that cannot be reached. The SDK answers 503 with a `Retry-After` header for that case, which is the ordinary HTTP way to say that a request may be tried again later.

Any other error gives `undefined` and should be a 500. An `InvalidConfigurationError` is a mistake of your setup, for example a relative `url` when there is no public origin, and a failure of your store or of your `domains` function reaches you as it is. None of them is the agent's fault.

### Routes that need the account

A signed-out request is fine for browsing or a guest cart. A route that acts on the User's account needs an access token. When the request has none, answer 401 with a `WWW-Authenticate` challenge that names the scopes the route needs and carries no `error` code, and the agent signs the User in with those scopes and sends the request again ([API errors](https://personalagentprotocol.org/docs/0.3/spec#apis), [scopes](https://personalagentprotocol.org/docs/0.3/spec#scopes)). `SignInRequiredError` builds that answer: throw it, and `toHttpErrorResponse` does the rest.

When the token is there but lacks a scope, answer 403 `insufficient_scope`, with the scopes the route needs in the `scope` attribute. The SDK has no class for this one. Scope rules are yours, so check `claims.scope` the way you do on any other route. The specification's example is `Bearer error="insufficient_scope", scope="orders:read orders:write"`. The code below also sends the `realm` and the `DPoP` challenge that the SDK adds to its own challenges when `dpop.mode` is `allowed`, the default.

```ts
import { SignInRequiredError, type VerifiedAccessTokenClaims } from '@auth0/auth0-api-js';
import { apiClient } from './auth0.js';
import { app, urlOf } from './express-route.js';

function hasScope(claims: VerifiedAccessTokenClaims, scope: string): boolean {
  return typeof claims.scope === 'string' && claims.scope.split(' ').includes(scope);
}

app.post('/orders', async (req, res, next) => {
  try {
    const { poppy, claims } = await apiClient.verifyPoppyRequest({
      method: req.method,
      url: urlOf(req),
      headers: req.headers,
      requireSession: true,
    });

    // Signed out: 401, with a challenge that names the scopes the agent must ask the User for.
    if (!claims) {
      throw new SignInRequiredError({ scope: 'orders:write' });
    }

    // Signed in, but the token lacks the scope: 403 `insufficient_scope`.
    if (!hasScope(claims, 'orders:write')) {
      res
        .status(403)
        .set('www-authenticate', [
          'Bearer realm="api", error="insufficient_scope", scope="orders:write"',
          'DPoP error="insufficient_scope", scope="orders:write", algs="ES256"',
        ])
        .end();
      return;
    }

    res.status(201).json({ session: poppy.key, account: claims.sub });
  } catch (error) {
    next(error);
  }
});
```

`SignInRequiredError` takes `scope` as a string of scopes separated by spaces, or as a list. If your client sets `dpop: { mode: 'required' }` or `'disabled'`, pass the same value as `dpopMode`, and send only the matching challenge in the 403, so the answer names only the schemes you accept.

### Session records

State that belongs to a Session, such as a cart or a draft order, needs a stable name. That name is `poppy.key`, and it is unique for each agent and Session ID. Two agents can choose the same `sid`, so key your state by `poppy.key`, never by `sessionId` alone. The key is opaque: store it as text and read it back unchanged.

A second question is whether a Session is continuing. A `sid` your API has not seen starts a signed-out Session. A known `sid` must come with the same User ID and Agent ID as before, and a Session you ended must be refused ([verification](https://personalagentprotocol.org/docs/0.3/spec#session-verification), [ending Sessions](https://personalagentprotocol.org/docs/0.3/spec#ending-sessions)). Give the SDK a `sessionStore` and it runs these checks and saves new Sessions. Without one, it returns the verified Session and your code decides.

#### The `PoppySessionStore` contract

Extend `PoppySessionStore` on top of your own storage. The SDK has no built-in store, no TTL and no clean-up. The class has two methods:

- `get(key)` resolves to the record stored under `key`, or to `undefined` or `null` when the key is unknown.
- `set(key, record)` must insert only if absent. It never overwrites, and it resolves to the record that is stored afterwards. Two first requests of one Session can arrive together, and the second one must compare itself with the record of the first.

A record is `{ userId, poppyAgentId?, ended? }`, and any truthy `ended` ends the Session. For a Session from the header, the agent chooses `userId` and `poppyAgentId`, and the specification sets no format for them. The SDK limits them only by the 16,384 characters of the Session JWT, so each can be several KB: size the columns of your table for that. If `get` or `set` throws, the request fails, the SDK accepts no Session, and the error reaches your code as it is.

#### A store backed by a Map

This one is complete. A Map lives in one process, so with more than one server keep the records in a shared database.

```ts
// memory-store.ts
import { PoppySessionStore, type PoppySessionRecord } from '@auth0/auth0-api-js';

// Fine for one process. With more than one server, keep the records in a shared database.
export class MemoryPoppySessionStore extends PoppySessionStore {
  readonly #records = new Map<string, PoppySessionRecord>();

  async get(key: string): Promise<PoppySessionRecord | undefined> {
    return this.#records.get(key);
  }

  async set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
    // Insert only if absent, and answer with the record that is stored, which may not be `record`.
    const existing = this.#records.get(key);
    if (existing) {
      return existing;
    }
    this.#records.set(key, record);
    return record;
  }

  // Ends a Session: later requests with its `sid` are refused with `session_ended`.
  end(key: string): void {
    const record = this.#records.get(key);
    if (record) {
      record.ended = true;
    }
  }
}
```

To run it, use a test agent, which stands in for a Personal Agent (see [Test your routes](#test-your-routes-with-auth0auth0-api-jstesting)). It shows three outcomes: a Session that continues, another User on the same `sid`, and an ended Session.

```ts
import { ApiClient } from '@auth0/auth0-api-js';
import { createTestAgent } from '@auth0/auth0-api-js/testing';
import { MemoryPoppySessionStore } from './memory-store.js';

const agent = await createTestAgent();
const store = new MemoryPoppySessionStore();
const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: { verifySession: true, sessionStore: store, agentMetadata: { fetch: agent.fetch } },
});

async function send(sid: string, sub: string) {
  const sessionJwt = await agent.createSessionJwt({
    aud: 'https://your-tenant.auth0.com/',
    htm: 'GET',
    htu: 'https://api.example.com/cart',
    sid,
    sub,
  });
  return apiClient.verifyPoppyRequest({
    method: 'GET',
    url: 'https://api.example.com/cart',
    headers: { 'poppy-session': sessionJwt },
    requireSession: true,
  });
}

const { poppy } = await send('sid-1', 'usr_1');
console.log(await store.get(poppy.key)); // { userId: 'usr_1' }

await send('sid-1', 'usr_2').catch((error) => console.log(error.reason)); // session_mismatch

store.end(poppy.key);
await send('sid-1', 'usr_1').catch((error) => console.log(error.code)); // session_ended
```

It prints:

```text
{ userId: 'usr_1' }
session_mismatch
session_ended
```

#### A store backed by SQL

`set` is the part to get right: insert if absent, then read the row back, so that two first requests of one Session compare with the same record. Run `get` and the read-back on the primary database, or with another consistent read: a replica that lags can miss the row, and then `set` must throw, because a made-up record would let the SDK accept the Session without comparing it with the stored one. `query` stands for your database client, so no library is assumed. `ON CONFLICT ... DO NOTHING` is the PostgreSQL and SQLite form; use your database's own insert-if-absent statement.

```sql
CREATE TABLE poppy_sessions (
  key      TEXT PRIMARY KEY,
  user_id  TEXT NOT NULL,
  agent_id TEXT,
  ended    BOOLEAN NOT NULL DEFAULT FALSE
);
```

```ts
import { PoppySessionStore, type PoppySessionRecord } from '@auth0/auth0-api-js';

// Your database client: run `sql` with `params` and return the rows.
export type Query = <Row>(sql: string, params: unknown[]) => Promise<Row[]>;

interface SessionRow {
  user_id: string;
  agent_id: string | null;
  ended: boolean | number;
}

const SELECT = 'SELECT user_id, agent_id, ended FROM poppy_sessions WHERE key = $1';

function toRecord(row: SessionRow): PoppySessionRecord {
  return { userId: row.user_id, poppyAgentId: row.agent_id ?? undefined, ended: Boolean(row.ended) };
}

export class SqlPoppySessionStore extends PoppySessionStore {
  readonly #query: Query;

  constructor(query: Query) {
    super();
    this.#query = query;
  }

  async get(key: string): Promise<PoppySessionRecord | undefined> {
    const [row] = await this.#query<SessionRow>(SELECT, [key]);
    return row && toRecord(row);
  }

  async set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
    // Insert only if absent. Two first requests of a Session can arrive together.
    await this.#query(
      'INSERT INTO poppy_sessions (key, user_id, agent_id) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING',
      [key, record.userId, record.poppyAgentId ?? null]
    );
    // Read back what is stored: the first request's row wins, and both requests compare with it.
    const [row] = await this.#query<SessionRow>(SELECT, [key]);
    if (!row) {
      // Never answer with `record` here. The request fails, and the SDK accepts no Session.
      throw new Error('The Session record was not found after the insert.');
    }
    return toRecord(row);
  }

  async end(key: string): Promise<void> {
    await this.#query('UPDATE poppy_sessions SET ended = TRUE WHERE key = $1', [key]);
  }
}
```

#### Ending a Session

Set `ended` when a Session is over, for example when a checkout completes: `store.end(poppy.key)` in the stores above. Later requests with that `sid` get `session_ended`, and the agent starts a new Session with a new `sid` and sends the request again, once. The old Session's state, such as a cart, does not carry over ([ending Sessions](https://personalagentprotocol.org/docs/0.3/spec#ending-sessions)). If you delete the record instead, the SDK forgets the Session, and a request with that `sid` starts a new one.

#### The same checks without a store

If your Sessions already live in your own database, run the two checks yourself right after `verifyPoppyRequest`. They are the ones the store runs, in the same order and with the same errors.

```ts
import {
  InvalidSessionError,
  SessionEndedError,
  type PoppySession,
  type PoppySessionRecord,
} from '@auth0/auth0-api-js';

// Your own table of Sessions, keyed by `poppy.key`. With a database, make the insert atomic.
const sessions = new Map<string, PoppySessionRecord>();

// Call it right after `verifyPoppyRequest`, for a Session from the `Poppy-Session` header.
export function checkSession(poppy: PoppySession): void {
  const known = sessions.get(poppy.key);
  if (!known) {
    // A new `sid` starts a signed-out Session.
    sessions.set(poppy.key, { userId: poppy.userId, poppyAgentId: poppy.agent.poppyAgentId });
    return;
  }
  if (known.ended) {
    throw new SessionEndedError();
  }
  // A known `sid` continues its Session, and must come with the same User ID and Agent ID.
  if (known.userId !== poppy.userId || known.poppyAgentId !== poppy.agent.poppyAgentId) {
    throw new InvalidSessionError('session_mismatch');
  }
}
```

#### Moving a guest cart when the User signs in

A Session keeps its `key` when it turns from signed out to signed in, so a guest cart you saved under `poppy.key` is still there. When a signed-in request arrives, move the cart to the account, which is `claims.sub`.

```ts
import type { PoppySession, VerifiedAccessTokenClaims } from '@auth0/auth0-api-js';

const guestCarts = new Map<string, string[]>(); // keyed by `poppy.key`
const accountCarts = new Map<string, string[]>(); // keyed by `claims.sub`

// Call it after `verifyPoppyRequest`. The `key` of a Session does not change when the User signs in.
export function moveGuestCart(poppy: PoppySession, claims: VerifiedAccessTokenClaims | undefined): void {
  const account = claims?.sub;
  const guestCart = guestCarts.get(poppy.key);
  if (poppy.state !== 'signed_in' || !account || !guestCart) {
    return;
  }
  accountCarts.set(account, [...(accountCarts.get(account) ?? []), ...guestCart]);
  guestCarts.delete(poppy.key);
}
```

#### Refusing an account change

Over time, one Session can carry access tokens of different accounts. The specification lets your API refuse that with `session_ended`, and the agent then starts a new Session for the other account ([signing in](https://personalagentprotocol.org/docs/0.3/spec#sign-in)). The SDK does not track accounts. Keep the account the Session first used in your own table, and throw `SessionEndedError` when it changes.

```ts
import { SessionEndedError, type PoppySession, type VerifiedAccessTokenClaims } from '@auth0/auth0-api-js';

// The account each Session first used, in your own table, keyed by `poppy.key`.
const accountOfSession = new Map<string, string>();

// Call it after `verifyPoppyRequest`. The SDK does not track accounts.
export function refuseAccountChange(poppy: PoppySession, claims: VerifiedAccessTokenClaims | undefined): void {
  const account = claims?.sub;
  if (!account) {
    return; // Signed out: no account to compare.
  }
  const first = accountOfSession.get(poppy.key);
  if (first === undefined) {
    accountOfSession.set(poppy.key, account);
  } else if (first !== account) {
    // The agent starts a new Session and sends the request again, once.
    throw new SessionEndedError('This Session was used with another account. Start a new Session.');
  }
}
```

### Sessions in a web app's access token

A Session can also arrive inside an access token. When a User has joined an agent's Session in the browser ([web browsing](https://personalagentprotocol.org/docs/0.3/spec#web-browsing)), Auth0 can issue your web app an access token whose `act` claim carries that Session: `act.sub` is the URL of the agent, `act.poppy_sid` the Session ID, `act.poppy_user_id` the User ID and `act.poppy_agent_id` the Agent ID, which may be left out. These are Auth0's beta claims, and their names can change.

`verifyPoppyRequest` reads them from the verified token whenever the request has no `Poppy-Session` header to check, whether Session checks are on or not. The result has `poppy.source === 'token'` and `state: 'signed_in'`. A token whose `act` has no `poppy_sid` holds no Session, such as a plain [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) delegation. Once `poppy_sid` is there, the rest must be well formed, or the call throws `malformed_session`.

Two things to know:

- The `key` of a token Session matches the `key` of the header Session with the same Session ID only when `act.sub` is the agent's metadata URL, because the key is made from the agent URL and the Session ID. If `act.sub` holds something else, the key is different, and so is `poppy.agent.cimdUrl`.
- `agents` does not filter these Sessions. It checks the `iss` of a `Poppy-Session` header. If your web app needs the allow list for token Sessions too, check `poppy.agent.cimdUrl` yourself:

```ts
import { InvalidSessionError, type VerifiedPoppyRequest } from '@auth0/auth0-api-js';

// The agents you registered: the same list you pass as `agents`.
const REGISTERED_AGENTS = new Set(['https://agent.example/agent.json']);

// Call it with the result of `verifyPoppyRequest`.
export function checkSessionAgent({ poppy }: VerifiedPoppyRequest): void {
  // `agents` filters the `Poppy-Session` header, not a Session that comes from an access token.
  if (poppy?.source === 'token' && !REGISTERED_AGENTS.has(poppy.agent.cimdUrl)) {
    throw new InvalidSessionError('agent_not_allowed');
  }
}
```

### Registered agents

Your Company decides which agents it accepts ([agent identity](https://personalagentprotocol.org/docs/0.3/spec#agent-identity)). Give the SDK that list as `agents`, or as `agents` in `auth0-poppy.json`, which `config` supplies. Each agent is the URL of its client metadata, its `client_id`.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

export const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: {
    verifySession: true,
    // The client metadata URL (the `client_id`) of each agent you accept.
    agents: ['https://agent.example/agent.json', 'https://assistant.example/client.json'],
  },
});
```

Set a list in production. Without one, any public HTTPS URL in the `iss` of a Session JWT makes your API fetch that agent's metadata. The caches described below bound the cost, but it is still one outbound request for each new agent URL, to a host you did not choose. The SDK does not check the address that a public name resolves to, so such a name can point to an internal address (see [How agent metadata is fetched](#how-agent-metadata-is-fetched)). With a list:

- A `Poppy-Session` header whose `iss` is not listed is refused with `agent_not_allowed`, before anything is fetched.
- While Session checks are on (`verifySession`, or `requireSession` on the call), an access token issued to a listed agent is refused with `missing_session` when it arrives without the header, because a registered agent sends the header on every request. The agent of a token is the first of `agentClientIdClaims` (`client_id`, then `azp`) that is a string in its claims.
- Sessions that come from an access token are not filtered (see [Sessions in a web app's access token](#sessions-in-a-web-apps-access-token)).

Entries must be `https:` URLs in canonical form, with no username, password or fragment, because agent URLs are compared character by character. The constructor throws otherwise, and it refuses an entry whose host the address rule above refuses, such as `localhost` or a private address, unless `allowPrivateAddresses` is on. The SDK copies the list when you build the client. To change it, or to stop accepting an agent, build a new client.

### How agent metadata is fetched

The first Session JWT from an agent makes the SDK fetch two documents from the agent's own host: its client metadata, at the URL in `iss`, and the key set that the `jwks_uri` of the metadata names. The agent chooses those URLs, so the SDK treats the answers as untrusted ([agent identity](https://personalagentprotocol.org/docs/0.3/spec#agent-identity), and the address rules in [discovery](https://personalagentprotocol.org/docs/0.3/spec#discovery)). These rules apply to every agent. Only the address rule, in the second row, is switched off by `allowPrivateAddresses`:

| Rule | If it is broken, the request is refused as |
| --- | --- |
| The `iss` is an `https:` URL of at most 2,048 characters, in canonical form, without credentials or a fragment. | `malformed_session` |
| The host is not `localhost` or a name under `.localhost`, not a name that only a local network can resolve (a name with no dot, or a name under `.local`, `.internal`, `.localdomain` or `.home.arpa`), and not an IP literal in a loopback, private, link-local or other non-public range. | `agent_not_allowed` |
| Neither document redirects. | `agent_metadata_invalid` |
| Each answers 200 with a UTF-8 JSON object of at most 64 KB (`maxBytes`). | `agent_metadata_invalid` |
| The `client_id` of the metadata is the URL it was fetched from. | `agent_metadata_invalid` |
| The `jwks_uri` is an agent URL, by the same rules as the `iss`, on the same hostname as the `client_id`. The port and path may differ. | `agent_metadata_invalid` |
| The key set has 1 to 100 keys, all public. Each key member is a string, a boolean, a finite number or an array of strings, or the whole key set is refused. | `agent_metadata_invalid` |
| Each document arrives in time: 5 seconds (`timeoutMs`) for the request and the whole body. | `temporarily_unavailable` (503) |
| The host can be reached, and does not answer 429 or 5xx. | `temporarily_unavailable` (503) |

The SDK sends no cookies, credentials or `Authorization` header with these requests. Because most of this work happens once per agent, the results are cached:

| What | How long | Notes |
| --- | --- | --- |
| Good metadata and keys | 600 seconds, for up to 100 agents | `agentMetadata.cache`. A `ttl` or `maxEntries` of `0` keeps none. |
| A failed fetch | 30 seconds | Always on, whatever `cache` says, for up to 100 agents (or `maxEntries`, if that is more). A host that is down is not asked again at once, and the 503 counts down the `retry-after`. |
| A refetch for an unknown key ID | At most once every 30 seconds for each agent | Always on, with the same limit on agents. A failed refetch counts too. |
| A verified delegation | Until its own `exp`, or as long as good keys are kept (`agentMetadata.cache.ttl`, 600 seconds by default), whichever comes first; up to 1,000 delegations | It is checked again against the key set of the agent at least that often. The key set is kept for the same time, so a key that the agent removes stops its delegations within about twice that time ([the specification](https://personalagentprotocol.org/docs/0.3/spec#delegated-key-security)). To stop accepting an agent at once, remove it from `agents`. That check comes first. |

**A hostname can still point somewhere internal.** The address check reads text. It refuses `localhost`, local-only names and IP literals, but it cannot see where a hostname resolves, so a name that points to an internal address passes. For stronger protection, pass a hardened `agentMetadata.fetch`, or route the requests through an egress proxy. Check the address that your function connects to, and not only one that a lookup returned first: resolving the name yourself and then calling `fetch` is not enough, because `fetch` resolves it again.

The SDK calls your function as `fetch(url, { method: 'GET', redirect: 'manual', headers: { accept: 'application/json' }, signal })` and sends nothing else. It must not follow redirects, and it should stop when the `signal` aborts.

```ts
import { ApiClient } from '@auth0/auth0-api-js';
import { hardenedFetch } from './hardened-fetch.js';

export const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: {
    verifySession: true,
    agents: ['https://agent.example/agent.json'],
    // Used only for the requests to agent hosts. Your own module, `hardened-fetch.ts`.
    agentMetadata: { fetch: hardenedFetch },
  },
});
```

Without `agentMetadata.fetch`, the SDK uses the `customFetch` of the client, and then the global `fetch`. The `customFetch` also carries the client's requests to Auth0 (discovery, JWKS and token exchange), so pass an egress proxy there to send all of them through it. A `customFetch` that adds credentials or rewrites hosts sees the agent URLs as well: set `agentMetadata.fetch` to keep it out of the requests to agent hosts.

**A local agent in development.** The specification forbids connecting to loopback, private and link-local addresses unless you configured it on purpose ([discovery](https://personalagentprotocol.org/docs/0.3/spec#discovery)). Turn on `allowPrivateAddresses` to test an agent that runs on your machine, and never in production. It accepts `localhost`, private addresses and local-only names. The URL must still be `https:`.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

export const apiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  poppy: {
    verifySession: true,
    agents: ['https://localhost:8443/agent.json'],
    // Development only. It lets the SDK fetch agents on localhost and on private addresses.
    agentMetadata: { allowPrivateAddresses: true },
  },
});
```

**If you run an agent.** Publish a new key in your `jwks_uri` before you sign with it. When a delegation names a key the API does not have, the SDK refetches your key set, but only once every 30 seconds for each agent, because anyone can trigger that refetch with forged requests that name your agent. A key that you use before you publish it can therefore be refused for up to 30 seconds. Keep an old key published until every delegation signed with it has expired.

### Test your routes with `@auth0/auth0-api-js/testing`

`createTestAgent()` is a fake Personal Agent for tests. It makes its own keys, signs real Session JWTs, and serves its client metadata and key set through `agent.fetch`, with no network. Pass that function as `agentMetadata.fetch` and your routes verify its requests the way they verify a real agent's. A signed-out request never calls Auth0, so these tests need no Auth0 mocks.

Create the agent and the client together in each test: the client caches an agent's keys by its URL, and every agent makes new keys. The example tests the Fetch API handler from above, with a valid Session and with an expired delegation. Import the testing entry in tests only.

```ts
import { describe, expect, test } from 'vitest';
import { ApiClient } from '@auth0/auth0-api-js';
import { createTestAgent } from '@auth0/auth0-api-js/testing';
import { createHandler } from './fetch-handler.js';
import { withErrorResponses } from './with-error-responses.js';

const ISSUER = 'https://your-tenant.auth0.com/';
const CART_URL = 'https://api.example.com/cart';

// Make the agent and the client together: the client caches an agent's keys by its URL.
async function setup() {
  const agent = await createTestAgent();
  const apiClient = new ApiClient({
    domain: 'your-tenant.auth0.com',
    audience: 'https://api.example.com',
    poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
  });
  return { agent, handle: withErrorResponses(createHandler(apiClient)) };
}

describe('GET /cart, signed out', () => {
  test('accepts a valid Session', async () => {
    const { agent, handle } = await setup();
    const sessionJwt = await agent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL });

    const response = await handle(new Request(CART_URL, { headers: { 'poppy-session': sessionJwt } }));

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ signedIn: false, account: null });
  });

  test('refuses an expired delegation with invalid_session', async () => {
    const { agent, handle } = await setup();
    const sessionJwt = await agent.createSessionJwt({
      aud: ISSUER,
      htm: 'GET',
      htu: CART_URL,
      defect: 'expired_delegation',
    });

    const response = await handle(new Request(CART_URL, { headers: { 'poppy-session': sessionJwt } }));

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'invalid_session' });
  });
});
```

`createTestAgent` takes `cimdUrl` (default `https://agent.example/agent.json`), `delegationAlg` (`'ES256'`, the default, or `'PS384'`) and `delegationLifetimeSeconds` (1 to 86400, default 3600). `agent.createSessionJwt` takes the `aud`, `htm` and `htu` of the request, and optionally `sid`, `sub`, `agentId`, `iat`, `jti`, `claims` and `header`. The last two set any claim or header member, and `undefined` removes it. Pass the `accessToken` of the request to put its `ath` in the JWT. For a signed-in test, the token still goes through `verifyAccessToken`, so mock the discovery and JWKS requests of your Auth0 domain, or pass a `customFetch`, as you do for your other token tests.

A `defect` makes one thing wrong in an otherwise valid JWT, so a negative test can check the response of that check:

| `defect` | What is wrong | Refused as |
| --- | --- | --- |
| `missing_delegation` | There is no `poppy_dlg` | `malformed_session` |
| `signed_with_agent_key` | Signed with the agent's own key, with no delegation | `malformed_session` |
| `session_wrong_typ` | The `typ` of the Session JWT is `JWT` | `malformed_session` |
| `expired_delegation` | The delegation expired an hour ago | `delegation_invalid` |
| `delegation_too_long` | The delegation's `exp` is 24 hours and 1 second after its `iat` | `delegation_invalid` |
| `delegation_from_future` | The delegation was issued an hour from now | `delegation_invalid` |
| `delegation_iss_mismatch` | The delegation's `iss` is another agent | `delegation_invalid` |
| `delegation_wrong_typ` | The delegation's `typ` is `JWT` | `delegation_invalid` |
| `delegation_unknown_kid` | The delegation's `kid` is not in the agent's key set | `delegation_invalid` |
| `delegation_private_cnf` | The delegated key in `cnf.jwk` has the private member `d` | `delegation_invalid` |
| `session_wrong_kid` | The `kid` is not the thumbprint of the delegated key | `signature_invalid` |
| `session_bad_signature` | Signed with a key that is not the delegated key | `signature_invalid` |

### Reference

#### `PoppyOptions`

The SDK reads the `poppy` option once, when you build the client, and an invalid value throws an `InvalidConfigurationError` there.

| Field | Default | What it does |
| --- | --- | --- |
| `config` | none | The parsed `auth0-poppy.json`. It supplies the `issuer` (the `aud` of Session JWTs), the `public_origin` of your API and the `agents`, and the SDK checks it against the client. |
| `verifySession` | `false` | Verifies the `Poppy-Session` header of every request that carries one. When `false`, the header is ignored unless the call sets `requireSession`. |
| `agents` | `config.agents`; with neither, no list | The agents you accept, by client metadata URL. See [Registered agents](#registered-agents). |
| `sessionStore` | none | A `PoppySessionStore`. With one, the SDK checks known Sessions and saves new ones. |
| `agentClientIdClaims` | `['client_id', 'azp']` | The claims of the access token that name the agent it was issued to. The first one that is a string is used. With a Session header, it must equal the `iss`. |
| `iatWindow` | `60` | How far the `iat` of a Session JWT may be from now, in seconds, in both directions. The edges are accepted. |
| `baseUrl` | The `public_origin` of the `config.apis` entry for your `audience`; otherwise none | The public origin of your API, such as `https://api.example.com`. See [Configure the client](#configure-the-client). |
| `agentMetadata.fetch` | The `customFetch` of the client, then the global `fetch` | The `fetch` for requests to agent hosts. |
| `agentMetadata.cache` | `{ ttl: 600, maxEntries: 100 }` | How long (in seconds) and for how many agents good metadata and keys are kept. |
| `agentMetadata.timeoutMs` | `5000` | The time limit for each document, for the request and the whole body: a whole number from 1 to 2147483647. |
| `agentMetadata.maxBytes` | `65536` | The size limit for each response body, in bytes. |
| `agentMetadata.allowPrivateAddresses` | `false` | Accepts agent URLs on `localhost`, on private addresses and on local-only names (a name with no dot, or under `.local`, `.internal`, `.localdomain` or `.home.arpa`). For development only. |

#### `PoppySession`

`poppy` in the result of `verifyPoppyRequest`.

| Field | What it holds |
| --- | --- |
| `sessionId` | The Session ID: `sid` of the Session JWT, or `act.poppy_sid` of the access token. The agent chooses it, so two agents can pick the same one. |
| `key` | An opaque key, unique for each agent and Session ID. Key your Session state by it. |
| `userId` | The pairwise User ID for your Company: `sub` of the Session JWT, or `act.poppy_user_id`. It is not the account. The account is `claims.sub`. |
| `agent.cimdUrl` | The URL of the agent's client metadata document, which is its `client_id`: `iss` of the Session JWT, or `act.sub`. |
| `agent.poppyAgentId` | The Agent ID, when the agent sent one: `agent_id` of the Session JWT, or `act.poppy_agent_id`. |
| `state` | `'signed_in'` when an access token was verified with the Session, and `'signed_out'` when the request had none. A Session from an access token is always `'signed_in'`. |
| `source` | `'header'` for the `Poppy-Session` header, and `'token'` for the `act` claim of an access token. |

#### `InvalidSessionReason`

Every reason is an `InvalidSessionError`: status 400, `invalid_session`. `error.reason` is a stable value for logs and tests. When the error has one, `error.cause?.code` names the exact check that failed, for example `client_id_mismatch` or `jwks_uri_invalid` for `agent_metadata_invalid`. Use it in your logs, and never send it to the agent. Its values can change during the beta. The agent stops sending the request until it fixes the cause, and a new Session does not help.

| Reason | When it happens | What the agent does |
| --- | --- | --- |
| `missing_session` | The call sets `requireSession` and the request has no Session. Or, while Session checks are on, an access token of a registered agent arrives without the header. | Sends the `Poppy-Session` header with every request. |
| `malformed_session` | The header is not one well-formed Session JWT: it was sent twice or joined with a comma, it is not in compact form or is over 16,384 characters, `typ` or `alg` is wrong, a header member or claim is missing or has the wrong type, `sid` is not 1 to 256 letters, digits, `-` or `_`, or `iss` is not an `https:` URL in canonical form. Also, the `act` claim of an access token holds a Session that is not well formed. | Fixes the JWT. |
| `agent_not_allowed` | The `iss` is not in `agents`, or its host is `localhost`, a private address or a local-only name while `allowPrivateAddresses` is off. | Nothing. Your Company has not registered it. |
| `agent_metadata_invalid` | The agent's metadata or key set cannot be used. See [How agent metadata is fetched](#how-agent-metadata-is-fetched). | Fixes its documents. The SDK remembers the failure for 30 seconds. |
| `delegation_invalid` | The delegation failed: it is not a JWT, `typ` or `alg` is wrong, the agent's key set has no usable key with its `kid` (the `kid` is missing, or the key with it has an `alg`, `use` or `key_ops` that does not fit; the SDK refetches the key set once every 30 seconds at most), the signature is wrong, it has expired, it was issued in the future, it lasts more than 24 hours, its `iss` is not the Session's `iss`, or its `cnf.jwk` is not a public P-256 key. | Sends a fresh delegation, signed with a published key. |
| `signature_invalid` | The `kid` of the Session JWT is not the thumbprint of the delegated key, or the JWT is not signed with that key. | Signs with the key its delegation vouches for. |
| `claim_mismatch` | `aud` is not your Auth0 issuer, `htm` is not the method, or `htu` is not the URL of the request. If every agent gets this, check the `url` you pass and `baseUrl`. | Signs a new JWT with the right claims. |
| `iat_out_of_window` | `iat` is further than `iatWindow` (60 seconds) from now, in either direction. | Signs a new JWT with the current time, and fixes its clock if it is off. |
| `ath_mismatch` | `ath` is not the hash of the access token, or it is there and the request has no token. | Computes `ath` from the token it sends, and leaves it out without a token. |
| `token_client_mismatch` | The access token was not issued to the agent in `iss`, or it names no client in any of the `agentClientIdClaims`. | Uses a token that was issued to itself. |
| `session_mismatch` | A known Session comes back with another User ID or Agent ID (needs a `sessionStore`, or your own check). | Fixes its bug: one `sid` must always come with the same User ID and Agent ID. |
