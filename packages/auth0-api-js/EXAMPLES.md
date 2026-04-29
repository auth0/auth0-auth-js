# Examples

- [Get a token on behalf of a user](#get-a-token-on-behalf-of-a-user)
- [Get an access token for a connection](#get-an-access-token-for-a-connection)
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

Use `getTokenOnBehalfOf()` when your API receives an Auth0 access token for itself and needs to
exchange it for another Auth0 access token targeting a downstream API, while preserving the same
user identity. This is especially useful for MCP servers and other intermediary APIs that need to
call downstream APIs on behalf of the user.

The flow has three steps:

1. **Verify** the incoming access token so your API rejects invalid or mis-targeted tokens before exchanging.
2. **Exchange** the verified token for a new access token scoped to the downstream API.
3. **Call** the downstream API using the exchanged token.

`getTokenOnBehalfOf()` requires a confidential client. The `ApiClient` must be initialized with
`clientId` and at least one of `clientSecret`, a private key, or mTLS credentials. Calling it
without client credentials throws `MissingClientAuthError`.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

// OBO requires a confidential client (clientId + clientSecret, private key JWT, or mTLS).
const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// `incomingAccessToken` is the raw JWT from the request's Authorization header,
// without the `Bearer ` prefix.
async function callCalendarOnBehalfOfUser(incomingAccessToken: string) {
  // Step 1: Verify the incoming token is valid and intended for this API.
  const claims = await apiClient.verifyAccessToken({
    accessToken: incomingAccessToken,
  });

  // Step 2: Exchange it for a token scoped to the downstream API.
  const obo = await apiClient.getTokenOnBehalfOf(incomingAccessToken, {
    audience: 'https://calendar-api.example.com',
    scope: 'calendar:read calendar:write',
  });

  // Step 3: Call the downstream API with the exchanged token.
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

The exchanged token preserves the user's identity in the `sub` claim and adds an `act` claim that
identifies your API as the actor that performed the exchange:

```json
{
  "sub": "auth0|user123",
  "aud": "https://calendar-api.example.com",
  "azp": "<AUTH0_CLIENT_ID>",
  "act": {
    "sub": "<AUTH0_CLIENT_ID>"
  }
}
```

The parameters for the `getTokenOnBehalfOf` method are as follows:

- `accessToken`: The incoming Auth0 access token used as the `subject_token`.
- `audience`: The identifier of the downstream API.
- `scope` (optional): The requested scopes for the downstream API.

If the exchange is successful, the method returns an `OnBehalfOfTokenResult` object containing:

- `accessToken`: The exchanged access token issued for the downstream API.
- `expiresAt`: The access token expiration time, represented in seconds since the Unix epoch.
- `scope`: The scope granted for the exchanged token, if returned.
- `tokenType`: The returned token type, if returned.
- `issuedTokenType`: The returned RFC 8693 issued token type, if returned.

> [!TIP]
> **Production notes:**
> - Pass the raw access token to `getTokenOnBehalfOf()`. Do not pass the full `Authorization` header or include the `Bearer ` prefix.
> - Verify the incoming token for your API before exchanging it so your application rejects invalid or mis-targeted tokens early.
> - The downstream `audience` must match an API identifier configured in your Auth0 tenant, and your client must be authorized to access it.
> - `getTokenOnBehalfOf()` only returns access-token-oriented fields. It does not expose `idToken` or `refreshToken`.

> [!NOTE]
> **DPoP:** `getTokenOnBehalfOf()` forwards the incoming access token as the
> [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) `subject_token`
> and relies on Auth0 to handle any DPoP-specific behavior for that token.

### Verifying an exchanged token on the downstream API

When the downstream API receives an exchanged token, it should verify the token, confirm that the
current actor is an expected caller, and optionally record the full delegation chain for audit logging.

Use `getCurrentActor()` to read the outermost `act.sub`. This is the client that performed the most
recent token exchange and is the only value that should be used for authorization decisions, per
[RFC 8693 §4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1).

Use `getDelegationChain()` to read the full chain of actors from newest to oldest. This is useful
for logging and audit, but must not be used for access control.

```ts
import { ApiClient, getCurrentActor, getDelegationChain } from '@auth0/auth0-api-js';

// On the downstream API, configure ApiClient with that API's own audience.
const calendarApiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: 'https://calendar-api.example.com',
});

const ALLOWED_ACTORS = ['<MCP_SERVER_CLIENT_ID>'];

async function handleCalendarApiRequest(accessToken: string) {
  const claims = await calendarApiClient.verifyAccessToken({ accessToken });

  // Use only the top-level act.sub for authorization decisions (RFC 8693 §4.1).
  const currentActor = getCurrentActor(claims);
  if (!currentActor || !ALLOWED_ACTORS.includes(currentActor)) {
    throw new Error('Actor not authorized');
  }

  // Use the full delegation chain for logging or audit only — never for authorization.
  auditLogger.info('delegated_request', {
    user: claims.sub,
    currentActor,
    delegationChain: getDelegationChain(claims),
  });
}
```

> [!IMPORTANT]
> Only the outermost `act.sub`, returned by `getCurrentActor()`, should be used for authorization
> decisions. Nested `act` values represent prior actors in the delegation chain and are informational
> only, per [RFC 8693 §4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1).

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
