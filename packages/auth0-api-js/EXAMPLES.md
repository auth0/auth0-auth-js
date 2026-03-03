# Examples

- [Get an access token for a connection](#get-an-access-token-for-a-connection)
- [Multiple Custom Domains (MCD) token verification](#multiple-custom-domains-mcd-token-verification)
- [DPoP Authentication](#dpop-authentication)
  - [Access token verifier options](#access-token-verifier-options)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
  - [Customize DPoP validation behavior](#customize-dpop-validation-behavior)
    - [DPoP Behavior Matrix](#dpop-behavior-matrix)
    - [Proof Timing Options](#proof-timing-options)

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

## Multiple Custom Domains (MCD) token verification

Use `domains` to support multiple custom domains, such as during migration or when MCD is enabled. When `domains` is specified, the SDK uses these domains for discovery and token verification, and does not rely on `domain`.
Provide `domains` as shown in the Auth0 Dashboard (for example, `brand.your-custom-domain.com`). Domains must not include path, query, or fragment components.

Before any metadata or JWKS request is made, the token’s `iss` claim must exactly match one of the normalized domains to prevent SSRF. Tokens using unsupported or symmetric algorithms (HS*) are rejected before any network call.


### Static domains
```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  audience: 'https://api.example.com',
  domains: [
    'your-tenant.auth0.com',
    'custom.example.com',
  ],
});

const payload = await apiClient.verifyAccessToken({ accessToken });
```

### Dynamic resolver
```ts
import { ApiClient, type DomainsResolver, type DomainsResolverContext } from '@auth0/auth0-api-js';

const domainsResolver: DomainsResolver = async ({ url, headers }: DomainsResolverContext) => {
  const host =
    headers?.['x-forwarded-host'] ??
    headers?.['host'] ??
    (url ? new URL(url).host : undefined);

  if (host === 'api.brand-1.com') {
    return ['brand-1.custom-domain.com'];
  } else if (host === 'api.brand-2.com') {
    return ['brand-2.custom-domain.com'];
  }

  // Fallback to default domain(s) if the host doesn't match any known patterns.
  return ['your-tenant.auth0.com'];
};

const apiClient = new ApiClient({
  audience: 'https://api.example.com',
  domains: domainsResolver,
  algorithms: ['RS256'], // optional, defaults to RS256
});

const payload = await apiClient.verifyAccessToken({
  accessToken,
  url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
  headers: req.headers,
});
```

> ⚠️ **Security Note**
>
> In many frameworks, request URLs are constructed from the `Host` or
> `X-Forwarded-Host` headers, which can be attacker-controlled if not properly
> validated. Always derive domains from trusted, validated host sources (for
> example, proxy allowlists or framework-provided trusted host configuration).
> The SDK does **not** validate host headers on your behalf.

## Discovery Cache
`discoveryCache` controls how long OIDC discovery metadata and JWKS entries are cached for `verifyAccessToken`, across both single-domain and MCD flows. Cache entries are evicted using LRU once `maxEntries` is reached.

- `ttl`: cache TTL in seconds (non-negative). Defaults to `600`.
- `maxEntries`: maximum entries per cache (non-negative). Defaults to `100`.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const cachedApiClient = new ApiClient({
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
  discoveryCache: { ttl: 600, maxEntries: 100 },
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
