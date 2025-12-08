# Examples

- [Get an access token for a connection](#get-an-access-token-for-a-connection)
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
| `disabled` | Only `Bearer` tokens are accepted. Rejects any non-`Bearer` scheme tokens (including `DPoP`). Accepts `DPoP`-bound tokens over `Bearer` (ignoring `cnf`) and ignores any `DPoP` proof headers if present. |
| `required` | Invalid configuration. `DPoP` is ignored, so `required: true` has no effect. `DPoP` is ignored entirely. |


#### Proof Timing Options

When `DPoP` is enabled, you can control the accepted timing of DPoP proofs using the following options:

  - `iatOffset`: The maximum age (in seconds) of a DPoP proof. Proofs with `iat` older than this offset (relative to now) will be rejected.
    Default: `300 seconds`(5 minutes)

  - `iatLeeway`: Clock skew tolerance (in seconds) when comparing a proof's `iat` with the current server time.
    Default: `30 seconds`