# Configuration

[← All examples](../EXAMPLES.md)

- [Configuration](#configuration)
    - [Configuring the Scopes](#configuring-the-scopes)
    - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
    - [Configuring mTLS (Mutual TLS)](#configuring-mtls-mutual-tls)
    - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
    - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
    - [Configuring discovery cache](#configuring-discovery-cache)

## Configuration

### Configuring the Scopes

By default, the SDK will request an Access Token using `'openid profile email offline_access'` as the scope. This can be changed by configuring `authorizationParams.scope`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const auth0 = new AuthClient({
  authorizationParams: {
    scope: 'scope_a openid profile email offline_access'
  }
});
```

In order to ensure the SDK can refresh tokens when expired, the `offline_access` scope should be included. It is also mandatory to include `openid` as part of `authorizationParams.scope`.


### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of `AuthClient`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
....................REMOVED FOR BREVITY.........................
-----END PRIVATE KEY-----`;
const clientAssertionSigningKey = await importPKCS8(clientPrivateKey, 'RS256');
const auth0 = new AuthClient({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

Note that the private keys should not be committed to source control, and should be stored securely.

### Configuring mTLS (Mutual TLS)

The SDK supports mTLS (Mutual TLS) authentication, which provides stronger security by using client certificates for authentication. When using mTLS, you don't need to provide a client secret or private key JWT since the client certificate serves as the authentication mechanism.

To use mTLS, set `useMtls: true` and provide a `customFetch` implementation that includes your client certificate:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';
import { Agent } from 'undici';

const auth0 = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  useMtls: true,
  customFetch: (url, options) => {
    return fetch(url, {
      ...options,
      dispatcher: new Agent({
        connect: {
          key: '...',
          cert: '...',
          ca: '...',
        },
      }),
    });
  },
});

// Example: Get a token using client credentials with mTLS
const tokenResponse = await auth0.getTokenByClientCredentials({
  audience: 'https://your-api.example.com',
});
```

**Key points for mTLS configuration:**

- **Client Certificate**: Your application must have a valid client certificate issued by a Certificate Authority (CA) that Auth0 trusts.
- **Domain Configuration**: Your Auth0 tenant must be configured to support mTLS endpoints.
- **No Additional Auth**: When `useMtls: true`, you don't need `clientSecret` or `clientAssertionSigningKey`. The one exception is `passkey.register()` / `passkey.challenge()`, which are not served on the mTLS endpoint aliases and accept only a `clientSecret`. See [Using Passkeys](./passkeys.md).
- **Custom Fetch Required**: You must provide a `customFetch` implementation that includes the client certificate in the TLS handshake.

> [!IMPORTANT]  
> mTLS requires proper certificate management and Auth0 tenant configuration. Make sure your Auth0 tenant supports mTLS endpoints and that your client certificates are properly configured in the Auth0 Dashboard. Learn how to configure mTLS in your Auth0 tenant by reading the [mTLS configuration documentation](https://auth0.com/docs/get-started/applications/configure-mtls).

### Configuring the `authorizationParams` globally

The `authorizationParams` object can be used to customize the authorization parameters that will be passed to the `/authorize` endpoint. This object can be passed when creating an instance of `AuthClient`, but it can also be specified when calling certain methods of the SDK, for example `buildAuthorizationUrl`. For each of these, the same rule applies in the sense that both `authorizationParams` objects will be merged, where those provided to the method, override those provided when creating the instance.

```ts
const auth0 = new AuthClient({
  authorizationParams: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const auth0 = new AuthClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when creating an instance of `AuthClient`:

```ts
const auth0 = new AuthClient({
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

### Configuring discovery cache

The SDK caches Auth0 OIDC discovery metadata in memory to avoid calling
`/.well-known/openid-configuration` on every flow.

Defaults:
- `ttl`: `600` seconds
- `maxEntries`: `100`

How it is used:
- Discovery metadata and JWKS are reused from in-memory cache across requests.
- `ttl` controls how long cached values are kept.
- `maxEntries` controls how many discovery entries are retained.

When to configure `discoveryCache`:
- [Multiple Custom Domains](https://auth0.com/docs/customize/custom-domains/multiple-custom-domains).
- High-throughput services where you want fewer metadata fetches.
- Memory-constrained environments where you want a smaller cache.

Most applications can keep the defaults. If you need different cache behavior, configure `discoveryCache`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const auth0 = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  discoveryCache: {
    ttl: 900,
    maxEntries: 200,
  },
});
```
To effectively disable discovery cache reuse, set `discoveryCache.ttl` to `0`.
