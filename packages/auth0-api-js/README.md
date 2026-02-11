The `@auth0/auth0-api-js` library allows for securing API's running on a JavaScript runtime.

Using this SDK as-is in your API may not be trivial, as it is not a plug-and-play library for your framework. Instead, it is designed to be used as a building block for building framework-specific SDKs.

![Release](https://img.shields.io/npm/v/@auth0/auth0-api-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-api-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/auth0-api-js
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Create the Auth0 SDK client

Create an instance of the `ApiClient`. This instance will be imported and used anywhere we need access to the methods.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```

The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application.
The `AUTH0_AUDIENCE` is the identifier of the API. You can find this in the API section of the Auth0 dashboard.

#### Environment Variable Support

The SDK supports automatic fallback to environment variables if configuration options are not provided:

```ts
// If AUTH0_DOMAIN and AUTH0_AUDIENCE are set in your environment
const apiClient = new ApiClient();

// Or mix and match
const apiClient = new ApiClient({
  domain: 'custom-domain.auth0.com', // Override env var
  // audience will fall back to AUTH0_AUDIENCE
  // clientId and clientSecret (if needed) will fall back to AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET
});
```

Supported environment variables:
- `AUTH0_DOMAIN` - Your Auth0 tenant domain
- `AUTH0_AUDIENCE` - Your API's audience/identifier
- `AUTH0_CLIENT_ID` - Your application's client ID (optional, required for certain methods)
- `AUTH0_CLIENT_SECRET` - Your application's client secret (optional, required for certain methods)
- `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` - Your application's client assertion signing key (optional - required for certain methods)

### 3. Verify the Access Token

The SDK's `verifyAccessToken` method can be used to verify the access token.

```ts
const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerifiedToken = await apiClient.verifyAccessToken({
  accessToken,
});
```

The SDK automatically validates claims like `iss`, `aud`, `exp`, and `nbf`. You can also pass additional claims to be required by configuring `requiredClaims`:

```ts
const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerifiedToken = await apiClient.verifyAccessToken({
  accessToken,
  requiredClaims: ['my_custom_claim'],
});
```

### 4. Verify DPoP Access Tokens
The `verifyAccessToken` method also supports validating DPoP-bound access tokens.  

When using `DPoP`, you must also supply `scheme`, `dpopProof`, `httpMethod`, and `httpUrl` from the incoming HTTP request so the SDK can validate the proof and ensure the token is bound to that request.

```ts
const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  dpop: {
    mode: 'required', // optional, defaults to 'allowed'
    iatOffset: 400, // optional, defaults to 300 seconds
    iatLeeway: 30, // optional, defaults to 30 seconds
  },
});

const accessToken = '...';
const decodedAndVerifiedToken = await apiClient.verifyAccessToken({
  accessToken,
  requiredClaims: ['my_custom_claim'],
  // Options required for DPoP bound token verification
  scheme: '<AUTHENTICATION_SCHEME>',
  dpopProof: '<DPOP_PROOF_JWT>',
  httpMethod: '<HTTP_METHOD>',
  httpUrl: '<HTTP_REQUEST_URL>'
});
```

See the [DPoP Authentication](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-api-js/EXAMPLES.md#dpop-authentication) in [EXAMPLES.md](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-api-js/EXAMPLES.md) for more examples and details.

### 5. Protected Resource Metadata (RFC 9728)

The SDK supports OAuth 2.0 Protected Resource Metadata as defined in [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728):

```ts
import {
  ProtectedResourceMetadataBuilder,
  BearerMethod,
  SigningAlgorithm,
} from '@auth0/auth0-api-js';

const resourceServerUrl = 'https://api.example.com';
const authServers = ['https://your-tenant.us.auth0.com'];

const metadata = new ProtectedResourceMetadataBuilder(resourceServerUrl, authServers)
  .withBearerMethodsSupported([BearerMethod.HEADER])
  .withResourceSigningAlgValuesSupported(
    SigningAlgorithm.RS256,
    SigningAlgorithm.ES256,
  )
  .withScopesSupported(['read', 'write', 'admin'])
  .build();

// Serve metadata from the standard RFC 9728 endpoint
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  res.json(metadata.toJSON());
});
```

### 6. Token Exchange

The SDK supports RFC 8693 OAuth 2.0 Token Exchange, allowing you to exchange tokens for different API audiences while preserving user identity.

#### When to Use Which Flow

- **Custom Token Exchange**: Use when you control the subject token format. Common scenarios:
  - Exchanging MCP server tokens for Auth0 tokens
  - Migrating from legacy authentication systems
  - Federating with partner systems using custom token formats
  - Exchanging tokens issued by your own services

- **Access Token Exchange with Token Vault** (via `getAccessTokenForConnection`): Use when exchanging for external provider's access tokens:
  - Accessing Google APIs with a user's Google token
  - Calling Facebook Graph API with a user's Facebook token
  - Any scenario where Auth0 manages the external provider's refresh tokens in the Token Vault

#### Custom Token Exchange Example

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Exchange a custom token (e.g., from an MCP server or legacy system)
const result = await apiClient.getTokenByExchangeProfile(
  userToken, // The token to exchange
  {
    subjectTokenType: 'urn:example:custom-token', // Your custom token type URN
    audience: 'https://api.backend.com',
  }
);

// Handle token expiry - check expiresAt and re-exchange when needed
// Note: expiresAt is in seconds, Date.now() is in milliseconds
const tokenIsValid = Math.floor(Date.now() / 1000) < result.expiresAt;
if (!tokenIsValid) {
  // Re-exchange with a fresh subject token (e.g., from your auth provider)
  const newSubjectToken = await getNewTokenFromYourProvider();
  const refreshed = await apiClient.getTokenByExchangeProfile(newSubjectToken, {
    subjectTokenType: 'urn:example:custom-token',
    audience: 'https://api.backend.com',
  });
}
```

> **Security Note**: The `extra` parameter (if exposed in your application) should never contain Personally Identifiable Information (PII) or sensitive data. Extra parameters may be logged by Auth0 or included in audit trails. Only use it for non-sensitive technical parameters that don't identify users.

Learn more: [Custom Token Exchange](https://auth0.com/docs/authenticate/custom-token-exchange) | [Token Vault](https://auth0.com/docs/secure/tokens/token-vault/access-token-exchange-with-token-vault)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/auth0-auth-js/blob/main/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-auth-js/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-api-js/LICENSE"> LICENSE</a> file for more info.
</p>
