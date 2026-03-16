The `@auth0/auth0-auth-js` library provides API's to interact with Auth0's Authentication Api's from withing JavaScript applications.

It contains methods to build Authorization URLs and Logout URLs, implement Backchannel Logout, verifying a logout token, to request Tokens using the Authorization Code Flow and Refresh Tokens, as well as retrieving a Token for a Connection, and managing Multi-Factor Authentication (MFA).


![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/auth0-auth-js
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Create the Auth0 SDK client

Create an instance of the `AuthClient`. This instance will be imported and used anywhere we need access to the authentication methods.


```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. 

### 3. Build the Authorization URL

Build the URL to redirect the user-agent to to request authorization at Auth0.

```ts
const authClient = new AuthClient({
  // ...
  authorizationParams: {
    redirect_uri: '<AUTH0_REDIRECT_URI>',
  },
  // ...
});

The `AUTH0_REDIRECT_URI` is needed to tell Auth0 what URL to redirect back to after successfull authentication, e.g. `http://localhost:3000/auth/callback`.
```

> [!IMPORTANT]  
> You will need to register the `AUTH0_REDIRECT_URI` in your Auth0 Application as an **Allowed Callback URL** via the [Auth0 Dashboard](https://manage.auth0.com).

In order to build the authorization URL, call `buildAuthorizationUrl()`, and redirect the user to the returned URL.

```ts
const { authorizationUrl, codeVerifier } = await authClient.buildAuthorizationUrl();
```

- `authorizationUrl`: The URL to redirect the user to.
- `codeVerifier`: The code verifier that should be stored and used when exchanging the code for tokens.

### 4. Build the Logout URL

Build the URL to redirect the user-agent to to request logout at Auth0.

```ts
const logoutUrl = authClient.buildLogoutUrl({
  returnTo: '<AUTH0_LOGOUT_RETURN_URL>',
});
```

> [!IMPORTANT]  
> You will need to register the `AUTH0_LOGOUT_RETURN_URL` in your Auth0 Application as an **Allowed Logout URL** via the [Auth0 Dashboard](https://manage.auth0.com).

The `AUTH0_LOGOUT_RETURN_URL` is needed to tell Auth0 what URL to redirect back to after successfully logging out, e.g. `http://localhost:3000`.

### 5. Token Exchange

The SDK supports RFC 8693 OAuth 2.0 Token Exchange for first-party on-behalf-of flows, enabling secure token exchanges while preserving user identity.

#### When to Use Which Flow

- **Custom Token Exchange**: Use when you control the subject token format. Common scenarios:
  - Exchanging MCP server tokens for Auth0 tokens
  - Migrating from legacy authentication systems
  - Federating with partner systems using custom token formats
  - Exchanging tokens issued by your own services

- **Access Token Exchange with Token Vault** (via `exchangeToken`): Use when exchanging for external provider's access tokens:
  - Accessing Google APIs with a user's Google token
  - Calling Facebook Graph API with a user's Facebook token
  - Any scenario where Auth0 manages the external provider's refresh tokens in the Token Vault

> **Deprecated:** `getTokenForConnection()` is deprecated. Use `exchangeToken({ connection, subjectToken, subjectTokenType, ... })` instead.

#### Custom Token Exchange Example

> **Note**: In this SDK, Custom Token Exchange currently requires a confidential client. Supported client authentication methods: `client_secret_post`, `private_key_jwt`, and `mTLS` (via `customFetch`). Public clients are not yet supported by this method.

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Exchange a custom token (e.g., from an MCP server or legacy system)
// The subjectTokenType identifies your token format (configured in your Token Exchange Profile)
const response = await authClient.exchangeToken({
  subjectTokenType: 'urn:example:custom-token', // Your custom token type URN
  subjectToken: userAccessToken,                 // The token to exchange
  audience: 'https://api.backend.com',
});

// Handle token expiry - check expiresAt and re-exchange when needed
// Note: expiresAt is in seconds, Date.now() is in milliseconds
const tokenIsValid = Math.floor(Date.now() / 1000) < response.expiresAt;
if (!tokenIsValid) {
  // Re-exchange the token or use a refresh token if available
  const refreshed = await authClient.exchangeToken({
    subjectTokenType: 'urn:example:custom-token',
    subjectToken: newSubjectToken,
    audience: 'https://api.backend.com',
  });
}
```

> **Security Note**: Never include PII, secrets, or sensitive data in the `extra` parameter.
> These values may be logged by Auth0 or intermediary systems. Use `extra` only for
> non-sensitive metadata like device IDs, session identifiers, or request context.

#### Token Vault Example

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Exchange an Auth0 access token for an external provider's access token (e.g., Google)
const response = await authClient.exchangeToken({
  connection: 'google-oauth2',
  subjectToken: auth0AccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  loginHint: 'user@example.com', // Optional: specify which account when user has multiple
  scope: 'https://www.googleapis.com/auth/calendar.readonly', // Optional: specific scopes
});

// Or exchange an Auth0 refresh token instead
const responseFromRefresh = await authClient.exchangeToken({
  connection: 'google-oauth2',
  subjectToken: auth0RefreshToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:refresh_token',
});

// Use the external provider's access token
console.log('External access token:', response.accessToken);
```

<details>
<summary><strong>Migration from deprecated getTokenForConnection()</strong></summary>

```ts
// ❌ Deprecated (still works, but will be removed in v2.0)
const response = await authClient.getTokenForConnection({
  connection: 'google-oauth2',
  accessToken: auth0AccessToken,
  loginHint: 'user@example.com',
});

// ✅ New unified API
const response = await authClient.exchangeToken({
  connection: 'google-oauth2',
  subjectToken: auth0AccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  loginHint: 'user@example.com',
});
```

</details>

Learn more: [Custom Token Exchange](https://auth0.com/docs/authenticate/custom-token-exchange) | [Token Vault](https://auth0.com/docs/secure/tokens/token-vault/access-token-exchange-with-token-vault)

### 6. Resource Owner Password Grant

> [!WARNING]  
> This flow should only be used from highly-trusted applications that cannot do redirects. If you can use redirect-based flows from your app, we recommend using the Authorization Code Flow instead.

The SDK supports Resource Owner Password Grant (ROPG) for scenarios where users authenticate by providing their username and password directly:

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
  realm: 'Username-Password-Authentication', // Optional: database connection name
  audience: 'https://api.example.com',        // Optional: API identifier
  scope: 'openid profile email',              // Optional: requested scopes
});

console.log('Access token:', tokenResponse.accessToken);
```

For server-side applications, you can pass the end-user's IP address for brute-force protection:

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
  auth0ForwardedFor: req.ip, // End-user's IP address
});
```

Learn more: [Resource Owner Password Flow](https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token)

### 7. Multi-Factor Authentication (MFA)

The SDK provides built-in support for managing Multi-Factor Authentication. You can enroll authenticators (OTP, SMS, email), list enrolled authenticators, challenge them for verification, and delete them.

```ts
// Access the MFA client via the authClient.mfa property
const mfaToken = '<mfa_token_from_mfa_error>';

// Enroll an OTP authenticator (Google Authenticator, Auth0, etc.)
const enrollment = await authClient.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken
});

// List all enrolled authenticators
const authenticators = await authClient.mfa.listAuthenticators({ mfaToken });

// Challenge an authenticator
const challenge = await authClient.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken
});

// Delete an authenticator
await authClient.mfa.deleteAuthenticator({
  authenticatorId: 'totp|dev_abc123',
  mfaToken
});
```

For detailed MFA examples including SMS enrollment, OOB challenges, and more, see the [MFA section in EXAMPLES.md](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/EXAMPLES.md#using-multi-factor-authentication-mfa).

### 8. More Examples

A full overview of examples can be found in [EXAMPLES.md](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/EXAMPLES.md).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/LICENSE"> LICENSE</a> file for more info.
</p>
