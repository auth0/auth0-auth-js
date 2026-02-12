The `@auth0/auth0-browser-js` library allows for implementing user authentication in browser-based web applications.

**✨ spa-js Compatible**: This SDK provides full compatibility with `@auth0/auth0-spa-js` while offering enhanced security, better storage options, and additional features like MFA management, DPoP support, and authenticated fetchers.

Using this SDK as-is in your application may not be trivial, as it is designed to be used as a building block for building framework-specific authentication SDKs.

![Release](https://img.shields.io/npm/v/@auth0/auth0-browser-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-browser-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 🔄 [Migration from spa-js](#migration-from-spa-js) - ✨ [Features](#features) - 💬 [Feedback](#feedback)

## Documentation

- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.
- [EXAMPLES.md](./EXAMPLES.md) - comprehensive examples covering all features.
- [MIGRATION.md](./MIGRATION.md) - migrate from @auth0/auth0-spa-js to @auth0/auth0-browser-js.

## Getting Started

- [1. Install the SDK](#1-install-the-sdk)
- [2. Create the Auth0 SDK client](#2-create-the-auth0-sdk-client)
- [3. Add login to your Application](#3-add-login-to-your-application)
- [4. Add logout to your application](#4-add-logout-to-your-application)

### 1. Install the SDK

```shell
npm i @auth0/auth0-browser-js
```

This library is designed to work in modern browsers and requires support for:
- ES6+
- Web Crypto API
- localStorage

### 2. Create the Auth0 SDK client

Create an instance of the `BrowserClient`. This instance will be imported and used anywhere we need access to the authentication methods.

```ts
import { BrowserClient } from '@auth0/auth0-browser-js';

const auth0 = new BrowserClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  secret: '<ENCRYPTION_SECRET>',
  authorizationParams: {
    redirect_uri: '<AUTH0_REDIRECT_URI>',
  },
});
```

The `AUTH0_DOMAIN` and `AUTH0_CLIENT_ID` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Single Page Application` (SPA)**.

The `ENCRYPTION_SECRET` is used to encrypt data stored in localStorage. This should be a strong, random string.

The `AUTH0_REDIRECT_URI` is needed to tell Auth0 what URL to redirect back to after successful authentication, e.g. `http://localhost:3000/callback`. Your application needs to handle this endpoint and call the SDK's `completeInteractiveLogin(url: URL)` to finish the authentication process.

### 3. Add login to your Application

Before using redirect-based login, ensure the `authorizationParams.redirect_uri` is configured when initializing the SDK:

```ts
const auth0 = new BrowserClient({
  // ...
  authorizationParams: {
    redirect_uri: '<AUTH0_REDIRECT_URI>',
  },
  // ...
});
```

> [!IMPORTANT]
> You will need to register the `AUTH0_REDIRECT_URI` in your Auth0 Application as an **Allowed Callback URLs** via the [Auth0 Dashboard](https://manage.auth0.com):

#### Option A: Native Methods

To add login to your application, call `startInteractiveLogin()`, and redirect the user to the returned URL:

```ts
async function login() {
  const authorizationUrl = await auth0.startInteractiveLogin();
  window.location.href = authorizationUrl.href;
}
```

Once the user has successfully authenticated, Auth0 will redirect the user back to the provided `authorizationParams.redirect_uri`. You need to handle this in your application:

```ts
async function handleCallback() {
  const url = new URL(window.location.href);
  await auth0.completeInteractiveLogin(url);

  // Redirect to your app's main page
  window.location.href = '/';
}
```

#### Option B: spa-js Compatible Methods

If you're familiar with `@auth0/auth0-spa-js`, you can use compatible methods:

```ts
// Automatically redirects to Auth0
await auth0.loginWithRedirect();

// Handle callback
await auth0.handleRedirectCallback();
window.location.href = '/';
```

Both approaches work identically. Choose the style that fits your preference.

### 4. Add logout to your application

To log the user out of your application, as well as from Auth0, call the SDK's `logout()` method and redirect the user to the returned URL:

```ts
async function logout() {
  const logoutUrl = await auth0.logout({ returnTo: window.location.origin });
  window.location.href = logoutUrl.href;
}
```

> [!IMPORTANT]
> You will need to register the `returnTo` URL in your Auth0 Application as an **Allowed Logout URLs** via the [Auth0 Dashboard](https://manage.auth0.com):

## Features

### 🔐 Enhanced Security
- **Encrypted Token Storage**: All tokens are encrypted at rest when using localStorage or sessionStorage
- **DPoP Support**: Demonstrating Proof-of-Possession for enhanced token security
- **Public Client Architecture**: No client secrets required in the browser

### 🔄 spa-js Compatibility
All `@auth0/auth0-spa-js` methods work identically:
- `loginWithRedirect()` / `handleRedirectCallback()`
- `getTokenSilently()` with `detailedResponse` option
- `isAuthenticated()` / `getIdTokenClaims()` / `checkSession()`
- `logout()` with spa-js options format
- `loginWithPopup()` / `getTokenWithPopup()`

See [MIGRATION.md](./MIGRATION.md) for migration guide.

### 💾 Flexible Storage Options
Choose the storage that fits your needs:
- **localStorage** (default): Encrypted, persists across browser sessions
- **sessionStorage**: Encrypted, cleared when tab closes
- **memory**: No encryption needed, cleared on page reload (spa-js behavior)

```typescript
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  cacheLocation: 'sessionstorage', // or 'memory' or 'localstorage'
  secret: 'encryption-secret', // Required for localStorage/sessionStorage
});
```

### 🔑 Built-in MFA Management
Manage multi-factor authentication without additional SDKs:

```typescript
// List enrolled authenticators
const authenticators = await auth0.mfa.listAuthenticators({ mfaToken });

// Enroll OTP authenticator
const enrollment = await auth0.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken,
});

// Challenge and verify
const challenge = await auth0.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken,
});
```

### 🌐 Authenticated Fetcher
Automatic token injection for API calls:

```typescript
const fetcher = auth0.createFetcher({
  baseUrl: 'https://api.example.com',
});

// Tokens are automatically added
const posts = await fetcher.fetchWithAuth('/posts');
const newPost = await fetcher.fetchWithAuth('/posts', {
  method: 'POST',
  body: JSON.stringify({ title: 'My Post' }),
});
```

### 🔁 Custom Token Exchange
Exchange external tokens for Auth0 tokens (RFC 8693):

```typescript
const tokenResponse = await auth0.loginWithCustomTokenExchange({
  subjectTokenType: 'urn:acme:legacy-token',
  subjectToken: legacyToken,
  audience: 'https://api.example.com',
  scope: 'openid offline_access',
});
```

### 🗂️ Cache Management

```typescript
// Clear all cached data
await auth0.clearCache();

// Clear but keep refresh token
await auth0.clearCache({ keepRefreshToken: true });

// Get cache keys
const keys = auth0.getCacheKeys();
```

### 📦 Multi-Resource Refresh Tokens (MRRT)
Request tokens for multiple audiences with a single refresh token:

```typescript
// Get token for first audience
const token1 = await auth0.getAccessToken({
  audience: 'https://api1.example.com',
});

// Get token for second audience (uses same refresh token)
const token2 = await auth0.getAccessToken({
  audience: 'https://api2.example.com',
});
```

For comprehensive examples, see [EXAMPLES.md](./EXAMPLES.md).

## Migration from spa-js

Migrating from `@auth0/auth0-spa-js` is straightforward:

**Before (spa-js):**
```typescript
import { createAuth0Client } from '@auth0/auth0-spa-js';

const auth0 = await createAuth0Client({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
});
```

**After (browser-js):**
```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';

const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret', // Required for encrypted storage
});

// Optional: Check session (replicates spa-js factory behavior)
await auth0.checkSession();
```

All spa-js methods work identically after initialization. See [MIGRATION.md](./MIGRATION.md) for a complete guide.

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-browser-js/LICENSE"> LICENSE</a> file for more info.
</p>
