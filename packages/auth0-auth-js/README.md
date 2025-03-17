The `@auth0/auth0-auth-js` library provides API's to interact with Auth0's Authentication Api's from withing JavaScript applications.

It contains methods to build Authorization URLs and Logout URLs, implement Backchannel Logout, verifying a logout token, and to request Tokens using the Authorization Code Flow and Refresh Tokens, as well as retrieving a Token for a Connection.


![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](https://auth0.github.io/auth0-auth-js/) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-auth-js/EXAMPLES.md) - examples for your different use cases.
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

### 5. More Examples

A full overview of examples can be found in [EXAMPLES.md](./EXAMPLES.md).

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-server-js/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./../../CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-js/issues).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-auth-js/LICENSE"> LICENSE</a> file for more info.
</p>
