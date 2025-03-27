# Change Log

## [v1.0.0](https://github.com/auth0/auth0-auth-js/tree/auth0-auth-js-v1.0.0) (2025-03-27)

The `@auth0/auth0-auth-js` library provides API's to interact with Auth0's Authentication Api's from withing JavaScript applications.

It contains methods to build Authorization URLs and Logout URLs, implement Backchannel Logout, verifying a logout token, and to request Tokens using the Authorization Code Flow and Refresh Tokens, as well as retrieving a Token for a Connection.

In version 1.0.0, we have added the following features:

- `AuthClient` class to interact with, that is configurable with:
  - `domain`: string
  - `clientId`: string
  - `clientSecret`: string
  - `clientAssertionSigningKey`: string | CryptoKey
  - `clientAssertionSigningAlg`: string
  - `authorizatationParams`: object
- `buildAuthorizationUrl(options)` method on `AuthClient`: Builds the URL to redirect the user-agent to to request authorization at Auth0.
  - `options.pushedAuthorizationRequests`: boolean
  - `options.authorizationParams`: object
- `buildLinkUserUrl(options)` method on `AuthClient`: Builds the URL to redirect the user-agent to to link a user to an existing account.
  - `options.connection`: string
  - `options.connectionScope`: string
  - `options.idToken`: string
  - `options.authorizationParams`: object
- `buildUnlinkUserUrl(options)` method on `AuthClient`: Builds the URL to redirect the user-agent to to unlink a user from an existing account.
  - `options.connection`: string
  - `options.idToken`: string
  - `options.authorizationParams`: object
- `backchannelAuthentication`method on `AuthClient`: Authenticates using Client-Initiated Backchannel Authentication.
- `getTokenByCode(url, options)` method on `AuthClient`: Requests a Token using the Authorization Code Flow.
  - `url`: string
  - `options.codeVerifier`: string
- `getTokenForConnection(options)` method on `AuthClient`: Requests a Token for a Connection.
  - `options.connection`: string
  - `options.loginHint`: string
  - `options.refreshToken`: string
- `getTokenByRefreshToken` method on `AuthClient`: Requests a Token using a Refresh Token.
  - `options.refreshToken`: string
- `buildLogoutUrl(options)` method on `AuthClient`: Builds the URL to redirect the user-agent to to logout from Auth0.
  - `options.returnTo`: string
- `verifyLogoutToken` method on `AuthClient`: Verifies a Logout Token.
    - `options.logoutToken`: string

