# Change Log

## [v1.4.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.4.0) (2026-01-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.3.0...auth0-auth-js-v1.4.0)

**Added**
- feat(auth0-auth-js): add Multi-Factor Authentication (MFA) support [\#99](https://github.com/auth0/auth0-auth-js/pull/99) ([gyaneshgouraw-okta](https://github.com/gyaneshgouraw-okta))

## [v1.3.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.3.0) (2025-12-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.2.0...auth0-auth-js-v1.3.0)

**Added**
- feat(auth0-auth-js): Add organization support to Custom Token Exchange [\#102](https://github.com/auth0/auth0-auth-js/pull/102) ([yogeshchoudhary147](https://github.com/yogeshchoudhary147))

## [v1.2.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.2.0) (2025-10-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.1.0...auth0-auth-js-v1.2.0)

**Added**
- feat(auth0-auth-js): Added exchangeToken() method with TypeScript overloads for Token Exchange Profile and Token Vault [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))
- feat(auth0-auth-js): Added ExchangeProfileOptions, TokenVaultExchangeOptions, TokenExchangeError, MissingClientAuthError [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))

**Deprecated**
- getTokenForConnection() → Use exchangeToken({ connection, ... }) [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))
- TokenForConnectionOptions → Use TokenVaultExchangeOptions [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))
- TokenForConnectionError → Use TokenExchangeError [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))

## [v1.1.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.1.0) (2025-09-16)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.0.2...auth0-auth-js-v1.1.0)

**Added**
- feat(auth0-auth-js): add support for access token subject type to Token Vault [\#43](https://github.com/auth0/auth0-auth-js/pull/43) ([guabu](https://github.com/guabu))
- feat(auth0-auth-js): make requestExpiry and authorizationDetails params explicit [\#51](https://github.com/auth0/auth0-auth-js/pull/51) ([guabu](https://github.com/guabu))
- feat(auth0-auth-js): support v2 logout endpoint for tenants that do not have an end_session_endpoint [\#48](https://github.com/auth0/auth0-auth-js/pull/48) ([frederikprijck](https://github.com/frederikprijck))
- feat(auth0-auth-js): add support for retrieving token by client credentials [\#42](https://github.com/auth0/auth0-auth-js/pull/42) ([frederikprijck](https://github.com/frederikprijck))
- feat(auth0-auth-js): expose more granular CIBA methods [\#55](https://github.com/auth0/auth0-auth-js/pull/55) ([guabu](https://github.com/guabu))
- feat(auth0-auth-js): add support for mTLS [\#52](https://github.com/auth0/auth0-auth-js/pull/52) ([frederikprijck](https://github.com/frederikprijck))
- feat(auth0-auth-js): ensure to throw an error when mTLS is being used without a custom fetch [\#61](https://github.com/auth0/auth0-auth-js/pull/61) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix(auth0-auth-js): fix parameter name of requested_expiry [\#54](https://github.com/auth0/auth0-auth-js/pull/54) ([guabu](https://github.com/guabu))

## [v1.0.2](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.0.2) (2025-06-18)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.0.1...auth0-auth-js-v1.0.2)

**Fixed**
- fix: support older entry points [\#26](https://github.com/auth0/auth0-auth-js/pull/26) ([CarsonF](https://github.com/CarsonF))
- fix(auth0-auth-js): Do not document bindingMessage as optional [\#19](https://github.com/auth0/auth0-auth-js/pull/19) ([frederikprijck](https://github.com/frederikprijck))

## [v1.0.1](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.0.1) (2025-03-28)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-auth-js-v1.0.0...auth0-auth-js-v1.0.1)

This version is the same as v1.0.0 in terms of features, but we have updated the README to fix a few broken links which requires a new patch release.

## [v1.0.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-auth-js-v1.0.0) (2025-03-27)

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

