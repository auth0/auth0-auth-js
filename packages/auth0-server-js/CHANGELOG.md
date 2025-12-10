# Change Log

## [v1.2.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.2.0) (2025-12-10)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-server-js-v1.1.0...auth0-server-js-v1.2.0)

**Added**
- feat(auth0-server-js): allow to configure path for cookie [\#94](https://github.com/auth0/auth0-auth-js/pull/94) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix(auth0-server-js): correctly calculate expiresAt when updating the state [\#91](https://github.com/auth0/auth0-auth-js/pull/91) ([frederikprijck](https://github.com/frederikprijck))

## [v1.1.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.1.0) (2025-09-16)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-server-js-v1.0.3...auth0-server-js-v1.1.0)

**Added**
- feat(auth0-server-js): expose the authClient for advanced use cases [\#58](https://github.com/auth0/auth0-auth-js/pull/58) ([guabu](https://github.com/guabu))
- feat(auth0-server-js): add support for mTLS [\#53](https://github.com/auth0/auth0-auth-js/pull/53) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix(auth0-server-js): correctly compare scopes before calling auth0 [\#40](https://github.com/auth0/auth0-auth-js/pull/40) ([frederikprijck](https://github.com/frederikprijck))

## [v1.0.3](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.0.3) (2025-06-23)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-server-js-v1.0.2...auth0-server-js-v1.0.3)

**Fixed**
- fix(auth0-server-js): StatelessStateStore cookie options [\#32](https://github.com/auth0/auth0-auth-js/pull/32) ([CarsonF](https://github.com/CarsonF))

## [v1.0.2](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.0.2) (2025-06-18)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-server-js-v1.0.1...auth0-server-js-v1.0.2)

**Added**
- feat(auth0-server-js): Add concrete store implementations that depend on a CookieHandler [\#28](https://github.com/auth0/auth0-auth-js/pull/28) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix: support older entry points [\#26](https://github.com/auth0/auth0-auth-js/pull/26) ([CarsonF](https://github.com/CarsonF))

## [v1.0.1](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.0.1) (2025-03-28)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-server-js-v1.0.0...auth0-server-js-v1.0.1)

This version is the same as v1.0.0 in terms of features, but we have updated the README to fix a few broken links which requires a new patch release.

## [v1.0.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-server-js-v1.0.0) (2025-03-27)

The `@auth0/auth0-server-js` library allows for implementing user authentication in web applications on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- `ServerClient` class to interact with, that is configurable with:
  - `domain`: string
  - `clientId`: string
  - `clientSecret`: string
  - `clientAssertionSigningKey`: string | CryptoKey
  - `clientAssertionSigningAlg`: string
  - `authorizatationParams`: object
  - `transactionIdentifier`: string
  - `stateIdentifier`: string
  - `transactionStore`: TransactionStore
  - `stateStore`: StateStore
- `startInteractiveLogin(options, storeOptions)` method on `ServerClient`: Starts the interactive login process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
  - `options.pushedAuthorizationRequests`: boolean
  - `options.appState`: object
  - `options.authorizationParams`: object
  - `storeOptions`: object
- `completeInteractiveLogin(url, storeOptions)` method on `ServerClient`:  Completes the interactive login process.
  - `url`: URL
  - `storeOptions`: object
- `startLinkUser(options, storeOptions)` method on `ServerClient`: Starts the user linking process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
  - `options.connection`: string
  - `options.connectionScope`: string
  - `options.appState`: object
  - `options.authorizationParams`: object
  - `storeOptions`: object
- `completeLinkUser(url, storeOptions)` method on `ServerClient`: Completes the user linking process.
  - `url`: URL
  - `storeOptions`: object
- `startUnlinkUser(options, storeOptions)` method on `ServerClient`: Starts the user unlinking process, and returns a URL to redirect the user-agent to to initialize user unlinking at Auth0.
  - `options.connection`: string
  - `options.appState`: object
  - `options.authorizationParams`: object
  - `storeOptions`: object
- `completeUnlinkUser(url, storeOptions)` method on `ServerClient`: Completes the user unlinking process.
  - `url`: URL
  - `storeOptions`: object
- `loginBackchannel(options, storeOptions)`method on `ServerClient`: Logs in using Client-Initiated Backchannel Authentication.
  - `options.bindingMessage`: string
  - `options.loginHint.sub`: object
  - `options.authorizationParams`: object
  - `storeOptions`: object
- `getUser(storeOptions)` method on `ServerClient`: Retrieves the user from the store, or undefined if no user found.
  - `storeOptions`: object
- `getSession(storeOptions)` method on `ServerClient`: Retrieve the user session from the store, or undefined if no session found.
  - `storeOptions`: object
- `getAccessToken(storeOptions)` method on `ServerClient`: Retrieves the access token from the store, or calls Auth0 when the access token is expired and a refresh token is available in the store.
  - `storeOptions`: object
- `getAccessTokenForConnection(options, storeOptions)` method on `ServerClient`: Retrieves an access token for a connection.
  - `options.connection`: string
  - `options.loginHint`: string
  - `storeOptions`: object
- `logout(opptions, storeOptions)` method on `ServerClient`: Logs the user out and returns a URL to redirect the user-agent to after they log out.
  - `options.returnTo`: string
  - `storeOptions`: object
- `handleBackchannelLogout(logoutToken, storeOptions)` method on `ServerClient`:  Handles the backchannel logout process by verifying the logout token and deleting the session from the store if the logout token was considered valid.
  - `logoutToken`: string
  - `storeOptions`: object
