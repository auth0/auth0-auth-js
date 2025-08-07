# Change Log

## [v1.1.0] (2025-08-06)

**Added**
- feat: Add support for resource server client capabilities
  - `ApiClient` now supports passing client credentials (client ID/secret or client assertion signing key) for the associated client
  - Added `getTokenForConnection()` method for retrieving access tokens for federated connections (relies on credentials)
  - New error types: `ClientAuthenticationError` and `ConnectionTokenError`

## [v1.0.2](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.0.2) (2025-06-18)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.0.1...auth0-api-js-v1.0.2)

**Fixed**
- fix: support older entry points [\#26](https://github.com/auth0/auth0-auth-js/pull/26) ([CarsonF](https://github.com/CarsonF))

## [v1.0.1](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.0.1) (2025-03-28)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.0.0...auth0-api-js-v1.0.1)

This version is the same as v1.0.0 in terms of features, but we have updated the README to fix a few broken links which requires a new patch release.


## [v1.0.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.0.1) (2025-03-27)

The `@auth0/auth0-api-js` library allows for securing API's running on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- `ApiClient` class to interact with, that is configurable with:
    - `domain`: string
    - `audience`: string
- `verifyAccessToken({ accessToken, requiredClaims })` method on `ApiClient` to verify an access token.
