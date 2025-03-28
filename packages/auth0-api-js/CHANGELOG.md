# Change Log

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
