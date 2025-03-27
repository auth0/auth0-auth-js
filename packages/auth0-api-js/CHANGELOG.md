# Change Log

## [v1.0.0](https://github.com/auth0/auth0-auth-js/tree/auth0-api-js-v1.0.0) (2025-03-27)

The `@auth0/auth0-api-js` library allows for securing API's running on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- `ApiClient` class to interact with, that is configurable with:
    - `domain`: string
    - `audience`: string
- `verifyAccessToken({ accessToken, requiredClaims })` method on `ApiClient` to verify an access token.
