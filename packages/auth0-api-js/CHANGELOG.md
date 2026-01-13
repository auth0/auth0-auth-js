# Change Log

## [v0.1.0](https://github.com/auth0/auth0-auth-js/tree/v0.1.0) (2026-01-13)

**Added**
- Adding DPoP Support [\#108](https://github.com/auth0/auth0-auth-js/pull/108) ([nandan-bhat](https://github.com/nandan-bhat))

**Fixed**
- chore: fix TypeDoc [\#107](https://github.com/auth0/auth0-auth-js/pull/107) ([frederikprijck](https://github.com/frederikprijck))
- fix(auth0-api-js): add missing exports [\#106](https://github.com/auth0/auth0-auth-js/pull/106) ([frederikprijck](https://github.com/frederikprijck))

## [v1.3.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.3.0) (2025-12-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.2.1...auth0-api-js-v1.3.0)

**Added**
- feat(auth0-api-js): Add organization support to Custom Token Exchange [\#102](https://github.com/auth0/auth0-auth-js/pull/102) ([yogeshchoudhary147](https://github.com/yogeshchoudhary147))

## [v1.2.1](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.2.1) (2025-10-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.2.0...auth0-api-js-v1.2.1)

**Fixed**
- fix(auth0-api-js): bump auth0-auth-js to 1.2.0 [\#84](https://github.com/auth0/auth0-auth-js/pull/84) ([frederikprijck](https://github.com/frederikprijck))

## [v1.2.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.2.0) (2025-10-15)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.1.0...auth0-api-js-v1.2.0)

**Added**
- feat(auth0-api-js): Added getTokenByExchangeProfile() for Custom Token Exchange [\#75](https://github.com/auth0/auth0-auth-js/pull/75) ([btiernay](https://github.com/btiernay))

## [v1.1.0](https://github.com/auth0/auth0-auth-js/releases/tag/auth0-api-js-v1.1.0) (2025-09-19)
[Full Changelog](https://github.com/auth0/auth0-auth-js/compare/auth0-api-js-v1.0.2...auth0-api-js-v1.1.0)

**Added**
- feat(auth0-api-js): add ProtectedResourceMetadata [\#60](https://github.com/auth0/auth0-auth-js/pull/60) ([patrickkang](https://github.com/patrickkang))
- fix(auth0-api-js): add missing fields to ProtectedResourceMetadata [\#63](https://github.com/auth0/auth0-auth-js/pull/63) ([patrickkang](https://github.com/patrickkang))
- feat(auth0-api-js): add bearer token parsing utils [\#69](https://github.com/auth0/auth0-auth-js/pull/69) ([patrickkang](https://github.com/patrickkang))
- feat(auth0-api-js): Add support for Token Vault to exchange access tokens [\#68](https://github.com/auth0/auth0-auth-js/pull/68) ([guabu](https://github.com/guabu))

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
