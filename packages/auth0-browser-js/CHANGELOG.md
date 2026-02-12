# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - spa-js Compatibility & Advanced Features

#### spa-js Compatible Methods
- `loginWithRedirect()` - Automatic redirect-based authentication (wraps `startInteractiveLogin()`)
- `handleRedirectCallback()` - Handle OAuth callback (wraps `completeInteractiveLogin()`)
- `getTokenSilently()` - Get access token with spa-js signature, supports `detailedResponse` option
- `isAuthenticated()` - Check if user is authenticated
- `getIdTokenClaims()` - Get decoded ID token claims with JWT decoder
- `checkSession()` - Silently check session validity

#### Popup Authentication
- `loginWithPopup()` - Authenticate via popup window with timeout and cancellation support
- `getTokenWithPopup()` - Acquire additional scopes via popup
- `PopupHandler` class for managing popup lifecycle
- `sendPopupResponse()` helper for popup callback pages
- New error classes: `PopupTimeoutError`, `PopupCancelledError`, `PopupOpenError`, `TimeoutError`

#### MFA Management
- Exposed `mfa` property from `@auth0/auth0-auth-js` providing full MFA API:
  - `mfa.listAuthenticators()` - List enrolled MFA authenticators
  - `mfa.enrollAuthenticator()` - Enroll new MFA authenticator (OTP, SMS, email)
  - `mfa.deleteAuthenticator()` - Delete enrolled authenticator
  - `mfa.challengeAuthenticator()` - Create MFA challenge

#### DPoP Support (Demonstrating Proof-of-Possession)
- `useDpop` option to enable DPoP for enhanced token security
- `generateDpopProof()` - Generate DPoP proof JWT with ECDSA P-256 signing
- `getDpopNonce()` / `setDpopNonce()` - Nonce management for DPoP
- Automatic DPoP handling in authenticated fetcher

#### Authenticated Fetcher
- `createFetcher()` - Factory method to create authenticated HTTP client
- `Fetcher` class with automatic token injection
- Support for Bearer and DPoP authorization schemes
- Automatic retry logic for DPoP nonce errors
- Custom token getter support

#### Custom Token Exchange (RFC 8693)
- `loginWithCustomTokenExchange()` - Exchange external tokens for Auth0 tokens
- Automatic token storage after successful exchange
- Support for additional exchange parameters

#### Storage Options
- `cacheLocation` option to choose storage backend:
  - `'localstorage'` (default) - Encrypted, persists across sessions
  - `'sessionstorage'` - Encrypted, cleared when tab closes
  - `'memory'` - No encryption, cleared on page reload (spa-js behavior)
- `SessionStorageStateStore` and `SessionStorageTransactionStore` implementations
- `MemoryStateStore` and `MemoryTransactionStore` implementations (no secret required)

#### Cache Management
- `getCacheKeys()` - Get all cache identifiers
- `clearCache()` - Clear all cached data
- `clearCache({ keepRefreshToken: true })` - Clear cache but preserve refresh token

#### Type System Enhancements
- Added 30+ new spa-js compatible type definitions:
  - `RedirectLoginOptions`, `RedirectLoginResult`
  - `GetTokenSilentlyOptions`, `GetTokenSilentlyVerboseResponse`
  - `PopupLoginOptions`, `PopupConfigOptions`, `GetTokenWithPopupOptions`
  - `IdToken` with full OIDC claims
  - `FetcherConfig`, `FetchWithAuthParams`
  - `CustomTokenExchangeOptions`
- Enhanced `LogoutOptions` to support both browser-js and spa-js formats

### Changed

- **ZERO BREAKING**: `logout()` method now accepts optional parameter (was required)
  - Supports both old format (`options.returnTo`) and new format (`options.logoutParams.returnTo`)
  - Supports `openUrl` option for custom redirect handling
  - Supports `federated` parameter for identity provider logout
- `BrowserClientOptions` now supports `cacheLocation` and `useDpop` options
- Constructor logic updated to support multiple storage backends based on `cacheLocation`

### Documentation

- Added `MIGRATION.md` - Comprehensive migration guide from `@auth0/auth0-spa-js`
- Updated `EXAMPLES.md` - Removed user linking examples (not implemented), added:
  - spa-js compatible method examples
  - Popup authentication examples
  - MFA management examples
  - DPoP usage examples
  - Custom token exchange examples
  - Authenticated fetcher examples
  - Storage options examples
  - Cache management examples
- Updated `README.md` - Added spa-js compatibility section, feature highlights, and migration overview

## [1.0.0] - TBD

### Added

- Initial release of `@auth0/auth0-browser-js`
- Browser-based authentication support with PKCE
- LocalStorage-based encrypted state and transaction stores
- Interactive login/logout
- User linking/unlinking
- Token management with refresh token support
- Multi-audience support with MRRT
