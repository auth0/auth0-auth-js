# Examples

Examples are split by feature. Each file below is self-contained.

## [Configuration](./examples/configuration.md)

- [Configuring the Scopes](./examples/configuration.md#configuring-the-scopes)
- [Configuring PrivateKeyJwt](./examples/configuration.md#configuring-privatekeyjwt)
- [Configuring mTLS (Mutual TLS)](./examples/configuration.md#configuring-mtls-mutual-tls)
- [Configuring the `authorizationParams` globally](./examples/configuration.md#configuring-the-authorizationparams-globally)
- [Configuring a `customFetch` implementation](./examples/configuration.md#configuring-a-customfetch-implementation)
- [Configuring discovery cache](./examples/configuration.md#configuring-discovery-cache)

## [Authorization URLs](./examples/authorization-urls.md)

- [Building the Authorization URL](./examples/authorization-urls.md#building-the-authorization-url)
    - [Passing `authorizationParams`](./examples/authorization-urls.md#passing-authorizationparams)
    - [Using Pushed Authorization Requests](./examples/authorization-urls.md#using-pushed-authorization-requests)
    - [Using Pushed Authorization Requests and Rich Authorization Requests](./examples/authorization-urls.md#using-pushed-authorization-requests-and-rich-authorization-requests)
- [Building Link User URL](./examples/authorization-urls.md#building-link-user-url)
    - [Passing `authorizationParams`](./examples/authorization-urls.md#passing-authorizationparams-1)
- [Building Unlink User URL](./examples/authorization-urls.md#building-unlink-user-url)
    - [Passing `authorizationParams`](./examples/authorization-urls.md#passing-authorizationparams-2)

## [Retrieving Tokens](./examples/tokens.md)

- [Using Client-Initiated Backchannel Authentication](./examples/tokens.md#using-client-initiated-backchannel-authentication)
- [Retrieving a Token using an Authorization Code](./examples/tokens.md#retrieving-a-token-using-an-authorization-code)
- [Retrieving a Token using a Refresh Token](./examples/tokens.md#retrieving-a-token-using-a-refresh-token)
    - [Using Multi-Resource Refresh Tokens (MRRT)](./examples/tokens.md#using-multi-resource-refresh-tokens-mrrt)
    - [Modifying Token Scopes](./examples/tokens.md#modifying-token-scopes)
- [Retrieving a Token using Resource Owner Password Grant](./examples/tokens.md#retrieving-a-token-using-resource-owner-password-grant)
    - [Specifying a Realm](./examples/tokens.md#specifying-a-realm)
    - [Specifying Audience and Scope](./examples/tokens.md#specifying-audience-and-scope)
    - [Passing the End-User's IP Address](./examples/tokens.md#passing-the-end-users-ip-address)
- [Retrieving a Token using Client Credentials](./examples/tokens.md#retrieving-a-token-using-client-credentials)
- [Retrieving a Token for a Connection](./examples/tokens.md#retrieving-a-token-for-a-connection)

## [Logout](./examples/logout.md)

- [Building the Logout URL](./examples/logout.md#building-the-logout-url)
- [Verifying the Logout Token](./examples/logout.md#verifying-the-logout-token)

## [Retrieving User Information](./examples/user-info.md)

- [Retrieving User Information](./examples/user-info.md#retrieving-user-information)
    - [Optional Subject Validation](./examples/user-info.md#optional-subject-validation)
    - [Error Handling](./examples/user-info.md#error-handling)

## [Passwordless Authentication](./examples/passwordless.md)

- [Classic Email/SMS Passwordless (/passwordless/start)](./examples/passwordless.md#classic-emailsms-passwordless-passwordlessstart)
    - [Sending an Email Code](./examples/passwordless.md#sending-an-email-code)
    - [Sending an Email Magic Link](./examples/passwordless.md#sending-an-email-magic-link)
    - [Sending an SMS Code](./examples/passwordless.md#sending-an-sms-code)
    - [Logging in with an Email Code](./examples/passwordless.md#logging-in-with-an-email-code)
    - [Logging in with an SMS Code](./examples/passwordless.md#logging-in-with-an-sms-code)
    - [Handling Multi-Factor Authentication](./examples/passwordless.md#handling-multi-factor-authentication)
- [Passwordless OTP on Database Connections](./examples/passwordless.md#passwordless-otp-on-database-connections)
    - [Prerequisites](./examples/passwordless.md#prerequisites)
    - [Email OTP on Database Connection](./examples/passwordless.md#email-otp-on-database-connection)
    - [Phone OTP on Database Connection](./examples/passwordless.md#phone-otp-on-database-connection)
    - [Error Handling and MFA](./examples/passwordless.md#error-handling-and-mfa)

## [Multi-Factor Authentication (MFA)](./examples/mfa.md)

- [Enrolling an Authenticator](./examples/mfa.md#enrolling-an-authenticator)
- [Listing Authenticators](./examples/mfa.md#listing-authenticators)
- [Challenging an Authenticator](./examples/mfa.md#challenging-an-authenticator)
- [Verifying an Authenticator](./examples/mfa.md#verifying-an-authenticator)
- [Deleting an Authenticator](./examples/mfa.md#deleting-an-authenticator)

## [Passkeys](./examples/passkeys.md)

- [Requesting a Signup Challenge](./examples/passkeys.md#requesting-a-signup-challenge)
- [Requesting a Login Challenge](./examples/passkeys.md#requesting-a-login-challenge)
- [Exchanging a Credential for Tokens](./examples/passkeys.md#exchanging-a-credential-for-tokens)
- [Error Handling](./examples/passkeys.md#error-handling)

## [Custom Token Exchange](./examples/custom-token-exchange.md)

- [Basic Exchange](./examples/custom-token-exchange.md#basic-exchange)
- [Delegation Exchange with Actor Token](./examples/custom-token-exchange.md#delegation-exchange-with-actor-token)
- [Reading the act Claim](./examples/custom-token-exchange.md#reading-the-act-claim)
- [M2M Delegation (No ID Token)](./examples/custom-token-exchange.md#m2m-delegation-no-id-token)
- [Error Handling](./examples/custom-token-exchange.md#error-handling)

## [Database Connections (Sign-up & Change Password)](./examples/database-connections.md)

- [Signing Up a User](./examples/database-connections.md#signing-up-a-user)
- [Requesting a Password Change](./examples/database-connections.md#requesting-a-password-change)
- [Error Handling](./examples/database-connections.md#error-handling)

## [HTTP Requests and Responses](./examples/http-requests-and-responses.md)

- [Per-Request Options](./examples/http-requests-and-responses.md#per-request-options)
    - [Cancelling a request](./examples/http-requests-and-responses.md#cancelling-a-request)
    - [Passing per-request headers](./examples/http-requests-and-responses.md#passing-per-request-headers)
    - [Using a one-off fetch](./examples/http-requests-and-responses.md#using-a-one-off-fetch)
- [Accessing the Full HTTP Response](./examples/http-requests-and-responses.md#accessing-the-full-http-response)
    - [Methods that support `fullResponse`](./examples/http-requests-and-responses.md#methods-that-support-fullresponse)
    - [TypeScript overload gotcha](./examples/http-requests-and-responses.md#typescript-overload-gotcha)
    - [Cache and performance considerations](./examples/http-requests-and-responses.md#cache-and-performance-considerations)
- [Handling API Errors with HTTP Metadata](./examples/http-requests-and-responses.md#handling-api-errors-with-http-metadata)
