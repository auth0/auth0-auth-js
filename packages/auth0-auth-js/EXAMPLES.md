# Examples

- [Configuration](#configuration)
    - [Configuring the Scopes](#configuring-the-scopes)
    - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
    - [Configuring mTLS (Mutual TLS)](#configuring-mtls-mutual-tls)
    - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
    - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
    - [Configuring discovery cache](#configuring-discovery-cache)
- [Building the Authorization URL](#building-the-authorization-url)
    - [Passing `authorizationParams`](#passing-authorizationparams)
    - [Using Pushed Authorization Requests](#using-pushed-authorization-requests)
    - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
- [Building Link User URL](#building-link-user-url)
    - [Passing `authorizationParams`](#passing-authorizationparams-1)
- [Building Unlink User URL](#building-unlink-user-url)
    - [Passing `authorizationParams`](#passing-authorizationparams-2)
- [Using Client-Initiated Backchannel Authentication](#using-client-initiated-backchannel-authentication)
- [Retrieving a Token using an Authorization Code](#retrieving-a-token-using-an-authorization-code)
- [Retrieving a Token using a Refresh Token](#retrieving-a-token-using-a-refresh-token)
    - [Using Multi-Resource Refresh Tokens (MRRT)](#using-multi-resource-refresh-tokens-mrrt)
    - [Modifying Token Scopes](#modifying-token-scopes)
- [Retrieving a Token using Resource Owner Password Grant](#retrieving-a-token-using-resource-owner-password-grant)
    - [Specifying a Realm](#specifying-a-realm)
    - [Specifying Audience and Scope](#specifying-audience-and-scope)
    - [Passing the End-User's IP Address](#passing-the-end-users-ip-address)
- [Retrieving a Token using Client Credentials](#retrieving-a-token-using-client-credentials)
- [Retrieving a Token for a Connection](#retrieving-a-token-for-a-connection)
- [Building the Logout URL](#building-the-logout-url)
- [Verifying the Logout Token](#verifying-the-logout-token)
- [Using Passwordless Authentication](#using-passwordless-authentication)
    - [Sending an Email Code](#sending-an-email-code)
    - [Sending an Email Magic Link](#sending-an-email-magic-link)
    - [Sending an SMS Code](#sending-an-sms-code)
    - [Logging in with an Email Code](#logging-in-with-an-email-code)
    - [Logging in with an SMS Code](#logging-in-with-an-sms-code)
    - [Handling Multi-Factor Authentication](#handling-multi-factor-authentication)
- [Using Multi-Factor Authentication (MFA)](#using-multi-factor-authentication-mfa)
    - [Enrolling an Authenticator](#enrolling-an-authenticator)
    - [Listing Authenticators](#listing-authenticators)
    - [Challenging an Authenticator](#challenging-an-authenticator)
    - [Deleting an Authenticator](#deleting-an-authenticator)
- [Using Passkeys](#using-passkeys)
- [Using Database Connections (Sign-up & Change Password)](#using-database-connections-sign-up--change-password)
    - [Requesting a Signup Challenge](#requesting-a-signup-challenge)
    - [Requesting a Login Challenge](#requesting-a-login-challenge)
    - [Exchanging a Credential for Tokens](#exchanging-a-credential-for-tokens)
    - [Error Handling](#error-handling)
- [Custom Token Exchange](#custom-token-exchange)
    - [Basic Exchange](#basic-exchange)
    - [Delegation Exchange with Actor Token](#delegation-exchange-with-actor-token)
    - [Reading the act Claim](#reading-the-act-claim)
    - [M2M Delegation (No ID Token)](#m2m-delegation-no-id-token)
    - [Error Handling](#error-handling-1)

## Configuration

### Configuring the Scopes

By default, the SDK will request an Access Token using `'openid profile email offline_access'` as the scope. This can be changed by configuring `authorizationParams.scope`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const auth0 = new AuthClient({
  authorizationParams: {
    scope: 'scope_a openid profile email offline_access'
  }
});
```

In order to ensure the SDK can refresh tokens when expired, the `offline_access` scope should be included. It is also mandatory to include `openid` as part of `authrizationParams.scope`.


### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of ServerClient:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
....................REMOVED FOR BREVITY.........................
-----END PRIVATE KEY-----`;
const clientAssertionSigningKey = await importPKCS8(clientPrivateKey, 'RS256');
const auth0 = new AuthClient({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

Note that the private keys should not be committed to source control, and should be stored securely.

### Configuring mTLS (Mutual TLS)

The SDK supports mTLS (Mutual TLS) authentication, which provides stronger security by using client certificates for authentication. When using mTLS, you don't need to provide a client secret or private key JWT since the client certificate serves as the authentication mechanism.

To use mTLS, set `useMtls: true` and provide a `customFetch` implementation that includes your client certificate:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';
import { Agent } from 'undici';

const auth0 = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  useMtls: true,
  customFetch: (url, options) => {
    return fetch(url, {
      ...options,
      dispatcher: new Agent({
        connect: {
          key: '...',
          cert: '...',
          ca: '...',
        },
      }),
    });
  },
});

// Example: Get a token using client credentials with mTLS
const tokenResponse = await auth0.getTokenByClientCredentials({
  audience: 'https://your-api.example.com',
});
```

**Key points for mTLS configuration:**

- **Client Certificate**: Your application must have a valid client certificate issued by a Certificate Authority (CA) that Auth0 trusts.
- **Domain Configuration**: Your Auth0 tenant must be configured to support mTLS endpoints.
- **No Additional Auth**: When `useMtls: true`, you don't need `clientSecret` or `clientAssertionSigningKey`.
- **Custom Fetch Required**: You must provide a `customFetch` implementation that includes the client certificate in the TLS handshake.

> [!IMPORTANT]  
> mTLS requires proper certificate management and Auth0 tenant configuration. Make sure your Auth0 tenant supports mTLS endpoints and that your client certificates are properly configured in the Auth0 Dashboard. Learn how to configure mTLS in your Auth0 tenant by reading the [mTLS configuration documentation](https://auth0.com/docs/get-started/applications/configure-mtls).

### Configuring the `authorizationParams` globally

The `authorizationParams` object can be used to customize the authorization parameters that will be passed to the `/authorize` endpoint. This object can be passed when creating an instance of `AuthClient`, but it can also be specified when calling certain methods of the SDK, for example `buildAuthorizationUrl`. For each of these, the same rule applies in the sense that both `authorizationParams` objects will be merged, where those provided to the method, override those provided when creating the instance.

```ts
const auth0 = new AuthClient({
  authorizationParams: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const auth0 = new AuthClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when creating an instance of `AuthClient`:

```ts
const auth0 = new AuthClient({
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

### Configuring discovery cache

The SDK caches Auth0 OIDC discovery metadata in memory to avoid calling
`/.well-known/openid-configuration` on every flow.

Defaults:
- `ttl`: `600` seconds
- `maxEntries`: `100`

How it is used:
- Discovery metadata and JWKS are reused from in-memory cache across requests.
- `ttl` controls how long cached values are kept.
- `maxEntries` controls how many discovery entries are retained.

When to configure `discoveryCache`:
- [Multiple Custom Domains](https://auth0.com/docs/customize/custom-domains/multiple-custom-domains).
- High-throughput services where you want fewer metadata fetches.
- Memory-constrained environments where you want a smaller cache.

Most applications can keep the defaults. If you need different cache behavior, configure `discoveryCache`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const auth0 = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  discoveryCache: {
    ttl: 900,
    maxEntries: 200,
  },
});
```
To effectively disable discovery cache reuse, set `discoveryCache.ttl` to `0`.

## Building the Authorization URL

The SDK provides a method to build the authorization URL, which can be used to redirect the user to to authenticate with Auth0:

Typically, you will want to ensure that the `authorizationParams.redirect_uri` is set to the URL that the user will be redirected back to after authentication. This URL should be registered in the Auth0 dashboard as a valid callback URL. This can either be done globally, when creating an instance of `AuthClient`, or when calling `buildAuthorizationUrl`.

```ts
const authClient = new AuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const { authorizationUrl, codeVerifier } = await authClient.buildAuthorizationUrl();
```


Calling `buildAuthorizationUrl` will return an object with two properties: `authorizationUrl` and `codeVerifier`. The `authorizationUrl` is the URL that should be used to redirect the user to authenticate with Auth0. The `codeVerifier` is a random string that should be stored securely, and will be used to exchange the authorization code for tokens.

> [!IMPORTANT]  
> You will need to register the `redirect_uri` in your Auth0 Application as an **Allowed Callback URL** via the [Auth0 Dashboard](https://manage.auth0.com).

### Passing `authorizationParams`

In order to customize the authorization parameters that will be added to the `/authorize` URL when calling `buildAuthorizationUrl()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const authClient = new AuthClient({
  authorizationParams: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const authClient = new AuthClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `buildAuthorizationUrl()`:

```ts
await authClient.buildAuthorizationUrl({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `buildAuthorizationUrl`, will override the same, statically configured, `authorizationParams` property on `AuthClient`.

### Using Pushed Authorization Requests

Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server by setting `pushedAuthorizationRequests` to true when calling `buildAuthorizationUrl`. 

```ts
const authorizationUrl = await authClient.buildAuthorizationUrl({ pushedAuthorizationRequests: true });
```
When calling `buildAuthorizationUrl` with `pushedAuthorizationRequests` set to true, the SDK will send all the parameters to Auth0 using an HTTP Post request, and returns an URL that you can use to redirect the user to in order to finish the login flow.

> [!IMPORTANT]  
> Using Pushed Authorization Requests requires the feature to be enabled in the Auth0 dashboard. Read [the documentation](https://auth0.com/docs/get-started/applications/configure-par) on how to configure PAR before enabling it in the SDK.

### Using Pushed Authorization Requests and Rich Authorization Requests

When using Pushed Authorization Requests, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`, additionally to setting `pushedAuthorizationRequests` to true.

```ts
const { authorizationUrl, codeVerifier } = await authClient.buildAuthorizationUrl({ 
  pushedAuthorizationRequests: true,
  authorizationParams: {
    authorization_details: JSON.stringify([{
      type: '<type>',
      // additional fields here
    }
  }])
});
```

When completing the interactive login flow, the SDK will expose the `authorizationDetails` in the returned value:

```ts
const { authorizationDetails } = await authClient.getTokenByCode(url, { codeVerifier });
console.log(authorizationDetails.type);
```

> [!IMPORTANT]  
> Using Pushed Authorization Requests and Rich Authorization Requests requires both features to be enabled in the Auth0 dashboard. Read [the documentation on how to configure PAR](https://auth0.com/docs/get-started/applications/configure-par), and [the documentation on how to configure RAR](https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests) before enabling it in the SDK.

## Building Link User URL

The SDK provides a method to build the Link User URL, which can be used to redirect the user to to link a user account at Auth0.

Typically, you will want to ensure that the `authorizationParams.redirect_uri` is set to the URL that the user will be redirected back to after linking the user. This URL should be registered in the Auth0 dashboard as a valid callback URL. This can either be done globally, when creating an instance of `AuthClient`, or when calling `buildLinkUserUrl`.

```ts
const authClient = new AuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const { linkUserUrl, codeVerifier } = await authClient.buildLinkUserUrl();
```

Calling `buildLinkUserUrl` will return an object with two properties: `linkUserUrl` and `codeVerifier`. The `linkUserUrl` is the URL that should be used to redirect the user to link a user account at Auth0. The `codeVerifier` is a random string that should be stored securely, and will be used to exchange the authorization code for tokens after successful account linking.

> [!IMPORTANT]  
> You will need to register the `redirect_uri` in your Auth0 Application as an **Allowed Callback URL** via the [Auth0 Dashboard](https://manage.auth0.com).

### Passing `authorizationParams`

In order to customize the authorization parameters that will be added to the `/authorize` URL when calling `buildLinkUserUrl()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const authClient = new AuthClient({
  authorizationParams: {
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const authClient = new AuthClient({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `buildLinkUserUrl()`:

```ts
await authClient.buildLinkUserUrl({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `buildLinkUserUrl`, will override the same, statically configured, `authorizationParams` property on `AuthClient`.

## Building Unlink User URL
The SDK provides a method to build the Unlink User URL, which can be used to redirect the user to to unlink a user account at Auth0.
Typically, you will want to ensure that the `authorizationParams.redirect_uri` is set to the URL that the user will be redirected back to after unlinking the user. This URL should be registered in the Auth0 dashboard as a valid callback URL. This can either be done globally, when creating an instance of `AuthClient`, or when calling `buildUnlinkUserUrl`.
```ts
const authClient = new AuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const { unlinkUserUrl, codeVerifier } = await authClient.buildUnlinkUserUrl();
```
Calling `buildUnlinkUserUrl` will return an object with two properties: `unlinkUserUrl` and `codeVerifier`. The `unlinkUserUrl` is the URL that should be used to redirect the user to unlink a user account at Auth0. The `codeVerifier` is a random string that should be stored securely, and will be used to exchange the authorization code for tokens after successful account linking.
> [!IMPORTANT]  
> You will need to register the `redirect_uri` in your Auth0 Application as an **Allowed Callback URL** via the [Auth0 Dashboard](https://manage.auth0.com).
### Passing `authorizationParams`
In order to customize the authorization parameters that will be added to the `/authorize` URL when calling `buildUnlinkUserUrl()`, you can statically configure them when instantiating the client using `authorizationParams`:
```ts
const authClient = new AuthClient({
  authorizationParams: {
    audience: "urn:custom:api",
  },
});
```
Apart from first-class properties such as `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.
```ts
const authClient = new AuthClient({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```
If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `buildUnlinkUserUrl()`:
```ts
await authClient.buildUnlinkUserUrl({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```
Keep in mind that, any `authorizationParams` property specified when calling `buildUnlinkUserUrl`, will override the same, statically configured, `authorizationParams` property on `AuthClient`.

## Using Client-Initiated Backchannel Authentication

Using Client-Initiated Backchannel Authentication can be done by calling `backchannelAuthentication()`:

```ts
const tokenResponse = await authClient.backchannelAuthentication({
  bindingMessage: '',
  loginHint: {
    sub: 'auth0|123456789'
  }
});
```

- `bindingMessage`: A human-readable message to be displayed at the consumption device and authentication device. This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
- `loginHint.sub`: The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.

> [!IMPORTANT]  
> Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
> Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

By default, the `backchannelAuthentication` method will handle the entire flow, including polling the token endpoint until the user has completed the authentication on their device. If you want to handle the polling yourself, you can do so by calling `initiateBackchannelAuthentication` and `backchannelAuthenticationGrant` separately:

```ts
const { authReqId, expiresIn, interval } = await authClient.initiateBackchannelAuthentication({
  bindingMessage: '',
  loginHint: {
    sub: 'auth0|123456789'
  }
});

// Poll the token endpoint using the authReqId
const tokenResponse = await authClient.backchannelAuthenticationGrant({ authReqId });
```

The `interval` property returned from `initiateBackchannelAuthentication` indicates the minimum amount of time in seconds that the client should wait between polling requests to the token endpoint. The `expiresIn` property indicates the amount of time in seconds that the authentication request is valid for. After this time, the user will need to start a new authentication request.

To learn more about the properties returned from `initiateBackchannelAuthentication`, please see the [Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow/user-authentication-with-ciba#step-3-client-application-polls-for-a-response).

## Retrieving a Token using an Authorization Code

After the user has authenticated with Auth0, they will be redirected back to the `redirect_uri` specified in the `authorizationParams`. The SDK provides a method, `getTokenByCode`, to exchange the authorization code for tokens by parsing the URL, containing `code`.

```ts
const { authorizationUrl, codeVerifier } = await authClient.buildAuthorizationUrl();

// Redirect the user to the authorization URL
// After the user authenticates, they will be redirected back to the redirect_uri
// with the authorization code
const url = 'http://localhost:3000/auth/callback?code=abc123';
const tokenResponse = await authClient.getTokenByCode(url, { codeVerifier });
```

If the login was initiated for a specific organization, pass `organization` to validate the returned ID token's organization claim. An organization ID (the `org_` prefix) is matched exactly against the `org_id` claim, while an organization name is matched case-insensitively against the `org_name` claim:

```ts
const tokenResponse = await authClient.getTokenByCode(url, {
  codeVerifier,
  organization: 'org_abc123',
});
```

If the claim is missing or does not match, `getTokenByCode` throws an `OrganizationValidationError`.

## Retrieving a Token using a Refresh Token

When a Refresh Token is available, the SDK's `getTokenByRefreshToken` can be used to retrieve a new Access Token by providing it said Refresh token:

```ts
const refreshToken = '<refresh_token>';
const tokenResponse = await authClient.getTokenByRefreshToken({ refreshToken });
```

The `tokenResponse` object will contain the new Access Token, and optionally a new Refresh Token (when Refresh Token Rotation is enabled in the Auth0 Dashboard).

### Using Multi-Resource Refresh Tokens (MRRT)

When refresh token policies are configured in your application, you can use a single refresh token to obtain access tokens for different APIs (audiences). Simply pass the desired `audience` parameter along with the refresh token:

```ts
const refreshToken = '<refresh_token>';
const tokenResponse = await authClient.getTokenByRefreshToken({
  refreshToken,
  audience: 'https://another-api.example.com'
});
```

You can also combine `audience` with `scope` to request specific permissions for the target API:

```ts
const refreshToken = '<refresh_token>';
const tokenResponse = await authClient.getTokenByRefreshToken({
  refreshToken,
  audience: 'https://another-api.example.com',
  scope: 'read:users write:users'
});
```

### Modifying Token Scopes

When using refresh tokens with the same audience, you can modify the scopes of your access token by passing the `scope` parameter:

```ts
const refreshToken = '<refresh_token>';
// Downscope: Request fewer permissions than originally granted
// If original access token had 'read:profile write:profile',
// you can request only 'read:profile'
const tokenResponse = await authClient.getTokenByRefreshToken({
  refreshToken,
  scope: 'read:profile'
});
```

Depending on your application's refresh token policies, you can also request additional scopes beyond those in the original access token:

```ts
const refreshToken = '<refresh_token>';
// Request additional scopes (e.g., adding 'delete:profile')
// If original access token had 'read:profile write:profile',
// you can request 'delete:profile' if allowed by your refresh token policies
const tokenResponse = await authClient.getTokenByRefreshToken({
  refreshToken,
  scope: 'read:profile write:profile delete:profile'
});
```

> [!NOTE]
> Downscoping (requesting fewer permissions) is always permitted. However, requesting scopes beyond those in the original grant depends on your application's refresh token policies.

## Retrieving a Token using Resource Owner Password Grant

> [!IMPORTANT]  
> This flow should only be used from highly-trusted applications that cannot do redirects. If you can use redirect-based flows from your app, we recommend using the Authorization Code Flow instead.
> 
> See [Auth0 ROPG Documentation](https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token) for more information.

The SDK's `getTokenByPassword` can be used to retrieve an Access Token using the Resource Owner Password Grant. This flow allows users to authenticate by providing their username/password directly:

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
});
```

### Specifying a Realm

You can specify a realm (database connection) to authenticate against:

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
  realm: 'Username-Password-Authentication',
});
```

### Specifying Audience and Scope

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
  audience: 'https://api.example.com',
  scope: 'openid profile email',
});
```

### Passing the End-User's IP Address

For brute-force protection to work in server-side scenarios, you can pass the end-user's IP address using the `auth0ForwardedFor` parameter:

```ts
const tokenResponse = await authClient.getTokenByPassword({
  username: 'user@example.com',
  password: 'password123',
  auth0ForwardedFor: req.ip, // Express.js example
});
```

## Retrieving a Token using Client Credentials

The SDK's `getTokenByClientCredentials` can be used to retrieve an Access Token using the Client Credentials flow. This is useful for machine-to-machine authentication scenarios where no user interaction is required:

```ts
const audience = 'https://my-api.example.com';
const tokenResponse = await authClient.getTokenByClientCredentials({ audience });
```

You can also specify an organization if needed:

```ts
const audience = 'https://my-api.example.com';
const organization = 'my-org-id';
const tokenResponse = await authClient.getTokenByClientCredentials({ 
  audience, 
  organization 
});
```

- `audience`: The audience (API identifier) for which the token should be requested.
- `organization`: Optional organization identifier when requesting tokens for a specific organization.

> [!IMPORTANT]  
> The Client Credentials flow requires your Auth0 application to be configured as a **Machine to Machine** application with the appropriate API permissions granted in the [Auth0 Dashboard](https://manage.auth0.com).

## Retrieving a Token for a Connection

The SDK's `getTokenForConnection()` can be used to retrieve an Access Token for a connection (e.g. `google-oauth2`) for the current logged-in user:

```ts
const refreshToken = '<refresh_token>';
const connection = 'google-oauth2';
const loginHint = '<login_hint>';
const tokenResponseForGoogle = await authClient.getTokenForConnection({ connection, refreshToken });
```

- `refreshToken`: The refresh token to use to retrieve the access token for the connection.
- `accessToken`: The access token to use to exchange for an access token for the connection.
- `connection`: The connection for which an access token should be retrieved, e.g. `google-oauth2` for Google.
- `loginHint`: Optional login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user.

Either the `refreshToken` or `accessToken` parameter can be specified, but not both.

Note that, when using `google-oauth2`, it's required to set both `authorizationParams.access_type` and `authorizationParams.prompt` to `offline` and `consent` respectively when building the authorization URL.

```ts
const { authorizationUrl, codeVerifier } = await authClient.buildAuthorizationUrl({
  authorizationParams: {
    access_type: 'offline',
    prompt: 'consent',
  },
});
```

## Building the Logout URL

The SDK provides a method to build the logout URL, which can be used to redirect the user to to logout from Auth0:

```ts
const returnTo = 'http://localhost:3000';
const logoutUrl = await authClient.logout({ returnTo });

// Redirect user to logoutUrl to logout from Auth0
```

> [!IMPORTANT]  
> You will need to register the `returnTo` in your Auth0 Application as an **Allowed Logout URL** via the [Auth0 Dashboard](https://manage.auth0.com).

## Verifying the Logout Token

In order to verify the logout token, the SDK provides a method `verifyLogoutToken`:

```ts
const logoutToken = '...';
const { sid, sub } = await authClient.verifyLogoutToken({ logoutToken });
```

When the verification is successful, the `sid` and `sub` claims will be returned. If not, an error will be thrown.

## Using Passwordless Authentication

Passwordless lets users authenticate with a one-time code (or magic link) delivered by email or SMS, rather than a password. There are two steps:

1. **Start** — send the code/link via the `passwordless` sub-client (`sendEmail` / `sendSms`).
2. **Login** — exchange the one-time code for tokens via `getTokenByPasswordlessEmail` / `getTokenByPasswordlessSms`.

> [!IMPORTANT]
> Your Auth0 application must have the **Passwordless OTP** grant enabled, with the Email and/or SMS connection configured. See the [Auth0 Passwordless documentation](https://auth0.com/docs/authenticate/passwordless) for tenant setup.

### Sending an Email Code

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

await authClient.passwordless.sendEmail({
  email: 'user@example.com',
  send: 'code', // default; can be omitted
});
```

### Sending an Email Magic Link

Pass `send: 'link'` together with the `authParams` used when the link is followed. Your application owns the `state` value. Completing a magic link is a no-PKCE authorization-code exchange handled by `getTokenByMagicLinkCode` (see below), **not** by the passwordless login methods and **not** by the PKCE-bound `getTokenByCode`.

```ts
await authClient.passwordless.sendEmail({
  email: 'user@example.com',
  send: 'link',
  authParams: {
    redirect_uri: 'https://my-app.example.com/callback',
    response_type: 'code',
    scope: 'openid profile',
    state: '<application_generated_state>',
  },
});
```

Completing the magic link on the callback route. The delivery endpoint registers no PKCE challenge, so the exchange omits the verifier; pass `expectedState` to validate the returned `state`.

```ts
// On GET /callback?code=...&state=...
const tokenResponse = await authClient.getTokenByMagicLinkCode(url, {
  expectedState: '<application_generated_state>',
});
```

> [!NOTE]
> For session management (state generation/persistence + session write), prefer `@auth0/auth0-server-js`'s `startPasswordless({ connection: 'email', send: 'link' })` / `completePasswordlessMagicLink`, which wrap this primitive.

### Sending an SMS Code

The phone number must be in E.164 format. SMS supports one-time codes only (no magic link).

```ts
await authClient.passwordless.sendSms({
  phoneNumber: '+14155550100',
});
```

### Logging in with an Email Code

Exchange the code the user received for a token set. Include `openid` in `scope` to receive an id_token, and `offline_access` to receive a refresh_token — the SDK does not inject scopes at this layer.

```ts
const tokenResponse = await authClient.getTokenByPasswordlessEmail({
  email: 'user@example.com',
  code: '123456',
  scope: 'openid profile',
});

// tokenResponse.accessToken, tokenResponse.idToken, tokenResponse.refreshToken
```

A `PasswordlessVerifyError` is thrown when the code is invalid, expired, or rate-limited.

### Logging in with an SMS Code

```ts
const tokenResponse = await authClient.getTokenByPasswordlessSms({
  phoneNumber: '+14155550100',
  code: '123456',
});
```

### Handling Multi-Factor Authentication

If the connection requires MFA, the login methods throw a `PasswordlessVerifyError` whose `cause.error` is `'mfa_required'`. Narrow it with the `isMfaRequiredError` type guard to read `cause.mfa_token`, then use it with the [MFA client](#using-multi-factor-authentication-mfa) to drive the challenge.

```ts
import { isMfaRequiredError } from '@auth0/auth0-auth-js';

try {
  await authClient.getTokenByPasswordlessEmail({ email: 'user@example.com', code: '123456' });
} catch (error) {
  if (isMfaRequiredError(error)) {
    const authenticators = await authClient.mfa.listAuthenticators({ mfaToken: error.cause.mfa_token });
    // ... continue the MFA challenge flow
  }
}
```

## Using Multi-Factor Authentication (MFA)

The SDK provides an MFA client to manage multi-factor authentication for your users. The MFA client is accessible via the `mfa` property on the `AuthClient` instance.

> [!IMPORTANT]
> MFA operations require an MFA token. This token is available on the error's `cause` when the server returns `mfa_required` during the authentication flow. Use the `isMfaRequiredError` type guard to detect this condition and access the token.

[Refer API Docs ](https://auth0.com/docs/api/authentication/muti-factor-authentication/request-mfa-challenge)

### Handling the MFA Required Response

When the server requires multi-factor authentication, token request methods (`getTokenByPassword`, `getTokenByRefreshToken`, `exchangeToken`, `passkey.getTokenByPasskey`) throw their usual error class (`TokenByPasswordError`, `TokenByRefreshTokenError`, `TokenExchangeError`, `PasskeyGetTokenError`) with extra MFA context on `cause`:

| Field | Type | Description |
|-------|------|-------------|
| `cause.error` | `'mfa_required'` | Indicates MFA is required |
| `cause.mfa_token` | `string` | Token to pass to MFA APIs |
| `cause.mfa_requirements` | `{ challenge?: Array<{ type: string }>; enroll?: Array<{ type: string }> }` | Which factors the user must challenge or enroll (optional) |

Use the exported `isMfaRequiredError` type guard to detect and narrow the error:

```ts
import { AuthClient, isMfaRequiredError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

try {
  const tokens = await authClient.getTokenByPassword({
    username: 'user@example.com',
    password: 'password123',
  });
} catch (error) {
  if (isMfaRequiredError(error)) {
    // TypeScript narrows: error.cause.mfa_token is guaranteed to be a string
    const { mfa_token, mfa_requirements } = error.cause;

    if (mfa_requirements?.enroll?.length) {
      // User needs to enroll a new factor — see "Enrolling an Authenticator" below
      const enrollment = await authClient.mfa.enrollAuthenticator({
        mfaToken: mfa_token,
        authenticatorTypes: ['otp'],
      });
    } else {
      // User has enrolled factors — see "Challenging an Authenticator" below
      const challenge = await authClient.mfa.challengeAuthenticator({
        mfaToken: mfa_token,
        challengeType: 'otp',
      });
    }
  }
}
```

The same pattern works for refresh token and token exchange flows:

```ts
import { isMfaRequiredError } from '@auth0/auth0-auth-js';

try {
  const tokens = await authClient.getTokenByRefreshToken({
    refreshToken: 'existing_refresh_token',
  });
} catch (error) {
  if (isMfaRequiredError(error)) {
    // Step-up MFA required for this audience/scope
    const challenge = await authClient.mfa.challengeAuthenticator({
      mfaToken: error.cause.mfa_token,
      challengeType: 'otp',
    });
  }
}
```

### Enrolling an Authenticator

To enroll a new MFA authenticator, use the `enrollAuthenticator` method. This example shows how to enroll an OTP authenticator (for TOTP apps like Google Authenticator or Auth0):

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Enroll an OTP authenticator
const mfaToken = '<mfa_token_from_challenge>';
const enrollmentResponse = await authClient.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken,
});

// The response contains the secret and QR code URI for user to scan
// enrollmentResponse.secret - Base32-encoded secret for TOTP generation
// enrollmentResponse.barcodeUri - URI for generating QR code
```

You can also enroll SMS-based authenticators:

```ts
// Enroll an SMS authenticator
const smsEnrollment = await authClient.mfa.enrollAuthenticator({
  authenticatorTypes: ['oob'],
  oobChannels: ['sms'],
  phoneNumber: '+1234567890',
  mfaToken,
});
```

### Listing Authenticators

To retrieve all enrolled authenticators for a user, use the `listAuthenticators` method:

```ts
const mfaToken = '<mfa_token>';
const authenticators = await authClient.mfa.listAuthenticators({ mfaToken });

// authenticators is an array of Authenticator objects
// Each authenticator has: id, authenticatorType, active, name, oobChannels (for OOB types), type
```

### Challenging an Authenticator

To initiate an MFA challenge for verification, use the `challengeAuthenticator` method:

```ts
const mfaToken = '<mfa_token>';

// Challenge with OTP
const otpChallenge = await authClient.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken,
});

// Challenge with SMS (OOB)
const smsChallenge = await authClient.mfa.challengeAuthenticator({
  challengeType: 'oob',
  authenticatorId: 'sms|dev_abc123',
  mfaToken,
});

// For OOB challenges, the response includes an oobCode
// smsChallenge.oobCode - Out-of-band code for verification
```

### Deleting an Authenticator

To remove a previously enrolled authenticator, use the `deleteAuthenticator` method:

```ts
const mfaToken = '<mfa_token>';
const authenticatorId = 'totp|dev_abc123';

await authClient.mfa.deleteAuthenticator({ authenticatorId, mfaToken });
```

## Using Passkeys

The SDK provides a passkey client for native WebAuthn-based authentication. The passkey client is accessible via the `passkey` property on the `AuthClient` instance.

> [!IMPORTANT]
> Passkeys require the following prerequisites:
> - A [custom domain](https://auth0.com/docs/customize/custom-domains) configured on your Auth0 tenant (e.g., `auth.example.com`, not `example.auth0.com`). The custom domain serves as the WebAuthn Relying Party (RP) ID.
> - A database connection with the `passkey` authentication method enabled.
> - Your application must be served over HTTPS on a domain that matches or is a subdomain of the configured RP ID.

The SDK is platform-agnostic — it does not call WebAuthn browser APIs directly. Your application is responsible for calling `navigator.credentials.create()` or `navigator.credentials.get()` and serializing the credential response before passing it to the SDK.

> [!IMPORTANT]
> **Client authentication differs across the passkey methods:**
> - `register()` and `challenge()` request a challenge using only the `client_id`, so they work with **public clients** (e.g. SPAs / native apps) as well as confidential clients.
> - `getTokenByPasskey()` performs the token exchange and **requires a confidential client** — you must configure either a `clientSecret` or a `clientAssertionSigningKey` (private key JWT). Called on a public client (no credentials), it throws (a `PasskeyGetTokenError` whose `cause` reports that a client secret or client assertion signing key must be provided).

Learn more: [Passkeys](https://auth0.com/docs/authenticate/database-connections/passkeys) | [Native Passkeys API](https://auth0.com/docs/authenticate/database-connections/passkeys/native-passkeys-api)

### Requesting a Signup Challenge

To register a new passkey for a user, request a signup challenge. The response contains WebAuthn public key creation options that should be passed to `navigator.credentials.create()`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_CUSTOM_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  name: 'Jane Doe',
});

// challenge.authSession — session identifier needed for the token exchange step
// challenge.authnParamsPublicKey — pass to navigator.credentials.create({ publicKey: ... })
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `email` | Optional | `string` | User's email address. Include if `email` is configured as an identifier in your database connection's [user attributes](https://auth0.com/docs/authenticate/database-connections/passkeys). |
| `username` | Optional | `string` | User's username. Include if `username` is configured as an identifier in your database connection's user attributes. |
| `phoneNumber` | Optional | `string` | User's phone number. Include if `phone` is configured as an identifier in your database connection's user attributes. |
| `name` | Optional | `string` | User's full display name. |
| `givenName` | Optional | `string` | User's given (first) name. |
| `familyName` | Optional | `string` | User's family (last) name. |
| `nickname` | Optional | `string` | User's nickname. |
| `picture` | Optional | `string` | URL to the user's profile picture. |
| `userMetadata` | Optional | `Record<string, string>` | Arbitrary metadata stored in the user's `user_metadata` field. |
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `organization` | Optional | `string` | Organization ID or name. Scopes the user to the specified organization context. |

> [!NOTE]
> Which identifiers (`email`, `username`, `phoneNumber`) you should provide depends on what's enabled in your Auth0 tenant's database connection attributes. Provide the identifiers that match your connection's configuration.

You can include additional user profile fields when [Flexible Identifiers](https://auth0.com/docs/authenticate/database-connections/passkeys) is enabled on your database connection:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  name: 'Jane Doe',
  givenName: 'Jane',
  familyName: 'Doe',
  phoneNumber: '+1234567890',
  username: 'janedoe',
  userMetadata: { preferred_language: 'en' },
});
```

To specify a database connection:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  realm: 'Username-Password-Authentication',
});
```

To register within an organization context:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  organization: 'org_abc123',
});
```

### Requesting a Login Challenge

To authenticate with an existing passkey, request a login challenge. The response contains WebAuthn public key request options that should be passed to `navigator.credentials.get()`:

```ts
const challenge = await authClient.passkey.challenge();

// challenge.authSession — session identifier needed for the token exchange step
// challenge.authnParamsPublicKey — pass to navigator.credentials.get({ publicKey: ... })
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `organization` | Optional | `string` | Organization ID or name. Scopes the authentication to the specified organization context. |

To specify a database connection:

```ts
const challenge = await authClient.passkey.challenge({
  realm: 'Username-Password-Authentication',
});
```

To authenticate within an organization context:

```ts
const challenge = await authClient.passkey.challenge({
  organization: 'org_abc123',
});
```

### Exchanging a Credential for Tokens

After the user completes the WebAuthn ceremony (either signup or login), exchange the credential response for Auth0 tokens.

> [!IMPORTANT]
> Unlike `register()` and `challenge()`, `getTokenByPasskey()` **requires a confidential client**. Configure the `AuthClient` with a `clientSecret` or a `clientAssertionSigningKey`:
>
> ```ts
> const authClient = new AuthClient({
>   domain: '<AUTH0_CUSTOM_DOMAIN>',
>   clientId: '<AUTH0_CLIENT_ID>',
>   clientSecret: '<AUTH0_CLIENT_SECRET>', // or clientAssertionSigningKey
> });
> ```

The WebAuthn API returns binary `ArrayBuffer` fields. These must be converted to base64url-encoded strings before passing to this method. Here is a helper function you can use:

```ts
function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
```

For a **signup** (registration) ceremony, the credential response includes `attestationObject`:

```ts
const credential = await navigator.credentials.create({
  publicKey: challenge.authnParamsPublicKey,
});

const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
    },
  },
});
```

For a **login** (authentication) ceremony, the credential response includes `authenticatorData`, `signature`, and `userHandle`:

```ts
const credential = await navigator.credentials.get({
  publicKey: challenge.authnParamsPublicKey,
});

const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: bufferToBase64url(credential.response.userHandle),
    },
  },
});
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `authSession` | Required | `string` | The session identifier returned from `register()` or `challenge()`. |
| `credential` | Required | `PasskeyCredentialResponse` | The serialized WebAuthn credential. For signup: include `attestationObject`. For login: include `authenticatorData`, `signature`, and `userHandle`. |
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `scope` | Optional | `string` | OAuth scopes to request (e.g., `'openid profile email'`). |
| `audience` | Optional | `string` | API identifier for the access token. Without this, an opaque token is returned instead of a JWT. |
| `organization` | Optional | `string` | Organization ID or name. Scopes tokens to the specified organization context. |

You can specify audience and scope to control the access token:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  audience: 'https://api.example.com',
  scope: 'openid profile email',
});
```

To specify a database connection:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  realm: 'Username-Password-Authentication',
});
```

To exchange within an organization context:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  organization: 'org_abc123',
});
```

When `organization` is provided, the returned ID token's organization claim is validated against it (an `org_` prefix is matched exactly against `org_id`, otherwise the value is matched case-insensitively against `org_name`). A mismatch throws an `OrganizationValidationError`.

### Error Handling

All passkey methods throw typed errors that can be caught and handled individually:

```ts
import {
  AuthClient,
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
} from '@auth0/auth0-auth-js';

try {
  const challenge = await authClient.passkey.register({
    email: 'user@example.com',
  });
} catch (error) {
  if (error instanceof PasskeyRegisterError) {
    console.error(error.message);       // Human-readable error message
    console.error(error.code);          // 'passkey_register_error'
    console.error(error.cause?.error);  // API error code (e.g., 'invalid_request')
    console.error(error.cause?.error_description); // API error detail
  }
}

try {
  const challenge = await authClient.passkey.challenge();
} catch (error) {
  if (error instanceof PasskeyChallengeError) {
    console.error(error.message);
    console.error(error.code);          // 'passkey_challenge_error'
  }
}

try {
  const tokens = await authClient.passkey.getTokenByPasskey({
    authSession: challenge.authSession,
    credential: serializedCredential,
  });
} catch (error) {
  if (error instanceof PasskeyGetTokenError) {
    console.error(error.message);
    console.error(error.code);          // 'passkey_get_token_error'
    console.error(error.cause?.error);  // e.g., 'invalid_grant', 'access_denied'
  }
}
```
> [!NOTE]
> When MFA is enabled, `getTokenByPasskey()` can fail with an `mfa_required` response — the passkey is verified, but the user must still complete a second factor. The thrown `PasskeyGetTokenError` carries `cause.mfa_token` and `cause.mfa_requirements` so you can continue with the MFA APIs. Use the `isMfaRequiredError` type guard to detect and narrow it:
>
> ```ts
> import { isMfaRequiredError } from '@auth0/auth0-auth-js';
>
> try {
>   const tokens = await authClient.passkey.getTokenByPasskey({
>     authSession: challenge.authSession,
>     credential: serializedCredential,
>   });
> } catch (error) {
>   if (isMfaRequiredError(error)) {
>     // error.cause.mfa_token is guaranteed to be a string here
>     const challenge = await authClient.mfa.challengeAuthenticator({
>       mfaToken: error.cause.mfa_token,
>       challengeType: 'otp',
>     });
>   }
> }
> ```
>
> See [Handling the MFA Required Response](#handling-the-mfa-required-response) for the full flow.

## Custom Token Exchange

`exchangeToken` implements [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) via an Auth0 Token Exchange Profile. It lets you swap a token issued by an external system (an MCP server, a legacy IdP, a partner service) for Auth0 tokens, preserving the user's identity.

### Basic Exchange

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
});

const tokens = await authClient.exchangeToken({
  subjectToken: externalToken,
  subjectTokenType: 'urn:acme:legacy-token',
  audience: 'https://api.example.com',
  scope: 'openid profile read:data',
});

console.log(tokens.accessToken);
```

When `organization` is provided and the exchange returns an ID token, its organization claim is validated against the requested value (an `org_` prefix is matched exactly against `org_id`, otherwise the value is matched case-insensitively against `org_name`). A missing or mismatched claim throws an `OrganizationValidationError`.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: externalToken,
  subjectTokenType: 'urn:acme:legacy-token',
  audience: 'https://api.example.com',
  scope: 'openid profile read:data',
  organization: 'org_abc123',
});
```

### Delegation Exchange with Actor Token

When an intermediate service acts on behalf of a user, pass the service's own token as `actorToken`. Both `actorToken` and `actorTokenType` must be provided together.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: userToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  actorToken: serviceAccountToken,
  actorTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'https://api.example.com',
});
```

### Reading the act Claim

When a delegation exchange succeeds, the `act` claim on `TokenResponse` identifies the acting party. It is sourced from the ID token when one is issued, or from the JWT access token in M2M flows where no ID token is returned.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: userToken,
  subjectTokenType: 'urn:acme:user-token',
  actorToken: serviceToken,
  actorTokenType: 'urn:acme:service-token',
  audience: 'https://api.example.com',
  scope: 'openid',
});

if (tokens.act) {
  console.log(tokens.act.sub);  // Subject of the acting party
  console.log(tokens.act.iss);  // Optional issuer of the actor token
}
```

### M2M Delegation (No ID Token)

In machine-to-machine flows the `openid` scope is not requested, so no ID token is issued. The SDK automatically falls back to reading the `act` claim from the JWT access token. If the access token is opaque, `act` will be `undefined`.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: serviceAToken,
  subjectTokenType: 'urn:acme:service-token',
  actorToken: serviceBToken,
  actorTokenType: 'urn:acme:service-token',
  audience: 'https://api.example.com',
  // no 'openid' in scope — no id_token will be returned
});

// act is populated from the JWT access token if it carries the claim
console.log(tokens.act?.sub);
```

### Error Handling

```ts
import { AuthClient, TokenExchangeError, OrganizationValidationError } from '@auth0/auth0-auth-js';

try {
  const tokens = await authClient.exchangeToken({
    subjectToken: externalToken,
    subjectTokenType: 'urn:acme:legacy-token',
    audience: 'https://api.example.com',
    organization: 'org_abc123',
  });
} catch (error) {
  if (error instanceof OrganizationValidationError) {
    // The ID token's organization claim did not match the requested organization.
    console.error(error.message);
    console.error(error.code);          // 'organization_validation_error'
  } else if (error instanceof TokenExchangeError) {
    console.error(error.message);       // Human-readable error message
    console.error(error.code);          // 'token_exchange_error'
    console.error(error.cause?.error);  // e.g., 'invalid_grant', 'access_denied'
  }
}
```

## Using Database Connections (Sign-up & Change Password)

The SDK exposes a database client via the `database` property on the `AuthClient` instance. It wraps the public `/dbconnections/signup` and `/dbconnections/change_password` Authentication API endpoints, letting you register users and trigger password-reset emails against an Auth0 [database connection](https://auth0.com/docs/authenticate/database-connections) such as `Username-Password-Authentication`.

> [!IMPORTANT]
> These endpoints are **public**: the SDK only sends `clientId` in the request body — never a client secret or assertion — so both public and confidential clients work. `changePassword` returns a **plain-text** confirmation string (read via `response.text()`), not JSON. For privacy, the server returns the same confirmation regardless of whether the email matches an existing account.

[Refer API Docs](https://auth0.com/docs/api/authentication/signup) | [Change Password](https://auth0.com/docs/api/authentication/database-ad-ldap-passive/change-password)

### Signing Up a User

`signUp` requires `email`, `password`, and `connection`. All other fields are optional. The result is normalized to `camelCase`, and `id` is resolved from whichever identifier the server returns (`id`, `_id`, or `user_id`).

```ts
import { AuthClient, SignUpError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

try {
  const user = await authClient.database.signUp({
    email: 'user@example.com',
    password: 'a-Str0ng-Password!',
    connection: 'Username-Password-Authentication',
    // Optional profile fields (sent as snake_case on the wire):
    username: 'jane',
    givenName: 'Jane',
    familyName: 'Doe',
    name: 'Jane Doe',
    nickname: 'jd',
    picture: 'https://example.com/jane.png',
    userMetadata: { plan: 'free' },
    // Optional per-request client override:
    // clientId: '<OTHER_CLIENT_ID>',
  });

  console.log(user.id);            // e.g. 'auth0|6a44...'; may be undefined if omitted by the server
  console.log(user.email);         // 'user@example.com'
  console.log(user.emailVerified); // false
} catch (error) {
  if (error instanceof SignUpError) {
    console.error(error.message);       // Human-readable message
    console.error(error.code);          // 'signup_error'
    console.error(error.cause?.error);  // e.g. 'invalid_signup', 'invalid_password', 'user_exists'
  }
}
```

The `SignUpResult` shape:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `string \| undefined` | Normalized identifier (`id` / `_id` / `user_id`); may be undefined |
| `email` | `string` | The registered email |
| `emailVerified` | `boolean` | Whether the email is already verified |
| `username`, `givenName`, `familyName`, `name`, `nickname`, `picture` | `string \| undefined` | Optional profile fields, mapped to `camelCase` |
| `userMetadata` | `Record<string, unknown> \| undefined` | Optional user metadata |

### Requesting a Password Change

`changePassword` requires `email` and `connection`. It triggers a password-reset email and resolves to the server's plain-text confirmation message.

```ts
import { AuthClient, ChangePasswordError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

try {
  const message = await authClient.database.changePassword({
    email: 'user@example.com',
    connection: 'Username-Password-Authentication',
    // Optional:
    // organization: 'org_123',
    // clientId: '<OTHER_CLIENT_ID>',
  });

  console.log(message); // "We've just sent you an email to reset your password."
} catch (error) {
  if (error instanceof ChangePasswordError) {
    console.error(error.message);       // Human-readable message
    console.error(error.code);          // 'change_password_error'
    console.error(error.cause?.error);  // server error code, when available
  }
}
```

### Error Handling

Both methods throw a dedicated error class — `SignUpError` or `ChangePasswordError`. Each carries a stable `code`, a human-readable `message`, and an optional `cause` populated from the Authentication API error response. The `cause` is sanitized to a fixed shape; unmodeled server fields are not exposed.

| Property | Type | Description |
|----------|------|-------------|
| `name` | `'SignUpError' \| 'ChangePasswordError'` | Error class name |
| `code` | `'signup_error' \| 'change_password_error'` | Stable, machine-readable code |
| `message` | `string` | Human-readable message (the server's `error_description` when present) |
| `cause` | `{ error: string; error_description: string; message?: string } \| undefined` | Sanitized API error body |

Validation failures are thrown synchronously before any network request when required fields are missing. Network failures are wrapped in the corresponding error class.
