# Retrieving Tokens

[← All examples](../EXAMPLES.md)

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
const tokenResponseForGoogle = await authClient.getTokenForConnection({ connection, refreshToken, loginHint });
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
