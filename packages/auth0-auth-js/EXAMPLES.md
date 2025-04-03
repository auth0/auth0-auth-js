# Examples

- [Configuration](#configuration)
    - [Configuring the Scopes](#configuring-the-scopes)
    - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
    - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
    - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
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
- [Retrieving a Token for a Connection](#retrieving-a-token-for-a-connection)
- [Building the Logout URL](#building-the-logout-url)
- [Verifying the Logout Token](#verifying-the-logout-token)

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

## Retrieving a Token using a Refresh Token

When a Refresh Token is available, the SDK's `getTokenByRefreshToken` can be used to retrieve a new Access Token by providing it said Refresh token:

```ts
const refreshToken = '<refresh_token>';
const tokenResponse = await authClient.getTokenByRefreshToken({ refreshToken });
```

The `tokenResponse` object will contain the new Access Token, and optionally a new Refresh Token (when Refresh Token Rotation is enabled in the Auth0 Dashboard).

## Retrieving a Token for a Connection

The SDK's `getTokenForConnection()` can be used to retrieve an Access Token for a connection (e.g. `google-oauth2`) for the current logged-in user:

```ts
const refreshToken = '<refresh_token>';
const connection = 'google-oauth2';
const loginHint = '<login_hint>';
const tokenResponseForGoogle = await authClient.getTokenForConnection({ connection, refreshToken });
```

- `refreshToken`: The refresh token to use to retrieve the access token.
- `connection`: The connection for which an access token should be retrieved, e.g. `google-oauth2` for Google.
- `loginHint`: Optional login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user. 

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