# Authorization URLs

[← All examples](../EXAMPLES.md)

- [Building the Authorization URL](#building-the-authorization-url)
    - [Passing `authorizationParams`](#passing-authorizationparams)
    - [Using Pushed Authorization Requests](#using-pushed-authorization-requests)
    - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
- [Building Link User URL](#building-link-user-url)
    - [Passing `authorizationParams`](#passing-authorizationparams-1)
- [Building Unlink User URL](#building-unlink-user-url)
    - [Passing `authorizationParams`](#passing-authorizationparams-2)

## Building the Authorization URL

The SDK provides a method to build the authorization URL, which can be used to redirect the user to authenticate with Auth0:

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
const { authorizationUrl } = await authClient.buildAuthorizationUrl({ pushedAuthorizationRequests: true });
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
    }]),
  },
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

The SDK provides a method to build the Link User URL, which can be used to redirect the user to link a user account at Auth0.

Typically, you will want to ensure that the `authorizationParams.redirect_uri` is set to the URL that the user will be redirected back to after linking the user. This URL should be registered in the Auth0 dashboard as a valid callback URL. This can either be done globally, when creating an instance of `AuthClient`, or when calling `buildLinkUserUrl`.

```ts
const authClient = new AuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const { linkUserUrl, codeVerifier } = await authClient.buildLinkUserUrl({
  connection: 'google-oauth2',
  connectionScope: 'https://www.googleapis.com/auth/calendar',
  idToken: '<id_token>',
});
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
  connection: 'google-oauth2',
  connectionScope: 'https://www.googleapis.com/auth/calendar',
  idToken: '<id_token>',
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `buildLinkUserUrl`, will override the same, statically configured, `authorizationParams` property on `AuthClient`.

## Building Unlink User URL
The SDK provides a method to build the Unlink User URL, which can be used to redirect the user to unlink a user account at Auth0.
Typically, you will want to ensure that the `authorizationParams.redirect_uri` is set to the URL that the user will be redirected back to after unlinking the user. This URL should be registered in the Auth0 dashboard as a valid callback URL. This can either be done globally, when creating an instance of `AuthClient`, or when calling `buildUnlinkUserUrl`.
```ts
const authClient = new AuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const { unlinkUserUrl, codeVerifier } = await authClient.buildUnlinkUserUrl({
  connection: 'google-oauth2',
  idToken: '<id_token>',
});
```
Calling `buildUnlinkUserUrl` will return an object with two properties: `unlinkUserUrl` and `codeVerifier`. The `unlinkUserUrl` is the URL that should be used to redirect the user to unlink a user account at Auth0. The `codeVerifier` is a random string that should be stored securely, and will be used to exchange the authorization code for tokens after successful account unlinking.
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
  connection: 'google-oauth2',
  idToken: '<id_token>',
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```
Keep in mind that, any `authorizationParams` property specified when calling `buildUnlinkUserUrl`, will override the same, statically configured, `authorizationParams` property on `AuthClient`.
