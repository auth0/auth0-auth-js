# Examples

- [Configuration](#configuration)
  - [Configuring the Store](#configuring-the-store)
    - [Stateless Store](#stateless-store)
    - [Stateful Store](#stateful-store)
  - [Configuring the Store Identifier](#configuring-the-store-identifier)
  - [Configuring the Scopes](#configuring-the-scopes)
  - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
  - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
  - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
- [Starting Interactive Login](#starting-interactive-login)
  - [Passing `authorizationParams`](#passing-authorization-params)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Using Pushed Authorization Requests](#the-returnto-parameter)
  - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions)
- [Completing Interactive Login](#completing-interactive-login)
  - [Retrieving `appState`](#retrieving-appstate)
  - [Passing `StoreOptions`](#passing-storeoptions-1)
- [Starting Link User](#starting-link-user)
  - [Passing `authorizationParams`](#passing-authorization-params-1)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Passing `StoreOptions`](#passing-storeoptions-1)
- [Completing Link User](#completing-link-user)
  - [Retrieving `appState`](#retrieving-appstate-1)
  - [Passing `StoreOptions`](#passing-storeoptions-2)
- [Login using Client-Initiated Backchannel Authentication](#login-using-client-initiated-backchannel-authentication)
  - [Using Rich Authorization Requests](#using-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions-2)
- [Retrieving the logged-in User](#retrieving-the-logged-in-user)
  - [Passing `StoreOptions`](#passing-storeoptions-3)
- [Retrieving an Access Token](#retrieving-an-access-token)
  - [Passing `StoreOptions`](#passing-storeoptions-4)
- [Retrieving an Access Token for a Connection](#retrieving-an-access-token-for-a-connections)
  - [Passing `StoreOptions`](#passing-storeoptions-5)
- [Logout](#logout)
  - [Passing the `returnTo` parameter](#passing-the-returnto-parameter)
  - [Passing `StoreOptions`](#passing-storeoptions-6)
- [Handle Backchannel Logout](#handle-backchannel-logout)
  - [Passing `StoreOptions`](#passing-storeoptions-7)

## Configuration

### Configuring the Store

The auth0-server-js SDK does not come with a built-in store for both transaction and state data, it's required to provide a persistent solution that fits your use-case.
The goal of auth0-server-js is to provide a flexible API that allows you to use any storage mechanism you prefer, but is mostly designed to work with cookie and session-based storage.

The SDK methods accept an optional `storeOptions` object that can be used to pass additional options to the storage methods, such as Request / Response object, allowing to control cookies in the storage layer.

For Web Applications, this may come down to a Stateless or Statefull session storage system.

#### Stateless Store

In stateless storage, the entire session data is stored in the cookie. This is the simplest form of storage, but it has some limitations, such as the maximum size of a cookie.

The implementation may vary depending on the framework of choice, here is an example using Fastify:


```ts
import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import { 
  AbstractStateStore,
  AbstractTransactionStore,
  ServerClient,
  StateData,
  TransactionData
} from '@auth0/auth0-server-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

const serverClient = new ServerClient<StoreOptions>({
  transactionStore: new StatelessTransactionStore({ secret: '<secret>' }),
  stateStore: new StatelessStateStore({ secret: '<secret>' }),
});

export class StatelessTransactionStore extends AbstractTransactionStore<StoreOptions> {
  async set(identifier: string, transactionData: TransactionData, removeIfExists?: boolean, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    // Note that `removeIfExists` is not used in Stateless storage, but it's kept for compatibility with Stateful storage.

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, transactionData, expiration);
    
    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const cookieValue = options.request.cookies[identifier];

    if (cookieValue) {
      return await this.decrypt(identifier, cookieValue);
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    options?.reply.clearCookie(identifier);
  }
}

export class StatelessStateStore extends AbstractStateStore<StoreOptions> {
  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: StoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    // Note that `removeIfExists` is not used in Stateless storage, but it's kept for compatibility with Stateful storage.

    const maxAge = ?; // Set the max age of the cookie
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: 'auto',
      maxAge,
    };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, stateData, expiration);

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const encryptedStateData = options.request.cookies[identifier];

    if (encryptedStateData) {
      return (await this.decrypt(identifier, encryptedStateData)) as StateData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    options?.reply.clearCookie(identifier);
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage instead.'
    );
  }
}
```

#### Stateful Store

In stateful storage, the session data is stored in a server-side storage mechanism, such as a database or cache. This allows for more flexibility in the size of the session data, but requires additional infrastructure to manage the storage.
The session is identified by a unique identifier that is stored in the cookie, which the storage would read in order to retrieve the session data from the server-side storage.


The implementation may vary depending on the framework of choice, here is an example using Fastify:

```ts
import type { FastifyReply, FastifyRequest } from "fastify";
import { CookieSerializeOptions } from '@fastify/cookie';
import { 
  AbstractStateStore,
  LogoutTokenClaims,
  ServerClient,
  StateData,
} from '@auth0/auth0-server-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

const serverClient = new ServerClient<StoreOptions>({
  transactionStore: new StatelessTransactionStore({ secret: '<secret>' }),
  stateStore: new StatefulStateStore({ secret: '<secret>' }),
});

export class StatefulStateStore extends AbstractStateStore<StoreOptions> {
  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: StoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    let sessionId = await this.getSessionId(identifier, options);

    // If this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session ID to prevent session fixation.
    if (sessionId && removeIfExists) {
      // Delete the session from the store by the sessionId.
      // await yourDeleteSessionLogic(sessionId);
      sessionId = generateId();
    }

    if (!sessionId) {
      sessionId = generateId();
    }

    const maxAge = ??; // Set the max age of the cookie
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: 'auto',
      maxAge,
    };
    const expiration = Date.now() / 1000 + maxAge;
    const encryptedStateData = await this.encrypt<{ id: string }>(
      identifier,
      {
        id: sessionId,
      },
      expiration
    );

    // Save the stateData in the store, identified by the sessionId.
    // await yourSaveSessionLogic(sessionId, stateData);

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      // Retrieve the stateData from the store, identified by the sessionId.
      // const stateData = await yourGetSessionLogic(sessionId);

      // If we have a session cookie, but no `stateData`, we should remove the cookie.
      if (!stateData) {
        options?.reply.clearCookie(identifier);
      }

      return stateData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      // Delete the session from the store by the sessionId.
      // await yourDeleteSessionLogic(sessionId);
    }

    options?.reply.clearCookie(identifier);
  }

  private async getSessionId(identifier: string, options: StoreOptions) {
    const cookieValue = options.request.cookies[identifier];
    if (cookieValue) {
      const sessionCookie = await this.decrypt<{ id: string }>(identifier, cookieValue);
      return sessionCookie.id;
    }
  }

  deleteByLogoutToken(claims: LogoutTokenClaims, options?: StoreOptions | undefined): Promise<void> {
    // Delete the session from the store by the LogoutTokenClaims (sub and sid)
    // await yourDeleteSessionByLogoutTokenLogic(sessionId);
  }
}
```

Note that `storeOptions` is optional, but required when wanting to interact with the framework to set cookies. Here's how to pass the `storeOptions` to `startInteractiveLogin()` in a Fastify application:

```ts
fastify.get('/auth/login', async (request, reply) => {
  const storeOptions = { request, reply };
  const authorizationUrl = await auth0Client.startInteractiveLogin({}, storeOptions);

  reply.redirect(authorizationUrl.href);
});
```

### Configuring the Store Identifier

By default, the SDK uses `__a0_tx` and `__a0_session` to identify the Transaction and State data in the store respectively.

To change this, the `transactionIdentifier` and `stateIdentifier` options can be set when instantiating `ServerClient`:

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const serverClient = new ServerClient({
  transactionIdentifier: '__my_tx',
  stateIdentifier: '__my_session',
});
```


### Configuring the Scopes

By default, the SDK will request an Access Token using `'openid profile email offline_access'` as the scope. This can be changed by configuring `authorizationParams.scope`:

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'scope_a openid profile email offline_access'
  }
});
```

In order to ensure the SDK can refresh tokens when expired, the `offline_access` scope should be included. It is also mandatory to include `openid` as part of `authrizationParams.scope`.


### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of ServerClient:

```ts
import { ServerClient } from '@auth0/auth0-server-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
....................REMOVED FOR BREVITY.........................
-----END PRIVATE KEY-----`;
const clientAssertionSigningKey = await importPKCS8(clientPrivateKey, 'RS256');
const serverClient = new ServerClient({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

Note that the private keys should not be committed to source control, and should be stored securely.


### Configuring the `authorizationParams` globally

The `authorizationParams` object can be used to customize the authorization parameters that will be passed to the `/authorize` endpoint. This object can be passed when creating an instance of `ServerClient`, but it can also be specified when calling certain methods of the SDK, for example `startInteractiveLogin()`. For each of these, the same rule applies in the sense that both `authorizationParams` objects will be merged, where those provided to the method, override those provided when creating the instance.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when creating an instance of `ServerClient`:

```ts
const serverClient = new ServerClient({
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

## Starting Interactive Login

As interactive login is a two-step process, it begins with configuring a `redirect_uri`, which is the URL Auth0 will redirect the user to after succesful authentication to complete the interactive login. Once configured, call `startInteractiveLogin` and redirect the user to the returned authorization URL:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  }
});
const authorizationUrl = await serverClient.startInteractiveLogin();
// Redirect user to authorizeUrl
```

### Passing `authorizationParams`

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startInteractiveLogin()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `startInteractiveLogin()`:

```ts
await serverClient.startInteractiveLogin({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `startInteractiveLogin`, will override the same, statically configured, `authorizationParams` property on `ServerClient`.


### Passing `appState` to track state during login

The `appState` parameter, passed to `startInteractiveLogin()`, can be used to track state which you want to get back after calling `completeInteractiveLogin`.

```ts
const authorizeUrl = await startInteractiveLogin({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await completeInteractiveLogin(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `authorizeUrl` and `url` are two distinct URLs.
> - `authorizeUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful authentication.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Using Pushed Authorization Requests

Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server by setting `pushedAuthorizationRequests` to true when calling `startInteractiveLogin`. 

```ts
const authorizationUrl = await serverClient.startInteractiveLogin({ pushedAuthorizationRequests: true });
```
When calling `startInteractiveLogin` with `pushedAuthorizationRequests` set to true, the SDK will send all the parameters to Auth0 using an HTTP Post request, and returns an URL that you can use to redirect the user to in order to finish the login flow.

> Using Pushed Authorization Requests requires the feature to be enabled in the Auth0 dashboard. Read [the documentation](https://auth0.com/docs/get-started/applications/configure-par) on how to configure PAR before enabling it in the SDK.

### Using Pushed Authorization Requests and Rich Authorization Requests

When using Pushed Authorization Requests, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`, additionally to setting `pushedAuthorizationRequests` to true.

```ts
const authorizationUrl = await serverClient.startInteractiveLogin({ 
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
const { authorizationDetails } = await serverClient.completeInteractiveLogin(url);
console.log(authorizationDetails.type);
```

> Using Pushed Authorization Requests and Rich Authorization Requests requires both features to be enabled in the Auth0 dashboard. Read [the documentation on how to configure PAR](https://auth0.com/docs/get-started/applications/configure-par), and [the documentation on how to configure RAR](https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests) before enabling it in the SDK.

### Passing `StoreOptions`

Just like most methods, `startInteractiveLogin` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const authorizeUrl = await serverClient.startInteractiveLogin({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Completing Interactive Login

As interactive login is a two-step process, after starting it, it also needs to be completed. This can be achieved using the SDK's `completeInteractiveLogin()`.

```ts
await auth.completeInteractiveLogin(url)
```

> The url passed to `completeInteractiveLogin` is the URL Auth0 redirects the user back to after successful authentication, and should contain `state` and either `code` or `error`.

### Retrieving `appState`

The `appState` parameter, passed to `startInteractiveLogin()`, can be retrieved again when calling `completeInteractiveLogin()`.

```ts
const authorizeUrl = await serverClient.startInteractiveLogin({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeInteractiveLogin(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `authorizeUrl` and `url` are two distinct URLs.
> - `authorizeUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful authentication.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.


### Passing `StoreOptions`

Just like most methods, `completeInteractiveLogin` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const authorizeUrl = await serverClient.completeInteractiveLogin({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Starting Link User

As user-linking is a two-step process, it begins with configuring a `redirect_uri`, which is the URL Auth0 will redirect the user to after succesful authentication to complete the user-linking. Once configured, call `startLinkUser` and redirect the user to the returned authorization URL:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  }
});
const linkUserUrl = await serverClient.startLinkUser();
// Redirect user to linkUserUrl
```

Once the link user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorizationParams`. At that point, it's required to call `completeLinkUser()` to finalize the user-linking process. Read more below in [Completing Link User](#completing-link-user).

### Passing `authorizationParams`

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startLinkUser()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as  `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `startLinkUser()`:

```ts
await serverClient.startLinkUser({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `startLinkUser`, will override the same, statically configured, `authorizationParams` property on `ServerClient`.


### Passing `appState` to track state during login

The `appState` parameter, passed to `startLinkUser()`, can be used to track state which you want to get back after calling `completeLinkUser`.

```ts
const linkUserUrl = await serverClient.startLinkUser({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeLinkUser(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `linkUserUrl` and `url` are two distinct URLs.
> - `linkUserUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to link the account.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful linking the account.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Passing `StoreOptions`

Just like most methods, `startLinkUser` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const authorizeUrl = await serverClient.startLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

## Completing Link User

As user-linking is a two-step process, after starting it, it also needs to be completed. This can be achieved using the SDK's `completeLinkUser()`.

```ts
await serverClient.completeLinkUser(url)
```

> The url passed to `completeLinkUser` is the URL Auth0 redirects the user back to after successful account linking, and should contain `state` and either `code` or `error`.

### Retrieving `appState`

The `appState` parameter, passed to `startLinkUser()`, can be retrieved again when calling `completeLinkUser()`.

```ts
const linkUserUrl = await serverClient.startLinkUser({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeLinkUser(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `linkUserUrl` and `url` are two distinct URLs.
> - `linkUserUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful linking the account.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.


### Passing `StoreOptions`

Just like most methods, `completeLinkUser` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const authorizeUrl = await serverClient.completeLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)


## Login using Client-Initiated Backchannel Authentication

Using Client-Initiated Backchannel Authentication can be done by calling `loginBackchannel()`:

```ts
await serverClient.loginBackchannel({
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

### Using Rich Authorization Requests

When using Client-Initiated Backchannel Authentication, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`:

```ts
const { authorizationDetails } = await serverClient.loginBackchannel({
  bindingMessage: '<binding_message>',
  loginHint: {
    sub: 'auth0|123456789'
  },
  authorizationParams: {
    authorization_details: JSON.stringify([{
      type: '<type>',
      // additional fields here
    }
  ])
});
```

> [!IMPORTANT]
> Using Client-Initiated Backchannel Authentication with Rich Authorization Requests (RAR) requires the feature to be enabled in the Auth0 dashboard.
> Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

### Passing `StoreOptions`

Just like most methods, `loginBackchannel` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
await serverClient.loginBackchannel({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving the logged-in User

The SDK's `getUser()` can be used to retrieve the current logged-in user:

```ts
await serverClient.getUser();
```

### Passing `StoreOptions`

Just like most methods, `getUser` accept an argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const user = await serverClient.getUser(storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving the Session Data

The SDK's `getSession()` can be used to retrieve the current session data:

```ts
const session = await serverClient.getSession();
```

### Passing `StoreOptions`

Just like most methods, `getSession` accept an argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const session = await serverClient.getSession(storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving an Access Token

The SDK's `getAccessToken()` can be used to retrieve an Access Token for the current logged-in user:

```ts
const accessToken = await serverClient.getAccessToken();
```

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `getAccessToken()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token.

### Passing `StoreOptions`

Just like most methods, `getAccessToken` accept an argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const accessToken = await serverClient.getAccessToken(storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving an Access Token for a Connections

The SDK's `getAccessTokenForConnection()` can be used to retrieve an Access Token for a connection (e.g. `google-oauth2`) for the current logged-in user:

```ts
const accessTokenForGoogle = await serverClient.getAccessTokenForConnection({ connection: 'google-oauth2' });
```

- `connection`: The connection for which an access token should be retrieved, e.g. `google-oauth2` for Google.
- `loginHint`: Optional login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user. 

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `getAccessTokenForConnection()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token for a connection.

### Passing `StoreOptions`

Just like most methods, `getAccessTokenForConnection()` accepts a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const accessToken = await serverClient.getAccessTokenForConnection({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Logout

Logging out ensures the stored tokens and user information are removed, and that the user is no longer considered logged-in by the SDK.
Additionally, calling `logout()` returns a URL to redirect the browser to, in order to logout from Auth0.

```ts
const logoutUrl = await serverClient.logout({});
// Redirect user to logoutUrl
```

### Passing the `returnTo` parameter

When redirecting to Auth0, the user may need to be redirected back to the application. To achieve that, you can specify the `returnTo` parameter wgen calling `logout()`.

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' });
// Redirect user to logoutUrl
```

### Passing `StoreOptions`

Just like most methods, `logout()` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const logoutUrl = await serverClient.logout({}, storeOptions);
// Redirect user to logoutUrl
```

Read more above in [Configuring the Store](#configuring-the-store)

## Handle Backchannel Logout

To handle backchannel logout, the SDK's `handleBackchannelLogout()` method needs to be called with a logoutToken:

```ts
const logoutToken = '';
await serverClient.handleBackchannelLogout(logoutToken);
```

Read more on [backchannel logout on Auth0 docs](https://auth0.com/docs/authenticate/login/logout/back-channel-logout).

### Passing `StoreOptions`

Just like most methods, `handleBackchannelLogout()` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const logoutToken = '';
const storeOptions = { /* ... */ };
await serverClient.handleBackchannelLogout(logoutToken, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)