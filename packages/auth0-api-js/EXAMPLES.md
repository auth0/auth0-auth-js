# Examples

The `@auth0/auth0-api-js` library provides two ways to integrate with your application: API and API as Client.

- [API Integration](#api-integration)
  - [Verify an Access Token](#verify-an-access-token)
- [API as Client Integration](#api-as-client-integration)
  - [Configuration](#configuration)
    - [Configuring the Store](#configuring-the-store)
    - [Configuring the Store Identifier](#configuring-the-store-identifier)
    - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
    - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
  - [Starting Link User](#starting-link-user)
    - [Passing `authorizationParams`](#passing-authorizationparams)
    - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
    - [Passing `StoreOptions`](#passing-storeoptions)
  - [Completing Link User](#completing-link-user)
    - [Retrieving `appState`](#retrieving-appstate)
    - [Passing `StoreOptions`](#passing-storeoptions) 

## API Integration

### Verify an Access Token

The SDK's `verifyAccessToken` method can be used to verify the access token.

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new apiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerfiedToken = await apiClient.verifyAccessToken({
  accessToken
});
```

Even thought the SDK automatically validates claims like `iss`, `aud`, `exp`, and `nbf`, you can also pass additional claims to be required:
Additionally, `requiredClaims` can be conf

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new apiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerfiedToken = await apiClient.verifyAccessToken({
  accessToken,
  requiredClaims: ['my_custom_claim']
});
```

## API as Client Integration

API as Client is a bit of an a-typical way to integrate Auth0 in API's, where the API will behave as a Client in the sense that it can request tokens using a user-based Authorization Code Flow.

In our case, this is being used to integrate User Linking, where the API will request tokens on behalf of the user to link their accounts.

> [!IMPORTANT]  
> If the above does not make sense to you, it may mean that this functionality isn't for your use-case.

## Configuration

When configuring the API as a Client, you will need to provide the following configuration:

```ts
import { ApiAuthClient } from '@auth0/auth0-api-js';

const apiAuthClient = new ApiAuthClient({
  domain: options.domain,
  audience: options.apiAsClient.audience,
  clientId: options.apiAsClient.clientId,
  clientSecret: options.apiAsClient.clientSecret,
  onUserLinked: options.apiAsClient.onUserLinked,
});
```

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
  AbstractTransactionStore,
  ApiAuthClient,
  TransactionData
} from '@auth0/auth0-api-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

const apiAuthClient = new ApiAuthClient<StoreOptions>({
  transactionStore: new StatelessTransactionStore({ secret: '<secret>' }),
});

export class StatelessTransactionStore extends AbstractTransactionStore<StoreOptions> {
  async set(identifier: string, transactionData: TransactionData, removeIfExists?: boolean, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    const expiration = Math.floor((Date.now() / 1000) + maxAge);
    const encryptedTransactionData = await this.encrypt(identifier, transactionData, expiration);

    options.reply.setCookie(identifier, encryptedTransactionData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const encryptedTransactionData = options.request.cookies[identifier];
    if (encryptedTransactionData) {
      return (await this.decrypt(identifier, encryptedTransactionData)) as TransactionData;
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
```

### Configuring the Store Identifier

By default, the SDK uses `__a0_api_tx` to identify the Transaction data in the store.

To change this, the `transactionIdentifier` option can be set when instantiating `ApiAuthClient`:

```ts
import { ApiAuthClient } from '@auth0/auth0-api-js';

const apiAuthClient = new ApiAuthClient({
  transactionIdentifier: '__my_tx',
});
```

### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of `ApiAuthClient`:

```ts
import { ApiAuthClient } from '@auth0/auth0-api-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
....................REMOVED FOR BREVITY.........................
-----END PRIVATE KEY-----`;
const clientAssertionSigningKey = await importPKCS8(clientPrivateKey, 'RS256');
const apiAuthClient = new ApiAuthClient({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

Note that the private keys should not be committed to source control, and should be stored securely.


### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when creating an instance of `ApiAuthClient`:

```ts
const apiAuthClient = new ApiAuthClient({
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```


## Starting Link User

As user-linking is a two-step process, it begins with configuring a `redirect_uri`, which is the URL Auth0 will redirect the user to after succesful authentication to complete the user-linking. Once configured, call `startLinkUser` and redirect the user to the returned authorization URL:

```ts
const apiAuthClient = new ApiAuthClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  }
});
const linkUserUrl = await auth0.startLinkUser();
// Redirect user to linkUserUrl
```

Once the link user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorizationParams`. At that point, it's required to call `completeLinkUser()` to finalize the user-linking process. Read more below in [Completing Link User](#completing-link-user).

### Passing `authorizationParams`

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startLinkUser()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const auth0 = new ServerClient({
  authorizationParams: {
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as  `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const auth0 = new ServerClient({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `startLinkUser()`:

```ts
await auth0.startLinkUser({
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
const linkUserUrl = await startLinkUser({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await completeLinkUser(url);
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
const authorizeUrl = await startLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

## Completing Link User

As user-linking is a two-step process, after starting it, it also needs to be completed. This can be achieved using the SDK's `completeLinkUser()`.

```ts
await auth.completeLinkUser(url)
```

> The url passed to `completeLinkUser` is the URL Auth0 redirects the user back to after successful account linking, and should contain `state` and either `code` or `error`.

### Retrieving `appState`

The `appState` parameter, passed to `startLinkUser()`, can be retrieved again when calling `completeLinkUser()`.

```ts
const linkUserUrl = await startLinkUser({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await completeLinkUser(url);
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
const authorizeUrl = await completeLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

