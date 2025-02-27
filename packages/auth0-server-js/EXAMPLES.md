# Examples

- [Configuration](#configuration)
  - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
  - [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)
  - [Configuring the Store Identifier](#configuring-the-store-identifier)
- [Starting Interactive Login](#starting-interactive-login)
  - [Passing authorization parameters](#passing-authorization-parameters)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Using Pushed Authorization Requests](#the-returnto-parameter)

## Configuration

### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of Auth0Client:

```ts
import { Auth0Client } from '@auth0/auth0-server-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = 'key_here';
const clientAssertionSigningKey = await importPKCS8<CryptoKey>(clientPrivateKey, 'RS256');
const auth0 = new Auth0Client({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

### Configuring the Transaction and State Store

Even though auth0-server-js comes with an in-memory store for both transaction and state data, it's recommended to provide a persistent solution in most scenario's.

The SDK methods accept an optional storeOptions object that can be used to pass additional options to the storage methods, such as Request / Response object, allowing to control cookies in the storage layer.

For Web Applications, this may come down to a cookie-based or session storage system whose implementation may vary depending on the framework of choice. Here is an example using Fastify:

```ts
import { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractEncryptedTransactionStore, AbstractEncryptedStateStore } from '@auth0/auth0-server-js';
import { StoreOptions } from '../types.js';

const auth0 = new Auth0Client<StoreOptions>({
  transactionStore: new CookieTransactionStore({ secret: options.secret }),
  stateStore: new CookieStateStore({ secret: options.secret }),
});

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export class CookieTransactionStore extends AbstractEncryptedTransactionStore<StoreOptions> {
  async onSet(identifier: string, encryptedTransactionData: string, options?: StoreOptions): Promise<void> {
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };
  
    options.reply.setCookie(identifier, encryptedTransactionData, cookieOpts);
  }

  async onGet(identifier: string, options?: StoreOptions): Promise<string | undefined> {
    return options.request.cookies[identifier];
  }

  async onDelete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    options?.reply.clearCookie(identifier);
  }
}

export class CookieStateStore extends AbstractEncryptedStateStore<StoreOptions> {
  async onSet(identifier: string, encryptedStateData: string, options?: StoreOptions | undefined): Promise<void> {
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async onGet(identifier: string, options?: StoreOptions | undefined): Promise<string | undefined> {
    return options.request.cookies[identifier];
  }

  async onDelete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    options?.reply.clearCookie(identifier);
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

To change this, the `transactionIdentifier` and `stateIdentifier` options can be set when instantiating `Auth0Client`:

```ts
const auth0 = new Auth0Client({
  transactionIdentifier: '__my_tx',
  stateIdentifier: '__my_session',
});
```

## Starting Interactive Login

### Passing authorization parameters

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startInteractiveLogin`, you can statically configure them when instantiating the client using `authorizationParameters`:

```ts
const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParameters` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar'
  },
});
```

### Passing `appState` to track state during login

The `appState` parameter, passed to `startInteractiveLogin()`, can be used to track state which you want to get back after calling `completeInteractiveLogin`.

```ts
const authorizeUrl = await startInteractiveLogin({ appState: { 'myKey': 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await completeInteractiveLogin(url);
console.log(appState.myKey); // Logs 'myValue'
```

This can be useful for a variaty of reasons, but is mostly supported to be able to support a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Using Pushed Authorization Requests

Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server by setting `pushedAuthorizationRequests` to true when calling `startInteractiveLogin`. 

```ts
const authorizeUrl = await startInteractiveLogin({ pushedAuthorizationRequests: true });
```
When calling `startInteractiveLogin` with `pushedAuthorizationRequests` set to true, the SDK will send all the parameters to Auth0 using an HTTP Post request, and returns an URL that you can use to redirect the user to in order to finish the login flow.
