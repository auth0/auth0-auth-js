The Auth0-Server-JS SDK is a library for implementing user authentication in JavaScript applications.

Using this SDK as-is in your application may not be trivial, as it is designed to be used as a building block for building framework-specific authentication SDKs.

![Release](https://img.shields.io/npm/v/@auth0/auth0-server-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-server-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-server-js/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/auth0-server-js
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Create the Auth0 SDK client

Create an instance of the `ServerClient`. This instance will be imported and used anywhere we need access to the authentication methods.

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const auth0 = new ServerClient<StoreOptions>({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  authorizationParams: {
    redirect_uri: '<AUTH0_REDIRECT_URI>',
  },
});
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.
The `AUTH0_REDIRECT_URI` is needed to tell Auth0 what URL to redirect back to after successfull authentication, e.g. `http://localhost:3000/auth/callback`. (note, your application needs to handle this endpoint and call the SDK's `completeInteractiveLogin(url: string)` to finish the authentication process. See below for more information)

### 3. Configuring the Store

The `auth0-server-js` SDK does not come with a built-in store for both transaction and state data, **it's required to provide a persistent solution** that fits your use-case.
The goal of `auth0-server-js` is to provide a flexible API that allows you to use any storage mechanism you prefer, but is mostly designed to work with cookie and session-based storage.

The SDK methods accept an optional `storeOptions` object that can be used to pass additional options to the storage methods, such as Request / Response objects, allowing to control cookies in the storage layer.

For Web Applications, this may come down to a Stateless or Statefull session storage system.

#### Stateless Store

In stateless storage, the entire session data is stored in the cookie. This is the simplest form of storage, but it has some limitations, such as the maximum size of a cookie.

The implementation may vary depending on the framework of choice, here is an example using Fastify:


```ts
import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import { 
  AbstractStateStore,
  TransactionStore,
  ServerClient,
  StateData,
  TransactionData
} from '@auth0/auth0-server-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new StatelessTransactionStore({ secret: options.secret }),
  stateStore: new StatelessStateStore({ secret: options.secret }),
});

export class StatelessTransactionStore implements TransactionStore<StoreOptions> {
  async set(identifier: string, transactionData: TransactionData, removeIfExists?: boolean, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    // Note that `removeIfExists` is not used in Stateless storage, but it's kept for compatibility with Stateful storage.

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };

    options.reply.setCookie(identifier, JSON.stringify(transactionData), cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error();
    }

    const cookieValue = options.request.cookies[identifier];
    
    if (cookieValue) {
      return JSON.parse(cookieValue) as TransactionData;
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

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new StatelessTransactionStore({ secret: '<secret>' }),
  stateStore: new StatefulStateStore({ secret: '<secret>' }),
});

export class StatefulStateStore extends AbstractSessionStore {
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

    const maxAge = ?; // Set the max age of the cookie
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

Because storage systems in Web Applications are mostly cookie-based, the `storeOptions` object is used to pass the `request` and `reply` objects to the storage methods, allowing to control cookies in the storage layer. It's expected to pass this to every interaction with the SDK.

### 4. Add login to your Application (interactive)

Before using redirect-based login, ensure the `authorizationParams.redirect_uri` is configured when initializing the SDK:

```ts
const auth0 = new ServerClient<StoreOptions>({
  // ...
  authorizationParams: {
    redirect_uri: '<AUTH0_REDIRECT_URI>',
  },
  // ...
});
```

> [!IMPORTANT]  
> You will need to register the `AUTH0_REDIRECT_URI` in your Auth0 Application as an **Allowed Callback URLs** via the [Auth0 Dashboard](https://manage.auth0.com):

In order to add login to any application, call `startInteractiveLogin()`, and redirect the user to the returned URL.

The implementation will vary based on the framework being used, but here is an example of what this would look like in Fastify:

```ts
fastify.get('/auth/login', async (request, reply) => {
  const authorizationUrl = await auth0Client.startInteractiveLogin({
    // The redirect_uri can also be configured here.
    authorizationParams: {
      redirect_uri: '<AUTH0_REDIRECT_URI>',
    },
  }, { request, reply });

  reply.redirect(authorizationUrl.href);
});
```

Once the user has succesfully authenticated, Auth0 will redirect the user back to the provided `authorizationParams.redirect_uri` which needs to be handled in the application.
The implementation will vary based on the framework used, but what needs to happen is:

- register an endpoint that will handle the configured `authorizationParams.redirect_uri`.
- call the SDK's `completeInteractiveLogin(url)`, passing it the full URL, including query parameters.

Here is an example of what this would look like in Fastify, with `authorizationParams.redirect_uri` configured as `http://localhost:3000/auth/callback`:

```ts
fastify.get('/auth/callback', async (request, reply) => {
  await auth0Client.completeInteractiveLogin(new URL(request.url, options.appBaseUrl), { request, reply });

  reply.redirect('/');
});
```

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-server-js/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./../../CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-js/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-fastify/LICENSE"> LICENSE</a> file for more info.
</p>
