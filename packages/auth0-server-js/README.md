The `@auth0/auth0-server-js` library allows for implementing user authentication in web applications on a JavaScript runtime.

Using this SDK as-is in your application may not be trivial, as it is designed to be used as a building block for building framework-specific authentication SDKs.

![Release](https://img.shields.io/npm/v/@auth0/auth0-server-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-server-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-server-js/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

- [1. Install the SDK](#1-install-the-sdk)
- [2. Create the Auth0 SDK client](#2-create-the-auth0-sdk-client)
- [3. Configuring the Store](#3-configuring-the-store)
  - [Stateless Store](#stateless-store)
  - [Stateful Store](#stateful-store)
- [4. Add login to your Application (interactive)](#4-add-login-to-your-application-interactive)
- [5. Add logout to your application](#5-add-logout-to-your-application)

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

The `auth0-server-js` SDK comes with a built-in store for both transaction and state data, however **it's required to provide it a CookieHandler implementation** that fits your use-case.
The goal of `auth0-server-js` is to provide a flexible API that allows you to use any storage mechanism you prefer, but is mostly designed to work with cookie and session-based storage kept in mind.

The SDK methods accept an optional `storeOptions` object that can be used to pass additional options to the storage methods, such as Request / Response objects, allowing to control cookies in the storage layer.

For Web Applications, this may come down to a Stateless or Statefull session storage system.

#### Stateless Store

In a stateless storage solution, the entire session data is stored in the cookie. This is the simplest form of storage, but it has some limitations, such as the maximum size of a cookie.

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

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: StoreOptions
  ): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.clearCookie(name);
  }
}

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({ secret: options.secret }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({ secret: options.secret }, new FastifyCookieHandler()),
});
```

#### Stateful Store

In stateful storage, the session data is stored in a server-side storage mechanism, such as a database. This allows for more flexibility in the size of the session data, but requires additional infrastructure to manage the storage.
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

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: StoreOptions,
  ): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.clearCookie(name);
  }
}

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({ secret: options.secret }, new FastifyCookieHandler()),
  stateStore: new StatefulStateStore({ secret: options.secret }, new FastifyCookieHandler()),
});

```

Note that `storeOptions` is optional in the SDK's methods, but required when wanting to interact with the framework to set cookies. Here's how to pass the `storeOptions` to `startInteractiveLogin()` in a Fastify application:

```ts
fastify.get('/auth/login', async (request, reply) => {
  const storeOptions = { request, reply };
  const authorizationUrl = await auth0Client.startInteractiveLogin({}, storeOptions);

  reply.redirect(authorizationUrl.href);
});
```

Because storage systems in Web Applications are mostly cookie-based, the `storeOptions` object is used to pass the `request` and `reply` (in the case of Fastify, as per the example) objects to the storage methods, allowing to control cookies in the storage layer. It's expected to pass this to every interaction with the SDK.

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

### 5. Add logout to your application

In order to log the user out of your application, as well as from Auth0, you can call the SDK's `logout()` method, and redirect the user to the returned URL.

```ts
fastify.get('/auth/logout', async (request, reply) => {
  const logoutUrl = await auth0Client.logout({ returnTo: '<RETURN_TO>' }, { request, reply });

  reply.redirect(logoutUrl.href);
});
```

> [!IMPORTANT]  
> You will need to register the `RETURN_TO` in your Auth0 Application as an **Allowed Logout URLs** via the [Auth0 Dashboard](https://manage.auth0.com):



## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/auth0-auth-js/blob/main/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-auth-js/issues).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-server-js/LICENSE"> LICENSE</a> file for more info.
</p>
