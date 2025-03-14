The Auth0 Fastify SDK is a library for implementing user authentication in Fastify applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-fastify)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-fastify)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](https://auth0.github.io/auth0-fastify/) - 💬 [Feedback](#feedback)

## Documentation

- [QuickStart](https://auth0.com/docs/quickstart/webapp/fastify)- our guide for adding Auth0 to your Fastify app.
- [Examples](https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-fastify/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

- [1. Install the SDK](#1-install-the-sdk)
- [2. Register the Auth0 Fastify plugin for Web Applications](#2-register-the-auth0-fastify-plugin-for-web-applications)
  - [Routes](#routes)
  - [Protecting Routes](#protecting-routes)
  - [Requesting an Access Token to call an API](#requesting-an-access-token-to-call-an-api)
- [3. Register the Auth0 Fastify plugin for APIs](#3-register-the-auth0-fastify-plugin-for-apis)
  - [Routes](#routes-1)
  - [Protecting API Routes](#protecting-api-routes)

### 1. Install the SDK

```shell
npm i @auth0/auth0-fastify
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Register the Auth0 Fastify plugin for Web Applications

Register the Auth0 fastify plugin for Web Applications with the Fastify instance.


```ts
import auth0 from '@auth0/fastify-web';

fastify.register(auth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  appBaseUrl: '<APP_BASE_URL>',
  sessionSecret: '<SESSION_SECRET>'
});
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.

The `SESSION_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

> [!IMPORTANT]  
> You will need to register the following URLs in your Auth0 Application via the [Auth0 Dashboard](https://manage.auth0.com):
>
> - Add `http://localhost:3000/auth/callback` to the list of **Allowed Callback URLs**
> - Add `http://localhost:3000` to the list of **Allowed Logout URLs**

#### Routes

The SDK for Web Applications mounts 4 main routes:

1. `/auth/login`: the login route that the user will be redirected to to initiate an authentication transaction
2. `/auth/logout`: the logout route that must be added to your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be added to your Auth0 application's Allowed Callback URLs
4. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

To disable this behavior, you can set the `mountRoutes` option to `false` (it's true by default):

```ts
fastify.register(auth0, {
  mountRoutes: false
});
```

Additionally, by setting `mountConnectRoutes` to `true` (it's false by default) the SDK also can also mount 4 routes useful for account-linking:

1. `/auth/connect`: the route that the user will be redirected to to initiate account linking
2. `/auth/connect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs
3. `/auth/unconnect`: the route that the user will be redirected to to initiate account linking
4. `/auth/unconnect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs

> [!IMPORTANT]  
> When `mountRoutes` is set to `false`, setting `mountConnectRoutes` has no effect.

To learn more about account linking, check out the [Account Linking](./EXAMPLES.md) examples.

#### Protecting Routes

In order to protect a Fastify route, you can use the SDK's `getSession()` method in a preHandler:

```ts
async function hasSessionPreHandler(request: FastifyRequest, reply: FastifyReply) {
  const session = await fastify.auth0Client!.getSession({ request, reply });

  if (!session) {
    reply.redirect('/auth/login');
  }
}

fastify.get(
  '/profile',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('profile.ejs', {
      name: user!.name,
    });
  }
);
```

> [!IMPORTANT]  
> The above is to protect server-side rendering routes by the means of a session, and not API routes using a bearer token. 


#### Requesting an Access Token to call an API

If you need to call an API on behalf of the user, you want to specify the `audience` parameter when registering the plugin. This will make the SDK request an access token for the specified audience when the user logs in.

```ts
fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  audience: '<AUTH0_AUDIENCE>',
  appBaseUrl: '<APP_BASE_URL>',
  sessionSecret: '<SESSION_SECRET>',
});
```
The `AUTH0_AUDIENCE` is the identifier of the API you want to call. You can find this in the API section of the Auth0 dashboard.

### 3. Register the Auth0 Fastify plugin for APIs

Register the Auth0 fastify plugin for API's with the Fastify instance.

```ts
import fastifyAuth0Api from '@auth0/fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```
The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an API. 
The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.

#### Routes

The SDK for API's can mount 6 routes when `mountConnectRoutes` is set to `true` (it's false by default):

1. `/api/connect/start`: the route that the user will call to create a ticket to be able to initiate account linking
2. `/api/connect`: the route that the user will call to initiate account linking, passing the ticket created in the previous step
3. `/api/connect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs
4. `/api/unconnect/start`: the route that the user will call to create a ticket to be able to initiate account unlinking
5. `/api/unconnect`: the route that the user will call to initiate account unlinking, passing the ticket created in the previous step
6. `/api/unconnect/callback`: the callback route for account unlinking that must be added to your Auth0 application's Allowed Callback URLs

#### Protecting API Routes

In order to protect an API route, you can use the SDK's `requireAuth()` method in a preHandler:

```ts
fastify.register(() => {
  fastify.get(
    '/protected-api',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.sub}`;
    }
  );
});
```

The SDK exposes the claims, extracted from the token, as the `user` property on the `FastifyRequest` object.
In order to use a custom user type to represent custom claims, you can configure the `Token` type in a module augmentation:

```ts
declare module '@auth0/auth0-fastify/api' {
  interface Token {
    id: number;
    name: string;
    age: number;
  }
}
```

Doing so will change the user type on the `FastifyRequest` object automatically:

```ts
fastify.register(() => {
  fastify.get(
    '/protected-api',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.name}`;
    }
  );
});
```

> [!IMPORTANT]  
> The above is to protect API routes by the means of a bearer token, and not server-side rendering routes using a session. 


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
