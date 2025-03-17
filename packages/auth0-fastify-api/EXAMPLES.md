# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
- [Protecting API Routes](#protecting-api-routes)

## Configuration

### Basic configuration

Register the Auth0 fastify plugin with the Fastify instance.

```ts
import fastifyAuth0 from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```

The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. 
The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when registering the plugin:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  /* ... */
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

## Protecting API Routes

In order to protect an API route, you can use the SDK's `requireAuth()` method in a preHandler:

```ts
import fastifyAuth0Api from '@auth0/auth0-fastify-api';

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
declare module '@auth0/auth0-fastify-api' {
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