# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Configuring the mounted routes](#configuring-the-mounted-routes)
- [Protecting Routes](#protecting-routes)
- [Requesting an Access Token to call an API](#requesting-an-access-token-to-call-an-api)

## Configuration

### Basic configuration

Register the Auth0 fastify plugin with the Fastify instance.

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  appBaseUrl: '<APP_BASE_URL>',
  sessionSecret: '<SESSION_SECRET>',
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



### Configuring the mounted routes

By default, the SDK mounts the following routes:

- `auth/login`
- `auth/callback`
- `auth/logout`
- `auth/backchannel-logout`

The SDK can also be configured not to register these routes by setting the `mountRoutes` option to `false`:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  /* ... */
  mountRoutes: false,
});
```

Additionally, by setting `mountConnectRoutes` to `true` (it's false by default) the SDK also can also mount 4 routes useful for account-linking:

1. `/auth/connect`: the route that the user will be redirected to to initiate account linking
2. `/auth/connect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs
3. `/auth/unconnect`: the route that the user will be redirected to to initiate account linking
4. `/auth/unconnect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs

> [!IMPORTANT]  
> When `mountRoutes` is set to `false`, setting `mountConnectRoutes` has no effect.

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when registering the plugin:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

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

## Protecting Routes

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

## Requesting an Access Token to call an API

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

Retrieving the token can be achieved by using `getAccessToken`:

```ts
const accessTokenResult = await fastify.auth0Client.getAccessToken({ request, reply });
console.log(accessTokenResult.accessToken);
```