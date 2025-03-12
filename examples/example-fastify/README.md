# Fastify Example

This example demonstrates how to use the `auth0-fastify` package to authenticate users in a Fastify application.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

Open `src/index.ts` and configure the SDK:

```ts
fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  appBaseUrl: 'http://localhost:3000',
  sessionSecret: '<SESSION_SECRET>',
  audience: '<AUTH0_AUDIENCE>',
});
```

With the configuration in place, the example can be started by running:

```bash
npm run start
``` 
