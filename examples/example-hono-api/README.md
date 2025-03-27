# Fastify Example

This example demonstrates how to use the `auth0-api-js` package to protect API's in a Hono application.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

```bash
npx wrangler secret put AUTH0_DOMAIN
npx wrangler secret put AUTH0_AUDIENCE 
```

Update types (optional)
```bash
npm run cf-typegen
```

With the configuration in place, the example can be deployed by running:

```bash
npm run deploy
``` 

## Endpoints

The example API has the following endpoints:

- `GET /api/public`: A public endpoint that can be accessed without authentication.
- `GET /api/private`: A private endpoint that can only be accessed by authenticated users.
- `GET /api/private/scope`: A private endpoint that can only be accessed by authenticated users with the `read:data` scope.

In order to call the `/api/private` and `/api/private-scope` endpoints, you need to include an `Authorization` header with a valid access token.
