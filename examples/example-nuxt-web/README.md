# Nuxt Example

This example demonstrates how to use the `auth0-server-js` package to authenticate users in a Nuxt application.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

Rename `.env.example` to `.env` and configure the domain and audience:

```ts
NUXT_AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
NUXT_AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
NUXT_AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
NUXT_AUTH0_SESSION_SECRET=YOUR_AUTH0_SESSION_SECRET
NUXT_AUTH0_APP_BASE_URL=http://localhost:3000
```

The `NUXT_AUTH0_SESSION_SECRET` is the key used to encrypt the session cookie. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

The `NUXT_AUTH0_APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

With the configuration in place, the example can be started by running:

```bash
npm run start
``` 

The application has 3 routes:

- `/`: The home route, displaying a message depending on the authentication state.
- `/public`: A public route that can be accessed without authentication.
- `/private`: A private route that can only be accessed by authenticated users.


In order to access the `/private` and route, you need to ensure the user is authenticated.

Additionally, navigating to the `/private` endpoint, without being authenticated, will redirect the user to the Auth0, and then redirect them back to the `/private` route after authentication.