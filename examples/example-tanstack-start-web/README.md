# Tanstack Start Example

This example demonstrates how to use the `auth0-server-js` package to authenticate users in a Tanstack Start application.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

Rename `.env.example` to `.env` and configure the domain and audience:

```ts
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
AUTH0_SESSION_SECRET=YOUR_AUTH0_SESSION_SECRET
APP_BASE_URL=http://localhost:3000
```

The `AUTH0_SESSION_SECRET` is the key used to encrypt the session cookie. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

With the configuration in place, the example can be started by running:

```bash
npm run start
``` 