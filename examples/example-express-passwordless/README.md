# Express Passwordless Example

This example demonstrates how to use the `@auth0/auth0-server-js` package to
authenticate users with **passwordless** authentication in an Express
application. It covers all three flows:

- **Email OTP** — a one-time code sent by email.
- **SMS OTP** — a one-time code sent by SMS (requires a configured SMS provider).
- **Magic link** — a sign-in link sent by email; clicking it completes login.

Unlike the interactive (redirect) login flow, passwordless OTP is a two-step,
non-redirect flow:

1. **Start** — the user submits an email or phone number, and Auth0 sends a
   one-time code. No session is created yet.
2. **Verify** — the user submits the received code, which is exchanged for
   tokens, and a session cookie is established.

The **magic link** flow is redirect-based: the link lands on `/auth/callback`
with an authorization `code` and `state`, which the SDK exchanges (without PKCE)
to establish the session.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

Rename `.env.example` to `.env` and configure your tenant:

```ts
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
AUTH0_SESSION_SECRET=YOUR_AUTH0_SESSION_SECRET
APP_BASE_URL=http://localhost:3000
```

The `AUTH0_SESSION_SECRET` is the key used to encrypt the session cookie. You
can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

The `APP_BASE_URL` is the URL that your application is running on. When
developing locally, this is most commonly `http://localhost:3000`.

### Tenant prerequisites

- Enable the **Passwordless** connection(s) you want to use (Email and/or SMS)
  in the Auth0 Dashboard (Authentication > Passwordless).
- The application must be a **Regular Web Application** with the
  **Passwordless OTP** grant enabled.
- For SMS, a working SMS provider must be configured on the tenant. Email is the
  simplest path for a runnable demo; SMS is optional.
- For the **magic link** flow: add `http://localhost:3000/auth/callback` to the
  application's **Allowed Callback URLs**, and enable the tenant setting
  `allow_magiclink_verify_without_session`. Without it the click fails with
  "The link must be opened on the same device and browser." This is a tenant
  setting nested under `universal_login.passwordless` (NOT a top-level `flags`
  entry — sending it under `flags` returns `400 Additional properties not allowed`):

  ```bash
  auth0 api patch tenants/settings \
    --data '{"universal_login":{"passwordless":{"allow_magiclink_verify_without_session":true}}}'
  ```

With the configuration in place, start the example with:

```bash
npm run start
```

## Routes

- `/`: Home route, displaying a message depending on authentication state.
- `/private`: A private route accessible only to authenticated users.
- `GET /auth/login`: Renders the form to choose a channel (email/SMS) and enter
  an identifier.
- `POST /auth/start`: Calls `startPasswordlessEmail` / `startPasswordlessSms` to
  send the one-time code.
- `POST /auth/verify`: Calls `loginWithPasswordlessEmail` /
  `loginWithPasswordlessSms` to exchange the code for tokens and establish the
  session, then redirects home.
- `POST /auth/start-link`: Calls `startPasswordlessMagicLink` to email a magic
  link (renders a "check your email" page; no session yet).
- `GET /auth/callback`: Calls `completePasswordlessMagicLink` to validate the
  `state`, exchange the code (no PKCE), establish the session, then redirects home.
- `GET /auth/logout`: Logs the user out.

## Error handling

The passwordless error classes live in `@auth0/auth0-auth-js` and are not
re-exported by `@auth0/auth0-server-js`. To keep this example's dependencies to
the server SDK only, the routes branch on the stable error `code` string rather
than `instanceof`:

- `passwordless_start_error` — sending the code failed (bad email/phone, SMS
  provider error, rate limit).
- `passwordless_verify_error` — the code was wrong, expired, or rate-limited.
- `mfa_required_error` — the connection requires MFA (out of scope for this
  example; a message is shown).
