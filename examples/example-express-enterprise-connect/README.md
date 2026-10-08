# Enterprise Connect Example (Express)

> **Early Access** — Enterprise Connect is in Early Access. To enable it for your tenant, contact Auth0 support.

A minimal Express application demonstrating the full Enterprise Connect (EC) flow using `@auth0/auth0-server-js`. In EC mode Auth0 acts as a pure SSO relay: it forwards the user to the enterprise IdP and returns OIDC tokens. Auth0 writes no session — this app owns its session via an HMAC-SHA256 signed cookie.

## Prerequisites

- Node.js 20 LTS or later
- npm 10+
- An Auth0 tenant with Enterprise Connect enabled and a **B2B Integration** application configured.

## Setup

**1. Configure the Auth0 application**

In your B2B Integration's **Settings** tab:

- Set **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
- Set **Allowed Logout URLs**: `http://localhost:3000/login`

**2. Configure environment variables**

Copy `.env.example` to `.env` and fill in the values:

```dotenv
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_B2B_INTEGRATION_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_B2B_INTEGRATION_CLIENT_SECRET
AUTH0_SESSION_SECRET=YOUR_LONG_RANDOM_SECRET_HERE
APP_BASE_URL=http://localhost:3000
```

> `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` come from the **B2B Integration** client, not a regular web application or SPA client.

Generate a value for `AUTH0_SESSION_SECRET`:

```shell
openssl rand -hex 32
```

**3. Install dependencies**

```shell
npm install
```

## Run

```shell
npm start
```

Open `http://localhost:3000` and enter a work email for a federated domain.

## Routes

| Route | Description |
|-------|-------------|
| `GET /` | Redirects to `/dashboard` (logged in) or `/login` (not logged in) |
| `GET /login` | Login form — enter a work email |
| `POST /login` | WebFinger domain discovery; redirects to Auth0 or `/login?mode=password` if not federated |
| `GET /auth/callback` | Exchanges authorization code for tokens; creates the app-owned session cookie |
| `GET /dashboard` | Protected route — shows authenticated user's claims |
| `GET /auth/logout` | Clears the app session cookie and redirects through Auth0 federated logout |
| `GET /check-domain?email=user@acme.com` | Standalone WebFinger check (returns `{ domain, federated }`) |

## Key Concepts

- **No Auth0 session** — `enterpriseConnect: true` installs a `NullStateStore`. `getSession()`, `getUser()`, and `getAccessToken()` are blocked.
- **App-owned session** — the session is an HMAC-SHA256 signed `httpOnly` cookie. Replace it with any session mechanism your app already uses.
- **Federated logout** — always pass `federated: true` to `auth0.logout()` so the enterprise IdP session is also terminated.
- **Token expiry** — the access token expires (typically 24 h) with no renewal path. Use the ID token claims to establish identity and issue your own tokens for API authorization.
