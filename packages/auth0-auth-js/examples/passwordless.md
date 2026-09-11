# Passwordless Authentication

[← All examples](../EXAMPLES.md)

- [Using Passwordless Authentication](#using-passwordless-authentication)
    - [Classic Email/SMS Passwordless (/passwordless/start)](#classic-emailsms-passwordless-passwordlessstart)
        - [Sending an Email Code](#sending-an-email-code)
        - [Sending an Email Magic Link](#sending-an-email-magic-link)
        - [Sending an SMS Code](#sending-an-sms-code)
        - [Logging in with an Email Code](#logging-in-with-an-email-code)
        - [Logging in with an SMS Code](#logging-in-with-an-sms-code)
        - [Handling Multi-Factor Authentication](#handling-multi-factor-authentication)
    - [Passwordless OTP on Database Connections](#passwordless-otp-on-database-connections)
        - [Prerequisites](#prerequisites)
        - [Email OTP on Database Connection](#email-otp-on-database-connection)
        - [Phone OTP on Database Connection](#phone-otp-on-database-connection)
        - [Error Handling and MFA](#error-handling-and-mfa)

## Using Passwordless Authentication

Passwordless lets users authenticate with a one-time code (or magic link) delivered by email or SMS, rather than a password. The SDK supports two passwordless approaches:

- **Email/SMS on Passwordless Connections** (classic `/passwordless/start` flow) — Steps 1–2 below.
- **OTP on Database Connections** (embedded `/otp/challenge` flow) — See [Passwordless OTP on Database Connections](#passwordless-otp-on-database-connections) below.

### Classic Email/SMS Passwordless (/passwordless/start)

There are two steps for the classic flow:

1. **Start** — send the code/link via the `passwordless` sub-client (`sendEmail` / `sendSms`).
2. **Login** — exchange the one-time code for tokens via `getTokenByPasswordlessEmail` / `getTokenByPasswordlessSms`.

> [!IMPORTANT]
> Your Auth0 application must have the **Passwordless OTP** grant enabled, with the Email and/or SMS connection configured. See the [Auth0 Passwordless documentation](https://auth0.com/docs/authenticate/passwordless) for tenant setup.

### Sending an Email Code

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

await authClient.passwordless.sendEmail({
  email: 'user@example.com',
  send: 'code', // default; can be omitted
});
```

### Sending an Email Magic Link

Pass `send: 'link'` together with the `authParams` used when the link is followed. Your application owns the `state` value. Completing a magic link is a no-PKCE authorization-code exchange handled by `getTokenByMagicLinkCode` (see below), **not** by the passwordless login methods and **not** by the PKCE-bound `getTokenByCode`.

```ts
await authClient.passwordless.sendEmail({
  email: 'user@example.com',
  send: 'link',
  authParams: {
    redirect_uri: 'https://my-app.example.com/callback',
    response_type: 'code',
    scope: 'openid profile',
    state: '<application_generated_state>',
  },
});
```

Completing the magic link on the callback route. The delivery endpoint registers no PKCE challenge, so the exchange omits the verifier; pass `expectedState` to validate the returned `state`.

```ts
// On GET /callback?code=...&state=...
const tokenResponse = await authClient.getTokenByMagicLinkCode(url, {
  expectedState: '<application_generated_state>',
});
```

> [!NOTE]
> For session management (state generation/persistence + session write), prefer `@auth0/auth0-server-js`'s `startPasswordless({ connection: 'email', send: 'link' })` / `completePasswordlessMagicLink`, which wrap this primitive.

### Sending an SMS Code

The phone number must be in E.164 format. SMS supports one-time codes only (no magic link).

```ts
await authClient.passwordless.sendSms({
  phoneNumber: '+14155550100',
});
```

### Logging in with an Email Code

Exchange the code the user received for a token set. Include `openid` in `scope` to receive an id_token, and `offline_access` to receive a refresh_token — the SDK does not inject scopes at this layer.

```ts
const tokenResponse = await authClient.getTokenByPasswordlessEmail({
  email: 'user@example.com',
  code: '123456',
  scope: 'openid profile',
});

// tokenResponse.accessToken, tokenResponse.idToken, tokenResponse.refreshToken
```

A `PasswordlessVerifyError` is thrown when the code is invalid, expired, or rate-limited.

### Logging in with an SMS Code

```ts
const tokenResponse = await authClient.getTokenByPasswordlessSms({
  phoneNumber: '+14155550100',
  code: '123456',
});
```

### Handling Multi-Factor Authentication

If the connection requires MFA, the login methods throw a `PasswordlessVerifyError` whose `cause.error` is `'mfa_required'`. Narrow it with the `isMfaRequiredError` type guard to read `cause.mfa_token`, then use it with the [MFA client](./mfa.md#using-multi-factor-authentication-mfa) to drive the challenge.

```ts
import { isMfaRequiredError } from '@auth0/auth0-auth-js';

try {
  await authClient.getTokenByPasswordlessEmail({ email: 'user@example.com', code: '123456' });
} catch (error) {
  if (isMfaRequiredError(error)) {
    const authenticators = await authClient.mfa.listAuthenticators({ mfaToken: error.cause.mfa_token });
    // ... continue the MFA challenge flow
  }
}
```

### Passwordless OTP on Database Connections

> [!NOTE]
> This feature is currently in Early Access (EA). Contact your Auth0 account team to have it enabled on your tenant.

For a database connection configured with `email_otp` or `phone_otp`, use the embedded OTP challenge flow instead of the classic `/passwordless/start`. This is a two-step process:

1. **Challenge** - request an OTP challenge for an email or phone identifier via `challengeWithEmail` / `challengeWithPhoneNumber`. Returns an opaque `authSession`.
2. **Exchange** - exchange the user-entered OTP and `authSession` for tokens via `getTokenByPasswordlessDbConnection`.

#### Prerequisites

Before using the OTP challenge flow, configure the following on your tenant:

**Application**

- Enable the **OTP grant type** under *Application Settings → Advanced Settings → Grant Types*.
- Enable the database connection on the application.
- The application must be a confidential client (configured with a `clientSecret` or `clientAssertionSigningKey`) to exchange the OTP for tokens.

<details>
<summary>Tenant and database connection setup</summary>

**Tenant**

- The tenant must use the **Identifier-First Authentication Profile**.

**Database connection — Authentication Methods** (*Authentication → Databases → your connection → Authentication Methods*)

- Enable **`email_otp`** (for email challenges) and/or **`phone_otp`** (for phone challenges): open *Configure* on the Email/Phone method and set *OTP for login* to **Allow**.

**Database connection — Attributes** (*Authentication → Databases → your connection → Attributes*)

- Add an **email** and/or **phone** attribute, then for each attribute enable **Use as Identifier**.
- Enable **Allow signup** on the attribute if you want new users to be able to sign up through the OTP flow (`allowSignup: true`).

**OTP delivery providers** (*Branding*)

- Configure an **email provider** (required for email OTP) and/or a **phone provider** (required for phone OTP). Without a configured phone provider, phone challenge requests fail with an error.
- For phone OTP, also enable the **Unified Phone Experience** under *Branding → Phone Provider*.

</details>

#### Email OTP on Database Connection

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Step 1: Request an OTP challenge
const challenge = await authClient.passwordless.challengeWithEmail({
  email: 'user@example.com',
  connection: 'my-db-connection',
  allowSignup: true,  // Optional: allow signup for new users
});

// User receives OTP via email, then:

// Step 2: Exchange the OTP and authSession for tokens
const tokens = await authClient.passwordless.getTokenByPasswordlessDbConnection({
  authSession: challenge.authSession,
  otp: '123456',  // User-entered code from email
  scope: 'openid profile email offline_access',
});

// tokens.accessToken, tokens.idToken, tokens.refreshToken
```

#### Phone OTP on Database Connection

```ts
// Step 1: Request an OTP challenge for SMS
const challenge = await authClient.passwordless.challengeWithPhoneNumber({
  phoneNumber: '+14155550100',
  connection: 'my-db-connection',
  deliveryMethod: 'text',  // 'text' (SMS) or 'voice' (call); omitted when not set, letting the server choose
  allowSignup: false,
});

// User receives OTP via SMS, then:

// Step 2: Exchange for tokens
const tokens = await authClient.passwordless.getTokenByPasswordlessDbConnection({
  authSession: challenge.authSession,
  otp: '123456',
  scope: 'openid profile',
});
```

#### Error Handling and MFA

Challenge requests throw `PasswordlessChallengeError` when validation fails, the request fails, or the server returns an error. The error includes `statusCode` and optional `validationErrors` for field-level issues:

```ts
import { PasswordlessChallengeError } from '@auth0/auth0-auth-js';

try {
  const challenge = await authClient.passwordless.challengeWithEmail({
    email: 'user@example.com',
    connection: 'my-db-connection',
  });
} catch (error) {
  if (error instanceof PasswordlessChallengeError) {
    console.error('Challenge failed:', error.message);
    console.error('Status:', error.statusCode);
    
    if (error.validationErrors) {
      error.validationErrors.forEach(ve => {
        console.error(`  - ${ve.field}: ${ve.message}`);
      });
    }
  }
}
```

The OTP exchange (`getTokenByPasswordlessDbConnection`) throws `PasswordlessDbGetTokenError` when the OTP is invalid, expired, or rate-limited. This is a distinct type from `PasswordlessVerifyError` (the classic email/SMS verify flow), so callers can tell the two flows apart. If the connection requires MFA, the error is still `PasswordlessDbGetTokenError` but its `cause.error` is `'mfa_required'` and `cause.mfa_token` carries the MFA token. Narrow with `isMfaRequiredError`:

```ts
import { PasswordlessDbGetTokenError, isMfaRequiredError } from '@auth0/auth0-auth-js';

try {
  const tokens = await authClient.passwordless.getTokenByPasswordlessDbConnection({
    authSession: challenge.authSession,
    otp: '123456',
  });
} catch (error) {
  if (isMfaRequiredError(error)) {
    // MFA is required; use the mfa_token to drive the MFA flow
    const authenticators = await authClient.mfa.listAuthenticators({
      mfaToken: error.cause.mfa_token,
    });
  } else if (error instanceof PasswordlessDbGetTokenError) {
    // Invalid/expired OTP, rate limiting, or a failed exchange
    console.error('OTP exchange failed:', error.message);
  }
}
```
