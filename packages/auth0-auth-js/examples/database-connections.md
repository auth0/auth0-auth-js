# Database Connections

[← All examples](../EXAMPLES.md)

- [Using Database Connections (Sign-up & Change Password)](#using-database-connections-sign-up--change-password)
    - [Signing Up a User](#signing-up-a-user)
    - [Requesting a Password Change](#requesting-a-password-change)
    - [Error Handling](#error-handling)

## Using Database Connections (Sign-up & Change Password)

The SDK exposes a database client via the `database` property on the `AuthClient` instance. It wraps the public `/dbconnections/signup` and `/dbconnections/change_password` Authentication API endpoints, letting you register users and trigger password-reset emails against an Auth0 [database connection](https://auth0.com/docs/authenticate/database-connections) such as `Username-Password-Authentication`.

> [!IMPORTANT]
> These endpoints are **public**: the SDK only sends `clientId` in the request body — never a client secret or assertion — so both public and confidential clients work. `changePassword` returns a **plain-text** confirmation string (read via `response.text()`), not JSON. For privacy, the server returns the same confirmation regardless of whether the email matches an existing account.

| Method | Path | SDK method | Description |
|--------|------|------------|-------------|
| `POST` | `/dbconnections/signup` | `database.signUp` | Register a new user on a database connection |
| `POST` | `/dbconnections/change_password` | `database.changePassword` | Trigger a password-reset email for a user |

Learn more: [Signup](https://auth0.com/docs/api/authentication/signup) | [Change Password](https://auth0.com/docs/api/authentication/database-ad-ldap-passive/change-password)

### Signing Up a User

`signUp` requires `email`, `password`, and `connection`. All other fields are optional. The result is normalized to `camelCase`, and `id` is resolved from whichever identifier the server returns (`id`, `_id`, or `user_id`).

```ts
import { AuthClient, SignUpError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

try {
  const user = await authClient.database.signUp({
    email: 'user@example.com',
    password: 'a-Str0ng-Password!',
    connection: 'Username-Password-Authentication',
    // Optional profile fields (sent as snake_case on the wire):
    username: 'jane',
    givenName: 'Jane',
    familyName: 'Doe',
    name: 'Jane Doe',
    nickname: 'jd',
    picture: 'https://example.com/jane.png',
    userMetadata: { plan: 'free' },
    // Optional per-request client override:
    // clientId: '<OTHER_CLIENT_ID>',
  });

  console.log(user.id);            // e.g. 'auth0|6a44...'; may be undefined if omitted by the server
  console.log(user.email);         // 'user@example.com'
  console.log(user.emailVerified); // false
} catch (error) {
  if (error instanceof SignUpError) {
    console.error(error.message);       // Human-readable message
    console.error(error.code);          // 'signup_error'
    console.error(error.cause?.error);  // e.g. 'invalid_signup', 'invalid_password', 'user_exists'
  }
}
```

The `SignUpResult` shape:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `string \| undefined` | Normalized identifier (`id` / `_id` / `user_id`); may be undefined |
| `email` | `string` | The registered email |
| `emailVerified` | `boolean` | Whether the email is already verified |
| `username`, `givenName`, `familyName`, `name`, `nickname`, `picture` | `string \| undefined` | Optional profile fields, mapped to `camelCase` |
| `userMetadata` | `Record<string, unknown> \| undefined` | Optional user metadata |

### Requesting a Password Change

`changePassword` requires `connection` plus at least one identifier — either `email` or `username` (`username` is for username-only database connections). It triggers a password-reset email and resolves to the server's plain-text confirmation message.

```ts
import { AuthClient, ChangePasswordError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

try {
  // Identify the user by email...
  const message = await authClient.database.changePassword({
    email: 'user@example.com',
    connection: 'Username-Password-Authentication',
    // Optional:
    // organization: 'org_123',
    // clientId: '<OTHER_CLIENT_ID>',
  });

  // ...or by username, for username-only connections:
  // const message = await authClient.database.changePassword({
  //   username: 'jane',
  //   connection: 'Username-Password-Authentication',
  // });

  console.log(message); // "We've just sent you an email to reset your password."
} catch (error) {
  if (error instanceof ChangePasswordError) {
    console.error(error.message);       // Human-readable message
    console.error(error.code);          // 'change_password_error'
    console.error(error.cause?.error);  // server error code, when available
  }
}
```

### Error Handling

Both methods throw a dedicated error class — `SignUpError` or `ChangePasswordError`. Each carries a stable `code`, a human-readable `message`, and an optional `cause` populated from the Authentication API error response. The `cause` is sanitized to a fixed shape; unmodeled server fields are not exposed.

| Property | Type | Description |
|----------|------|-------------|
| `name` | `'SignUpError' \| 'ChangePasswordError'` | Error class name |
| `code` | `'signup_error' \| 'change_password_error'` | Stable, machine-readable code |
| `message` | `string` | Human-readable message (the server's `error_description` when present) |
| `cause` | `{ error: string; error_description: string; message?: string } \| undefined` | Sanitized API error body |

Validation failures are thrown synchronously before any network request when required fields are missing. Network failures are wrapped in the corresponding error class.
