# Passkeys

[← All examples](../EXAMPLES.md)

- [Using Passkeys](#using-passkeys)
    - [Requesting a Signup Challenge](#requesting-a-signup-challenge)
    - [Requesting a Login Challenge](#requesting-a-login-challenge)
    - [Exchanging a Credential for Tokens](#exchanging-a-credential-for-tokens)
    - [Error Handling](#error-handling)

## Using Passkeys

The SDK provides a passkey client for native WebAuthn-based authentication. The passkey client is accessible via the `passkey` property on the `AuthClient` instance.

> [!IMPORTANT]
> Passkeys require the following prerequisites:
> - A [custom domain](https://auth0.com/docs/customize/custom-domains) configured on your Auth0 tenant (e.g., `auth.example.com`, not `example.auth0.com`). The custom domain serves as the WebAuthn Relying Party (RP) ID.
> - A database connection with the `passkey` authentication method enabled.
> - Your application must be served over HTTPS on a domain that matches or is a subdomain of the configured RP ID.

The SDK is platform-agnostic — it does not call WebAuthn browser APIs directly. Your application is responsible for calling `navigator.credentials.create()` or `navigator.credentials.get()` and serializing the credential response before passing it to the SDK.

> [!IMPORTANT]
> **Client authentication differs across the passkey methods:**
> - `register()` and `challenge()` work with both **public clients** (e.g. SPAs / native apps, which authenticate with `client_id` alone) and **confidential clients**. For a confidential client, configure a `clientSecret` and the SDK sends it as `client_secret` on these requests.
>
>   These two endpoints accept `client_secret` as their only body-level credential, so it is the only way to authenticate a confidential client on them. They do **not** accept `client_assertion`, and they are **not** served on the mTLS endpoint aliases. A client configured with only a `clientAssertionSigningKey` (private key JWT), or with only `useMtls`, therefore has no credential the SDK can send here: the request goes out with `client_id` alone and Auth0 rejects it. To use these two endpoints, configure the application for client secret authentication and pass a `clientSecret`. The limitation is specific to them, so `getTokenByPasskey()` still works with `clientAssertionSigningKey` or mTLS.
> - `getTokenByPasskey()` performs the token exchange and **requires a confidential client**. You must configure a `clientSecret`, a `clientAssertionSigningKey` (private key JWT), or mTLS. Because it goes through the token endpoint, it supports every client-authentication method. Called on a public client (no credentials), it throws a `PasskeyGetTokenError` whose `cause.message` is `'The client secret or client assertion signing key must be provided.'`. No request is made in that case, so `cause.error` and `cause.error_description` are empty.

Learn more: [Passkeys](https://auth0.com/docs/authenticate/database-connections/passkeys) | [Native Passkeys API](https://auth0.com/docs/authenticate/database-connections/passkeys/native-passkeys-api)

### Requesting a Signup Challenge

To register a new passkey for a user, request a signup challenge. The response contains WebAuthn public key creation options that should be passed to `navigator.credentials.create()`:

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_CUSTOM_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
});

const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  name: 'Jane Doe',
});

// challenge.authSession — session identifier needed for the token exchange step
// challenge.authnParamsPublicKey — pass to navigator.credentials.create({ publicKey: ... })
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `email` | Optional | `string` | User's email address. Include if `email` is configured as an identifier in your database connection's [user attributes](https://auth0.com/docs/authenticate/database-connections/passkeys). |
| `username` | Optional | `string` | User's username. Include if `username` is configured as an identifier in your database connection's user attributes. |
| `phoneNumber` | Optional | `string` | User's phone number. Include if `phone` is configured as an identifier in your database connection's user attributes. |
| `name` | Optional | `string` | User's full display name. |
| `givenName` | Optional | `string` | User's given (first) name. |
| `familyName` | Optional | `string` | User's family (last) name. |
| `nickname` | Optional | `string` | User's nickname. |
| `picture` | Optional | `string` | URL to the user's profile picture. |
| `userMetadata` | Optional | `Record<string, string>` | Arbitrary metadata stored in the user's `user_metadata` field. |
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `organization` | Optional | `string` | Organization ID or name. Scopes the user to the specified organization context. |

> [!NOTE]
> Which identifiers (`email`, `username`, `phoneNumber`) you should provide depends on what's enabled in your Auth0 tenant's database connection attributes. Provide the identifiers that match your connection's configuration.

You can include additional user profile fields when [Flexible Identifiers](https://auth0.com/docs/authenticate/database-connections/passkeys) is enabled on your database connection:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  name: 'Jane Doe',
  givenName: 'Jane',
  familyName: 'Doe',
  phoneNumber: '+1234567890',
  username: 'janedoe',
  userMetadata: { preferred_language: 'en' },
});
```

To specify a database connection:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  realm: 'Username-Password-Authentication',
});
```

To register within an organization context:

```ts
const challenge = await authClient.passkey.register({
  email: 'user@example.com',
  organization: 'org_abc123',
});
```

### Requesting a Login Challenge

To authenticate with an existing passkey, request a login challenge. The response contains WebAuthn public key request options that should be passed to `navigator.credentials.get()`:

```ts
const challenge = await authClient.passkey.challenge();

// challenge.authSession — session identifier needed for the token exchange step
// challenge.authnParamsPublicKey — pass to navigator.credentials.get({ publicKey: ... })
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `organization` | Optional | `string` | Organization ID or name. Scopes the authentication to the specified organization context. |

To specify a database connection:

```ts
const challenge = await authClient.passkey.challenge({
  realm: 'Username-Password-Authentication',
});
```

To authenticate within an organization context:

```ts
const challenge = await authClient.passkey.challenge({
  organization: 'org_abc123',
});
```

### Exchanging a Credential for Tokens

After the user completes the WebAuthn ceremony (either signup or login), exchange the credential response for Auth0 tokens.

> [!IMPORTANT]
> Unlike `register()` and `challenge()`, `getTokenByPasskey()` **requires a confidential client**. Configure the `AuthClient` with a `clientSecret`, a `clientAssertionSigningKey`, or mTLS:
>
> ```ts
> const authClient = new AuthClient({
>   domain: '<AUTH0_CUSTOM_DOMAIN>',
>   clientId: '<AUTH0_CLIENT_ID>',
>   clientSecret: '<AUTH0_CLIENT_SECRET>', // or clientAssertionSigningKey
> });
> ```

The WebAuthn API returns binary `ArrayBuffer` fields. These must be converted to base64url-encoded strings before passing to this method. Here is a helper function you can use:

```ts
function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
```

For a **signup** (registration) ceremony, the credential response includes `attestationObject`:

```ts
const credential = await navigator.credentials.create({
  publicKey: challenge.authnParamsPublicKey,
});

const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
    },
  },
});
```

For a **login** (authentication) ceremony, the credential response includes `authenticatorData`, `signature`, and `userHandle`:

```ts
const credential = await navigator.credentials.get({
  publicKey: challenge.authnParamsPublicKey,
});

const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: bufferToBase64url(credential.response.userHandle),
    },
  },
});
```

#### Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `authSession` | Required | `string` | The session identifier returned from `register()` or `challenge()`. |
| `credential` | Required | `PasskeyCredentialResponse` | The serialized WebAuthn credential. For signup: include `attestationObject`. For login: include `authenticatorData`, `signature`, and `userHandle`. |
| `realm` | Optional | `string` | Database connection name. If not provided, the tenant's default database connection is used. |
| `scope` | Optional | `string` | OAuth scopes to request (e.g., `'openid profile email'`). |
| `audience` | Optional | `string` | API identifier for the access token. Without this, an opaque token is returned instead of a JWT. |
| `organization` | Optional | `string` | Organization ID or name. Scopes tokens to the specified organization context. |

You can specify audience and scope to control the access token:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  audience: 'https://api.example.com',
  scope: 'openid profile email',
});
```

To specify a database connection:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  realm: 'Username-Password-Authentication',
});
```

To exchange within an organization context:

```ts
const tokens = await authClient.passkey.getTokenByPasskey({
  authSession: challenge.authSession,
  credential: serializedCredential,
  organization: 'org_abc123',
});
```

When `organization` is provided, the returned ID token's organization claim is validated against it (an `org_` prefix is matched exactly against `org_id`, otherwise the value is matched case-insensitively against `org_name`). A mismatch throws an `OrganizationValidationError`.

### Error Handling

All passkey methods throw typed errors that can be caught and handled individually:

```ts
import {
  AuthClient,
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
} from '@auth0/auth0-auth-js';

try {
  const challenge = await authClient.passkey.register({
    email: 'user@example.com',
  });
} catch (error) {
  if (error instanceof PasskeyRegisterError) {
    console.error(error.message);       // Human-readable error message
    console.error(error.code);          // 'passkey_register_error'
    console.error(error.cause?.error);  // API error code (e.g., 'invalid_request')
    console.error(error.cause?.error_description); // API error detail
  }
}

try {
  const challenge = await authClient.passkey.challenge();
} catch (error) {
  if (error instanceof PasskeyChallengeError) {
    console.error(error.message);
    console.error(error.code);          // 'passkey_challenge_error'
  }
}

try {
  const tokens = await authClient.passkey.getTokenByPasskey({
    authSession: challenge.authSession,
    credential: serializedCredential,
  });
} catch (error) {
  if (error instanceof PasskeyGetTokenError) {
    console.error(error.message);
    console.error(error.code);          // 'passkey_get_token_error'
    console.error(error.cause?.error);  // e.g., 'invalid_grant', 'access_denied'
  }
}
```
> [!NOTE]
> When MFA is enabled, `getTokenByPasskey()` can fail with an `mfa_required` response — the passkey is verified, but the user must still complete a second factor. The thrown `PasskeyGetTokenError` carries `cause.mfa_token` and `cause.mfa_requirements` so you can continue with the MFA APIs. Use the `isMfaRequiredError` type guard to detect and narrow it:
>
> ```ts
> import { isMfaRequiredError } from '@auth0/auth0-auth-js';
>
> try {
>   const tokens = await authClient.passkey.getTokenByPasskey({
>     authSession: challenge.authSession,
>     credential: serializedCredential,
>   });
> } catch (error) {
>   if (isMfaRequiredError(error)) {
>     // error.cause.mfa_token is guaranteed to be a string here
>     const challenge = await authClient.mfa.challengeAuthenticator({
>       mfaToken: error.cause.mfa_token,
>       challengeType: 'otp',
>     });
>   }
> }
> ```
>
> See [Handling the MFA Required Response](./mfa.md#handling-the-mfa-required-response) for the full flow.

> [!NOTE]
> If a confidential client has no `clientSecret` configured, because it uses only a `clientAssertionSigningKey` (private key JWT) or only `useMtls`, then `register()` and `challenge()` fail. Auth0 rejects the request and the SDK surfaces its response unchanged:
>
> ```ts
> // error.code                     -> 'passkey_register_error' | 'passkey_challenge_error'
> // error.cause?.error             -> the error code Auth0 returned
> // error.cause?.error_description -> the matching description from Auth0
> ```
>
> The SDK does not interpret or normalize these values, and the exact code depends on how the application is configured in the Auth0 Dashboard. Log `error.cause` rather than branching on it.
>
> Retrying will not help, since the SDK has no credential these endpoints accept. To fix it, set the application's authentication method to **Client Secret** in the Auth0 Dashboard, then pass that secret as `clientSecret` on the `AuthClient`. See [Using Passkeys](#using-passkeys) for the full explanation.
>
> `getTokenByPasskey()` is unaffected and works with `clientAssertionSigningKey` or mTLS, since it goes through the token endpoint.
