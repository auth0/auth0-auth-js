# HTTP Requests and Responses

[← All examples](../EXAMPLES.md)

- [Per-Request Options](#per-request-options)
    - [Cancelling a request](#cancelling-a-request)
    - [Passing per-request headers](#passing-per-request-headers)
    - [Using a one-off fetch](#using-a-one-off-fetch)
- [Accessing the Full HTTP Response](#accessing-the-full-http-response)
    - [Methods that support `fullResponse`](#methods-that-support-fullresponse)
    - [TypeScript overload gotcha](#typescript-overload-gotcha)
    - [Cache and performance considerations](#cache-and-performance-considerations)
- [Handling API Errors with HTTP Metadata](#handling-api-errors-with-http-metadata)

## Per-Request Options

Every network-performing method on `AuthClient` accepts an optional trailing `RequestOptions` argument. It applies to that single call only and never mutates the client's shared configuration, so it is safe to use across concurrent requests.

```ts
export interface RequestOptions {
  /** An AbortSignal to cancel the underlying HTTP request. */
  signal?: AbortSignal;
  /** Extra headers merged into this request. `Authorization` and the telemetry `Auth0-Client` header cannot be overridden. */
  headers?: Record<string, string>;
  /** A one-off fetch used for this request only. It replaces the base transport for the call and is re-wrapped with the SDK's telemetry wrapper (so `Auth0-Client` is still sent). It does **not** inherit mTLS — if you rely on mTLS, the fetch you supply must itself be mTLS-capable. */
  customFetch?: typeof fetch;
}
```

### Cancelling a request

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000);

const tokens = await authClient.getTokenByRefreshToken(
  { refreshToken },
  { signal: controller.signal }
);
```

### Passing per-request headers

```ts
await authClient.getTokenByRefreshToken(
  { refreshToken },
  { headers: { 'X-Request-Id': requestId } }
);
```

Reserved headers set by the SDK win: a caller-supplied `Authorization` header is ignored, and the telemetry `Auth0-Client` header is always sent.

### Using a one-off fetch

```ts
await authClient.getTokenByRefreshToken(
  { refreshToken },
  { customFetch: myInstrumentedFetch }
);
```

The per-request fetch replaces the transport for that call only. It is re-wrapped internally with the telemetry wrapper, so the `Auth0-Client` header is still sent. It does **not** inherit mTLS — if you rely on mTLS, the fetch you supply must itself be mTLS-capable.

> **Note:** The URL builders (`buildAuthorizationUrl`, `buildLinkUserUrl`, `buildUnlinkUserUrl`, `buildLogoutUrl`) do not perform a token-endpoint request and therefore do not accept `RequestOptions`. (They may still trigger a one-time OIDC discovery fetch on a cold cache.)

## Accessing the Full HTTP Response

When you need to inspect the raw HTTP response from Auth0 (status code, headers, or body), pass `fullResponse: true` to any supported method. Instead of the bare return value, the method returns an `ApiResponse<T>` envelope that pairs the parsed `data` with the raw `Response`:

```ts
import type { ApiResponse, TokenResponse } from '@auth0/auth0-auth-js';

const result: ApiResponse<TokenResponse> = await authClient.getTokenByRefreshToken({
  refreshToken,
  fullResponse: true,
});

console.log(result.data.accessToken); // Parsed token data
console.log(result.response.status);  // 200
console.log(result.response.headers.get('content-type')); // 'application/json'
```

The `response` field is a clone of the Web-standard `Response` object. You can call `.headers.get()`, check `.ok`, or clone the body for further inspection.

### Methods that support `fullResponse`

All token-returning methods that accept an options object support `fullResponse: true`:

- `getTokenByRefreshToken`
- `getTokenByCode`
- `getTokenByPassword`
- `getTokenByClientCredentials`
- `getTokenByPasswordlessEmail` / `getTokenByPasswordlessSms`
- `getTokenByMagicLinkCode`
- `exchangeToken`
- `getTokenForConnection`
- `backchannelAuthentication`
- `mfa.verify`
- `passkey.getTokenByPasskey`
- `passwordless.getTokenByPasswordlessDbConnection`

The following non-token methods also support it. Their envelope carries the raw `Response` alongside the same `data` they return by default, so the `data` field is `void` (`undefined`) for the passwordless methods and the confirmation `string` for `changePassword`:

- `database.signUp` — `ApiResponse<SignUpResult>`
- `database.changePassword` — `ApiResponse<string>`
- `passwordless.sendEmail` — `ApiResponse<void>`
- `passwordless.sendSms` — `ApiResponse<void>`

```ts
import type { ApiResponse, SignUpResult } from '@auth0/auth0-auth-js';

// A void-data method: the envelope exposes the response, `data` is undefined.
const sent: ApiResponse<void> = await authClient.passwordless.sendEmail({
  email: 'user@example.com',
  fullResponse: true,
});
const rateLimitRemaining = sent.response.headers.get('x-ratelimit-remaining');

// signUp pairs the normalized user with the raw response.
const signup: ApiResponse<SignUpResult> = await authClient.database.signUp({
  email: 'user@example.com',
  password: 'a-strong-password',
  connection: 'Username-Password-Authentication',
  fullResponse: true,
});
console.log(signup.data.id, signup.response.headers.get('x-request-id'));
```

Unlike the token methods, these four hit the network on every call regardless of `fullResponse`, so requesting the envelope does not change their performance characteristics or bypass any cache.

### TypeScript overload gotcha

The `fullResponse` field must be a literal `true`, not a variable set to `true`. Spreading into a new object widens the type from literal `true` to `boolean`, which breaks overload resolution:

```ts
// ❌ Incorrect — spread widens `true` to `boolean`
const opts = { refreshToken, fullResponse: true };
const result = await authClient.getTokenByRefreshToken({ ...opts }); // TypeScript infers bare TokenResponse

// ✅ Correct — inline literal
const inlineResult = await authClient.getTokenByRefreshToken({
  refreshToken,
  fullResponse: true,
});

// ✅ Also correct — spread with type assertion
const spreadResult = await authClient.getTokenByRefreshToken({
  ...opts,
  fullResponse: true as const,
});
```

### Cache and performance considerations

Requesting `fullResponse: true` forces a live token-endpoint call even when a cached token is still valid. In methods like `getTokenByRefreshToken`, if the SDK has a valid cached token, it bypasses the cache and performs a refresh-token exchange to obtain the `Response`. This is intentional: the HTTP response can only come from a real network call.

If you call a token method repeatedly with `fullResponse: true`, each call triggers a round-trip to the token endpoint. For high-throughput scenarios, consider toggling `fullResponse` only when you need the metadata (for example, on errors or specific audit paths).

### HTTP Metadata on Errors

You do not need `fullResponse` to inspect the HTTP response of a *failed* call. When a request fails, the thrown error carries the response metadata directly, so retry and support-correlation logic works the same whether or not you opted into the success envelope. Every SDK error (the token errors, and the `mfa` / `passkey` / `passwordless` / `database` sub-client errors) exposes three optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `statusCode` | `number` | HTTP status of the failed response (e.g. `429`). |
| `headers` | `Headers` | Native Fetch `Headers`. Read individual values with `.get(...)` — e.g. `.get('retry-after')`, `.get('x-request-id')`. |
| `body` | `string` | Raw response body text. |

All three are optional: they are populated when the failure carried an HTTP response, and are `undefined` for non-HTTP failures (for example, a synchronous validation error thrown before any request).

```ts
import { TokenByRefreshTokenError } from '@auth0/auth0-auth-js';

try {
  await authClient.getTokenByRefreshToken({ refreshToken });
} catch (error) {
  if (error instanceof TokenByRefreshTokenError) {
    if (error.statusCode === 429) {
      const retryAfter = error.headers?.get('retry-after');
      // ...back off for `retryAfter` seconds, then retry
    }
    // Correlate with Auth0 support using the request id, when present.
    const requestId = error.headers?.get('x-request-id');
    console.error(error.statusCode, requestId, error.body);
  }
}
```

These fields are **additive** — existing `catch` blocks, `instanceof` checks, and `error.cause` access are unchanged. Errors that never reach the network (such as a bad phone-number format rejected before the request) simply leave the three fields `undefined`.

> [!NOTE]
> `sendEmail`, `sendSms`, and `changePassword` return bare `void` / `string` by default, but accept `fullResponse: true` to return an `ApiResponse<T>` envelope when you need success-path HTTP metadata (see [Accessing the Full HTTP Response](#accessing-the-full-http-response)). The remaining `void`-returning methods (`deleteAuthenticator`, `revokeRefreshToken`) do not expose success metadata, but their **errors** still carry `statusCode` / `headers` / `body`.

## Handling API Errors with HTTP Metadata

All errors thrown by `AuthClient` and its sub-clients carry `statusCode` and `headers` from
the HTTP response that caused the failure. Use these fields to implement retry logic, surface
diagnostic information, or handle specific HTTP-level conditions without needing `fullResponse: true`.

`statusCode` and `headers` are `undefined` when the error occurred before any HTTP response was
received (for example, a network error or DNS failure).

```typescript
import { AuthClient, TokenByRefreshTokenError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({ domain: '...', clientId: '...', clientSecret: '...' });

try {
  const tokens = await authClient.getTokenByRefreshToken({ refreshToken });
} catch (err) {
  if (err instanceof TokenByRefreshTokenError) {
    console.error('Token refresh failed', {
      code: err.code,
      statusCode: err.statusCode,       // e.g. 401, 429
      retryAfter: err.headers?.get('Retry-After'),
    });

    if (err.statusCode === 429) {
      // Rate limited — read Retry-After and back off before retrying.
      const retryAfter = err.headers?.get('Retry-After');
      // ... schedule retry
    }
  }
}
```

The `statusCode` and `headers` fields are available on all error types:

- `TokenByCodeError`, `TokenByRefreshTokenError`, `TokenByPasswordError`
- `TokenByClientCredentialsError`, `TokenExchangeError`, `TokenForConnectionError`
- `BackchannelAuthenticationError`, `TokenRevocationError`
- `PasswordlessStartError`, `PasswordlessVerifyError`, `PasswordlessDbGetTokenError`
- `PasswordlessChallengeError` (always had `statusCode`; `headers` added in 1.x)
- `SignUpError`, `ChangePasswordError`

URL-build errors (`BuildAuthorizationUrlError`, `BuildLinkUserUrlError`,
`BuildUnlinkUserUrlError`) intentionally do not carry `statusCode` or `headers` — they are
thrown before any HTTP request is made.
