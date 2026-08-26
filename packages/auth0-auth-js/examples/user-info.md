# Retrieving User Information

The SDK provides a method to retrieve user profile information from the OIDC `/userinfo` endpoint. This is useful when you need to fetch fresh user claims using an access token.

> [!IMPORTANT]
> The access token must be accepted by the `/userinfo` endpoint, which depends on how it was obtained:
>
> - **Without Multi-Resource Refresh Tokens (MRRT):** use a default OIDC access token — one issued
>   without an explicit `audience` parameter.
> - **With MRRT:** access tokens are audience-bound, so you must explicitly request the userinfo
>   endpoint as the audience (e.g. `audience: 'https://<AUTH0_DOMAIN>/userinfo'`) when obtaining the
>   token. A token bound to a different resource-server audience is rejected by `/userinfo`, typically
>   resulting in a `UserInfoError` (HTTP 401 or 403).
>
> If you have a known `sub` from a session or ID token, pass it as `expectedSubject` to guard against
> token substitution (recommended, though optional for node-auth0 parity).

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Retrieve user information with an access token
const userInfo = await authClient.getUserInfo({
  accessToken: '<access_token>',
});

console.log(userInfo.sub);
console.log(userInfo.email);
console.log(userInfo.name);
```

The returned `UserInfoResponse` object contains OIDC standard claims like `sub`, `email`, `name`, and other profile information. The exact claims returned depend on the scopes requested during authentication and the user's profile data.

## Optional Subject Validation

You can optionally validate that the returned `sub` claim matches an expected value. This is useful for security checks:

```ts
const userInfo = await authClient.getUserInfo({
  accessToken: myAccessToken,
  expectedSubject: 'auth0|user123',
});

// If the returned sub doesn't match expectedSubject, getUserInfo() throws UserInfoError
```

If the `expectedSubject` parameter is not provided, subject validation is skipped.

## Error Handling

The `getUserInfo()` method throws `UserInfoError` when the request fails. Common error scenarios include:

- **401 Unauthorized**: The access token is expired, revoked, or invalid.
- **403 Forbidden**: The access token is valid but lacks the required scope.
- **Subject Mismatch**: The returned `sub` claim does not match the `expectedSubject` (if provided).

```ts
import { AuthClient, UserInfoError } from '@auth0/auth0-auth-js';

try {
  const userInfo = await authClient.getUserInfo({
    accessToken: myAccessToken,
  });
} catch (error) {
  if (error instanceof UserInfoError) {
    console.error('Failed to retrieve user info:', error.message);
    console.error('Error code:', error.code);           // 'user_info_error'
    console.error('OAuth error:', error.cause?.error);  // e.g., 'unauthorized'
  }
}
```
