# Examples

- [Get an access token for a connection](#get-an-access-token-for-a-connection)

## Get an access token for a connection

The `getAccessTokenForConnection` method allows you to exchange an Auth0 token for a federated provider access token using Token Vault.

### When to use which token

**Public clients (SPA, mobile, native):**
- Use `accessToken` - your backend receives the Auth0 access token from the Authorization header
- Public clients should not handle refresh tokens

**Confidential clients (backend services):**
- Use `accessToken` when handling an incoming request that only carries an access token
- Use `refreshToken` only when your backend already holds a securely stored Auth0 refresh token

### Examples

Using an access token (public clients or confidential clients with incoming access token):

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

const tokenSet = await apiClient.getAccessTokenForConnection({
  connection: 'google-oauth2',
  accessToken: '<auth0_access_token>', // From Authorization header
  loginHint: 'user@example.com', // Optional
});
```

Using a refresh token (confidential clients only):

```ts
const tokenSet = await apiClient.getAccessTokenForConnection({
  connection: 'google-oauth2',
  refreshToken: '<auth0_refresh_token>', // Securely stored server-side
});
```

### Parameters

- `connection`: The name of the connection to get the token for.
- `accessToken`: The Auth0 access token to use. Use for public clients or when your backend only has an access token.
- `refreshToken`: The Auth0 refresh token to use. Use only in confidential backends that securely store refresh tokens.
- `loginHint` (optional): An optional login hint to pass to the connection.

> [!NOTE]
> Provide exactly one of `accessToken` or `refreshToken`. The SDK automatically sets the appropriate `subject_token_type`.

If the exchange is successful, the method will return a `ConnectionTokenSet` object containing the following properties:

- `accessToken`: The access token issued by the connection.
- `scope`: The scope granted by the connection.
- `expiresAt`: The access token expiration time, represented in seconds since the Unix epoch.
- `connection`: The name of the connection the token was requested for.
- `loginHint`: An optional login hint that was passed during the exchange.

For additional details, please refer to the [Token Vault documentation](https://auth0.com/docs/secure/tokens/token-vault).
