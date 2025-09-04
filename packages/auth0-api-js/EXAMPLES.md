# Examples

- [Get an access token for a connection](#get-an-access-token-for-a-connection)

## Get an access token for a connection

To get an access token for a connection using the `getAccessTokenForConnection` method, you need to instantiate the `AuthClient` with a `clientId` and `clientSecret`:

```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

const tokenSet = await apiClient.getAccessTokenForConnection({
  connection: 'my-connection',
  accessToken: 'my-access-token',
  loginHint: 'login-hint', // Optional
});
```

For additional details, please refer to the [Token Vault documentation](https://auth0.com/docs/secure/tokens/token-vault).

