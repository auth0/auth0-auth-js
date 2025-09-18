# Examples

- [Get an access token for a connection](#get-an-access-token-for-a-connection)

## Get an access token for a connection

The `getAccessTokenForConnection` method allows you to exchange an access token for an access token for a specific connection. To use this method, you will need to instantiate the `ApiClient` with the client credentials:
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
