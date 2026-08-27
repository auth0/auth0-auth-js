# Logout

[← All examples](../EXAMPLES.md)

## Building the Logout URL

The SDK provides a method to build the logout URL, which can be used to redirect the user to logout from Auth0:

```ts
const returnTo = 'http://localhost:3000';
const logoutUrl = await authClient.buildLogoutUrl({ returnTo });

// Redirect user to logoutUrl to logout from Auth0
```

> [!IMPORTANT]  
> You will need to register the `returnTo` in your Auth0 Application as an **Allowed Logout URL** via the [Auth0 Dashboard](https://manage.auth0.com).

## Verifying the Logout Token

In order to verify the logout token, the SDK provides a method `verifyLogoutToken`:

```ts
const logoutToken = '...';
const { sid, sub } = await authClient.verifyLogoutToken({ logoutToken });
```

When the verification is successful, the `sid` and `sub` claims will be returned. If not, an error will be thrown. A logout token only has to carry one of the two, so either claim can be `undefined`, and the token is rejected when both are missing. Verification also checks the signature, issuer, audience, and the `events` claim, and rejects a token that carries a `nonce`.
