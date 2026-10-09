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

## Skipping the logout confirmation prompt

When [RP-Initiated Logout is enabled](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0) for your tenant, Auth0 can show a page that asks the user to confirm the logout. It does so when the logout request has neither an `id_token_hint` nor a matching `logout_hint`, or when the hint belongs to a different session than the one in the user's browser. The page protects users from other sites that log them out: the [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specification calls a logout request without a valid `id_token_hint` "a potential means of denial of service". If the user cancels the page, Auth0 keeps the session, even if your app has already cleared its own.

To skip the page for a logout that the user asked for, pass the user's ID token as `idToken`. The SDK sends it to Auth0 as the `id_token_hint` parameter, which Auth0 recommends:

```ts
const logoutUrl = await authClient.buildLogoutUrl({
  returnTo,
  idToken, // The ID token you received when the user logged in
});
```

The ID token can be expired, so there is no need to refresh it first. Only send an ID token that has a `sid` claim. Without it, Auth0 cannot tie the token to the session in the user's browser, and it ends whichever session the browser has, without asking.

The ID token carries the profile claims of the user and becomes part of the URL. That URL can end up in the logs of servers and proxies, and in the browser history. Servers and proxies also limit how long a URL or a header can be, often to between 4 KB and 8 KB. If either is a concern, pass the ID of the user's Auth0 session as `logoutHint` instead. This is the `sid` claim of the ID token. The SDK sends it to Auth0 as the `logout_hint` parameter, and Auth0 also skips the page:

```ts
const logoutUrl = await authClient.buildLogoutUrl({
  returnTo,
  logoutHint: sid, // The `sid` claim of the ID token
});
```

Not every ID token has a `sid` claim. For example, the ones issued by the password, passkey and token exchange grants do not.

> [!IMPORTANT]
> With a hint, Auth0 ends the session without asking the user. The page no longer protects the user from other sites that trigger a logout, so make sure only the user can trigger the route in your app that redirects to the logout URL. The safest way is a `POST` request with CSRF protection. If you keep a `GET` route, only add the hint when the `Sec-Fetch-Site` header is `same-origin` or `none`. For any other request, build the logout URL without a hint, so that Auth0 keeps asking the user to confirm. That covers requests from other sites, requests from subdomains of your site that you do not fully trust (`same-site`), and requests from browsers that do not send the header.

> [!NOTE]
> Send `idToken` or `logoutHint`, not both. If you send both, they must belong to the same session, otherwise Auth0 rejects the request.
>
> If the ID token or the session ID belongs to a different session than the one in the user's browser, Auth0 shows the confirmation page anyway. If the ID token is invalid or was issued to a different application, Auth0 shows an error page.

> [!NOTE]
> `idToken` and `logoutHint` only apply when RP-Initiated Logout is enabled for your tenant. Otherwise the SDK builds a `/v2/logout` URL and leaves them out.

## Verifying the Logout Token

In order to verify the logout token, the SDK provides a method `verifyLogoutToken`:

```ts
const logoutToken = '...';
const { sid, sub } = await authClient.verifyLogoutToken({ logoutToken });
```

When the verification is successful, the `sid` and `sub` claims will be returned. If not, an error will be thrown. A logout token only has to carry one of the two, so either claim can be `undefined`, and the token is rejected when both are missing. Verification also checks the signature, issuer, audience, and the `events` claim, and rejects a token that carries a `nonce`.
