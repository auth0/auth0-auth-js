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

When [RP-Initiated Logout is enabled](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0) for your tenant, Auth0 shows a page that asks the user to confirm the logout when the request carries neither an `id_token_hint` nor a `logout_hint`. The [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specification requires this, because a logout request that cannot be tied to the user's session could come from another site. If the user cancels the page, Auth0 keeps its session, even if your app has already cleared its own.

To skip the page, pass the user's ID token as `idTokenHint`. The SDK sends it as the `id_token_hint` parameter:

```ts
const logoutUrl = await authClient.buildLogoutUrl({
  returnTo,
  idTokenHint: idToken, // The ID token you received when the user logged in
});
```

The specification says the server should accept an expired ID token here, so you don't need to refresh it just to log out. Only send an ID token that has a `sid` claim, which names the Auth0 session it belongs to. Not every ID token has one, so check for it before you send the token.

The ID token carries the user's profile claims and becomes part of the URL, which can end up in server and proxy logs and in the browser history. Servers and proxies also limit URL length, often to between 4 KB and 8 KB. If either is a concern, pass the `sid` claim of the ID token as `logoutHint` instead. The SDK sends it as the `logout_hint` parameter, and Auth0 skips the page for it too:

```ts
const logoutUrl = await authClient.buildLogoutUrl({
  returnTo,
  logoutHint: sid, // The `sid` claim of the ID token
});
```

> [!IMPORTANT]
> With a hint, Auth0 ends its session without asking the user, so the page no longer protects the user from other sites that trigger a logout. Make sure only the user can trigger the route in your app that redirects to the logout URL. The safest way is a `POST` request with CSRF protection. If you keep a `GET` route, only add the hint when the `Sec-Fetch-Site` request header is `same-origin` or `none`. Build the URL without a hint for every other request, so that Auth0 keeps asking. That includes `same-site` requests, which can come from subdomains of your site that you don't fully trust, and requests from browsers that don't send the header. Users in these cases still see the confirmation page. A `POST` route with CSRF protection doesn't have this limit.

> [!NOTE]
> You only need one of `idTokenHint` and `logoutHint`. If you send both, make sure they belong to the same session. If the ID token belongs to a different session than the one in the user's browser, the specification requires the server to ask the user anyway.

## Passing `state`

`state` is an opaque value that Auth0 sends back to `returnTo` after logout, so your app can carry data across the logout round trip:

```ts
const logoutUrl = await authClient.buildLogoutUrl({ returnTo, state: '<opaque_value>' });
```

Only `returnTo` has to be registered as an **Allowed Logout URL**; `state` is not checked against it. `state` is part of the URL, so don't put secrets in it.

## Choosing the logout endpoint

By default, the SDK uses the tenant's `end_session_endpoint` (RP-Initiated Logout, `/oidc/logout`) when the tenant offers one, and `/v2/logout` otherwise. Set `strategy` to choose:

- `'auto'` (default): as described above.
- `'oidc'`: always `end_session_endpoint`. Throws a `NotSupportedError` with code `rp_initiated_logout_not_supported_error` when the tenant doesn't offer it.
- `'v2'`: always `/v2/logout`, for apps whose Allowed Logout URLs are set up for it.

```ts
const logoutUrl = await authClient.buildLogoutUrl({ returnTo, strategy: 'v2' });
```

`/v2/logout` doesn't take `idTokenHint`, `logoutHint` or `state`, so they're left out of that URL.

## Verifying the Logout Token

In order to verify the logout token, the SDK provides a method `verifyLogoutToken`:

```ts
const logoutToken = '...';
const { sid, sub } = await authClient.verifyLogoutToken({ logoutToken });
```

When the verification is successful, the `sid` and `sub` claims will be returned. If not, an error will be thrown. A logout token only has to carry one of the two, so either claim can be `undefined`, and the token is rejected when both are missing. Verification also checks the signature, issuer, audience, and the `events` claim, and rejects a token that carries a `nonce`.
