# Examples

- [Configuration](#configuration)
  - [Configuring the Store](#configuring-the-store)
    - [Stateless Store](#stateless-store)
    - [Stateful Store](#stateful-store)
  - [Configuring Cookies Secret Rotation](#configuring-cookies-secret-rotation)
  - [Configuring the Store Identifier](#configuring-the-store-identifier)
  - [Configuring the Scopes](#configuring-the-scopes)
  - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
  - [Configuring mTLS (Mutual TLS)](#configuring-mtls-mutual-tls)
  - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
  - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
  - [Configuring discovery cache](#configuring-discovery-cache)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Dynamic Domain Resolver](#dynamic-domain-resolver)
  - [Resolver Mode](#resolver-mode)
  - [Redirect URI Requirements](#redirect-uri-requirements)
  - [Legacy Sessions and Migration](#legacy-sessions-and-migration)
  - [Security Requirements](#security-requirements)
- [Starting Interactive Login](#starting-interactive-login)
  - [Passing `authorizationParams`](#passing-authorization-params)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Using Pushed Authorization Requests](#using-pushed-authorization-requests)
  - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions)
- [Completing Interactive Login](#completing-interactive-login)
  - [Retrieving `appState`](#retrieving-appstate)
  - [Passing `StoreOptions`](#passing-storeoptions-1)
- [Starting Link User](#starting-link-user)
  - [Passing `authorizationParams`](#passing-authorization-params-1)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Passing `StoreOptions`](#passing-storeoptions-1)
- [Completing Link User](#completing-link-user)
  - [Retrieving `appState`](#retrieving-appstate-1)
  - [Passing `StoreOptions`](#passing-storeoptions-2)
- [Login using Client-Initiated Backchannel Authentication](#login-using-client-initiated-backchannel-authentication)
  - [Using Rich Authorization Requests](#using-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions-2)
- [Retrieving the logged-in User](#retrieving-the-logged-in-user)
  - [Passing `StoreOptions`](#passing-storeoptions-3)
- [Retrieving the Session Data](#retrieving-the-session-data)
  - [Passing `StoreOptions`](#passing-storeoptions-4)
- [Retrieving an Access Token](#retrieving-an-access-token)
  - [Using Multi-Resource Refresh Tokens (MRRT)](#using-multi-resource-refresh-tokens-mrrt)
  - [Modifying Token Scopes](#modifying-token-scopes)
  - [Passing `StoreOptions`](#passing-storeoptions-5)
- [Retrieving an Access Token for a Connection](#retrieving-an-access-token-for-a-connection)
  - [Passing `StoreOptions`](#passing-storeoptions-6)
- [Logout](#logout)
  - [Passing the `returnTo` parameter](#passing-the-returnto-parameter)
  - [Passing `StoreOptions`](#passing-storeoptions-7)
- [Handle Backchannel Logout](#handle-backchannel-logout)
  - [Passing `StoreOptions`](#passing-storeoptions-8)

## Configuration

### Configuring the Store

The `auth0-server-js` SDK comes with a built-in store for both transaction and state data, however **it's required to provide it a CookieHandler implementation** that fits your use-case.
The goal of `auth0-server-js` is to provide a flexible API that allows you to use any storage mechanism you prefer, but is mostly designed to work with cookie and session-based storage kept in mind.

The SDK methods accept an optional `storeOptions` object that can be used to pass additional options to the storage methods, such as Request / Response objects, allowing to control cookies in the storage layer.
When using domain resolution, ensure `storeOptions` includes the framework request so the resolver can read headers or other request data.

For Web Applications, this may come down to a Stateless or Statefull session storage system.

#### Stateless Store

In a stateless storage solution, the entire session data is stored in the cookie. This is the simplest form of storage, but it has some limitations, such as the maximum size of a cookie.

The implementation may vary depending on the framework of choice, here is an example using Fastify:

```ts
import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import {
  AbstractStateStore,
  AbstractTransactionStore,
  ServerClient,
  StateData,
  TransactionData,
} from '@auth0/auth0-server-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.clearCookie(name);
  }
}

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({ secret: options.secret }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({ secret: options.secret }, new FastifyCookieHandler()),
});
```

#### Stateful Store

In stateful storage, the session data is stored in a server-side storage mechanism, such as a database. This allows for more flexibility in the size of the session data, but requires additional infrastructure to manage the storage.
The session is identified by a unique identifier that is stored in the cookie, which the storage would read in order to retrieve the session data from the server-side storage.

The implementation may vary depending on the framework of choice, here is an example using Fastify:

```ts
import type { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractStateStore, LogoutTokenClaims, ServerClient, StateData } from '@auth0/auth0-server-js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    // Handle storeOptions being undefined if needed.
    return storeOptions!.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    // Handle storeOptions being undefined if needed.
    storeOptions!.reply.clearCookie(name);
  }
}

const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({ secret: options.secret }, new FastifyCookieHandler()),
  stateStore: new StatefulStateStore({ secret: options.secret }, new FastifyCookieHandler()),
});
```

Note that `storeOptions` is optional in the SDK's methods, but required when wanting to interact with the framework to set cookies. Here's how to pass `storeOptions` to `startInteractiveLogin()` in a Fastify application:

```ts
fastify.get('/auth/login', async (request, reply) => {
  const storeOptions = { request, reply };
  const authorizationUrl = await auth0Client.startInteractiveLogin({}, storeOptions);

  reply.redirect(authorizationUrl.href);
});
```

Because storage systems in Web Applications are mostly cookie-based, the `storeOptions` object is used to pass the `request` and `reply` (in the case of Fastify, as per the example) objects to the storage methods, allowing to control cookies in the storage layer. It's expected to pass this to every interaction with the SDK.

### Configuring Cookies Secret Rotation

The SDK supports secret rotation for enhanced security, allowing you to change the encryption secret used for cookies without invalidating existing sessions. This is achieved by providing an array of secrets instead of a single string.

#### How Secret Rotation Works

When you provide an array of secrets:
1. **New data is always encrypted with the newest secret** (first element in the array)
2. **Old data can be decrypted using any secret in the array** (newest to oldest)
3. **Graceful fallback** occurs automatically when decrypting existing cookies

This allows for zero-downtime secret rotation where existing user sessions remain valid while new sessions use the updated secret.

#### Implementing Secret Rotation

**Step 1: Add the new secret to the array**

When it's time to rotate your secret, add the new secret as the first element while keeping the old secret(s):

```ts
const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({
    secret: ['new-secret-key', 'old-secret-key']
  }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({
    secret: ['new-secret-key', 'old-secret-key']
  }, new FastifyCookieHandler()),
});
```

**Step 2: Monitor and wait for old sessions to expire**

Keep both secrets in the configuration for a period that covers your longest session duration (e.g., if sessions last 7 days, keep both secrets for at least 7 days).

**Step 3: Remove the old secret**

Once you're confident all sessions encrypted with the old secret have expired, remove it from the array:

```ts
const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({
    secret: 'new-secret-key'  // or ['new-secret-key'] - both work
  }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({
    secret: 'new-secret-key'
  }, new FastifyCookieHandler()),
});
```

#### Multiple Secret Rotation

You can maintain multiple old secrets if needed, for example during multiple rotations or longer transition periods:

```ts
const auth0 = new ServerClient<StoreOptions>({
  transactionStore: new CookieTransactionStore({
    secret: [
      'newest-secret',    // Used for all new encryptions
      'middle-secret',    // Fallback for existing sessions
      'oldest-secret'     // Fallback for very old sessions
    ]
  }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({
    secret: [
      'newest-secret',
      'middle-secret',
      'oldest-secret'
    ]
  }, new FastifyCookieHandler()),
});
```

The SDK will try secrets in order (newest to oldest) when decrypting, ensuring optimal performance while maintaining backward compatibility.

### Configuring the Store Identifier

By default, the SDK uses `__a0_tx` and `__a0_session` to identify the Transaction and State data in the store respectively.

To change this, the `transactionIdentifier` and `stateIdentifier` options can be set when instantiating `ServerClient`:

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const serverClient = new ServerClient({
  transactionIdentifier: '__my_tx',
  stateIdentifier: '__my_session',
});
```

### Configuring the Scopes

By default, the SDK will request an Access Token using `'openid profile email offline_access'` as the scope. This can be changed by configuring `authorizationParams.scope`:

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'scope_a openid profile email offline_access',
  },
});
```

In order to ensure the SDK can refresh tokens when expired, the `offline_access` scope should be included. It is also mandatory to include `openid` as part of `authrizationParams.scope`.

### Configuring PrivateKeyJwt

The SDK requires you to provide either a client secret, or private key JWT. Private Key JWT can be used by setting `clientAssertionSigningKey` when creating an instance of ServerClient:

```ts
import { ServerClient } from '@auth0/auth0-server-js';
import { importPKCS8 } from 'jose';

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
....................REMOVED FOR BREVITY.........................
-----END PRIVATE KEY-----`;
const clientAssertionSigningKey = await importPKCS8(clientPrivateKey, 'RS256');
const serverClient = new ServerClient({
  clientId: '<client_id>',
  clientAssertionSigningKey,
});
```

Note that the private keys should not be committed to source control, and should be stored securely.

### Configuring mTLS (Mutual TLS)

The SDK supports mTLS (Mutual TLS) authentication, which provides stronger security by using client certificates for authentication. When using mTLS, you don't need to provide a client secret or private key JWT since the client certificate serves as the authentication mechanism.

To use mTLS, set `useMtls: true` and provide a `customFetch` implementation that includes your client certificate:

```ts
import { ServerClient } from '@auth0/auth0-server-js';
import { Agent } from 'undici';

const serverClient = new ServerClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  useMtls: true,
  customFetch: (url, options) => {
    return fetch(url, {
      ...options,
      dispatcher: new Agent({
        connect: {
          key: '...',
          cert: '...',
          ca: '...',
        },
      }),
    });
  },
  stateStore: myStateStore,
  transactionStore: myTransactionStore,
});

// Example usage: Start interactive login with mTLS
const authorizationUrl = await serverClient.startInteractiveLogin();
```

**Key points for mTLS configuration:**

- **Client Certificate**: Your application must have a valid client certificate issued by a Certificate Authority (CA) that Auth0 trusts.
- **Domain Configuration**: Your Auth0 tenant must be configured to support mTLS endpoints.
- **No Additional Auth**: When `useMtls: true`, you don't need `clientSecret` or `clientAssertionSigningKey`.
- **Custom Fetch Required**: You must provide a `customFetch` implementation that includes the client certificate in the TLS handshake.
- **Store Configuration**: mTLS works with both stateless and stateful store configurations.

> [!IMPORTANT]  
> mTLS requires proper certificate management and Auth0 tenant configuration. Make sure your Auth0 tenant supports mTLS endpoints and that your client certificates are properly configured in the Auth0 Dashboard. Learn how to configure mTLS in your Auth0 tenant by reading the [mTLS configuration documentation](https://auth0.com/docs/get-started/applications/configure-mtls).

### Configuring the `authorizationParams` globally

The `authorizationParams` object can be used to customize the authorization parameters that will be passed to the `/authorize` endpoint. This object can be passed when creating an instance of `ServerClient`, but it can also be specified when calling certain methods of the SDK, for example `startInteractiveLogin()`. For each of these, the same rule applies in the sense that both `authorizationParams` objects will be merged, where those provided to the method, override those provided when creating the instance.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar',
  },
});
```

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when creating an instance of `ServerClient`:

```ts
const serverClient = new ServerClient({
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

### Configuring discovery cache

By default, the SDK caches discovery metadata and JWKS in memory using an LRU cache
with a TTL of `600` seconds and a maximum of `100` entries. To override these defaults:

Discovery cache entries are keyed by Auth0 domain and mTLS mode. In practice, you
only approach `100` entries if one process handles more than 100 distinct
`domain + mTLS` combinations within the TTL window.

```ts
const serverClient = new ServerClient({
  discoveryCache: {
    ttl: 900,
    maxEntries: 200,
  },
});
```
To effectively disable discovery cache, set `discoveryCache.ttl` to `0`.

To learn more, see [`@auth0/auth0-auth-js` discovery cache examples](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/EXAMPLES.md#configuring-discovery-cache).

## Multiple Custom Domains (MCD)

Multiple Custom Domains (MCD) lets you resolve the Auth0 domain per request while keeping a single SDK instance. This is useful when one application serves multiple customer domains (for example, `brand-1.my-app.com` and `brand-2.my-app.com`), each mapped to a different `Auth0` custom domain.

`MCD` is enabled by providing a `domain resolver function` instead of a static domain string, enabling you to dynamically define the `Auth0` custom domain at run-time.

Resolver mode is intended for the custom domains of a single `Auth0` tenant. It is not a supported way to connect multiple `Auth0` tenants to one application.

### Dynamic Domain Resolver

Provide a resolver function to select the domain at runtime. The resolver should return the `Auth0 Custom Domain` (for example, `brand-1.custom-domain.com`). Returning `null` or an empty value throws `InvalidConfigurationError`.
The resolver receives a `context` object, which is the same `storeOptions` object passed to SDK method calls. 


In framework integrations (or higher-level framework SDKs), this is usually provided by the integration layer and contains request-specific values (for example `{ request, reply }` in Fastify).

#### Scenario 1: Host-based resolver with default fallback

```ts
import { ServerClient } from '@auth0/auth0-server-js';
import type { DomainResolver } from '@auth0/auth0-server-js';

type StoreOptions = { request: { headers: Record<string, string | undefined> } };
const defaultAuth0Domain = 'auth.custom-domain.com';

const domainResolver: DomainResolver<StoreOptions> = async (context) => {
  const host = context?.request?.headers.host;
  const domains = {
    'brand-1.my-app.com': 'auth.custom-domain-1.com',
    'brand-2.my-app.com': 'auth.custom-domain-2.com'
  };
  return domains[host] ?? defaultAuth0Domain;
};

const auth0 = new ServerClient<StoreOptions>({
  domain: domainResolver,
  clientId: '<client_id>',
  clientSecret: '<client_secret>',
  transactionStore,
  stateStore,
});
```

#### Scenario 2: Header-to-domain map (trusted app request context)

```ts
const headerValueToAuth0Domain: Record<string, string> = {
  workspace_a: 'workspace-a.custom-domain.com',
  workspace_b: 'workspace-b.custom-domain.com',
};

const domainResolver: DomainResolver<StoreOptions> = (context) => {
  // Example app header used for routing. This is app-specific context, not Auth0 tenant metadata.
  const routingKey = context?.request?.headers['x-tenant-id'];
  if (!routingKey) return 'auth.custom-domain.com';
  return headerValueToAuth0Domain[routingKey] ?? 'auth.custom-domain.com';
};
```

### Resolver Mode

Resolver mode means `domain` is configured as a resolver function. The SDK then passes your per-request `storeOptions` into that resolver so it can choose the correct Auth0 domain for the current request.
- If your resolver depends on request context (for example headers), pass `storeOptions` to each SDK method invocation.
- If your resolver gets context from another source (for example `AsyncLocalStorage`), it can still work without `storeOptions`.
- If `storeOptions` is omitted for an SDK method invocation, the resolver receives `context` as `undefined`.

The following `Fastify` example shows how to pass per-request `storeOptions` to each SDK method so the resolver and stores can use request-specific context during `login`, `callback`, and `logout`.
<a id="mcd-fastify-example"></a>
```ts
fastify.get('/auth/login', async (request, reply) => {
  const storeOptions = { request, reply };
  const redirectUri = resolveRedirectUri(request); // Implement in your app with safe host/scheme validation.
  const authorizationUrl = await auth0.startInteractiveLogin(
    {
      authorizationParams: {
        redirect_uri: redirectUri,
      },
    },
    storeOptions // Passing `storeOptions`
  );
  reply.redirect(authorizationUrl.href);
});

fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };
  const callbackUrl = new URL(request.url, resolveBaseUrl(request));
  await auth0.completeInteractiveLogin(callbackUrl, storeOptions); // Passing `storeOptions`
  reply.redirect('/');
});

fastify.get('/auth/logout', async (request, reply) => {
  const storeOptions = { request, reply };
  const returnTo = resolveReturnTo(request);
  const logoutUrl = await auth0.logout({ returnTo }, storeOptions); // Passing `storeOptions`
  reply.redirect(logoutUrl.href);
});
```

### Redirect URI Requirements

While using MCD, interactive flows still require an **absolute** `authorizationParams.redirect_uri`. The SDK does not infer it from the request. You can set it once on the `ServerClient` or override it per call. In [Resolver Mode](#resolver-mode) deployments you will typically pass `authorizationParams` per call (for example `startInteractiveLogin`) so each request uses the correct app domain.

```ts
const authorizationUrl = await auth0.startInteractiveLogin(
  {
    authorizationParams: {
      redirect_uri: 'https://brand-1.my-app.com/auth/callback',
    },
  },
  { request, reply }
);
```

In the [Fastify example](#mcd-fastify-example) above, the `/auth/login` handler already shows this pattern by resolving `redirect_uri` per request. You must implement `resolveRedirectUri(request)` in your app and validate host/scheme safely for your deployment.

> **Note:**
>
> In [Resolver Mode](#resolver-mode), MCD needs an ID token in the callback so the SDK can validate the `iss` claim.
> The `openid` scope is required to receive an ID token.
> The SDK includes `openid` by default and ensures it is present even when you provide a custom `authorizationParams.scope`.

### Legacy Sessions and Migration

When moving from a static domain setup to [Resolver Mode](#resolver-mode), existing sessions can continue to work if the resolver returns the same Auth0 `custom domain` that was used for those legacy sessions.

If the resolver returns a different `domain`, the SDK treats the session as missing and requires the user to sign in again. This is intentional to keep sessions isolated per domain.

### Security Requirements
When configuring SDKs to resolve tenant custom domains via the domain resolver functions, you are responsible for ensuring that all resolved domains are trusted.
Mis-configuring the domain resolver is a critical security risk that can lead to authentication bypass on the `relying party` (RP) or expose the application to `Server-Side Request Forgery` (SSRF).

**Single Tenant Limitation:**
The domain resolvers are intended solely for multiple custom domains belonging to the same `Auth0` tenant. It is not a supported mechanism for connecting multiple `Auth0` tenants to a single application.

**Secure Proxy Requirement:**
When using `Multiple Custom Domains` (MCD), your application must be deployed behind a secure `Edge` or `Reverse Proxy` (e.g., `Cloudflare`, `Nginx`, or `AWS ALB`).
The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process.
This can result in malicious redirects, where users are sent to `unauthorized` or `fraudulent` endpoints during the login and logout flows.

## Starting Interactive Login

As interactive login is a two-step process, it begins with configuring a `redirect_uri`, which is the URL Auth0 will redirect the user to after successful authentication to complete the interactive login. Once configured, call `startInteractiveLogin` and redirect the user to the returned authorization URL:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const authorizationUrl = await serverClient.startInteractiveLogin();
// Redirect user to authorizeUrl
```

The `redirect_uri` must be an absolute URL.

If you need to compute the redirect URI per request (for example in multi-domain deployments), pass `authorizationParams.redirect_uri` to `startInteractiveLogin()` to override the configured value.

### Passing `authorizationParams`

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startInteractiveLogin()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
  },
});
```

Apart from first-class properties such as `scope`, `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar',
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `startInteractiveLogin()`:

```ts
await serverClient.startInteractiveLogin({
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'urn:custom:api',
    foo: 'bar',
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `startInteractiveLogin`, will override the same, statically configured, `authorizationParams` property on `ServerClient`.

### Passing `appState` to track state during login

The `appState` parameter, passed to `startInteractiveLogin()`, can be used to track state which you want to get back after calling `completeInteractiveLogin`.

```ts
const authorizeUrl = await startInteractiveLogin({ appState: { myKey: 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await completeInteractiveLogin(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `authorizeUrl` and `url` are two distinct URLs.
>
> - `authorizeUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful authentication.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Using Pushed Authorization Requests

Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server by setting `pushedAuthorizationRequests` to true when calling `startInteractiveLogin`.

```ts
const authorizationUrl = await serverClient.startInteractiveLogin({ pushedAuthorizationRequests: true });
```

When calling `startInteractiveLogin` with `pushedAuthorizationRequests` set to true, the SDK will send all the parameters to Auth0 using an HTTP Post request, and returns an URL that you can use to redirect the user to in order to finish the login flow.

> Using Pushed Authorization Requests requires the feature to be enabled in the Auth0 dashboard. Read [the documentation](https://auth0.com/docs/get-started/applications/configure-par) on how to configure PAR before enabling it in the SDK.

### Using Pushed Authorization Requests and Rich Authorization Requests

When using Pushed Authorization Requests, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`, additionally to setting `pushedAuthorizationRequests` to true.

```ts
const authorizationUrl = await serverClient.startInteractiveLogin({
  pushedAuthorizationRequests: true,
  authorizationParams: {
    authorization_details: JSON.stringify([{
      type: '<type>',
      // additional fields here
    }
  }])
});
```

When completing the interactive login flow, the SDK will expose the `authorizationDetails` in the returned value:

```ts
const { authorizationDetails } = await serverClient.completeInteractiveLogin(url);
console.log(authorizationDetails.type);
```

> Using Pushed Authorization Requests and Rich Authorization Requests requires both features to be enabled in the Auth0 dashboard. Read [the documentation on how to configure PAR](https://auth0.com/docs/get-started/applications/configure-par), and [the documentation on how to configure RAR](https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests) before enabling it in the SDK.

### Passing `StoreOptions`

Just like most methods, `startInteractiveLogin` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const authorizeUrl = await serverClient.startInteractiveLogin({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Completing Interactive Login

As interactive login is a two-step process, after starting it, it also needs to be completed. This can be achieved using the SDK's `completeInteractiveLogin()`.

```ts
await auth.completeInteractiveLogin(url);
```

> The url passed to `completeInteractiveLogin` is the URL Auth0 redirects the user back to after successful authentication, and should contain `state` and either `code` or `error`.

### Retrieving `appState`

The `appState` parameter, passed to `startInteractiveLogin()`, can be retrieved again when calling `completeInteractiveLogin()`.

```ts
const authorizeUrl = await serverClient.startInteractiveLogin({ appState: { myKey: 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeInteractiveLogin(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `authorizeUrl` and `url` are two distinct URLs.
>
> - `authorizeUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful authentication.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Passing `StoreOptions`

Just like most methods, `completeInteractiveLogin` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const authorizeUrl = await serverClient.completeInteractiveLogin({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Starting Link User

As user-linking is a two-step process, it begins with configuring a `redirect_uri`, which is the URL Auth0 will redirect the user to after succesful authentication to complete the user-linking. Once configured, call `startLinkUser` and redirect the user to the returned authorization URL:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    redirect_uri: 'http://localhost:3000/auth/callback',
  },
});
const linkUserUrl = await serverClient.startLinkUser();
// Redirect user to linkUserUrl
```

The `redirect_uri` must be an absolute URL.

If you need to compute the redirect URI per request (for example in multi-domain deployments), pass `authorizationParams.redirect_uri` to `startLinkUser()` to override the configured value.

Once the link user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorizationParams`. At that point, it's required to call `completeLinkUser()` to finalize the user-linking process. Read more below in [Completing Link User](#completing-link-user).

### Passing `authorizationParams`

In order to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startLinkUser()`, you can statically configure them when instantiating the client using `authorizationParams`:

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    audience: 'urn:custom:api',
  },
});
```

Apart from first-class properties such as `audience` and `redirect_uri`, `authorizationParams` also supports passing any arbitrary custom parameter to `/authorize`.

```ts
const serverClient = new ServerClient({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar',
  },
});
```

If a more dynamic configuration of the `authorizationParams` is needed, they can also be configured when calling `startLinkUser()`:

```ts
await serverClient.startLinkUser({
  authorizationParams: {
    audience: 'urn:custom:api',
    foo: 'bar',
  },
});
```

Keep in mind that, any `authorizationParams` property specified when calling `startLinkUser`, will override the same, statically configured, `authorizationParams` property on `ServerClient`.

### Passing `appState` to track state during login

The `appState` parameter, passed to `startLinkUser()`, can be used to track state which you want to get back after calling `completeLinkUser`.

```ts
const linkUserUrl = await serverClient.startLinkUser({ appState: { myKey: 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeLinkUser(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `linkUserUrl` and `url` are two distinct URLs.
>
> - `linkUserUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to link the account.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful linking the account.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Passing `StoreOptions`

Just like most methods, `startLinkUser` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const authorizeUrl = await serverClient.startLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

## Completing Link User

As user-linking is a two-step process, after starting it, it also needs to be completed. This can be achieved using the SDK's `completeLinkUser()`.

```ts
await serverClient.completeLinkUser(url);
```

> The url passed to `completeLinkUser` is the URL Auth0 redirects the user back to after successful account linking, and should contain `state` and either `code` or `error`.

### Retrieving `appState`

The `appState` parameter, passed to `startLinkUser()`, can be retrieved again when calling `completeLinkUser()`.

```ts
const linkUserUrl = await serverClient.startLinkUser({ appState: { myKey: 'myValue' } });

// Redirect the user, and wait to be redirected back
const { appState } = await serverClient.completeLinkUser(url);
console.log(appState.myKey); // Logs 'myValue'
```

> Note: In the above example, `linkUserUrl` and `url` are two distinct URLs.
>
> - `linkUserUrl` points to `/authorize` on your Auth0 domain, and is the URL the user is redirected to in order to authenticate.
> - `url` points to a URL in the application, and is the URL Auth0 redirects the user back to after successful linking the account.

Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-js`.

### Passing `StoreOptions`

Just like most methods, `completeLinkUser` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const authorizeUrl = await serverClient.completeLinkUser({}, storeOptions);
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

## Login using Client-Initiated Backchannel Authentication

Using Client-Initiated Backchannel Authentication can be done by calling `loginBackchannel()`:

```ts
await serverClient.loginBackchannel({
  bindingMessage: '',
  loginHint: {
    sub: 'auth0|123456789',
  },
});
```

- `bindingMessage`: A human-readable message to be displayed at the consumption device and authentication device. This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
- `loginHint.sub`: The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.

> [!IMPORTANT]
> Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
> Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

### Using Rich Authorization Requests

When using Client-Initiated Backchannel Authentication, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`:

```ts
const { authorizationDetails } = await serverClient.loginBackchannel({
  bindingMessage: '<binding_message>',
  loginHint: {
    sub: 'auth0|123456789'
  },
  authorizationParams: {
    authorization_details: JSON.stringify([{
      type: '<type>',
      // additional fields here
    }
  ])
});
```

> [!IMPORTANT]
> Using Client-Initiated Backchannel Authentication with Rich Authorization Requests (RAR) requires the feature to be enabled in the Auth0 dashboard.
> Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

### Passing `StoreOptions`

Just like most methods, `loginBackchannel` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
await serverClient.loginBackchannel({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving the logged-in User

The SDK's `getUser()` can be used to retrieve the current logged-in user:

```ts
await serverClient.getUser();
```

### Passing `StoreOptions`

Just like most methods, `getUser` accept an argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const user = await serverClient.getUser(storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving the Session Data

The SDK's `getSession()` can be used to retrieve the current session data:

```ts
const session = await serverClient.getSession();
```

### Passing `StoreOptions`

Just like most methods, `getSession` accept an argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const session = await serverClient.getSession(storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving an Access Token

The SDK's `getAccessToken()` can be used to retrieve an Access Token for the current logged-in user:

```ts
const accessToken = await serverClient.getAccessToken();
```

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `getAccessToken()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token.

### Using Multi-Resource Refresh Tokens (MRRT)

When refresh token policies are configured in your application, you can use the refresh token stored in the session to obtain access tokens for different APIs (audiences). Simply pass the desired `audience` parameter to `getAccessToken()`:

```ts
const accessToken = await serverClient.getAccessToken({
  audience: 'https://another-api.example.com'
});
```

You can also combine `audience` with `scope` to request specific permissions for the target API:

```ts
const accessToken = await serverClient.getAccessToken({
  audience: 'https://another-api.example.com',
  scope: 'read:users write:users'
});
```

### Modifying Token Scopes

When retrieving an access token for the same audience, you can modify the scopes by passing the `scope` parameter:

```ts
// Downscope: Request fewer permissions than originally granted
// If original access token had 'read:profile write:profile',
// you can request only 'read:profile'
const accessToken = await serverClient.getAccessToken({
  scope: 'read:profile'
});
```

Depending on your application's refresh token policies, you can also request additional scopes beyond those in the original access token:

```ts
// Request additional scopes (e.g., adding 'delete:profile')
// If original access token had 'read:profile write:profile',
// you can request 'delete:profile' if allowed by your refresh token policies
const accessToken = await serverClient.getAccessToken({
  scope: 'read:profile write:profile delete:profile'
});
```

> [!NOTE]
> Downscoping (requesting fewer permissions) is always permitted. However, requesting scopes beyond those in the original grant depends on your application's refresh token policies.

### Passing `StoreOptions`

Just like most methods, `getAccessToken` accepts a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = { /* ... */ };
const accessToken = await serverClient.getAccessToken({}, storeOptions);
```

If you're also passing token options (such as `audience` or `scope`), you can combine them:

```ts
const options = {
  audience: 'https://api.example.com',
  scope: 'read:users',
};
const storeOptions = { /* ... */ };
const accessToken = await serverClient.getAccessToken(options, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving an Access Token for a Connection

The SDK's `getAccessTokenForConnection()` can be used to retrieve an Access Token for a connection (e.g. `google-oauth2`) for the current logged-in user:

```ts
const accessTokenForGoogle = await serverClient.getAccessTokenForConnection({ connection: 'google-oauth2' });
```

- `connection`: The connection for which an access token should be retrieved, e.g. `google-oauth2` for Google.
- `loginHint`: Optional login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user.

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `getAccessTokenForConnection()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token for a connection.

### Passing `StoreOptions`

Just like most methods, `getAccessTokenForConnection()` accepts a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const accessToken = await serverClient.getAccessTokenForConnection({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Logout

Logging out ensures the stored tokens and user information are removed, and that the user is no longer considered logged-in by the SDK.
Additionally, calling `logout()` returns a URL to redirect the browser to, in order to logout from Auth0.

```ts
const logoutUrl = await serverClient.logout({});
// Redirect user to logoutUrl
```

### Passing the `returnTo` parameter

When redirecting to Auth0, the user may need to be redirected back to the application. To achieve that, you can specify the `returnTo` parameter wgen calling `logout()`.

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' });
// Redirect user to logoutUrl
```

### Passing `StoreOptions`

Just like most methods, `logout()` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const logoutUrl = await serverClient.logout({}, storeOptions);
// Redirect user to logoutUrl
```

Read more above in [Configuring the Store](#configuring-the-store)

## Handle Backchannel Logout

To handle backchannel logout, the SDK's `handleBackchannelLogout()` method needs to be called with a logoutToken:

```ts
const logoutToken = '';
await serverClient.handleBackchannelLogout(logoutToken);
```

Read more on [backchannel logout on Auth0 docs](https://auth0.com/docs/authenticate/login/logout/back-channel-logout).

### Passing `StoreOptions`

Just like most methods, `handleBackchannelLogout()` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const logoutToken = '';
const storeOptions = {
  /* ... */
};
await serverClient.handleBackchannelLogout(logoutToken, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)
