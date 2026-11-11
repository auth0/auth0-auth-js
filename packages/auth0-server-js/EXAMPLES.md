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
- [Anonymous Sessions](#anonymous-sessions)
  - [Configuring the anonymous store](#configuring-the-anonymous-store)
  - [Creating an anonymous session](#creating-an-anonymous-session)
  - [Getting an access token](#getting-an-access-token)
  - [Reading the session](#reading-the-session)
  - [Ending the anonymous session](#ending-the-anonymous-session)
  - [Merging what the visitor did before they logged in](#merging-what-the-visitor-did-before-they-logged-in)
  - [Handling errors](#handling-errors)
  - [Linking the anonymous session to the user created at login](#linking-the-anonymous-session-to-the-user-created-at-login)
  - [Prerequisites for anonymous sessions](#prerequisites-for-anonymous-sessions)
  - [Passing `StoreOptions` to the anonymous methods](#passing-storeoptions-to-the-anonymous-methods)
- [Personal Agent Protocol (Poppy)](#personal-agent-protocol-poppy)
  - [What the SDK does for you](#what-the-sdk-does-for-you)
  - [Configuring Poppy](#configuring-poppy)
  - [Serving the discovery files](#serving-the-discovery-files)
  - [The login route](#the-login-route)
  - [The callback](#the-callback)
  - [Who is driving](#who-is-driving)
  - [The guest's access token](#the-guests-access-token)
  - [How long an agent session lasts](#how-long-an-agent-session-lasts)
  - [A browser that already has a login](#a-browser-that-already-has-a-login)
  - [Keeping guests somewhere else](#keeping-guests-somewhere-else)
  - [Handling errors](#handling-errors-1)
  - [Testing your integration](#testing-your-integration)
  - [Production notes](#production-notes)
  - [Reference](#reference)
- [Starting Interactive Login](#starting-interactive-login)
  - [Passing `authorizationParams`](#passing-authorization-params)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Logging in to an Organization](#logging-in-to-an-organization)
  - [Using Experiment Center](#using-experiment-center)
  - [Using Pushed Authorization Requests](#using-pushed-authorization-requests)
  - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions)
- [Completing Interactive Login](#completing-interactive-login)
  - [Retrieving `appState`](#retrieving-appstate)
  - [Passing `StoreOptions`](#passing-storeoptions-1)
- [Starting Link User](#starting-link-user)
  - [Passing `authorizationParams`](#passing-authorization-params-1)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Passing `StoreOptions`](#passing-storeoptions-2)
- [Completing Link User](#completing-link-user)
  - [Retrieving `appState`](#retrieving-appstate-1)
  - [Passing `StoreOptions`](#passing-storeoptions-3)
- [Login using Client-Initiated Backchannel Authentication](#login-using-client-initiated-backchannel-authentication)
- [Passwordless Authentication](#passwordless-authentication)
  - [Using Rich Authorization Requests](#using-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions-4)
- [Login and Signup using Passkeys](#login-and-signup-using-passkeys)
  - [Choosing the Passkey Methods](#choosing-the-passkey-methods)
  - [Starting a Signup](#starting-a-signup)
  - [Starting a Login](#starting-a-login)
  - [Completing the Passkey Flow](#completing-the-passkey-flow)
  - [Example: Server Routes and Browser Code](#example-server-routes-and-browser-code)
  - [Verifying the Email or Phone Number at Signup](#verifying-the-email-or-phone-number-at-signup)
  - [Passing `StoreOptions`](#passing-storeoptions-5)
  - [Using a custom Transaction Store](#using-a-custom-transaction-store)
  - [Keeping the `authSession` yourself](#keeping-the-authsession-yourself)
- [Login using Custom Token Exchange](#login-using-custom-token-exchange)
  - [Performing a delegation exchange without a session](#performing-a-delegation-exchange-without-a-session)
  - [Using actor tokens for delegation](#using-actor-tokens-for-delegation)
  - [Passing `StoreOptions`](#passing-storeoptions-6)
- [Retrieving User Information](#retrieving-user-information)
  - [Passing `StoreOptions`](#passing-storeoptions-7)
- [Impersonation via Session Transfer](#impersonation-via-session-transfer)
  - [Initiator: requesting a Session Transfer Token and redirecting](#initiator-requesting-a-session-transfer-token-and-redirecting)
  - [Target: redeeming the Session Transfer Token](#target-redeeming-the-session-transfer-token)
  - [Reading the `act` claim on the impersonation session](#reading-the-act-claim-on-the-impersonation-session)
- [Retrieving the logged-in User](#retrieving-the-logged-in-user)
  - [Passing `StoreOptions`](#passing-storeoptions-8)
- [Retrieving the Session Data](#retrieving-the-session-data)
  - [Passing `StoreOptions`](#passing-storeoptions-9)
- [Retrieving an Access Token](#retrieving-an-access-token)
  - [Using Multi-Resource Refresh Tokens (MRRT)](#using-multi-resource-refresh-tokens-mrrt)
  - [Modifying Token Scopes](#modifying-token-scopes)
  - [Passing `StoreOptions`](#passing-storeoptions-10)
- [Retrieving an Access Token for a Connection](#retrieving-an-access-token-for-a-connection)
  - [Passing `StoreOptions`](#passing-storeoptions-11)
- [Accessing the full HTTP response](#accessing-the-full-http-response)
- [Revoking a Refresh Token](#revoking-a-refresh-token)
  - [Revoking the session token](#revoking-the-session-token)
  - [Revoking an explicit token](#revoking-an-explicit-token)
  - [Revoking on logout](#revoking-on-logout)
- [Logout](#logout)
  - [Passing the `returnTo` parameter](#passing-the-returnto-parameter)
  - [Passing `StoreOptions`](#passing-storeoptions-12)
- [Handle Backchannel Logout](#handle-backchannel-logout)
  - [Passing `StoreOptions`](#passing-storeoptions-13)
- [Per-Request Options](#per-request-options)
  - [Argument shape](#argument-shape)
  - [Cancelling a request](#cancelling-a-request)
  - [Passing per-request headers](#passing-per-request-headers)
  - [Using a one-off fetch](#using-a-one-off-fetch)
  - [Cache hits are a no-op](#cache-hits-are-a-no-op)
  - [`logout()` applies `RequestOptions` to revocation only](#logout-applies-requestoptions-to-revocation-only)
  - [Sub-client argument shapes](#sub-client-argument-shapes)
  - [Methods that do not accept `RequestOptions`](#methods-that-do-not-accept-requestoptions)
- [Enterprise Connect](#enterprise-connect)
  - [Domain Discovery](#enterprise-connect-domain-discovery)
  - [Handling the Callback](#enterprise-connect-callback)
  - [App-Owned Session](#enterprise-connect-session)
  - [Protecting Routes](#enterprise-connect-protecting-routes)
  - [Logout](#enterprise-connect-logout)
  - [Back-Channel Logout](#enterprise-connect-back-channel-logout)
  - [Token Expiry](#enterprise-connect-token-expiry)
  - [EC for Identity Only](#enterprise-connect-identity-only)
  - [Allowed Logout URLs](#enterprise-connect-allowed-logout-urls)
  - [Blocked Methods](#enterprise-connect-blocked-methods)

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

A passkey flow started with `passkey.startSignup()` or `passkey.startLogin()` is kept in the Transaction Store under its own identifier, `__a0_passkey_tx`, which `passkeyTransactionIdentifier` changes. No identifier may be the start of another one, because the cookie-backed session and anonymous stores find their cookies by prefix. The passkey methods throw an `InvalidConfigurationError` when `passkeyTransactionIdentifier` starts with, or is the start of, `transactionIdentifier`, `stateIdentifier` or, when an `anonymousStore` is configured, `anonymousSessionIdentifier`. If you use your own transaction store, see [Using a custom Transaction Store](#using-a-custom-transaction-store).

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
- **No Additional Auth**: When `useMtls: true`, you don't need `clientSecret` or `clientAssertionSigningKey`. The one exception is `passkey.startSignup()` / `passkey.startLogin()` (and the lower-level `passkey.register()` / `passkey.challenge()`), which are not served on the mTLS endpoint aliases and accept only a `clientSecret`. See [Login and Signup using Passkeys](#login-and-signup-using-passkeys).
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
with a `TTL` of `600` seconds and a maximum of `100` entries. To override these defaults:

Discovery cache entries are keyed by Auth0 domain and mTLS mode. In practice, you
only approach `100` entries if one process handles more than 100 distinct
`domain + mTLS` combinations within the `TTL` window.

Most applications can keep the defaults, but you may want to adjust `discoveryCache` in the following cases:
- Increase `maxEntries` if one process may use more than `100` distinct `domain + mTLS` combinations during the `TTL` window. This is most common in [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd) deployments that work with many Auth0 domains.
- Decrease `maxEntries` if memory usage matters more than avoiding repeated discovery.
- Increase `ttl` if the same Auth0 domains are reused frequently and you want to reduce repeated discovery and JWKS fetches after cache entries expire.
- Decrease `ttl` if you want the SDK to pick up Auth0 metadata or signing key changes sooner.
- Set `ttl` to `0` if you want to effectively disable discovery cache.

Rule of thumb:
- Set `maxEntries` to cover the number of distinct Auth0 domains a single process is expected to use during the `TTL` window, with some headroom.

```ts
const serverClient = new ServerClient({
  discoveryCache: {
    ttl: 900,
    maxEntries: 200,
  },
});
```
To learn more, see [`@auth0/auth0-auth-js` discovery cache examples](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/examples/configuration.md#configuring-discovery-cache).

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

> [!NOTE]
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

## Anonymous Sessions

> [!NOTE]
> Anonymous Sessions are in Early Access. The feature has to be enabled on your tenant before any of the calls below work.

An anonymous session gives a visitor an identity before they log in. Auth0 issues an access token whose subject looks like `anon@<uuid>`, so your own API can accept calls from a visitor who does not have an account yet. You can attach `metadata` when you create the session, for example the campaign the visitor arrived from.

The `ServerClient` exposes this as the `anonymous` sub-client:

| Method | What it does |
| --- | --- |
| `anonymous.createSession(options?, storeOptions?)` | Creates the anonymous session and returns the first access token. |
| `anonymous.getAccessToken(options?, storeOptions?)` | Returns the cached access token, or asks Auth0 for a new one. |
| `anonymous.getSession(storeOptions?)` | Returns the stored anonymous session. |
| `anonymous.logout(storeOptions?)` | Drops the anonymous session from your store. |

An anonymous session holds no refresh token. Auth0 returns an opaque `session token` once at creation, which the SDK keeps in your store and uses to mint short lived access tokens. The `session token` is never exposed to your application code.

### Configuring the anonymous store

`anonymous` is only available once an `anonymousStore` is configured. Reading `serverClient.anonymous` without one throws an `InvalidConfigurationError`.

The anonymous session lives in its own store, separate from the user session. An anonymous visitor is not logged in, so `getSession()` and `getUser()` keep returning `undefined` until a real login happens.

`StatelessAnonymousStore` is the built in store. It takes the same `CookieHandler` you already pass to the other stores:

```ts
import {
  StatelessAnonymousStore,
  CookieTransactionStore,
  ServerClient,
  StatelessStateStore,
} from '@auth0/auth0-server-js';

const serverClient = new ServerClient<StoreOptions>({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  transactionStore: new CookieTransactionStore({ secret }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({ secret }, new FastifyCookieHandler()),
  anonymousStore: new StatelessAnonymousStore({ secret }, new FastifyCookieHandler()),
});
```

The cookie is `HttpOnly` and encrypted with your `secret`, and is split into chunks when the value outgrows a single cookie. It accepts:

- `sessionTokenLifetime`: the lifetime of an anonymous session in seconds, used to work out the cookie's `Max-Age`. Defaults to 30 days, which matches the Auth0 default. Set it to match `sessions.anonymous.lifetime_in_minutes` on your tenant.
- `cookie.sameSite` (default `lax`), `cookie.secure` (default `true`) and `cookie.path` (default `/`).

The cookie lifetime is anchored to the moment the session was created. Auth0 hands out the `session token` once and never reissues it, so a rolling expiry would keep a 30 day session alive forever.

The cookie name comes from `anonymousSessionIdentifier`, which defaults to `__a0_anon`. To keep the anonymous session somewhere else, extend `AbstractAnonymousStore`, which gives you the same encryption helpers as the other stores.

One more option lives on the `ServerClient` itself:

- `clearAnonymousSessionOnLogin`: whether the anonymous session is dropped once the visitor logs in. Defaults to `true`. See [Ending the anonymous session](#ending-the-anonymous-session).

### Creating an anonymous session

```ts
const tokenSet = await serverClient.anonymous.createSession(
  {
    audience: 'https://api.example.com',
    scope: 'read:articles',
    metadata: { campaign: 'summer-sale' },
  },
  storeOptions
);

// tokenSet.accessToken, tokenSet.audience, tokenSet.scope, tokenSet.expiresAt
```

- `audience`: the API the access token is for. Falls back to `authorizationParams.audience` when omitted.
- `scope`: the scopes to request. This does **not** fall back to `authorizationParams.scope`, because that value describes a logged in user and usually asks for `openid profile email offline_access`, none of which apply to an anonymous visitor.
- `metadata`: string values only, at most 1024 bytes in total. Auth0 accepts `metadata` **only** when the session is created. It cannot be changed later, so pass everything you need in this call.

Calling `createSession()` again replaces the stored session. The visitor gets a new anonymous identity and the old one is forgotten.

### Getting an access token

```ts
const tokenSet = await serverClient.anonymous.getAccessToken(
  { audience: 'https://api.example.com' },
  storeOptions
);
```

Tokens are cached per `audience` and requested `scope`. When the cached token is still valid it is returned as is. When it is expired, or when you ask for an audience the session has no token for, the SDK mints a new one from the stored `session token` and updates the cache.

Auth0 can grant a narrower `scope` than you asked for. A scope an anonymous caller is not entitled to is dropped and the call still succeeds, with `tokenSet.scope` telling you what the token really carries. That outcome is cached against the scope you asked for, so asking again returns the same token instead of minting a new one every time. Read `tokenSet.scope` if your API depends on a specific scope being present.

`getAccessToken()` throws `MissingAnonymousSessionError` when there is no anonymous session, so create one first.

### Reading the session

```ts
const session = await serverClient.anonymous.getSession(storeOptions);

if (session) {
  // session.sub, session.metadata, session.createdAt, session.tokenSets
}
```

- `sub`: the anonymous identity, in the form `anon@<uuid>`. This is the subject your API sees on an anonymous access token, so it is the key you store anonymous data under. It may be `undefined` if the first token was minted for an audience with token encryption (`token_encryption`) enabled — the access token is an encrypted JWE that only that API can read, so the SDK cannot extract `sub` from it. Once you call `getAccessToken()` for any non-encrypted audience, the SDK fills `sub` in automatically. If all your audiences use token encryption, `sub` will never be available here, so pick at least one non-encrypted audience if you need it.
- `metadata`: the metadata you passed to `createSession()`. Auth0 accepts metadata only at creation, so this value cannot go stale.
- `createdAt`: when the anonymous session was created, in seconds.
- `tokenSets`: the cached access tokens, one per `audience` and requested `scope`. Always check `tokenSet.scope` to confirm what Auth0 actually granted — anonymous callers may receive fewer scopes than requested, and the narrowed grant is what the token carries.

`getSession()` is a local read of your store and makes no call to Auth0.

The `session token` is stripped from the result, so it never reaches your application code or a template.

### Ending the anonymous session

An anonymous session ends in one of three ways.

**Logging in ends it, automatically.** Every method that writes a user session drops the anonymous session right after: `completeInteractiveLogin()`, `completePasswordless()`, `completePasswordlessMagicLink()`, `loginBackchannel()`, `loginWithCustomTokenExchange()`, `passkey.complete()`, `passkey.getToken()` and `mfa.verify()`. Nothing to call, and nothing left behind:

```ts
fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };

  // The anonymous session is gone by the time this returns.
  await serverClient.completeInteractiveLogin(new URL(request.url, appBaseUrl), storeOptions);

  reply.redirect('/');
});
```

The visitor is a known user once they log in, so keeping the anonymous session would mean holding a second identity for them, with a 30 day credential still sitting in the browser and `anonymous.getAccessToken()` still minting tokens for a visitor who now has an account.

The clearing is best effort and runs after the user session is written, so a store that is briefly unavailable can never fail a login that already succeeded.

To keep the anonymous session across login, set `clearAnonymousSessionOnLogin: false`:

```ts
const serverClient = new ServerClient<StoreOptions>({
  // ...
  anonymousStore: new StatelessAnonymousStore({ secret }, new FastifyCookieHandler()),
  clearAnonymousSessionOnLogin: false,
});
```

You then own the cleanup, and have to call `anonymous.logout()` yourself once you are done. In most cases you do not need this flag: read the anonymous session **before** you complete the login instead, as shown in [Merging what the visitor did before they logged in](#merging-what-the-visitor-did-before-they-logged-in).

**Logging out ends it.** `serverClient.logout()` clears the anonymous session together with the user session, and does so even when there is no user session to clear, because a visitor who only ever browsed anonymously can log out too. `clearAnonymousSessionOnLogin` does not affect this: that flag is about giving your application room to finish its post login work, not about keeping an anonymous identity after the visitor has left.

The only exception is resolver (multi tenant) mode with a stored user session that belongs to a different Auth0 domain than the request resolves to. Nothing local is cleared in that case, the anonymous session included, since that state belongs to another tenant.

The SDK never calls `POST /anonymous/logout`. That endpoint clears the `auth0_anon` cookie in a browser and revokes nothing, and your server never holds that cookie. If the visitor's browser created an anonymous session of its own, through [`auth0-spa-js`](https://github.com/auth0/auth0-spa-js) for example, that cookie is not covered by this SDK and has to be cleared from the browser.

**You can end it yourself, at any time.**

```ts
await serverClient.anonymous.logout(storeOptions);
```

This clears the anonymous session from your store. It makes no call to Auth0: an anonymous session cannot be revoked, and it stops working on its own once its lifetime is over. Access tokens already handed out stay valid until they expire.

### Merging what the visitor did before they logged in

The anonymous `sub` is the key your anonymous data is stored under, so read it **before** you complete the login, while the anonymous session is still there:

```ts
fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };

  // Read the anonymous identity first: completing the login drops the anonymous session.
  const anonymousSession = await serverClient.anonymous.getSession(storeOptions);

  await serverClient.completeInteractiveLogin(new URL(request.url, appBaseUrl), storeOptions);

  const user = await serverClient.getUser(storeOptions);

  if (anonymousSession?.sub && user) {
    await mergeCart(anonymousSession.sub, user.sub);
  } else if (anonymousSession && !anonymousSession.sub) {
    // The anonymous session exists but its `sub` could not be read, so there is no key to
    // merge on. Log it: silently skipping the merge looks identical to a visitor who simply
    // never had an anonymous session. See `sub` under Reading the session.
    request.log.warn('anonymous session has no readable sub, skipping merge');
  }

  reply.redirect('/');
});
```

This is a merge in your own application: your cart, your analytics, your database. Auth0 links the anonymous session to the login automatically when `startInteractiveLogin()` is used (see [Linking the anonymous session to the user created at login](#linking-the-anonymous-session-to-the-user-created-at-login)), but that linking does not merge your application data — moving guest data into the user's account is still your responsibility.

`sub` is the only key you get, so store your anonymous data under it from the start. If you only ever mint tokens for audiences with token encryption enabled, `sub` will never be populated and this merge cannot work — make sure at least one of your audiences is non-encrypted if you need the anonymous identity.

### Handling errors

```ts
import {
  AnonymousSessionError,
  AnonymousSessionExpiredError,
  MissingAnonymousSessionError,
} from '@auth0/auth0-server-js';

try {
  const tokenSet = await serverClient.anonymous.getAccessToken({}, storeOptions);
} catch (error) {
  if (error instanceof MissingAnonymousSessionError) {
    // No anonymous session yet. Create one.
  }

  if (error instanceof AnonymousSessionExpiredError) {
    // The anonymous session is gone and has been cleared from the store.
    // Create a new one, but note that the old `metadata` is lost.
  }

  if (error instanceof AnonymousSessionError) {
    // Anything Auth0 rejected, for example `feature_not_enabled`, `invalid_target` or
    // `access_denied`. Read `error.code` to see which.
    console.error(error.code, error.message);
  }
}
```

`AnonymousSessionExpiredError` means the anonymous session reached the end of its lifetime. The SDK clears the store for you, so the next `createSession()` starts clean.

### Linking the anonymous session to the user created at login

`startInteractiveLogin()` links an active anonymous session to the user at login automatically. When `anonymousStore` is configured and a session is in the store, the SDK mints a **Session Transfer Ticket** before the redirect and appends it to the `/authorize` URL as `anon_transfer_token`. Auth0 redeems the ticket during authorization and makes the anonymous session available to Actions as `event.anonymous_session`.

No extra configuration is required. The ticket is a short-lived (30-second) stateless JWE and is consumed once. If minting the ticket fails for any reason, login continues without it — the anonymous session is simply not linked on that attempt (fail-open). Auth0 also fails open if the ticket has expired by the time `/authorize` processes it, so a slow network or a delayed redirect does not block login.

The logins that do not go through `/authorize` cannot carry the ticket. `passkey.complete()`, `passkey.getToken()`, `completePasswordless()`, `completePasswordlessMagicLink()`, `loginBackchannel()`, and `loginWithCustomTokenExchange()` take no anonymous session parameter, and Auth0 ignores any anonymous session on those endpoints. For those flows, do the merge in your own application as shown in [Merging what the visitor did before they logged in](#merging-what-the-visitor-did-before-they-logged-in).

### Prerequisites for anonymous sessions

- Anonymous sessions enabled on your tenant.
- The API you request an `audience` for has to allow anonymous access.
- A configured `anonymousStore`.

### Passing `StoreOptions` to the anonymous methods

Every method on the `anonymous` sub-client takes `storeOptions` as its last argument, which is passed to the configured anonymous store:

```ts
const storeOptions = {
  /* ... */
};
await serverClient.anonymous.createSession({}, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Personal Agent Protocol (Poppy)

> [!NOTE]
> Poppy support is in beta. It is opt-in. It was written against [Poppy 0.3](https://personalagentprotocol.org/docs/0.3/spec#intro), which is a draft, and the API is marked `@beta`, so names and behaviour can still change. The version in your config is served as you wrote it, and the SDK does not check it against a version it knows. Newer versions of the protocol can change names or add members that this package does not know yet. The tests of this package use signed test tokens and a fake Auth0. They do not run against a live tenant, so what Auth0 does in the steps below is described as designed and is not yet proven end to end.

A Personal Agent is an AI assistant that acts for a person. With Poppy, the Personal Agent Protocol, an agent can also use your website in a browser of its own. The agent's browser _joins_ the agent's Poppy Session, so your website sees one Session for the person, whether or not the agent has signed in ([Web browsing in the specification](https://personalagentprotocol.org/docs/0.3/spec#web-browsing)).

The `ServerClient` exposes this as the `poppy` sub-client. It is available once you pass the `poppy` option, and reading `serverClient.poppy` without it throws an `InvalidConfigurationError`. Like the other methods, the ones that read a store take `storeOptions` as their last argument. See [Configuring the Store](#configuring-the-store).

| Method | What it does |
| --- | --- |
| `poppy.getDiscoveryDocument(path)` | Builds the two JSON files that agents read, for your framework to serve. |
| `poppy.verifyConfig()` | Compares your config with the metadata of Auth0, as an agent does, and returns the problems it finds. |
| `poppy.parseLoginInitiation(url, options)` | Checks the query of a request to your login route. |
| `poppy.getVisitor(storeOptions?)` | Tells who is behind a request: nobody, an anonymous visitor, a user (maybe a signed-in agent) or a guest. |
| `poppy.getContext(storeOptions?)` | Tells whether a person or an agent's browser makes a request. |
| `poppy.getGuestAccessToken(storeOptions?)` | Returns the access token of a guest. |

### What the SDK does for you

When an agent joins, your website gets a login that carries the Poppy Session. The SDK turns it into the right session and gives it a deadline. This is the join in five steps:

1. The agent reads the two discovery files of your website. Your app serves them, and this package builds them from your config. See [Serving the discovery files](#serving-the-discovery-files).
2. The agent's browser opens the join page that your config names (`web.browser_session_endpoint`), and the agent authorizes the join with its Poppy Session. Auth0 is expected to provide this page, so you do not build it. The join is signed in when the agent authorizes it with an access token for a person's account, and it is a guest join otherwise.
3. Auth0 sends the browser to your login route, which is the Application Login URI of your Auth0 application, as it is stored. Today's builds add no parameters to it, and a later build is expected to add `iss` and `target_link_uri`. Your route checks the ones that are there and starts a normal login. See [The login route](#the-login-route).
4. Auth0 logs the browser in without showing a login page, and sends it to your callback with a code.
5. Your callback calls `completeInteractiveLogin()`. The SDK finds the Poppy Session in the ID token and writes a guest or a signed-in session. See [The callback](#the-callback). From then on, each request from that browser tells you who is driving. See [Who is driving](#who-is-driving).

A join ends as one of two things:

| | Guest | Signed in |
| --- | --- | --- |
| The agent joined | Without an access token. | With an access token for a person's account. |
| Where the SDK keeps it | In the guest store, in the `__a0_poppy` cookies. | In the state store, as a normal user session. |
| `getSession()` and `getUser()` | Do not return it. A guest is never a user. | Return the person, with the agent in `user.act`. |
| `poppy.getVisitor()` | `{ kind: 'guest', poppy }` | `{ kind: 'user', user, poppy }` |
| Access token | `poppy.getGuestAccessToken()` | `getAccessToken()`, until the token of the join expires. |

Both end at a deadline, and nothing extends it. See [How long an agent session lasts](#how-long-an-agent-session-lasts).

What the SDK does not do:

- **It does not check scopes.** Narrowing the token of your web app to the agent's scopes is not done yet, so your website cannot tell what the agent is allowed to do. Apply your own rules to what an agent may do in the browser.
- **It does not see a sign-out or a disconnect.** An agent session can outlive them, up to its deadline. See [How long an agent session lasts](#how-long-an-agent-session-lasts).
- **It keeps no Poppy Session records.** The ID token carries the Session id and the user id, and the SDK gives you those values.
- **It reads no files.** You pass the parsed `auth0-poppy.json`.
- **It mounts no routes and renders no pages.** Your app does, or a framework SDK built on this package, such as `auth0-express` or `auth0-fastify`, once it supports Poppy.

### Configuring Poppy

Do this once, when your app starts. The `poppy` option takes your Poppy config and a guest store.

The config is `auth0-poppy.json`, the Poppy file of your website. You can write it by hand. It stays in your code and is never served. These are the fields that this package reads:

```json
{
  "protocol_version": "0.3",
  "organization": { "name": "Zepto", "domain": "zepto.example" },
  "issuer": "https://auth.zepto.example/",
  "scopes": {
    "orders:read": {
      "description": "See your orders.",
      "hints": { "changes": "none", "personal_data": true }
    }
  },
  "web": {
    "browser_session_endpoint": "https://auth.zepto.example/poppy/<AUTH0_CLIENT_ID>/browser-session"
  }
}
```

`scopes`, `apis`, `web.client_id` and `web.unscoped` are optional. Fields that this package does not read are ignored and never served. The rules under **The checks**, below, say what each field must hold.

**`web.unscoped`.** Set it to `true` when your website does not apply the other scopes of the config, so that a signed-in browser with the scope `poppy:browser-sign-in` has the full access of the account there. It is a member of Poppy 0.4. An agent reads it before it asks for the scope, so a website that gives that access must say so. The package serves the value as you wrote it, and serves nothing when you leave it out.

This package reads no files, so your app reads the file and passes the parsed object. On Node.js:

```ts
import { readFileSync } from 'node:fs';

const poppyConfig = JSON.parse(readFileSync(new URL('./auth0-poppy.json', import.meta.url), 'utf8'));
```

On Cloudflare Workers, or with a bundler that can import JSON, import the file instead:

```ts
import poppyConfig from './auth0-poppy.json' with { type: 'json' };
```

Then pass the config and a guest store as `poppy`. `StatelessPoppyGuestStore` keeps the guest in encrypted, `HttpOnly` cookies, and it takes the same `secret` and `CookieHandler` as the other stores:

```ts
import {
  CookieTransactionStore,
  ServerClient,
  StatelessPoppyGuestStore,
  StatelessStateStore,
} from '@auth0/auth0-server-js';

const serverClient = new ServerClient<StoreOptions>({
  domain: 'auth.zepto.example',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  authorizationParams: { redirect_uri: 'https://zepto.example/auth/callback' },
  transactionStore: new CookieTransactionStore({ secret }, new FastifyCookieHandler()),
  stateStore: new StatelessStateStore({ secret }, new FastifyCookieHandler()),
  poppy: {
    config: poppyConfig,
    guestStore: new StatelessPoppyGuestStore({ secret }, new FastifyCookieHandler()),
    agentSessionMaxAge: 3600, // optional, in seconds: the longest an agent session lasts (the default is 7200)
  },
});
```

A guest cookie that is forged, tampered with or expired reads as no guest, and the `poppy` reads never throw for it. An empty list of secrets is different. It is a mistake in your app and not a forged cookie, so when a guest cookie is present, the read fails with an `InvalidConfigurationError`.

The config must be plain JSON data. The `ServerClient` takes a copy of it when it is created, and the checks below run on that copy, so a later change to your object has no effect. A value that cannot be copied, such as a function, gives an `InvalidConfigurationError`.

**The domain.** Poppy has one issuer, so `domain` must be a string and not a domain resolver. The `issuer` in the config must be `https://`, then that domain, then a trailing slash. Use the domain that your `issuer` names, which is usually your custom domain. The SDK normalizes `domain` first, so `'auth.zepto.example'`, `'https://auth.zepto.example'` and `'AUTH.zepto.example'` all give the issuer `https://auth.zepto.example/`.

**The login URI.** Auth0 sends an agent's browser to the Application Login URI of your Auth0 application (`initiate_login_uri` in the Management API). Set it to your login route, for example `https://zepto.example/auth/login`, and register your callback as an Allowed Callback URL as usual. Turn `poppy` on first. See [Production notes](#production-notes).

**The checks.** The `ServerClient` checks the `poppy` option when it is created, so a wrong config stops your app at startup and not on a visitor's login. It throws an `InvalidConfigurationError` for the first rule that fails. The message starts with `Invalid poppy configuration: `, names the field and never shows its value. For example:

```text
Invalid poppy configuration: config.issuer must match Auth0's issuer for the ServerClient domain exactly, trailing slash included.
```

The rules are:

- `domain` is a string, and `config.issuer` matches it as described above.
- `config.protocol_version` is a string of the form `major.minor`, such as `'0.3'`: digits, a dot and digits, with up to four digits in each part. Only the shape is checked. The value is served in `poppy.json` as you wrote it.
- `config.organization` has a non-empty `name` and a `domain`. The `domain` is a lowercase host name, with no scheme, port, path or trailing dot.
- `config.web.browser_session_endpoint` is an `https` URL. When `config.web.client_id` is set, it is the `clientId` of the `ServerClient`. When `config.web.unscoped` is set, it is `true` or `false`.
- Each entry of `config.scopes` has a non-empty `description` and a name in printable ASCII, with no space, double quote or backslash. Its `hints`, when present, have `changes` set to `none`, `reversible` or `irreversible`, and a boolean `personal_data`. Each entry of `config.apis` has a non-empty `type`, a non-empty `description` and an `https` `url`.
- `agentSessionMaxAge`, when set, is a positive whole number of seconds.
- `protectedResource`, when set, has a `resource` that is a non-empty string and `authorization_servers` that is a list of non-empty strings. See [Serving the discovery files](#serving-the-discovery-files).
- `poppy` is not combined with `enterpriseConnect`.

### Serving the discovery files

Before an agent uses your website, it reads two JSON files from your domain. The SDK builds them, and your framework serves them:

- `/.well-known/poppy.json` says what your website offers: the organization, the issuer, the scopes, the APIs and the join endpoint ([Discovery in the specification](https://personalagentprotocol.org/docs/0.3/spec#discovery)). It is built from your config and does not depend on `protectedResource`.
- `/.well-known/oauth-protected-resource` names your website as a protected resource and lists its authorization servers ([OAuth server in the specification](https://personalagentprotocol.org/docs/0.3/spec#oauth-server), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html#section-2)).

`poppy.getDiscoveryDocument(path)` returns `{ status, headers, body }` for these two paths and `undefined` for any other path. The status is always `200`, `body` is the JSON text, and the headers are `content-type: application/json` and `cache-control: public, max-age=300`. Each call returns a new object. Pass the path without its query: `/.well-known/poppy.json?x=1` gives `undefined`.

Mount one handler for both paths at the root of your domain. Keep it outside any session handling: agents call it, and the response must not read or set a cookie.

```ts
import type { FastifyReply, FastifyRequest } from 'fastify';

// The public URL of your website. The other snippets use it too.
const appBaseUrl = 'https://zepto.example';

async function discovery(request: FastifyRequest, reply: FastifyReply) {
  const document = serverClient.poppy.getDiscoveryDocument(new URL(request.url, appBaseUrl).pathname);

  if (!document) {
    return reply.code(404).send();
  }

  return reply.code(document.status).headers(document.headers).send(document.body);
}

fastify.get('/.well-known/poppy.json', discovery);
fastify.get('/.well-known/oauth-protected-resource', discovery);
```

`oauth-protected-resource` is inferred from your config. The `resource` is `https://` and the `organization.domain`, and `authorization_servers` is the `issuer`, written exactly as in the file. For the config above, the file is:

```json
{ "resource": "https://zepto.example", "authorization_servers": ["https://auth.zepto.example/"] }
```

Use the `protectedResource` option when you need other values, for example a second authorization server. A member you give is served as it is, and a member you leave out is inferred. Other RFC 9728 members that you add, such as `scopes_supported`, are served after those two. Here `resource` is still inferred:

```ts
import type { PoppyOptions } from '@auth0/auth0-server-js';

const poppy: PoppyOptions<StoreOptions> = {
  config: poppyConfig,
  guestStore,
  protectedResource: {
    authorization_servers: ['https://auth.zepto.example/', 'https://login.partner.example/'],
  },
};
```

The members must be plain data that can be served as JSON. As for `config`, the `ServerClient` takes a copy when it is created, and a member it cannot copy, such as a function, gives an `InvalidConfigurationError`.

A value that agents would reject is still served, because you wrote it on purpose, and `verifyConfig()` reports it. The `resource` must be exactly `https://` and the `organization.domain`, and `authorization_servers` must list the `issuer` exactly as the config writes it, trailing slash included.

An agent compares your files with the metadata of Auth0. When they do not match, the agent does not use your files, and it does not tell you. `poppy.verifyConfig()` makes the same comparison. Call it once when your app starts, and log each issue. It never rejects, even when Auth0 cannot be reached:

```ts
const issues = await serverClient.poppy.verifyConfig();

for (const issue of issues) {
  console.warn(`Poppy configuration issue ${issue.code}: ${issue.message}`);
}
```

The result is `[]` when there is nothing to report. The `message` is a fixed text that never holds a token or a value from your options, so it is safe to log.

| Code | What it means |
| --- | --- |
| `protected_resource_override_mismatch` | A value in `protectedResource` is one that agents reject. This check needs no request. |
| `protected_resource_missing` | The `protected_resources` of the Auth0 metadata does not list `https://zepto.example`, the resource of your website. Agents do not use `poppy.json` until it does. |
| `scopes_not_supported` | The `scopes_supported` of the Auth0 metadata does not list some scopes that agents request: the scopes of your config and, when your `protocol_version` is 0.4 or later, `poppy:browser-sign-in`, which a website with a browser join has to support. The message names them. |
| `metadata_unavailable` | The metadata could not be read, so the two checks that need it were not made. |

Auth0's discovery documents do not yet publish `protected_resources` or Poppy scopes, so `protected_resource_missing` and `scopes_not_supported` are expected until they do. Read them as information, not as a failure.

`verifyConfig()` does not compare the issuer. The `ServerClient` already refuses a config whose issuer does not match its domain.

### The login route

Auth0 sends an agent's browser to the Application Login URI of your Auth0 application, which is your login route, as it is stored. Today's builds add no parameters to it. A later build is expected to add `iss` and `target_link_uri` ([OpenID Connect Core, section 4](https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin)).

Anyone can send a browser to that route with any query, so check the request before you start the login. `poppy.parseLoginInitiation(url, { appOrigin })` does the checks and gives you the pieces to use. It works with or without `iss` and `target_link_uri`:

- **`iss`.** The method checks it when it is there. It must appear once and be the `issuer` of your config, character for character. Otherwise the method throws an `IssuerValidationError`. A request with no `iss` is accepted.
- **`target_link_uri`.** This is the page the agent wants to land on, once Auth0 sends it. The method gives it to you as `returnTo` only when it appears once, it is an absolute `https:` or `http:` URL without a user name or password, and it is on the origin of `appOrigin`. In every other case there is no `returnTo` and no error: use your default landing page. This keeps your login route from being an open redirect.
- **`authorizationParams`.** Every other query parameter, with one value each (the last). It never has `iss` or `target_link_uri`.

Without `iss` there is nothing to check, and without `target_link_uri` there is no `returnTo`. The route still starts the login, and it also works for people who log in without an agent.

Three rules for your code:

- Take `appOrigin` from your own configuration, such as your public base URL. Never take it from the `Host` header of the request.
- Redirect to `returnTo` whole. Do not keep only its path: a path that starts with two slashes, such as `//evil.example/x`, is read as another site when it stands alone.
- Treat `authorizationParams` as data from a browser. Pass on only the parameters you expect.

```ts
import { IssuerValidationError } from '@auth0/auth0-server-js';

fastify.get('/auth/login', async (request, reply) => {
  const storeOptions = { request, reply };

  try {
    const { returnTo, authorizationParams } = serverClient.poppy.parseLoginInitiation(
      new URL(request.url, appBaseUrl),
      { appOrigin: appBaseUrl }
    );

    // Pass on only what you expect to /authorize.
    const forwarded = ['login_hint', 'ui_locales'];

    const authorizationUrl = await serverClient.startInteractiveLogin(
      {
        authorizationParams: Object.fromEntries(
          Object.entries(authorizationParams).filter(([name]) => forwarded.includes(name))
        ),
        appState: { returnTo },
      },
      storeOptions
    );

    return reply.redirect(authorizationUrl.href);
  } catch (error) {
    if (error instanceof IssuerValidationError) {
      return reply.code(400).send('Bad request');
    }

    throw error;
  }
});
```

`appBaseUrl` is the constant of [Serving the discovery files](#serving-the-discovery-files): the public URL of your website. Only its origin counts for `appOrigin`. Write the scheme. `parseLoginInitiation()` throws a `TypeError` for a value that is not an absolute URL, such as `zepto.example`. It reads `localhost:3000` as a URL with the scheme `localhost:`, so no landing page is ever on its origin.

### The callback

The callback is the redirect URI of your application. `completeInteractiveLogin()` exchanges the code and looks at the ID token. A login that carries a Poppy Session takes the Poppy path, and any other login works as it always did. For an agent's join, the result also has `poppy`, a `PoppyAgentContext` that says who joined:

```ts
fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };

  const { appState, poppy } = await serverClient.completeInteractiveLogin<{ returnTo?: string }>(
    new URL(request.url, appBaseUrl),
    storeOptions
  );

  if (poppy) {
    // poppy.state is 'signed_out' for a guest and 'signed_in' for a signed-in agent.
    request.log.info({ state: poppy.state, agent: poppy.agent.cimdUrl }, 'an agent joined');
  }

  return reply.redirect(appState?.returnTo ?? '/');
});
```

The SDK writes the guest or the session before `completeInteractiveLogin()` returns. A guest goes to the guest store. It ends an agent session of the browser, and it leaves a person's own login and the anonymous session alone. A signed-in agent gets a fresh user session, and the regular anonymous session is cleared as for any login (see `clearAnonymousSessionOnLogin`). `returnTo` is the value that your login route stored in `appState`. This call can throw, for example when the agent session has already ended. See [Handling errors](#handling-errors-1).

**Cookies set during the callback are read only on the next request.** The browser sends the new cookies later, so in the callback `getVisitor()`, `getUser()` and `getSession()` do not show what this login has just written. Use `poppy` from the result. Its `key` names the agent's data, for a guest and for a signed-in agent.

For example, an anonymous visitor may have built a cart before the join. This needs an `anonymousStore` on the `ServerClient`, as in [Configuring the anonymous store](#configuring-the-anonymous-store): `serverClient.anonymous` throws an `InvalidConfigurationError` without one. Read the anonymous session first, as in [Merging what the visitor did before they logged in](#merging-what-the-visitor-did-before-they-logged-in), and merge the cart in the same request:

```ts
fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };

  // Read this first: a signed-in join clears the anonymous session.
  const anonymousSession = await serverClient.anonymous.getSession(storeOptions);

  const { appState, poppy } = await serverClient.completeInteractiveLogin<{ returnTo?: string }>(
    new URL(request.url, appBaseUrl),
    storeOptions
  );

  if (poppy && anonymousSession?.sub) {
    // Merge, do not overwrite: the agent's API calls may already have made a cart under `poppy.key`.
    // A guest join keeps the anonymous session, so its cart stays where it is as well.
    await mergeCart(anonymousSession.sub, poppy.key);
  }

  return reply.redirect(appState?.returnTo ?? '/');
});
```

### Who is driving

Your pages need to know who is behind each request. A website that uses anonymous sessions and Poppy meets five situations, and each has its own read, its own token method and its own key. `poppy.getVisitor()` reads them in one safe order and returns one result, so a single `switch` handles all of them and the guest is not forgotten. A `user` with `poppy` set is a signed-in agent.

The function below picks the key to store a visitor's data under. Because of the `never` check, your build stops when a later version adds a kind of visitor that you do not handle:

```ts
import type { PoppyVisitor } from '@auth0/auth0-server-js';

function dataKeyOf(visitor: PoppyVisitor): string | undefined {
  switch (visitor.kind) {
    case 'none':
      return undefined;
    case 'anonymous':
      return visitor.anonymous.sub;
    case 'user':
      // A signed-in agent shares its data with your API, which finds it by the key of the Session.
      return visitor.poppy ? visitor.poppy.key : visitor.user.sub;
    case 'guest':
      return visitor.poppy.key;
    default: {
      const unreachable: never = visitor;

      return unreachable;
    }
  }
}

const key = dataKeyOf(await serverClient.poppy.getVisitor(storeOptions));
```

| Situation | `getVisitor()` | Read without `getVisitor()` | Access token | What it can show | Key for its data |
| --- | --- | --- | --- | --- | --- |
| A signed-in user | `{ kind: 'user', user }` | `getUser()`, `getSession()` | `getAccessToken()` | The user's account. | `user.sub` |
| A regular anonymous session | `{ kind: 'anonymous', anonymous }` | `anonymous.getSession()` | `anonymous.getAccessToken()` | The pages for a visitor who has not logged in. | `anonymous.sub` |
| A Poppy guest | `{ kind: 'guest', poppy }` | `poppy.getContext()` | `poppy.getGuestAccessToken()` | The same pages as for an anonymous visitor. | `poppy.key` |
| A signed-in agent | `{ kind: 'user', user, poppy }` | `getUser()`, with the agent in `user.act`, and `poppy.getContext()` | `getAccessToken()`, until the token of the join expires | The person's account, within your own rules for agents. | `poppy.key` |
| Nobody | `{ kind: 'none' }` | `undefined`, and `{ kind: 'human' }` for `getContext()` | None | The public pages. | None |

**The order is part of the contract.** `getVisitor()` reads a guest first, then the user session, then the regular anonymous session. The first one it finds decides. For a guest, this follows the advice of the guides: keep the cookie of the Session apart from the login cookie, and check it first ([Browser sessions in the guides](https://personalagentprotocol.org/docs/0.3/guides#company-browsing)). A guest comes first because an agent that has not signed in drives the browser. That browser can still hold a person's own login. A guest join leaves that login alone, and the agent must not act as that person. So `getUser()` still returns the person, and `getVisitor()` reports the guest. A guest or a session that has ended is read as absent, and the next step is made. The anonymous step needs an `anonymousStore` on the `ServerClient`. Without one, `getVisitor()` skips it and never returns `anonymous`.

`getVisitor()` writes nothing, sends no request to Auth0, and reads each store at most once. It deletes a guest or a session that has ended. When a store fails, the error reaches your code and the stores after it are not read. So a store that is down never turns a guest into a user. `kind: 'user'` means that `getUser()` returns that user. A session that has tokens but no user reads as `none`, or as `anonymous` when there is an anonymous session.

When you only need to know whether an agent drives the browser, `poppy.getContext()` is the lower-level read. It returns `{ kind: 'human' }` or a `PoppyAgentContext`. A signed-in agent is also visible in the ordinary reads, as a user whose `act` holds the Poppy members:

```ts
const context = await serverClient.poppy.getContext(storeOptions);

if (context.kind === 'agent') {
  // context.state is 'signed_out' for a guest and 'signed_in' for a signed-in agent.
  console.log(context.agent.cimdUrl, context.key);
}

// A signed-in agent is an ordinary user session with the agent in `act`, typed as `PoppyActClaim`.
const user = await serverClient.getUser(storeOptions);

if (user?.act?.poppy_sid) {
  console.log(user.act.sub, user.act.poppy_user_id);
}
```

Key an agent's data on `poppy.key`, for example its cart. The key is opaque. It is the same value that the Poppy support in a coming `@auth0/auth0-api-js` release returns for the same Session, so your website and your API can find the same cart. It does not change when the agent signs in, because that is the same Session. The `poppy_*` members of `act` are claims that Auth0 sends in the beta, and their names may change. Prefer `poppy.getContext()` and `getVisitor()`.

**Do not send a guest to your login route.** A guest cannot sign in on your website. The person the agent acts for signs in through the agent, and the agent then joins again. Auth0 can keep the anonymous session of the join for single sign-on, so your login route may bring back the same guest. A redirect from a protected page to the login route then repeats without end. Answer a guest with a page or an error instead, and send only a visitor who is not a guest to the login route.

Code that only calls `getSession()` or `getUser()` never treats a guest as a customer. But it sees a signed-in agent as a user: the person's session, with the agent in `act`. Narrowing the web token to the agent's scopes is not done yet (see "What the SDK does not do" in [What the SDK does for you](#what-the-sdk-does-for-you)). So apply your own rules to what an agent may do in the browser, for example by checking `visitor.poppy` before a purchase.

### The guest's access token

A guest is not a user, so `getAccessToken()` is not for it. That method reads the user session, which a guest does not have. When the browser also holds a person's own login, it returns the token of that person, so pick the method from the `kind` of `getVisitor()`. `poppy.getGuestAccessToken()` returns the access token that Auth0 issued when the guest's browser joined. Use it when your server calls your own API for the guest:

```ts
const tokenSet = await serverClient.poppy.getGuestAccessToken(storeOptions);

if (!tokenSet) {
  // Treat the request as signed out.
} else {
  // tokenSet.accessToken, tokenSet.audience, tokenSet.scope, tokenSet.expiresAt
}
```

It never calls Auth0 and never refreshes the token. `undefined` means there is no token to use: the browser has no guest, the guest has ended, or the token has expired. The guest can outlive its token, so treat the request as signed out until the agent joins again.

### How long an agent session lasts

When the callback writes a guest or a signed-in session, it gives it a deadline. The deadline is the earliest of:

- the time of the login plus `agentSessionMaxAge`, which is 7200 seconds (two hours) by default,
- the `exp` of the ID token,
- the `poppy_session_exp` of the `act` claim, when Auth0 sends it (it does not today; a fraction is rounded down),
- the `session_expiry` claim of the ID token, when it has one (see [Session expiry from upstream IdP](#session-expiry-from-upstream-idp-ipsie-session_expiry)).

`agentSessionMaxAge` is a positive whole number of seconds, set in the `poppy` option as in [Configuring Poppy](#configuring-poppy). It can only make a session shorter, because the other limits still apply. Until Auth0 sends `poppy_session_exp`, the SDK does not know when the agent's Poppy Session ends, so the deadline can be later than that end.

Nothing can extend the deadline. The SDK stores no refresh token for an agent, and a read does not roll the deadline forward. This is what you see:

- A guest and a session are treated as ended 30 seconds before the deadline, to absorb clock differences. The cookie of a guest also expires at the deadline.
- When the session has ended, `getSession()` and `getUser()` return `undefined`, a guest reads as no guest, and `getAccessToken()` throws a `SessionExpiredError`. The ended session is deleted.
- Before that, `getAccessToken()` returns the token of the join until it expires. After that, it throws a `TokenByRefreshTokenError`, because there is no refresh token to renew it. Its `code` is `token_by_refresh_token_error`.
- A login whose deadline has already passed, or is 30 seconds away or less, is refused with a `SessionExpiredError`, and nothing is stored.

**What ends an agent session.** The deadline ends it. So does a call to `logout()`, for example when the person signs out on your site. A newer login in the same browser ends it too: a signed-in join or a normal login replaces it, and a guest join deletes it (see [A browser that already has a login](#a-browser-that-already-has-a-login)). With a stateful state store, `handleBackchannelLogout()` can end a signed-in agent session too, if Auth0 sends a logout token for that login. It never touches a guest. At the deadline the agent joins again, and a new join writes a new session with a new deadline.

**What the SDK does not see.** The specification says that the cookie of the Session must stop acting for the account when the person signs out or disconnects the agent ([the cookie in Web browsing](https://personalagentprotocol.org/docs/0.3/spec#web-browsing), [Ending Sessions](https://personalagentprotocol.org/docs/0.3/spec#ending-sessions)). The SDK does not see either event. It stores no refresh token for an agent, and nothing in the Poppy support watches for them. So neither event ends an agent session by itself. Other parts of your setup can still end it, such as `logout()`. The deadline is at most `agentSessionMaxAge` after the login (two hours by default). This is not done yet in this beta. If your site needs it, set a short `agentSessionMaxAge` and re-check on your own before an action that matters.

### A browser that already has a login

An agent's browser can already hold a login, a guest or an agent session when it joins. The specification says what a join does to a login that the browser already has. It also ends the sign-in of a Session when the agent joins again without an access token ([Web browsing in the specification](https://personalagentprotocol.org/docs/0.3/spec#web-browsing)). This is what the SDK does:

| The browser has | The login is | User session after | Guest after | Anonymous session after |
| --- | --- | --- | --- | --- |
| Nothing | A guest join | None | Written | Kept |
| Nothing | A signed-in join as Ana | Fresh, for Ana | None | Cleared |
| Ana's own login | A guest join | Unchanged | Written | Kept |
| An agent session for Ana | A guest join | None: the agent session is deleted | Written | Kept |
| A guest | A guest join for another Session | None | Replaced | Kept |
| A guest | A signed-in join | Fresh | Dropped | Cleared |
| Ana's own login | A signed-in join as Ana | Fresh: nothing of the earlier login is kept | None | Cleared |
| An agent session for Ana | A signed-in join as Ana | Fresh, with the agent of the new join | None | Cleared |
| Bob's own login | A signed-in join as Ana | Fresh, for Ana | None | Cleared |
| An agent session for Ana | A normal login as Ana | Fresh, without the agent | Unchanged | Cleared |
| A guest | A normal login as Ana | The normal session | Kept | Cleared |

"Fresh" means a session built from the new login only: no claim, token set or refresh token of an earlier session, and a new session id. "Cleared" means that `clearAnonymousSessionOnLogin: false` keeps the anonymous session instead.

A guest join ends an agent session of the browser, whichever Poppy Session it belongs to. It leaves a person's own login and the regular anonymous session alone.

- **`logout()` drops the guest** as well as the user session and the anonymous session. A guest store that fails does not stop the logout.
- **A normal login keeps the guest.** After a person logs in the usual way in a browser that holds a guest, `getVisitor()` and `getContext()` still report the guest first, while `getUser()` returns the person.

The other login methods follow the callback. `passkey.complete()`, `completePasswordless()`, `completePasswordlessMagicLink()`, `loginBackchannel()`, `loginWithCustomTokenExchange()` and `mfa.verify()` end an agent session of the browser and start a fresh session from their own login, as the normal login in the table does. The new session has no agent in `act`, and the deadline of the agent session does not carry over. These methods are not joins, so they return no `poppy` result. `completeLinkUser()` and `completeUnlinkUser()` go through `completeInteractiveLogin()`, so they follow the same rules, but they return only `appState` and drop a `poppy` result.

### Keeping guests somewhere else

`StatelessPoppyGuestStore` needs no server-side storage. To keep guests in a database or a cache, extend `AbstractPoppyGuestStore`. It gives you the same encryption as the other stores, through `this.encrypt()` and `this.decrypt()`. The `ServerClient` calls the store with the identifier `__a0_poppy` and a `PoppyGuestData`:

```ts
import { AbstractPoppyGuestStore } from '@auth0/auth0-server-js';
import type { PoppyGuestData } from '@auth0/auth0-server-js';

class DatabaseGuestStore extends AbstractPoppyGuestStore<StoreOptions> {
  async set(identifier: string, guest: PoppyGuestData, removeIfExists?: boolean, storeOptions?: StoreOptions) {
    const seconds = guest.expiresAt - Math.floor(Date.now() / 1000);

    // Keep nothing past `expiresAt`.
    if (seconds <= 0) {
      return this.delete(identifier, storeOptions);
    }

    const value = await this.encrypt(identifier, guest, guest.expiresAt);

    await guestRecords.put(browserIdOf(storeOptions), value, { ttlSeconds: seconds });
  }

  async get(identifier: string, storeOptions?: StoreOptions) {
    const value = await guestRecords.get(browserIdOf(storeOptions));

    if (!value) {
      return undefined;
    }

    try {
      return await this.decrypt<PoppyGuestData>(identifier, value);
    } catch (error) {
      // The SDK needs this error to delete a guest that has expired.
      // Check the code and not the class, so it works with any copy of jose.
      if (error instanceof Error && 'code' in error && error.code === 'ERR_JWT_EXPIRED') {
        throw error;
      }

      // Any other record that cannot be opened is no guest.
      return undefined;
    }
  }

  async delete(identifier: string, storeOptions?: StoreOptions) {
    await guestRecords.delete(browserIdOf(storeOptions));
  }
}
```

`browserIdOf()` stands for your own code. It must return an id that your server issued to this browser and that nobody can guess, such as a random value in an `HttpOnly` cookie of its own. Never use a value that the visitor can choose: whoever sends the id gets the guest.

Never keep a record past its `expiresAt` (Unix time, in seconds): a guest must not outlive its deadline. The SDK checks `expiresAt` on every read too, so this only keeps your store clean. When it finds a guest that has ended, or a record that lacks the members it needs, it deletes it and reads no guest. Return `undefined` from `get()` for a record you cannot open, as the snippet does. Let the error of an expired value through, as `StatelessPoppyGuestStore` does. Its `code` is `ERR_JWT_EXPIRED`. Let it through, and the SDK deletes the guest. An error from your store reaches your code, and it is never read as an empty store.

### Handling errors

As Auth0 has it today, a browser that already has a login that the join may not replace gets an error page from Auth0 itself. The page is at the `/authorize` endpoint of Auth0, with the HTTP status 400 and the error `session_conflict`. The browser is not sent to your callback, so nothing arrives at your code and there is nothing to handle. The agent has to start again in a fresh browser.

The errors that do reach your code, and what to show:

| Where | Error | Cause | What to show |
| --- | --- | --- | --- |
| `poppy.parseLoginInitiation()` | `IssuerValidationError` | The `iss` of the login request is not the issuer of your config. It can also be empty or repeated. | A `400` page. Do not start the login. |
| `completeInteractiveLogin()` | `TokenByCodeError` | Any other token error: Auth0 refused the login, or the code exchange failed. If a later Auth0 build sends the browser back with an error instead of its own page, it belongs here too. | Your usual login error page. The snippet below rethrows it, so your usual error handler answers. |
| `completeInteractiveLogin()` | `MissingTransactionError` | No login is in progress: the transaction that your login route stored is missing, has expired or was already used. | An error page that tells the agent to join again. |
| `completeInteractiveLogin()` | `SessionExpiredError` | The agent session has already ended, or ends in 30 seconds or less. Nothing is stored. | An error page that tells the agent to join again. |
| `completeInteractiveLogin()` | `InvalidPoppySessionError` | The `act` claim holds a Poppy Session that is not well formed, or the login carries Auth0's guest marker but no valid Poppy Session. Nothing is stored. The message names the member and never shows its value. | An error page that tells the agent to join again. |
| `new ServerClient()` | `InvalidConfigurationError` | The `poppy` option is not valid. The message names the field. | Nothing: fix the option. The app does not start. |

Do not put the message of an error, or its `cause`, on the page. Log the `code`.

```ts
import { InvalidPoppySessionError, MissingTransactionError, SessionExpiredError } from '@auth0/auth0-server-js';

// A join that cannot go on: the agent has to join again.
const joinAgain = [MissingTransactionError, SessionExpiredError, InvalidPoppySessionError];

fastify.get('/auth/callback', async (request, reply) => {
  const storeOptions = { request, reply };

  try {
    await serverClient.completeInteractiveLogin(new URL(request.url, appBaseUrl), storeOptions);
  } catch (error) {
    if (joinAgain.some((type) => error instanceof type)) {
      return reply.code(400).send('The agent session cannot be used. Join again.');
    }

    throw error;
  }

  return reply.redirect('/');
});
```

### Testing your integration

You do not need a tenant to test your routes. Sign an ID token with `jose` that carries the `act` members of the Poppy Session (and `sub_profile` for a guest), let a fake Auth0 answer the token request with it, complete the login, and assert `getContext()`. The fake Auth0 here is a `customFetch`. You can use MSW instead. The stores keep their cookies in a `Map` that stands for the browser:

```ts
import {
  CookieTransactionStore,
  ServerClient,
  StatelessPoppyGuestStore,
  StatelessStateStore,
} from '@auth0/auth0-server-js';
import type { CookieHandler } from '@auth0/auth0-server-js';
import { SignJWT, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';

type Browser = Map<string, string>;

const cookieHandler: CookieHandler<Browser> = {
  setCookie: (name, value, _options, browser) => void browser?.set(name, value),
  getCookie: (name, browser) => browser?.get(name),
  getCookies: (browser) => Object.fromEntries(browser ?? []),
  deleteCookie: (name, browser) => void browser?.delete(name),
};

const secret = 'a-secret-that-is-at-least-32-characters-long';
const { privateKey } = await generateKeyPair('RS256');
let idToken = '';

// A fake Auth0: the discovery document, and a token endpoint that answers with the ID token of the test.
const customFetch: typeof fetch = async (input) => {
  const { pathname } = new URL(input instanceof Request ? input.url : String(input));

  if (pathname === '/.well-known/openid-configuration') {
    return Response.json({
      issuer: 'https://auth.zepto.example/',
      authorization_endpoint: 'https://auth.zepto.example/authorize',
      token_endpoint: 'https://auth.zepto.example/oauth/token',
    });
  }

  if (pathname === '/oauth/token') {
    return Response.json({
      id_token: idToken,
      access_token: 'at_join',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid',
    });
  }

  return new Response(null, { status: 404 });
};

const serverClient = new ServerClient<Browser>({
  domain: 'auth.zepto.example',
  clientId: 'client_1',
  clientSecret: 'secret_1',
  customFetch,
  authorizationParams: { redirect_uri: 'https://zepto.example/auth/callback' },
  transactionStore: new CookieTransactionStore<Browser>({ secret }, cookieHandler),
  stateStore: new StatelessStateStore<Browser>({ secret }, cookieHandler),
  poppy: {
    config: {
      protocol_version: '0.3',
      organization: { name: 'Zepto', domain: 'zepto.example' },
      issuer: 'https://auth.zepto.example/',
      web: { browser_session_endpoint: 'https://auth.zepto.example/poppy/client_1/browser-session' },
    },
    guestStore: new StatelessPoppyGuestStore<Browser>({ secret }, cookieHandler),
  },
});

// The agent's browser joins: it starts a login, comes back with a code, and Auth0 answers with a signed ID token.
async function join(browser: Browser, claims: Record<string, unknown>) {
  idToken = await new SignJWT({
    act: { sub: 'https://agent.example/agent.json', poppy_sid: 'Yx2b7Qd_Kp8mR3vT1nWc4A', poppy_user_id: 'usr_Q7c1vK' },
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer('https://auth.zepto.example/')
    .setAudience('client_1')
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(privateKey);

  await serverClient.startInteractiveLogin({}, browser);

  return serverClient.completeInteractiveLogin(new URL('https://zepto.example/auth/callback?code=abc'), browser);
}

const guest = { sub: 'anon_poppy@abc', sub_profile: 'urn:auth0:anonymous_user' };

// The key of the agent's Session, or undefined when a person drives the browser.
async function keyOf(browser: Browser) {
  const context = await serverClient.poppy.getContext(browser);

  return context.kind === 'agent' ? context.key : undefined;
}

describe('an agent joins the website', () => {
  it('keeps a guest apart from the users', async () => {
    const browser: Browser = new Map();

    await join(browser, guest);

    expect(await serverClient.getUser(browser)).toBeUndefined();
    expect(await serverClient.poppy.getContext(browser)).toMatchObject({ kind: 'agent', state: 'signed_out' });
  });

  it('signs the person in when the agent joins again with a token, and the key stays the same', async () => {
    const browser: Browser = new Map();

    await join(browser, guest);
    const key = await keyOf(browser);

    await join(browser, { sub: 'auth0|ana' });

    expect((await serverClient.getUser(browser))?.sub).toBe('auth0|ana');
    expect(await serverClient.poppy.getContext(browser)).toMatchObject({ kind: 'agent', state: 'signed_in' });
    expect(key).toEqual(expect.any(String));
    expect(await keyOf(browser)).toBe(key);
  });
});
```

### Production notes

- **Use HTTPS.** Like the cookies of the session and of the anonymous session, the `__a0_poppy` cookies are `HttpOnly`, `Secure` and `SameSite=Lax` by default. Browsers do not send `Secure` cookies over plain HTTP. Set `cookie: { secure: false }` on the guest store only for local development, and keep the other defaults.
- **Rotate secrets.** The guest store takes the same `secret` as the other stores, and accepts a list. The first secret encrypts, and all of them decrypt. See [Configuring Cookies Secret Rotation](#configuring-cookies-secret-rotation).

  ```ts
  const guestStore = new StatelessPoppyGuestStore({ secret: [newSecret, oldSecret] }, new FastifyCookieHandler());
  ```

- **Behind a proxy, use the public URL.** Build the URL you pass to `completeInteractiveLogin()` and to `parseLoginInitiation()` from the public base URL of your website, and use the same value as `appOrigin`. Do not build either from the `Host` header or from the internal address of your server.
- **Never log tokens.** Do not log access tokens, ID tokens, cookies or the values of the query parameters of the login request. The messages of the errors and of `verifyConfig()` are fixed texts, so they are safe to log.
- **Turn `poppy` on before the login URI receives joins.** Without the option, the callback does not know about agents, so a join makes an ordinary session. A guest would become a user. Those sessions may have a refresh token and never get the deadline of an agent session. Turn `poppy` on first, and then set the Application Login URI.
- **A sign-out or a disconnect is not seen yet.** The SDK does not see either event, so neither ends an agent session by itself. See [How long an agent session lasts](#how-long-an-agent-session-lasts).
- **Guest detection depends on Auth0's guest marker.** The SDK reads a guest from the `sub_profile` claim, which holds `urn:auth0:anonymous_user`. Until Auth0 sends that claim, it also reads the temporary `anon_poppy@` prefix of `sub`. This is one reason why the feature is in beta.
- **Poppy is a draft.** The support was written against Poppy 0.3. The version in your config is served as you wrote it, and the SDK does not check it against a version it knows. Newer versions of the protocol can change names or add members that this package does not know yet.

### Reference

#### `PoppyOptions`

The type of the `poppy` option of the `ServerClient`:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `config` | `PoppyConfig` | Required | The parsed `auth0-poppy.json`. |
| `guestStore` | `PoppyGuestStore` | Required | Where guests are kept. Use `StatelessPoppyGuestStore`, or your own store that extends `AbstractPoppyGuestStore`. |
| `agentSessionMaxAge` | `number` | `7200` | The longest an agent's session lasts, in seconds. A positive whole number. The session can end sooner. |
| `protectedResource` | `PoppyProtectedResource` | Inferred from `config` | Your own values for `oauth-protected-resource`. See [Serving the discovery files](#serving-the-discovery-files). |

`StatelessPoppyGuestStore` takes `{ secret, cookie? }` and a `CookieHandler`. `cookie` has `sameSite` (default `lax`), `secure` (default `true`) and `path` (default `/`). The guest is kept in cookies named `__a0_poppy.0`, `__a0_poppy.1` and so on, and they last until the deadline of the guest. The name `__a0_poppy` is reserved and cannot be changed. Do not set `stateIdentifier`, `transactionIdentifier` or `anonymousSessionIdentifier` to a prefix of it, such as `__a0_pop`, because a store that finds its cookies by prefix would pick up the guest cookies. The client does not check this when you build it.

#### `PoppyContext`

`poppy.getContext()` returns `{ kind: 'human' }` for a person, and a `PoppyAgentContext` for an agent's browser. The same `PoppyAgentContext` is `poppy` in `getVisitor()` and in the result of `completeInteractiveLogin()`. It also holds `sessionId` and `userId`, the ids of the Poppy Session and of the user. These members matter most:

| Member | Type | Description |
| --- | --- | --- |
| `state` | `'signed_out'` or `'signed_in'` | `'signed_out'` is a guest. `'signed_in'` is a user whose session has the agent in `act`. |
| `agent.cimdUrl` | `string` | The URL of the client metadata document of the agent. It identifies the agent. |
| `agent.poppyAgentId` | `string`, optional | The id of the agent inside its Personal Agent, when it runs several agents. |
| `key` | `string` | An opaque key for this agent and this Session. It is the same value that the Poppy support in a coming `@auth0/auth0-api-js` release returns for the Session. |

#### `PoppyConfigIssue`

`poppy.verifyConfig()` returns a list of these, which is empty when there is nothing to report. Each has a `code` and a `message`, a fixed text that is safe to log. The codes are in the table of [Serving the discovery files](#serving-the-discovery-files). Auth0's discovery documents do not yet publish `protected_resources` or Poppy scopes, so `protected_resource_missing` and `scopes_not_supported` are expected until they do. Read them as information, not as a failure.

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

### Logging in to an Organization

Pass `organization` to log a user in to a specific Auth0 organization. It can be an organization ID (e.g. `org_abc123`) or an organization name (e.g. `acme-corp`). You can set it as a client-wide default, per login, or through `authorizationParams`:

```ts
// Client-wide default
const serverClient = new ServerClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  stateStore,
  transactionStore,
  authorizationParams: { redirect_uri: '<AUTH0_REDIRECT_URI>' },
  organization: 'org_abc123',
});

// Per login (overrides the client-wide default)
await serverClient.startInteractiveLogin({ organization: 'org_abc123' });

// Also supported per login through authorizationParams
await serverClient.startInteractiveLogin({ authorizationParams: { organization: 'org_abc123' } });
```

Per-login values (the `organization` option or `authorizationParams.organization`) take precedence over the client-wide default. When both per-login forms are provided, the `organization` option wins.

To handle an organization invitation (for example from an invitation link containing `invitation` and `organization` query parameters), forward the `invitation` ticket alongside the `organization`:

```ts
await serverClient.startInteractiveLogin({
  organization: 'org_abc123',
  invitation: 'inv_ticket_789',
});
```

When `organization` is provided, the organization claim of the returned ID token is validated during `completeInteractiveLogin`:

- an organization ID (the `org_` prefix) is matched **exactly** (case-sensitive) against the `org_id` claim;
- an organization name (no `org_` prefix) is matched **case-insensitively** against the `org_name` claim.

If the claim is missing or does not match, `completeInteractiveLogin` throws an `OrganizationValidationError` and no session is persisted.

```ts
import { OrganizationValidationError } from '@auth0/auth0-server-js';

try {
  await serverClient.completeInteractiveLogin(url);
} catch (error) {
  if (error instanceof OrganizationValidationError) {
    // The user did not authenticate into the requested organization.
  }
}
```

See the [Auth0 Organizations documentation](https://auth0.com/docs/manage-users/organizations) for setup and concepts.

### Using Experiment Center

Pass `experiment_id` and `variation_id` via `authorizationParams` to force a user into a specific [Experiment Center](https://auth0.com/docs/customize/experiment-center/overview) variation for the login request, bypassing the server-side deterministic assignment. Both IDs are obtained from your Auth0 Dashboard or the Management API.

```ts
await serverClient.startInteractiveLogin({
  authorizationParams: {
    experiment_id: '<EXPERIMENT_ID>',
    variation_id: '<VARIATION_ID>',
  },
});
```

When the experiment uses segment targeting, also pass `segment_id`:

```ts
await serverClient.startInteractiveLogin({
  authorizationParams: {
    experiment_id: '<EXPERIMENT_ID>',
    variation_id: '<VARIATION_ID>',
    segment_id: '<SEGMENT_ID>',
  },
});
```

> [!IMPORTANT]
> Pass `experiment_id` and `variation_id` per-call via `startInteractiveLogin`, not in the
> `ServerClient` constructor's `authorizationParams`. Setting them at construction time pins
> every login to the same variation, which cancels out the A/B test.
>
> Experiment Center is an Enterprise feature. Refer to the [Experiment Center documentation](https://auth0.com/docs/customize/experiment-center/overview) for more information and setup.

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

## Login and Signup using Passkeys

Passkeys let users sign up and log in with a WebAuthn credential (for example, a device biometric or security key) instead of a password.

The WebAuthn ceremony (`navigator.credentials.create()` / `navigator.credentials.get()`) can only run in the browser, so every passkey flow takes two requests to your server:

1. The browser asks your server to start the flow. Your server calls `passkey.startSignup()` (signup) or `passkey.startLogin()` (login) and returns the result to the browser.
2. The browser runs the WebAuthn ceremony with `authnParamsPublicKey` and sends the resulting credential to your server. Your server calls `passkey.complete()`, which exchanges the credential for tokens and creates the session.

Between the two requests, the SDK keeps the flow, including the Auth0 `authSession`, in the Transaction Store, so the `authSession` never reaches your code or the browser's JavaScript. With `CookieTransactionStore`, it travels only inside the encrypted `httpOnly` cookie.

> [!IMPORTANT]
> Before using passkeys, ensure the following are configured in your [Auth0 Dashboard](https://manage.auth0.com):
>
> 1. **Enable the passkey authentication method**: Go to **Authentication** > **Database** > your connection > **Authentication Methods** > **Passkey**.
> 2. **Enable the WebAuthn passkey grant**: Go to your **Application** > **Advanced Settings** > **Grant Types** and enable the **Passkey** grant. `passkey.complete()` exchanges the credential via this grant, so the token exchange fails without it.
> 3. **A custom domain is required**: Passkeys are bound to an origin (domain). A [custom domain](https://auth0.com/docs/customize/custom-domains) must be configured — passkeys will not work on the default `*.auth0.com` domain.
> 4. **Use that connection**: Pass its name as `realm` to `passkey.startSignup()` and `passkey.startLogin()`, or set it as the tenant's **Default Directory**. Without a `realm`, Auth0 uses the Default Directory, and the request fails when there is none. `passkey.complete()` uses the connection the flow started with.
>
> Read [the Auth0 docs](https://auth0.com/docs/authenticate/database-connections/passkeys) to learn more about passkeys.

> [!IMPORTANT]
> **Client authentication differs across the passkey methods.**
>
> `passkey.startSignup()` and `passkey.startLogin()` (like the lower-level `passkey.register()` and `passkey.challenge()`) accept `client_secret` as their only client credential. If your application is a confidential client, configure a `clientSecret` on the `ServerClient` and the SDK sends it on these requests.
>
> These endpoints do not accept a private key JWT, and they are not served on the mTLS endpoint aliases. An application configured with only a `clientAssertionSigningKey` or only `useMtls` therefore has no credential the SDK can send to them, and Auth0 rejects the request. To use them, set the application's authentication method to **Client Secret** in the Auth0 Dashboard and pass that secret as `clientSecret`.
>
> `passkey.complete()` and `passkey.getToken()` are not affected. They go through the token endpoint, so they work with a `clientSecret`, a `clientAssertionSigningKey`, or mTLS.

### Choosing the Passkey Methods

The passkey client has two sets of methods. Use `passkey.startSignup()`, `passkey.startLogin()` and `passkey.complete()`. The lower-level `passkey.register()`, `passkey.challenge()` and `passkey.getToken()` run the same flows, but leave keeping the flow to your application:

| | `startSignup()`, `startLogin()`, `complete()` | `register()`, `challenge()`, `getToken()` |
|---|---|---|
| The `authSession` | Kept in the Transaction Store. Your code and the browser's JavaScript never see it, and errors never carry it. | Returned to your application, which passes it back to `getToken()`. It usually travels through the browser. |
| `storeOptions` on the start call | Needed: the start call writes the flow to the Transaction Store (with `CookieTransactionStore`, the `__a0_passkey_tx` cookie). | Used only to resolve the domain in resolver mode. |
| What the browser sends to finish | The credential, and the one-time codes when the signup needs them. | The `authSession`, the credential and the codes. Your server adds the same `realm` and `organization` as at the start. |
| Checks before Auth0 is called | The flow has not expired, the credential names its challenge (Auth0 verifies the signature), and every identifier that needs a code has one. | None. |
| After a wrong one-time code | The SDK keeps the flow and the identifiers that still need a code. | Your application keeps the `authSession` and the identifiers from the error. |
| Flows at a time | One per browser: a new start replaces the stored flow. | As many as your application keeps. |
| Resolver mode | `complete()` uses the domain that started the flow. | Your resolver must return the same domain for every call. |

The two sets do not mix: finish a flow started with `startSignup()` or `startLogin()` with `complete()`, and one started with `register()` or `challenge()` with `getToken()`. Use the lower-level methods only when you need to keep the flow yourself, for example to run several passkey flows in one browser at once. See [Keeping the `authSession` yourself](#keeping-the-authsession-yourself).

### Starting a Signup

To register a new user, call `passkey.startSignup()` with the user's profile and return the result to the browser:

```ts
const { authnParamsPublicKey, verificationRequired } = await serverClient.passkey.startSignup(
  { email: 'user@example.com', name: 'Jane Doe', realm: 'Username-Password-Authentication' },
  storeOptions
);
```

- `authnParamsPublicKey`: WebAuthn credential creation options. The browser passes these to `navigator.credentials.create()`.
- `verificationRequired`: Present when the connection requires identifier verification, for example `['email']`. Auth0 has sent a one-time code to each listed identifier. See [Verifying the Email or Phone Number at Signup](#verifying-the-email-or-phone-number-at-signup).

The SDK stores the `authSession`, the challenge, the domain, the `realm` and `organization` you passed, and `verificationRequired` in the Transaction Store. With `CookieTransactionStore`, this is the encrypted `httpOnly` cookie `__a0_passkey_tx`, which expires together with the Auth0 auth session (60 seconds, or 15 minutes with identifier verification).

This method does not create a session. On a confidential client it needs a `clientSecret`; see the client authentication note [above](#login-and-signup-using-passkeys).

### Starting a Login

To log in an existing user, call `passkey.startLogin()` and return the result to the browser:

```ts
const { authnParamsPublicKey } = await serverClient.passkey.startLogin(
  { realm: 'Username-Password-Authentication' },
  storeOptions
);
```

- `authnParamsPublicKey`: WebAuthn credential request options. The browser passes these to `navigator.credentials.get()`.

The flow is stored the same way as for a signup. This method does not create a session either. If the page runs conditional UI (passkey autofill) and then starts another flow, abort the pending `navigator.credentials.get()` call: a credential for the replaced flow is rejected with `MissingTransactionError`. A login flow also expires after 60 seconds, so with conditional UI, start a new flow and a new conditional `get()` before then. Every start replaces the pending flow in this browser, in every tab, so stop renewing it while a signup is in progress: it would replace the signup, and the one-time codes the user received would stop working.

### Completing the Passkey Flow

After the browser has run the WebAuthn ceremony, it sends the serialized credential back to your server. Call `passkey.complete()` to exchange it for tokens and create the session:

```ts
await serverClient.passkey.complete({ credential, verification }, storeOptions);
```

- `credential`: The serialized credential from `navigator.credentials.create()` (signup) or `navigator.credentials.get()` (login).
- `verification`: The one-time codes, only when `startSignup()` returned `verificationRequired`: one code for each listed identifier, for example `{ email: '123456' }`. Omit it otherwise, including on login. See [Verifying the Email or Phone Number at Signup](#verifying-the-email-or-phone-number-at-signup).
- `scope` and `audience`: Optional. They default to the values in the `ServerClient`'s `authorizationParams`.

The SDK takes the `authSession`, `realm`, `organization` and domain from the stored flow, never from the request. In resolver mode, the tenant that started the flow is used.

On success, the resulting session is persisted to the State Store, exactly like an interactive login. Afterwards, [`getUser()`](#retrieving-the-logged-in-user), [`getAccessToken()`](#retrieving-an-access-token) and [`logout()`](#logout) all work as usual.

When using Rich Authorization Requests (RAR), `passkey.complete()` returns the granted `authorizationDetails`:

```ts
const { authorizationDetails } = await serverClient.passkey.complete({ credential }, storeOptions);
```

#### Handling errors and retries

`passkey.complete()` deletes the stored flow once Auth0 has used the auth session: on success, on `mfa_required`, when Auth0 reports the auth session as used, expired or invalid, and when the ID token organization does not match. After any other failure, the flow is kept and you can call `complete()` again with the same credential. If Auth0 had used the auth session after all, that call fails with `invalid_grant` and deletes it. The thrown errors never carry the `authSession`.

| Error | Meaning | What to do |
|-------|---------|------------|
| `PasskeyGetTokenError` with `isRetryable` set to `true` | A one-time code was wrong. `error.verificationRequired` lists the identifiers that still need a code. | Ask for codes for those identifiers only, then call `complete()` again with the same credential. |
| `PasskeyGetTokenError` with `cause.error` set to `invalid_request` | The request was incomplete or invalid. A missing or blank one-time code is reported this way before Auth0 is called, for example as `Missing required parameter: verification.email`, and then the error has no `statusCode`. | Fix the input, then call `complete()` again with the same credential. |
| `isMfaRequiredError(error)` is `true` | The passkey, and any codes, were accepted, but the user must complete MFA. No session is persisted yet. | Continue with the MFA APIs, see [Handling an `mfa_required` response](#handling-an-mfa_required-response). |
| `PasskeyGetTokenError` with `statusCode` set to 429 | Rate limited. Auth0 checks this before it uses the attempt. | Wait, then send the same request again. `error.headers?.get('retry-after')` can tell you how long. |
| `MissingTransactionError` | No flow to complete: none was started, it expired, or the credential was created for an older start (for example in another tab). Auth0 was not called. | Start a new flow. |
| `MissingRequiredArgumentError` | The credential, or its `response.clientDataJSON`, is missing or cannot be read. Auth0 was not called, and the flow is kept. | Fix the request. |
| Anything else | Usually the end of the attempt, for example after too many wrong codes or when the time ran out. A temporary failure, such as a server or network error, also lands here, and the flow is kept then. The error does not tell the two apart. | Send the same request once more, and start a new flow if that fails too. The second try is safe: a flow that is over fails again. |

Never use the HTTP status or the message to tell a wrong code from a failure that ends the attempt: the two can share both. Use `isRetryable`.

#### Handling an `mfa_required` response

When MFA is enabled, `passkey.complete()` can fail with an `mfa_required` response: the passkey is verified, but the user must still complete a second factor. The thrown `PasskeyGetTokenError` carries `cause.mfa_token` and `cause.mfa_requirements`, and **no session is persisted**. Use the `isMfaRequiredError` type guard to detect it and continue with the MFA APIs exposed on `serverClient.mfa`:

```ts
import { isMfaRequiredError } from '@auth0/auth0-server-js';

try {
  await serverClient.passkey.complete({ credential }, storeOptions);
} catch (error) {
  if (isMfaRequiredError(error)) {
    // error.cause.mfa_token is guaranteed to be a string here
    await serverClient.mfa.challengeAuthenticator({
      mfaToken: error.cause.mfa_token,
      challengeType: 'otp',
    });
    // ...then complete the challenge with serverClient.mfa.verify()
  }
}
```

### Example: Server Routes and Browser Code

The following Fastify example has a route to start a signup, a route to start a login, and one route that completes both. It also works for a signup with identifier verification. `parseSignupForm` stands for your own input validation. The last argument of each SDK call is a [`RequestOptions`](#per-request-options) object, used here to forward the end user's IP address.

```ts
import {
  isMfaRequiredError,
  MissingRequiredArgumentError,
  MissingTransactionError,
  PasskeyGetTokenError,
} from '@auth0/auth0-server-js';
import type {
  PasskeyCompleteOptions,
  PasskeyCredentialResponse,
  PasskeyVerificationCodes,
} from '@auth0/auth0-server-js';

// Set on the server, never from the browser. The flow keeps them for complete().
const realm = 'Username-Password-Authentication';

// When the connection verifies identifiers, every call sends new codes: rate-limit this route.
fastify.post('/passkey/signup/start', async (request, reply) => {
  // Your own validation. It returns `PasskeyRegisterOptions` with only the fields the user may set,
  // and `deliveryMethod` only when the user picked 'text' or 'voice'.
  const signup = parseSignupForm(request.body);
  const { authnParamsPublicKey, verificationRequired } = await serverClient.passkey.startSignup(
    { ...signup, realm }, // and `organization`, if you use one
    { request, reply },
    { headers: { 'auth0-forwarded-for': request.ip } } // behind a proxy, configure trustProxy
  );
  return { authnParamsPublicKey, verificationRequired: verificationRequired ?? [] };
});

fastify.post('/passkey/login/start', async (request, reply) => {
  const { authnParamsPublicKey } = await serverClient.passkey.startLogin(
    { realm },
    { request, reply },
    { headers: { 'auth0-forwarded-for': request.ip } }
  );
  return { authnParamsPublicKey };
});

// Completes the signup or login that was started last in this browser.
fastify.post('/passkey/finish', async (request, reply) => {
  const input = parseFinishBody(request.body);
  if (!input) {
    // Nothing reached Auth0, so the flow is still open.
    return reply.code(400).send({ status: 'invalid' });
  }
  try {
    await serverClient.passkey.complete(input, { request, reply }, {
      headers: { 'auth0-forwarded-for': request.ip },
    });
    return { status: 'complete' };
  } catch (error) {
    if (isMfaRequiredError(error)) {
      // The passkey was accepted (for a signup, the user exists now), but the user must complete MFA. Do not
      // return `error.cause.mfa_token` here: keep it where the browser cannot read it, for example in a
      // short-lived encrypted cookie or your server-side session store, and continue with `serverClient.mfa`
      // (see MFA.md).
      return { status: 'mfa_required' };
    }
    if (error instanceof PasskeyGetTokenError && error.isRetryable) {
      return reply.code(400).send({ status: 'retry', verificationRequired: error.verificationRequired ?? [] });
    }
    if (error instanceof PasskeyGetTokenError && error.statusCode === 429) {
      // Auth0 checks its rate limit before it uses the attempt, so the same request can be sent again later.
      return reply.code(429).send({ status: 'wait' });
    }
    if (
      error instanceof MissingRequiredArgumentError ||
      (error instanceof PasskeyGetTokenError && error.cause?.error === 'invalid_request')
    ) {
      // An incomplete or invalid request, for example a missing code. The flow is kept.
      return reply.code(400).send({ status: 'invalid' });
    }
    if (error instanceof MissingTransactionError) {
      // No flow to complete: none was started, it expired, or it was replaced or used up. Auth0 was not called.
      return reply.code(400).send({ status: 'restart' });
    }
    // Usually the end of the attempt (too many wrong codes, an expired or used session), but after a server or
    // network error the flow is kept. The browser sends the same request once more: a flow that is over fails again.
    return reply.code(400).send({ status: 'failed' });
  }
});

// Never pass the raw request body to complete(): the browser could then choose `scope` or `audience`.
// Copy only the fields you validated.
function parseFinishBody(body: unknown): PasskeyCompleteOptions | undefined {
  const { credential, verification } = (body ?? {}) as Record<string, unknown>;
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) {
    return undefined;
  }
  // Accept only `email` and `phone` codes, as strings of at most 10 characters. `complete()` rejects a missing
  // or blank code for an identifier that needs one.
  const codes: PasskeyVerificationCodes = {};
  for (const key of ['email', 'phone'] as const) {
    const code = (verification as Record<string, unknown> | null | undefined)?.[key];
    if (code === undefined) {
      continue;
    }
    if (typeof code !== 'string' || code.length > 10) {
      return undefined;
    }
    codes[key] = code;
  }
  return {
    credential: credential as PasskeyCredentialResponse,
    verification: Object.keys(codes).length > 0 ? codes : undefined,
  };
}
```

The start routes leave out error handling. `passkey.startSignup()` throws a `PasskeyRegisterError` when Auth0 rejects the request, for example when the user already exists, the phone channel is not supported, a code could not be sent, or the request is rate limited (`error.statusCode` is 429). `passkey.startLogin()` throws a `PasskeyChallengeError`. Nothing is stored then. Catch the error and return a generic error to the browser.

In the browser, a signup without identifier verification takes three calls:

```ts
// `post` sends JSON and returns the parsed response body, also for a 400 or 429 response.
const start = await post('/passkey/signup/start', { email });
const credential = await createPasskey(start.authnParamsPublicKey); // navigator.credentials.create(), serialized
const result = await post('/passkey/finish', { credential });
```

A login is the same, with `/passkey/login/start` and `navigator.credentials.get()`. `createPasskey` calls `navigator.credentials.create()` with `authnParamsPublicKey` and serializes the result. The binary fields of `authnParamsPublicKey`, such as `challenge` and, for a signup, `user.id`, are base64url strings: decode them to `ArrayBuffer`s first, or use `PublicKeyCredential.parseCreationOptionsFromJSON()` (`parseRequestOptionsFromJSON()` for a login) where the browser supports it. The auth-js documentation has a [base64url helper](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-auth-js/examples/passkeys.md#exchanging-a-credential-for-tokens) for encoding the result. Send only the fields of `PasskeyCredentialResponse`, as the helper does. Do not send the output of `credential.toJSON()`: Auth0 rejects the extra fields in `response` with an `invalid_request` error.

Add CSRF protection to the finish route, because it writes the session cookie.

### Verifying the Email or Phone Number at Signup

A connection can require the user's email address, phone number, or both to be verified during signup. When it does, `passkey.startSignup()` returns `verificationRequired`, and Auth0 sends a one-time code to each listed identifier during that call. Your application collects the codes from the user and passes them to `passkey.complete()` as `verification`. The profile field is `phoneNumber`, but its identifier and code are `phone`:

```ts
const { authnParamsPublicKey, verificationRequired } = await serverClient.passkey.startSignup(
  { email: 'user@example.com', phoneNumber: '+15551234567' },
  storeOptions
); // verificationRequired: ['email', 'phone']

// ...the user enters the codes, and the browser creates the passkey...
await serverClient.passkey.complete({ credential, verification: { email: '123456', phone: '654321' } }, storeOptions);
```

When `verificationRequired` is absent, nothing changes: omit `verification`, as on login.

Only the identifiers you pass to `passkey.startSignup()` or `passkey.register()` are verified, using the connection's signup verification settings: an email address must be set to be verified with a one-time code (a verification link does not use this flow), and a phone number must be set to be verified. To choose how the phone code is delivered, pass `deliveryMethod` (`'text'` or `'voice'`). Leave it out to let Auth0 use the channel the connection supports (SMS when it supports both or none). A channel that the connection does not support makes the start call fail with `invalid_request`.

With the [example routes](#example-server-routes-and-browser-code), the flow has four steps:

1. The browser POSTs to the signup start route. The server calls `passkey.startSignup()` and returns `authnParamsPublicKey` and `verificationRequired`.
2. The browser asks the user for the codes, and only then calls `navigator.credentials.create()`. A user who never receives a code is then not left holding a passkey for an account that was never created. To send new codes, call the start route again before the passkey is created. Every call starts a new flow, so the browser must use the `authnParamsPublicKey` from its latest response. The user has 15 minutes to enter the codes, retries included. A login started in the meantime, in any tab or by renewing passkey autofill, replaces the signup, and the codes stop working.
3. The browser POSTs the serialized credential and the codes to the finish route, and the server calls `passkey.complete()`.
4. On a wrong code, the browser asks again only for the identifiers that are still listed. It POSTs again with the same credential, kept in page memory, so the user does not see a second passkey prompt. The SDK keeps the shorter list too, so the next `complete()` needs codes only for those identifiers.

#### Browser steps

The browser collects the codes before it creates the passkey, and keeps the credential for any retry:

```ts
const MAX_RETRIES = 5; // your own limit for wrong codes, see the security notes below

const start = await post('/passkey/signup/start', { email });
let verification = await askForCodes(start.verificationRequired); // for example { email: '123456' }, or undefined
const credential = await createPasskey(start.authnParamsPublicKey);
let result = await post('/passkey/finish', { credential, verification });
let retries = 0;
let resent = false;
while (result.status === 'retry' || result.status === 'wait' || (result.status === 'failed' && !resent)) {
  if (result.status === 'retry') {
    if (++retries > MAX_RETRIES) {
      result = { status: 'restart' };
      break;
    }
    verification = await askForCodes(result.verificationRequired); // only the identifiers that are still listed
  } else if (result.status === 'wait') {
    await waitBeforeRetry(); // rate limited: send the same codes again, without new codes or a new signup
  } else {
    resent = true; // the flow may still be open: send the same request once more
  }
  result = await post('/passkey/finish', { credential, verification });
}
// result.status is now 'complete', 'mfa_required', 'restart' or 'failed' (start again). A status of 'invalid' means the request was malformed.
```

`askForCodes` shows one input for each identifier it receives and does not return until every input holds a non-blank code of at most 10 characters. It returns `{ email?, phone? }`, or `undefined` when the list is empty. `waitBeforeRetry` tells the user to try again in a moment and waits until they do. Keep the credential in page memory for the retries.

#### Security and operational notes

- Rate-limit the signup start route. Every call to `passkey.startSignup()` sends new codes, so a route that anyone can call can be used to send messages to any email address or phone number. Do not rely only on Auth0's limits: add your own limits per IP address and per email address or phone number. Text messages and voice calls cost money, so also consider a bot check (for example a CAPTCHA) and accepting only the phone country codes you serve.
- Forward the end user's IP address in the `auth0-forwarded-for` header on the signup start and finish requests, as the example does. Your server makes these requests, so Auth0 otherwise sees your server's address. Auth0 uses the header only for applications with **Trust Token Endpoint IP Header** turned on (in the application's **Advanced Settings** > **OAuth**), and `passkey.startSignup()` rejects a value that is not a valid IP address. Behind a proxy, configure Fastify's `trustProxy` option so that `request.ip` is the user's address. Trust only the proxies you control, because otherwise a caller can put any address in `X-Forwarded-For`.
- Never log the codes, the credential, or a whole `PasskeyGetTokenError`: its `cause` can contain an `mfa_token`.
- Send one finish request at a time, for example by disabling the submit button while a request is pending. Parallel requests can use up the allowed attempts, or reach Auth0 after the auth session is already used.
- Cap the number of retries in the browser, as the example does with `MAX_RETRIES`. Auth0 limits the wrong codes it accepts, but its response does not say how many attempts are left. Once the cap is reached, treat the attempt as finished and start again from the start route.
- If a step after the verification fails (for example, an Action denies the login), the user may already exist. A new signup then fails, so offer passkey login.

### Passing `StoreOptions`

The passkey methods accept a `storeOptions` argument, after the method's own options:

- `passkey.startSignup()` and `passkey.startLogin()` store the flow via the configured `transactionStore`, passing `storeOptions` along to it (and using it for domain resolution in resolver mode).
- `passkey.complete()` reads, updates and deletes the flow in the `transactionStore` and persists the session via the configured `stateStore`, passing `storeOptions` along to both.
- The lower-level `passkey.register()` and `passkey.challenge()` store nothing, and use `storeOptions` only to resolve the domain in resolver mode. `passkey.getToken()` persists the session via the `stateStore`, passing `storeOptions` along to it.

```ts
const storeOptions = {
  /* ... */
};
await serverClient.passkey.complete({ credential }, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

### Using a custom Transaction Store

The passkey methods keep their flow in the same `transactionStore` as the redirect-login flows, under their own identifier (`__a0_passkey_tx` by default). `CookieTransactionStore` already does everything below. If you use your own store, for example one backed by Redis:

- Keep entries on the server, or encrypt and authenticate them, as `CookieTransactionStore` does through `AbstractTransactionStore`. They hold secrets such as the `authSession`, and the domain that the SDK sends your client credentials to when it completes the flow.
- Key entries by the `identifier` the SDK passes, for example as `<browser id>:<identifier>`, and keep every property of the `TransactionData` you receive. A store that ignores the identifier keeps one entry for both flows, so one flow replaces or reads the other's entry. Before the passkey methods, the SDK used only one identifier with this store, so check an existing store before you use them.
- Do not keep a passkey entry past its `expiresAt` (Unix time, in seconds). The SDK checks it too, so this only keeps your store clean.
- Log or monitor failures inside your store. After the token exchange, `passkey.complete()` deletes or updates its entry on a best-effort basis and does not report a store error: after a success, Auth0 has already issued the tokens (and, for a signup, created the user), so the login still succeeds; after a failed exchange, the original error is thrown.

A used entry left behind is harmless. Auth0 rejects its auth session if it is sent again, the next `passkey.startSignup()` or `passkey.startLogin()` replaces it, and it expires at its `expiresAt`. If the update after a wrong code fails, the entry keeps the earlier list of identifiers, so the next `complete()` call also needs the codes Auth0 has already accepted.

### Keeping the `authSession` yourself

The lower-level `passkey.register()`, `passkey.challenge()` and `passkey.getToken()` keep no flow state. They return the `authSession`, and your application passes it back to `passkey.getToken()` together with the same `realm` and `organization`. They remain supported.

```ts
const realm = 'Username-Password-Authentication';
const { authSession, authnParamsPublicKey } = await serverClient.passkey.challenge({ realm }, storeOptions);

// ...the browser runs navigator.credentials.get() and sends the credential back...

await serverClient.passkey.getToken({ authSession, credential, realm }, storeOptions);
```

Compared with `passkey.complete()`, your application takes over what the SDK does with the stored flow:

- Keep the `authSession` between the start and the finish, and pass it to every `getToken()` call. When it travels through the browser, take only the `authSession`, the credential and the codes from the browser: set `realm`, `organization`, `scope` and `audience` on the server.
- `getToken()` does not check that the credential was created for the challenge of that `authSession`. A credential from another attempt, for example from another tab, uses up the attempt.
- For identifier verification, send a code for every identifier in the latest list, and after a wrong code only for the identifiers in `error.verificationRequired`. `getToken()` does not check the codes.

> [!IMPORTANT]
> When using a domain resolver (resolver mode), the `authSession` is tied to the domain that issued the challenge. The `storeOptions` you pass to `passkey.getToken()` must make your resolver return the **same** domain as for `passkey.register()` / `passkey.challenge()`, otherwise the token exchange resolves a different domain and fails. This also applies to every `passkey.getToken()` retry after a wrong verification code.

#### Identifier verification with `passkey.getToken()`

The [steps above](#verifying-the-email-or-phone-number-at-signup) apply, with these changes:

- The start route calls `passkey.register()` and also returns the `authSession` to the browser.
- The browser sends `authSession: start.authSession` with every finish request, next to the credential and the codes.
- The finish route also reads and validates `authSession`, then calls `getToken()` with the same `realm` and `organization` as `passkey.register()`:

```ts
await serverClient.passkey.getToken({ authSession, credential, realm, organization, verification }, { request, reply }, {
  headers: { 'auth0-forwarded-for': request.ip },
});
```

#### Handling `passkey.getToken()` errors

Handle the errors as in the [`passkey.complete()` table](#handling-errors-and-retries), with these differences:

- After a wrong code (`isRetryable`), call `passkey.getToken()` again with the same `authSession` (Auth0 returns it unchanged as `error.authSession`) and the same `credential`, sending codes only for the identifiers in `error.verificationRequired`.
- Only Auth0 reports an `invalid_request`, for example for a missing code. The attempt usually stays open: fix the request and send it again with the same `authSession` and `credential`.
- There is no `MissingTransactionError`. To start again, call `passkey.register()` or `passkey.challenge()`. Restarting a signup sends new codes, so let the user decide.

## Login using Custom Token Exchange

Custom Token Exchange allows you to establish an Auth0 session from an external token (e.g. a Google ID token, a legacy system token) without an interactive browser flow. This requires a [Token Exchange Profile](https://auth0.com/docs/authenticate/custom-token-exchange) configured in your Auth0 tenant.

Use `loginWithCustomTokenExchange()` when you want to exchange an external token and persist the resulting tokens as a user session:

```ts
await serverClient.loginWithCustomTokenExchange({
  subjectToken: externalToken,
  subjectTokenType: 'urn:acme:legacy-token',
  audience: 'https://api.example.com',
  scope: 'openid profile email offline_access',
});
```

After a successful exchange, the resulting tokens are stored in the StateStore — the user is effectively logged in. You can then use `getUser()`, `getSession()`, and `getAccessToken()` as you would after any other login flow.

> [!NOTE]
> The `openid` scope is required for `loginWithCustomTokenExchange()` to receive an ID token and populate the session user. If `openid` is not included in `scope`, the SDK will inject it automatically — the same behaviour as other login methods. If no `scope` is provided at all, the SDK defaults to `openid profile email offline_access`.

### Performing a delegation exchange without a session

Use `customTokenExchange()` when you need downstream tokens for a service call but do not want to create or modify a user session — for example, in delegation or impersonation flows:

```ts
const tokenResponse = await serverClient.customTokenExchange({
  subjectToken: incomingAccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'https://downstream-api.example.com',
});

// Use tokenResponse.accessToken to call the downstream API
```

No StateStore reads or writes occur — `storeOptions` is only used for domain resolution in resolver mode.

### Using actor tokens for delegation

When performing a delegation exchange where an intermediate service acts on behalf of a user, provide `actorToken` and `actorTokenType` together. Both are required when using actor tokens:

```ts
const tokenResponse = await serverClient.customTokenExchange({
  subjectToken: userToken,
  subjectTokenType: 'urn:acme:user-token',
  actorToken: serviceAccountToken,
  actorTokenType: 'urn:acme:service-token',
  audience: 'https://api.example.com',
});

// tokenResponse.act contains the actor claim from the issued token:
// { sub: 'service-account-id', ... }
console.log(tokenResponse.act?.sub);
```

> [!IMPORTANT]
> When an actor token is used, Auth0 does not issue a refresh token — even if `offline_access` is included in the scope. This applies to both `customTokenExchange()` and `loginWithCustomTokenExchange()`. For `loginWithCustomTokenExchange()`, this means `getAccessToken()` will throw once the access token expires, as it cannot silently refresh. Your application should handle this by re-running the exchange to obtain a new token.

### Passing `StoreOptions`

Just like most methods, both `loginWithCustomTokenExchange()` and `customTokenExchange()` accept a second argument that is used to pass to the configured store and domain resolver:

```ts
const storeOptions = {
  /* ... */
};
await serverClient.loginWithCustomTokenExchange({ subjectToken, subjectTokenType }, storeOptions);

const tokenResponse = await serverClient.customTokenExchange({ subjectToken, subjectTokenType }, storeOptions);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving User Information

`getUserInfo()` fetches user profile claims from the OIDC `/userinfo` endpoint for an access token you supply. Use it when you need fresh user claims for a token your application already holds.

> [!IMPORTANT]
> You must pass the access token explicitly. `getUserInfo()` does **not** read the token from the session and does **not** trigger a refresh.
>
> The access token must be accepted by the `/userinfo` endpoint, which depends on how it was obtained:
>
> - **Without Multi-Resource Refresh Tokens (MRRT):** use a default OIDC access token — one issued without an explicit `audience` parameter.
> - **With MRRT:** access tokens are audience-bound, so you must explicitly request the userinfo endpoint as the audience (e.g. `audience: 'https://<AUTH0_DOMAIN>/userinfo'`) when obtaining the token. A token bound to a different resource-server audience is rejected by `/userinfo`, typically resulting in a `UserInfoError` (HTTP 401 or 403).
>
> If you have a known `sub` from the session or an ID token, pass it as `expectedSubject` to guard against token substitution (recommended, though optional).

```ts
import { UserInfoError } from '@auth0/auth0-server-js';

try {
  const userInfo = await serverClient.getUserInfo({
    accessToken: '<access_token>',
    expectedSubject: '<known_sub>', // optional; throws UserInfoError on mismatch
  });

  console.log(userInfo.sub);
  console.log(userInfo.email);
  console.log(userInfo.name);
} catch (error) {
  if (error instanceof UserInfoError) {
    console.error('Failed to retrieve user info:', error.message);
    // The underlying client throws before parsing the response body, so
    // error.cause?.error is not populated for /userinfo errors. Use the HTTP
    // context instead, when present (e.g. an Auth0 401/403).
    console.error('HTTP status:', error.statusCode); // e.g. 401
    console.error('Request ID:', error.headers?.get('x-request-id'));
  }
}
```

The returned `UserInfoResponse` contains OIDC standard claims like `sub`, `email`, and `name`. The exact claims depend on the scopes granted to the access token.

### Passing `StoreOptions`

`getUserInfo()` accepts an optional second argument passed to the configured domain resolver, so the request resolves against the correct tenant in [resolver mode](#dynamic-domain-resolver). An optional third argument is a [`RequestOptions`](#per-request-options) forwarded to the underlying `/userinfo` request (e.g. an `AbortSignal` or custom headers):

```ts
const storeOptions = {
  /* ... */
};
const userInfo = await serverClient.getUserInfo({ accessToken: '<access_token>' }, storeOptions);

// With per-request options:
const controller = new AbortController();
const userInfo2 = await serverClient.getUserInfo(
  { accessToken: '<access_token>' },
  storeOptions,
  { signal: controller.signal }
);
```

Read more above in [Configuring the Store](#configuring-the-store)

## Impersonation via Session Transfer

Custom Token Exchange Impersonation via Session Transfer lets a support/admin application log an agent **into a target web application as a customer** — for example, so a support engineer can reproduce a customer's exact experience without ever knowing their password. It builds on Custom Token Exchange and involves two roles and two applications:

- **Initiator** — your support/admin app (this SDK). It requests a short-lived, single-use **Session Transfer Token (STT)** and redirects the agent's browser to the target app's login URL carrying the STT.
- **Target** — the customer's own web app. Its login route forwards the STT to `/authorize`, where Auth0 redeems it and establishes an ephemeral, device-bound session **as the customer**, recording the agent in the `act` (actor) claim.

The STT is **opaque, single-use, and short-lived (~60s)**. The SDK requests it, surfaces it, and helps you build the redirect — it never decodes, validates, caches, or persists it.

> [!IMPORTANT]
> This is a two-client, two-role flow with tenant prerequisites configured out of band (via the Management API / Dashboard):
>
> - The feature flag `cte_session_transfer_token` must be enabled on the tenant.
> - The **issuing (initiator) client** needs `session_transfer.can_create_session_transfer_token: true` and a Custom Token Exchange profile / Action that calls `setActor`.
> - The **redeeming (target) client** needs `session_transfer.delegation.allow_delegated_access: true`, `session_transfer.allowed_authentication_methods` including `"query"`, and `session_transfer.delegation.enforce_device_binding` (`"ip"` by default).
>
> See the [Custom Token Exchange documentation](https://auth0.com/docs/authenticate/custom-token-exchange) for the full setup.

### Initiator: requesting a Session Transfer Token and redirecting

The agent must be **logged in** to the initiator app: the SDK sources the actor from the agent's current session ID token by default (refreshing it if it has expired). Run your own authorization check — _is this agent allowed to impersonate this customer, right now?_ — before calling the SDK.

```ts
// In your support console's "View as customer" route (agent is already logged in):
const result = await serverClient.requestSessionTransferToken(
  {
    // Your own proof of which customer to impersonate — validated by your Action.
    // The SDK never produces this; you supply it in whatever form your Action expects.
    subjectToken,
    subjectTokenType: 'urn:acme:customer-subject',
    // Optional: forward custom context to your Action (e.g. an audited reason).
    extra: { reason: 'Investigating TCK-4821' },
  },
  storeOptions
);

// Build the redirect to the TARGET app's login URL (a trusted, app-controlled value).
const url = serverClient.buildSessionTransferRedirect('https://app.example.com/auth/login', result);

// Hand the URL to your framework's redirect (e.g. Fastify: reply.redirect(url.toString())).
```

> [!IMPORTANT]
> An **actor is mandatory** for an STT — that is what makes this auditable impersonation ("X acting as Y") rather than a silent takeover. If no explicit `actor` is passed and no usable session ID token can be resolved (no logged-in agent, or an expired ID token with no refresh token), the SDK throws a `TokenExchangeError` with code `actor_unavailable` **before any network call**.

By default the actor is the agent session's ID token, and the SDK refreshes it automatically when it has expired and a refresh token is available. To supply the acting party explicitly, pass `actor`. An explicit `actor` takes precedence and **the session is not read at all** — the SDK never touches the state store, so this also works where there is no logged-in agent:

```ts
const result = await serverClient.requestSessionTransferToken(
  {
    subjectToken,
    subjectTokenType: 'urn:acme:customer-subject',
    actor: { token: agentIdToken }, // type defaults to the ID token URN
  },
  storeOptions
);
```

Because you are now supplying the token yourself, it is on you to supply a valid one. When the actor token type is the ID token URN — which it is by default — Auth0 validates the token, so it must be an **unexpired, asymmetrically-signed Auth0 ID token**:

- Signed with **RS256 or PS256**. `HS256` is rejected because it uses a shared secret.
- Unexpired, and carrying `sub`, `iss`, `exp`, and `iat`.
- Issued to the **same client** that is making the exchange (its `aud` must be this client's ID).
- Belonging to a user who still exists and is not blocked.

An ID token from the agent's own session on this client satisfies all of these. A token that fails any of them comes back as a `TokenExchangeError` from the token endpoint.

If the customer belongs to an organization, there is an `organization` on both calls. They do different things, so pick based on what you need:

```ts
const result = await serverClient.requestSessionTransferToken(
  {
    subjectToken,
    subjectTokenType: 'urn:acme:customer-subject',
    organization: 'org_globex',
  },
  storeOptions
);

const url = serverClient.buildSessionTransferRedirect('https://app.example.com/auth/login', result, {
  organization: 'org_globex',
});
```

These are two separate parameters on two separate requests, and one does not imply the other:

- On the mint, the tenant validates the organization against the client's organization settings while issuing the STT. An organization the client is not allowed to use fails at that call, instead of the STT being issued without it.
- On the redirect, it is forwarded to the target's `/authorize` as part of a normal interactive login, the same as any other org-scoped login.

The redirect one is what scopes the session the target ends up with. Passing `organization` only on the mint gets you the validation, but it does not org-scope the target's session, so pass it on the redirect as well when you need that.

An `organization` the tenant rejects surfaces as a `TokenExchangeError`. A blank one throws `OrganizationValidationError` before the session is read or any network call is made.

> [!NOTE]
> `buildSessionTransferRedirect` attaches a single-use credential to the URL, so `targetLoginUrl` **must be a trusted, app-controlled value** and use `https` (`http` is allowed only for the loopback hosts `localhost`, `127.0.0.1`, and `[::1]`). Never derive it from untrusted input such as a `returnTo` parameter, or the token could leak to an attacker-controlled host.

The exchange is **stateless** — the STT is never written to the session or state store. Do not cache or persist it; hand it straight to the redirect and discard it.

### Target: redeeming the Session Transfer Token

On the target app, the STT is redeemed as part of a **standard interactive login** — you just forward `session_transfer_token` (and `organization`, when present) to `/authorize` via `startInteractiveLogin`'s `authorizationParams`:

```ts
// In the target app's login route, reading session_transfer_token from the query string:
const url = await serverClient.startInteractiveLogin(
  {
    authorizationParams: {
      session_transfer_token: sessionTransferToken,
      organization, // only when the STT was issued in an organization context
    },
  },
  storeOptions
);

// Redirect the browser to `url`; the callback completes with a standard authorization-code login.
```

> [!NOTE]
> The `session_transfer_token` is redeemed as a **query** parameter, so the redeeming client's `session_transfer.allowed_authentication_methods` must include `"query"`. The established session is short-lived (hard-capped at 2 hours) and **cannot mint a refresh token** — to continue, re-run the whole flow. If the target needs `online_access`, set it through the SDK's `scope` configuration.

> [!NOTE]
> Because the STT travels as a query parameter, it can land in places that log or retain full URLs — web-server access logs, proxy/CDN logs, and the browser's history. This is inherent to the redemption mechanism and is mitigated by the token being **single-use and short-lived (~60s)** and, when configured, **device-bound** (`enforce_device_binding`): a leaked STT is worthless once redeemed or expired. Even so, avoid logging redemption URLs verbatim, and never persist or forward the STT beyond the immediate redirect.

### Reading the `act` claim on the impersonation session

Once the target session is established, the acting agent is available as the `act` claim on the session user — read it through the existing session surface to drive UI such as an impersonation banner:

```ts
const session = await serverClient.getSession(storeOptions);
const actor = session?.user?.act; // { sub: 'support-agent-007', ... } when impersonated
```

## Passwordless Authentication

The server client exposes passwordless as session-aware methods around the Authentication API. The surface mirrors `@auth0/nextjs-auth0` (`passwordless.start()` / `passwordless.verify()`): `startPasswordless` sends the code or link; `completePasswordless` exchanges the one-time code and persists the resulting session to the configured state store (no redirect, no PKCE). Both methods are discriminated on `connection` (`'email' | 'sms'`).

> [!IMPORTANT]
> Your Auth0 application must have the **Passwordless OTP** grant enabled, with the Email and/or SMS connection configured. See the [Auth0 Passwordless documentation](https://auth0.com/docs/authenticate/passwordless).

### Starting a Passwordless Login

```ts
// Email — one-time code (default)
await serverClient.startPasswordless({ connection: 'email', email: 'user@example.com', send: 'code' });

// Email — magic link (see "Completing a Magic-Link Login" below)
await serverClient.startPasswordless({
  connection: 'email',
  email: 'user@example.com',
  send: 'link',
  redirectUri: 'https://my-app.example.com/auth/callback',
  scope: 'openid profile',
});

// SMS — one-time code (E.164 phone)
await serverClient.startPasswordless({ connection: 'sms', phoneNumber: '+14155550100' });
```

An optional `language` (BCP-47 tag, e.g. `'fr-CA'`) is forwarded as the `x-request-language` header to localize the email/SMS template.

### Completing a Passwordless Login

`completePasswordless` exchanges the `verificationCode` and establishes a session. The `openid` scope is always ensured by the server layer.

```ts
await serverClient.completePasswordless({
  connection: 'email',
  email: 'user@example.com',
  verificationCode: '123456',
  authorizationParams: { scope: 'openid profile' },
});

// The user is now logged in; getUser() / getAccessToken() work as usual.
const accessToken = await serverClient.getAccessToken();
```

```ts
await serverClient.completePasswordless({
  connection: 'sms',
  phoneNumber: '+14155550100',
  verificationCode: '123456',
});
```

A `PasswordlessVerifyError` is thrown for an invalid/expired/rate-limited code; an `MfaRequiredError` is thrown (and propagated unchanged) when the connection requires MFA. Both are exported from `@auth0/auth0-auth-js`.

> [!IMPORTANT]
> If your deployment performs concurrent logins for the same session identifier, use a state store with atomic (compare-and-set) writes to avoid last-write-wins races.

### Completing a Magic-Link Login

A magic link is an authorization-code flow whose first leg is delivered by email instead of a browser redirect. Send the link with `startPasswordless({ connection: 'email', send: 'link', redirectUri })`, then call `completePasswordlessMagicLink` on the callback route. The SDK generates and persists an anti-forgery `state`, validates it on return, exchanges the code **without PKCE**, and writes the session. The interactive login path (`completeInteractiveLogin`) is not used.

```ts
// 1. Send the link. The SDK owns `state`; `client_id`, `response_type`, and `state` cannot be overridden.
await serverClient.startPasswordless(
  {
    connection: 'email',
    send: 'link',
    email: 'user@example.com',
    redirectUri: 'https://app.example.com/auth/callback',
    scope: 'openid profile',
  },
  storeOptions
);

// 2. On GET /auth/callback?code=...&state=..., complete the login.
const result = await serverClient.completePasswordlessMagicLink(
  new URL(req.url, 'https://app.example.com'),
  storeOptions
);

// The user is now logged in; getUser() / getAccessToken() work as usual.
```

`completePasswordlessMagicLink` throws `MissingTransactionError` when no start transaction is found, and `PasswordlessVerifyError` when the returned `state` is missing or does not match the persisted `state`.

> [!IMPORTANT]
> Server-side completion requires the tenant setting `allow_magiclink_verify_without_session: true`. Without it, the click fails with "The link must be opened on the same device and browser." The callback URL passed as `redirectUri` must be registered on the application.
>
> This setting is nested under `universal_login.passwordless` (NOT a top-level `flags` entry; sending it under `flags` returns `400 Additional properties not allowed`):
>
> ```bash
> auth0 api patch tenants/settings \
>   --data '{"universal_login":{"passwordless":{"allow_magiclink_verify_without_session":true}}}'
> ```

### Passing `StoreOptions`

Like other methods, all passwordless methods accept a second argument forwarded to the configured stores (and to the domain resolver in [Resolver Mode](#resolver-mode)):

```ts
const storeOptions = {
  /* ... */
};
await serverClient.completePasswordless(
  { connection: 'email', email: 'user@example.com', verificationCode: '123456' },
  storeOptions
);
```

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

## Accessing the full HTTP response

When you need access to the raw HTTP response from the token endpoint (for example, to inspect custom headers, rate-limit headers, or debug unexpected behavior), you can pass `fullResponse: true` to any of the six server-js token methods:

- `getAccessToken`
- `loginBackchannel`
- `completePasswordless`
- `getAccessTokenForConnection`
- `loginWithCustomTokenExchange`
- `customTokenExchange`

Instead of returning the bare token data, the method returns an `ApiResponse<T>` envelope with two fields:

- `data`: The token set or result object you would normally receive.
- `response`: The raw `Response` object from the token endpoint, including `status`, `headers`, and `ok`.

Here is an example using `getAccessToken`:

```ts
const result = await serverClient.getAccessToken({ fullResponse: true }, storeOptions);

// Access the token set
console.log(result.data.accessToken);

// Inspect the raw HTTP response
console.log(result.response.status); // e.g., 200
console.log(result.response.headers.get('x-ratelimit-remaining')); // custom header from Auth0
console.log(result.response.ok); // true if 2xx
```

You can also combine `fullResponse` with other options like `audience` or `scope`:

```ts
const result = await serverClient.getAccessToken({
  audience: 'https://api.example.com',
  scope: 'read:users',
  fullResponse: true,
}, storeOptions);
```

### Performance consideration: cache bypass

When `fullResponse: true` is set, the SDK **always** calls the token endpoint, even if a valid cached token exists. This is necessary because the `Response` object can only be produced by a live HTTP call. A cache hit returns no `Response`, so the SDK bypasses the cache and issues a refresh-token exchange.

This means passing `fullResponse: true` on every call to `getAccessToken()` forces a network round-trip per request, which can impact performance. Use it only when you truly need the response metadata, not as the default pattern for retrieving tokens.

### TypeScript usage note

Pass `fullResponse: true` as a literal value, not a variable. If you use object spread to build the options, explicitly annotate `fullResponse` with `as const` to preserve the literal type:

```ts
// ✅ Correct: literal true
const result = await serverClient.getAccessToken({ fullResponse: true });

// ✅ Correct: as const preserves the literal type
const options = { audience: 'https://api.example.com', fullResponse: true as const };
const result = await serverClient.getAccessToken(options);

// ❌ Wrong: spreads widen `true` to `boolean`, overload resolution fails
const baseOpts = { audience: 'https://api.example.com' };
const result = await serverClient.getAccessToken({ ...baseOpts, fullResponse: true }); // returns TokenSet, not ApiResponse
```

If the wrong overload is selected at compile time (because `fullResponse` widened to `boolean`), you will see a TypeScript error when trying to access `result.response`, or your code will assume `result` is a `TokenSet` when it should be an `ApiResponse<TokenSet>`.

## Session expiry from upstream IdP (IPSIE `session_expiry`)

When you use an Okta or OIDC **enterprise connection** configured with `id_token_session_expiry_supported: true`, Auth0 includes a `session_expiry` claim in the ID token it issues to your application. This claim is an absolute Unix timestamp (seconds) that marks the latest moment the upstream identity provider considers the session valid. It is computed by Auth0 as the earliest of: your tenant's absolute session lifetime, the upstream IdP's own session expiry, and any value an Action sets via `api.session.setExpiresAt`.

### What the SDK does automatically

No configuration or code change is required. When the claim is present, the SDK:

- persists it on the session as a top-level `sessionExpiresAt` (Unix seconds);
- treats the session as expired once `sessionExpiresAt` is reached (with a small 30-second leeway for clock skew), on **every** `getSession()` / `getUser()` / `getAccessToken()` call;
- never refreshes a token once the ceiling has passed; and
- caps the session cookie lifetime at the ceiling as a defense-in-depth backstop.

`getAccessTokenForConnection()` is **not** capped by the ceiling: connection (Token Vault) tokens are the upstream IdP's own tokens, governed by that IdP's `expires_in` rather than the Auth0 session, so they keep working past the ceiling.

This is layered **on top of** your existing idle and absolute session timeouts — it does not replace them. The session ends at whichever limit is reached first.

### Behavior on expiry

- `getSession()` and `getUser()` return `undefined` (the session is also cleared from the store). Your existing "not logged in → redirect to login" path runs unchanged.
- `getAccessToken()` throws `SessionExpiredError` (`error.code === 'session_expired'`) — as do `startLinkUser()` and `startUnlinkUser()`. Catch it and send the user to log in again. (`getAccessTokenForConnection()` does not throw on the ceiling; see the note above.)

```ts
import { SessionExpiredError } from '@auth0/auth0-server-js';

try {
  const { accessToken } = await serverClient.getAccessToken(storeOptions);
  // use accessToken
} catch (error) {
  if (error instanceof SessionExpiredError) {
    return redirect(await serverClient.startInteractiveLogin({ authorizationParams: { prompt: 'login' } }, storeOptions));
  }
  throw error;
}
```

### Reading the value (optional)

To show a "your session ends soon" prompt, read the ceiling off the session:

```ts
const session = await serverClient.getSession(storeOptions);
if (session?.sessionExpiresAt) {
  const remainingSeconds = session.sessionExpiresAt - Math.floor(Date.now() / 1000);
  // e.g. show a banner when remainingSeconds < 5 * 60
}
```

Do not copy `sessionExpiresAt` into a separate long-lived store and trust it later — always re-read it relative to the current wall clock.

### Upgrading existing apps

Once an enterprise connection has the option enabled, `getSession()` / `getUser()` can return `undefined` for a user who was previously logged in, once the ceiling is reached. If your code assumed these always return a value after login, add a null check. Sessions created before the upgrade (or through connections without the option) have no `sessionExpiresAt` and behave exactly as before.

### Prerequisites

- The connection must be an `okta` or `oidc` enterprise connection with `id_token_session_expiry_supported: true` (Dashboard toggle "Use ID Token for Session Expiry", Management API, or Terraform).
- Authorization Code flow.

## Revoking a Refresh Token

Revoking a refresh token invalidates it at Auth0 so it can no longer be used to obtain new access tokens.
This is useful when implementing secure logout flows or when a user's session needs to be forcibly terminated.

Revocation requires the application to have been granted `offline_access` scope so Auth0 issues a refresh token, and the target API must have **Allow Offline Access** enabled.

> **Note:** Revocation does not affect access tokens that have already been issued. They remain valid until their expiry. For immediate session termination, combine revocation with `logout()`.

### Revoking the session token

When called without arguments, `revokeRefreshToken()` reads the refresh token directly from the current session:

```ts
await serverClient.revokeRefreshToken();
```

If no session exists or the session has no refresh token, a `MissingSessionError` is thrown.

### Revoking an explicit token

A specific token can be passed via `options.token`, bypassing the session lookup:

```ts
await serverClient.revokeRefreshToken({ token: '<refresh_token>' });
```

In resolver mode, the domain-match guard still applies even when a token is supplied explicitly. If the session domain does not match the domain resolved for the current request (or if the session has no stored domain), the call returns without revoking. Pass an empty string to `options.token` to get a `MissingRequiredArgumentError` rather than a silent no-op.

### Revoking on logout

`logout()` automatically revokes the session's refresh token before clearing the local session.
Revocation is best-effort: if it fails for any reason (network error, token already revoked, misconfiguration), logout still proceeds. In resolver mode, both revocation and local session deletion only occur when the stored session domain matches the resolved domain — if they differ, the session belongs to a different tenant and is left untouched.

```ts
const logoutUrl = await serverClient.logout({
  returnTo: 'http://localhost:3000',
});
// Redirect user to logoutUrl
```

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

## Enterprise Connect

> [!NOTE]
> Enterprise Connect is in **Early Access**. To enable it for your tenant, contact Auth0 support.

Enterprise Connect (EC) is an SSO relay mode for B2B applications. Auth0 acts as a pure federation layer — it redirects the user to the enterprise IdP, exchanges the resulting assertion for OIDC tokens, and returns. Auth0 writes no session. Your app owns its session entirely.

Setting `enterpriseConnect: true` on `ServerClient` switches the SDK into EC mode:

- A `NullStateStore` is installed internally — no Auth0 session is ever written.
- `getSession`, `getUser`, `getAccessToken`, and other session-dependent methods throw `EnterpriseConnectNotSupportedError` at call time.
- `startEnterpriseLogin` performs WebFinger domain discovery and returns a `URL | null`.
- `completeInteractiveLogin` returns `{ user, idTokenClaims, appState, authorizationDetails }` with raw OIDC claims; it does not persist anything.

> [!NOTE]
> Enterprise Connect requires a B2B Integration application on an Auth0 tenant with Enterprise Connect enabled. Use the **B2B Integration** client credentials (`AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`), not a regular web application client.

```ts
import { ServerClient, CookieTransactionStore } from '@auth0/auth0-server-js';

const auth0 = new ServerClient({
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  enterpriseConnect: true,
  authorizationParams: {
    redirect_uri: `${process.env.APP_BASE_URL}/auth/callback`,
    scope: 'openid profile email',
  },
  transactionStore: new CookieTransactionStore(
    { secret: process.env.AUTH0_SESSION_SECRET! },
    new ExpressCookieHandler()
  ),
});
```

> [!NOTE]
> Do **not** include `offline_access` in scope — there is no refresh token in EC mode and `getAccessToken` is blocked. See [Token Expiry](#enterprise-connect-token-expiry) for details.

### Domain Discovery {#enterprise-connect-domain-discovery}

`startEnterpriseLogin` combines WebFinger discovery with authorization initiation. It returns a `URL` to redirect to if the domain is federated, or `null` if not:

```ts
app.post('/login', async (req, res, next) => {
  try {
    const { email } = req.body;

    const authUrl = await auth0.startEnterpriseLogin(
      { email, returnTo: '/dashboard' },
      { request: req, response: res }
    );

    if (authUrl) {
      return res.redirect(authUrl.href);
    }

    // Domain is not federated — redirect to your existing login route
    res.redirect('/login?mode=password');
  } catch (err) {
    next(err);
  }
});
```

To check federation without initiating login (e.g. to conditionally render UI), use `isFederatedDomain` directly:

```ts
import { isFederatedDomain } from '@auth0/auth0-server-js';

const email = String(req.query.email ?? '');
const domain = email.split('@')[1];
const federated = await isFederatedDomain(process.env.AUTH0_DOMAIN!, domain);
```

> [!NOTE]
> `isFederatedDomain` is a routing hint, not a security control. Always validate the returned ID token and `org_id` claim after the Auth0 callback.

### Handling the Callback {#enterprise-connect-callback}

`completeInteractiveLogin` exchanges the authorization code for tokens and returns the ID token claims. In EC mode it does **not** write to any state store:

```ts
app.get('/auth/callback', async (req, res, next) => {
  try {
    const result = await auth0.completeInteractiveLogin(
      new URL(req.url, process.env.APP_BASE_URL),
      { request: req, response: res }
    );

    const user = result.user;
    if (!user) {
      return res.redirect('/login?error=no-session');
    }

    // Optional: validate org_id against an allowlist before trusting it.
    // if (user['org_id'] !== expectedOrgId) throw new Error('Unexpected organization');

    await setAppSession(res, {
      sub: user.sub,
      email: user.email,
      orgId: user['org_id'] ?? '',
      name: user.name,
    });

    const returnTo = result.appState?.returnTo ?? '/';
    res.redirect(returnTo);
  } catch (err) {
    next(err);
  }
});
```

### App-Owned Session {#enterprise-connect-session}

In EC mode Auth0 writes no session. The following pattern signs the session payload with HMAC-SHA256 and stores it in an `httpOnly` cookie. Replace it with any session mechanism your app already has.

```ts
const enc = new TextEncoder();
const key = () =>
  crypto.subtle.importKey(
    'raw',
    enc.encode(process.env.AUTH0_SESSION_SECRET!),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

async function getAppSession(req: Request) {
  const raw = req.cookies['app_session'];
  if (!raw) return null;
  const [body, signature] = raw.split('.');
  if (!body || !signature) return null;
  try {
    const valid = await crypto.subtle.verify(
      'HMAC',
      await key(),
      Buffer.from(signature, 'base64url'),
      enc.encode(body)
    );
    return valid ? JSON.parse(Buffer.from(body, 'base64url').toString()) : null;
  } catch {
    return null;
  }
}

async function setAppSession(res: Response, session: object) {
  const body = Buffer.from(JSON.stringify(session)).toString('base64url');
  const signature = Buffer.from(
    await crypto.subtle.sign('HMAC', await key(), enc.encode(body))
  ).toString('base64url');
  res.cookie('app_session', `${body}.${signature}`, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });
}
```

### Protecting Routes {#enterprise-connect-protecting-routes}

`auth0.getUser()` and `auth0.getSession()` throw in EC mode. Read from your own session cookie instead:

```ts
async function requireSession(req: Request, res: Response, next: NextFunction) {
  const session = await getAppSession(req);
  if (!session) return res.redirect('/login');
  (req as any).appUser = session;
  next();
}

app.get('/dashboard', requireSession, (req, res) => {
  const user = (req as any).appUser;
  const safeEmail = String(user.email).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  res.send(`Welcome, ${safeEmail}`);
});
```

### Logout {#enterprise-connect-logout}

Clear your own session cookie and redirect through Auth0's logout with `federated: true` to also terminate the enterprise IdP session:

```ts
app.get('/auth/logout', async (req, res, next) => {
  try {
    res.clearCookie('app_session', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });

    const logoutUrl = await auth0.logout(
      { returnTo: `${process.env.APP_BASE_URL}/login`, federated: true },
      { request: req, response: res }
    );

    res.redirect(logoutUrl.href);
  } catch (err) {
    next(err);
  }
});
```

> [!WARNING]
> Without `federated: true`, the enterprise IdP session stays active. The next call to `startEnterpriseLogin` for the same user may silently re-authenticate them without a prompt.

### Back-Channel Logout {#enterprise-connect-back-channel-logout}

`handleBackchannelLogout` is a no-op in EC mode: there is no Auth0 session to delete, so the method completes successfully without side effects. The IdP receives a successful response:

```ts
app.post('/auth/backchannel-logout', async (req, res, next) => {
  try {
    await auth0.handleBackchannelLogout(req.body.logout_token, storeOptions);
    // Optionally: clear the app session by sub/sid from the logout token claims
    res.sendStatus(200);
  } catch (err) {
    next(err);
  }
});
```

### Token Expiry {#enterprise-connect-token-expiry}

> [!WARNING]
> The access token issued in EC mode expires at its default TTL (typically 24 hours) with **no renewal path**. `getAccessToken` is blocked in EC mode — there is no refresh token and no silent re-authentication. Do not pass the Auth0 access token to your APIs; it will expire and cannot be refreshed. Issue your own tokens from the ID token claims returned by `completeInteractiveLogin` instead.

### EC for Identity Only {#enterprise-connect-identity-only}

Enterprise Connect is designed for **identity only**: use it to establish who the user is, then issue your app's own tokens for downstream API authorization.

```ts
// In the callback: extract only the identity claims you need
const appSession = {
  sub: user.sub,           // stable user identifier
  email: user.email,
  orgId: user['org_id'],   // organization the user authenticated into
  name: user.name,
};

// Issue your own token (e.g. a JWT signed with your own key) for API calls.
// Do NOT forward the Auth0 access token — it will expire and cannot be renewed.
```

### Allowed Logout URLs {#enterprise-connect-allowed-logout-urls}

> [!IMPORTANT]
> The `returnTo` URL passed to `auth0.logout()` must be registered in the Auth0 Dashboard under **Applications → [Your B2B Integration] → Allowed Logout URLs**. Without this registration, Auth0 rejects the post-logout redirect and the user lands on an Auth0 error page.

### Blocked Methods {#enterprise-connect-blocked-methods}

The following methods throw `EnterpriseConnectNotSupportedError` in EC mode:

| Method / Getter | Reason |
|-----------------|--------|
| `getSession` | No Auth0 session is written |
| `getUser` | No Auth0 session is written |
| `getAccessToken` | No refresh token; token cannot be renewed |
| `getAccessTokenForConnection` | Requires a session |
| `revokeRefreshToken` | No refresh token issued |
| `loginWithCustomTokenExchange` | Session-dependent |
| `requestSessionTransferToken` | Session-dependent |
| `buildSessionTransferRedirect` | Session-dependent |
| `startLinkUser` / `completeLinkUser` | Session-dependent |
| `startUnlinkUser` / `completeUnlinkUser` | Session-dependent |
| `loginBackchannel` | Session-dependent |
| `startPasswordless` / `completePasswordless` | Session-dependent |
| `completePasswordlessMagicLink` | Session-dependent |
| `mfa` (getter) | Session-dependent sub-client |
| `passkey` (getter) | Session-dependent sub-client |
| `database` (getter) | Session-dependent sub-client |

```ts
import { EnterpriseConnectNotSupportedError } from '@auth0/auth0-server-js';

try {
  await auth0.getSession(storeOptions);
} catch (err) {
  if (err instanceof EnterpriseConnectNotSupportedError) {
    // err.code === 'enterprise_connect_not_supported'
    console.error('Not available in Enterprise Connect mode:', err.message);
  }
}
```

## Per-Request Options

Most network-performing methods on `ServerClient` accept an optional trailing `RequestOptions` argument. It applies to that single call only and never mutates the client's shared configuration, so it is safe to use across concurrent requests. The type is re-exported from `@auth0/auth0-server-js`, so you do not need to depend on `@auth0/auth0-auth-js` to reference it. For methods that do not expose this parameter, see [Methods that do not accept `RequestOptions`](#methods-that-do-not-accept-requestoptions) below.

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

`requestOptions` is orthogonal to the client-level `customFetch`: the client-level one is baked in when the `ServerClient` is constructed and applies to every call, while `requestOptions` is composed on top of it for a single call.

### Argument shape

`requestOptions` is a **trailing positional** parameter that comes *after* `storeOptions`. If you want per-request options but have no store options to pass, pass `undefined` as the placeholder:

```ts
const controller = new AbortController();

// storeOptions and requestOptions
await serverClient.getAccessTokenForConnection(
  { connection: 'google-oauth2' },
  storeOptions,
  { signal: controller.signal }
);

// requestOptions only — `undefined` holds the storeOptions slot
await serverClient.getAccessTokenForConnection(
  { connection: 'google-oauth2' },
  undefined,
  { signal: controller.signal }
);
```

The methods on `ServerClient` that accept it, all in the `(…, storeOptions?, requestOptions?)` shape:

| Method | `requestOptions` reaches |
|--------|--------------------------|
| `completeInteractiveLogin` | The code-for-token exchange |
| `completeLinkUser` / `completeUnlinkUser` | The code-for-token exchange (both delegate to `completeInteractiveLogin`) |
| `loginBackchannel` | The backchannel authorize + token polling |
| `startPasswordless` | The `/passwordless/start` request (email or SMS) |
| `completePasswordless` | The passwordless token request |
| `completePasswordlessMagicLink` | The magic-link code exchange |
| `getAccessToken` | The refresh-token exchange, on a cache miss only |
| `getAccessTokenForConnection` | The Token Vault exchange, on a cache miss only |
| `revokeRefreshToken` | The token revocation request |
| `logout` | The token revocation only |
| `loginWithCustomTokenExchange` / `customTokenExchange` | The RFC 8693 token exchange |
| `requestSessionTransferToken` | The Session Transfer Token exchange |

> **Note:** `getAccessToken` exposes `requestOptions` on its options-form overload only — `getAccessToken(options, storeOptions?, requestOptions?)`. The legacy store-options-only overload, `getAccessToken(storeOptions?)`, is slated for removal in the next major and was not extended, so `getAccessToken(undefined, { signal })` does not compile. Use the options form.

### Cancelling a request

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000);

const tokenSet = await serverClient.getAccessToken(
  { audience: 'https://api.example.com' },
  storeOptions,
  { signal: controller.signal }
);
```

### Passing per-request headers

```ts
await serverClient.revokeRefreshToken({}, storeOptions, { headers: { 'X-Request-Id': requestId } });
```

Reserved headers set by the SDK win: a caller-supplied `Authorization` header is ignored, and the telemetry `Auth0-Client` header is always sent.

### Using a one-off fetch

```ts
await serverClient.completeInteractiveLogin(callbackUrl, storeOptions, { customFetch: myInstrumentedFetch });
```

The per-request fetch replaces the transport for that call only. It is re-wrapped internally with the telemetry wrapper, so the `Auth0-Client` header is still sent. It does **not** inherit mTLS — if you rely on mTLS, the fetch you supply must itself be mTLS-capable.

### Cache hits are a no-op

`getAccessToken` and `getAccessTokenForConnection` return the cached token set from the state store when it has not expired, before any network call is made. On that path there is nothing for `requestOptions` to apply to, so `signal`, `headers` and `customFetch` are all silently ignored:

```ts
const controller = new AbortController();
controller.abort();

// Resolves with the cached token; the aborted signal never comes into play.
const tokenSet = await serverClient.getAccessToken({}, storeOptions, { signal: controller.signal });
```

This matters most for cancellation: if a caller passes a `signal` expecting to bound the total time of `getAccessToken`, a cache hit will complete regardless. Only the cache-miss refresh honours it.

### `logout()` applies `RequestOptions` to revocation only

`logout()` does two things: it revokes the session's refresh token (best-effort), then it builds the Auth0 logout URL. Only the first is a network call, so `requestOptions` is forwarded to the revocation and nothing else. Building the logout URL is local string work and issues no request, so a `signal` cannot cancel it and per-request `headers` have nothing to attach to.

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 2000);

// The signal bounds the revocation attempt. The returned URL is built either way,
// because revocation is best-effort and its failure must not block logout.
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' }, storeOptions, {
  signal: controller.signal,
});
```

### Sub-client argument shapes

The `database`, `passkey` and `mfa` sub-clients accept `requestOptions` too, but their argument shapes are not all the same. The three MFA methods that never touch the state store take `requestOptions` as their *second* argument, because they have no `storeOptions` to take:

| Method | Shape |
|--------|-------|
| `mfa.listAuthenticators` | `(options, requestOptions?)` |
| `mfa.enrollAuthenticator` | `(options, requestOptions?)` |
| `mfa.challengeAuthenticator` | `(options, requestOptions?)` |
| `mfa.verify` | `(options, storeOptions?, requestOptions?)` |
| `passkey.startSignup` | `(options, storeOptions?, requestOptions?)` |
| `passkey.startLogin` | `(options?, storeOptions?, requestOptions?)` |
| `passkey.complete` | `(options, storeOptions?, requestOptions?)` |
| `passkey.register` | `(options, storeOptions?, requestOptions?)` |
| `passkey.challenge` | `(options?, storeOptions?, requestOptions?)` |
| `passkey.getToken` | `(options, storeOptions?, requestOptions?)` |
| `database.signUp` | `(options, storeOptions?, requestOptions?)` |
| `database.changePassword` | `(options, storeOptions?, requestOptions?)` |

So `requestOptions` is the last argument everywhere, matching `ServerClient`'s own methods, but its position shifts:

```ts
// Second argument: no storeOptions on this method.
await serverClient.mfa.challengeAuthenticator(
  { mfaToken, challengeType: 'otp' },
  { signal: controller.signal }
);

// Third argument: mfa.verify writes the session, so it takes storeOptions.
await serverClient.mfa.verify(
  { mfaToken, factorType: 'otp', otp: '123456' },
  storeOptions,
  { signal: controller.signal }
);

// Third argument, with `undefined` for storeOptions.
await serverClient.database.signUp(
  { email: 'user@example.com', password: 'a-Str0ng-Password!', connection: 'Username-Password-Authentication' },
  undefined,
  { signal: controller.signal }
);
```

This mirrors `@auth0/auth0-auth-js`, where the same three MFA methods take `(options, requestOptions?)`. The asymmetry is intentional: a `storeOptions` parameter on a method that neither reads nor writes the store would be dead weight.

### Methods that do not accept `RequestOptions`

- `getUser` and `getSession` are pure reads from the state store and make no network call, so `requestOptions` would have no effect. `getUser` is called out here on purpose: upstream migration notes group it with `getAccessToken`, `getAccessTokenForConnection` and `revokeRefreshToken`, so it is a reasonable place to come looking. Those three are threaded; `getUser` is deliberately excluded, because adding a parameter that can never do anything costs the public surface more than the asymmetry does.
- `startInteractiveLogin`, `startLinkUser` and `startUnlinkUser` build a redirect URL through the underlying auth-js URL builders, which do not accept `RequestOptions`. (They may still trigger a one-time OIDC discovery fetch on a cold cache.)
- `buildSessionTransferRedirect` is a pure URL builder and performs no request at all.
- `handleBackchannelLogout` is excluded because the auth-js method it delegates to, `verifyLogoutToken`, takes no `requestOptions`. Its JWKS fetch therefore always uses the client's configured `customFetch` and cannot be given a per-request `signal`. A future auth-js minor may close this gap.
