# Examples

- [Configuration](#configuration)
  - [Configuring the Store](#configuring-the-store)
    - [Stateless Store](#stateless-store)
    - [Stateful Store](#stateful-store)
    - [Writing a session store](#writing-a-session-store)
  - [Configuring Cookies Secret Rotation](#configuring-cookies-secret-rotation)
  - [Configuring the Store Identifier](#configuring-the-store-identifier)
  - [Configuring the Scopes](#configuring-the-scopes)
  - [Configuring PrivateKeyJwt](#configuring-privatekeyjwt)
  - [Configuring mTLS (Mutual TLS)](#configuring-mtls-mutual-tls)
  - [Configuring the `authorizationParams` globally](#configuring-the-authorizationparams-globally)
  - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
  - [Configuring a request time limit](#configuring-a-request-time-limit)
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
- [Starting Interactive Login](#starting-interactive-login)
  - [Passing `authorizationParams`](#passing-authorization-params)
  - [Requiring a recent login with `max_age`](#requiring-a-recent-login-with-max_age)
  - [Passing `appState` to track state during login](#passing-appstate-to-track-state-during-login)
  - [Logging in to an Organization](#logging-in-to-an-organization)
  - [Using Experiment Center](#using-experiment-center)
  - [Using Pushed Authorization Requests](#using-pushed-authorization-requests)
  - [Using Pushed Authorization Requests and Rich Authorization Requests](#using-pushed-authorization-requests-and-rich-authorization-requests)
  - [Passing `StoreOptions`](#passing-storeoptions)
- [Completing Interactive Login](#completing-interactive-login)
  - [Logging in again without logging out](#logging-in-again-without-logging-out)
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
  - [Forcing a refresh](#forcing-a-refresh)
  - [Refreshing before expiry](#refreshing-before-expiry)
  - [Choosing the authorization scheme](#choosing-the-authorization-scheme)
  - [Updating the session after a refresh](#updating-the-session-after-a-refresh)
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
  - [Skipping the logout confirmation prompt](#skipping-the-logout-confirmation-prompt)
  - [Passing `state`](#passing-state)
  - [Choosing the logout endpoint](#choosing-the-logout-endpoint)
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

#### Writing a session store

With `StatefulStateStore`, the SDK keeps only a session ID in an encrypted cookie. Your store holds the session data. It implements the `SessionStore` interface and is passed as the `store` option. The `update` method is optional.

```ts
import {
  ServerClient,
  StatefulStateStore,
  type LogoutTokenClaims,
  type SessionStore,
  type StateData,
} from '@auth0/auth0-server-js';
import { Pool } from 'pg';

class PostgresSessionStore implements SessionStore<StoreOptions> {
  constructor(private readonly pool: Pool) {}

  async get(identifier: string): Promise<StateData | undefined> {
    const result = await this.pool.query('SELECT data FROM sessions WHERE id = $1', [identifier]);
    return result.rows[0]?.data;
  }

  async set(identifier: string, stateData: StateData): Promise<void> {
    await this.pool.query(
      'INSERT INTO sessions (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data',
      [identifier, JSON.stringify(stateData)]
    );
  }

  // One conditional write: it never creates a row.
  async update(identifier: string, stateData: StateData): Promise<boolean> {
    const result = await this.pool.query('UPDATE sessions SET data = $2 WHERE id = $1', [
      identifier,
      JSON.stringify(stateData),
    ]);
    return (result.rowCount ?? 0) > 0;
  }

  async delete(identifier: string): Promise<void> {
    await this.pool.query('DELETE FROM sessions WHERE id = $1', [identifier]);
  }

  async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
    await this.pool.query("DELETE FROM sessions WHERE data->'internal'->>'sid' = $1", [claims.sid]);
  }
}

const pool = new Pool();

const auth0 = new ServerClient<StoreOptions>({
  // ...
  stateStore: new StatefulStateStore(
    { secret: options.secret, store: new PostgresSessionStore(pool) },
    new FastifyCookieHandler()
  ),
});
```

A session save can run at the same time as a logout, for example from another browser tab. If the save writes the row again after the logout, the user is logged in again.

The SDK calls `update` only when it saves an existing session, for example after it refreshes tokens in `getAccessToken()`. A new login always uses `set` with a fresh session ID.

- **With `update`:** Write the data in one conditional statement, not as a `get` followed by a `set`. The write must only change an existing row. It resolves `true` if the row was updated and `false` if there was no row. When it resolves `false`, the SDK skips both the row write and the cookie write, so the logout holds. The tokens are still returned to the caller. Only the save is skipped.
- **Without `update`:** The SDK calls `get`, then writes with `set` only if the row is still there. These two calls are not atomic, so a logout that lands between them can still be undone. Only `update` closes that gap.

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

### Configuring a request time limit

Set `httpTimeout` to put a time limit, in milliseconds, on each HTTP request the SDK makes to Auth0. A request that takes longer is aborted, and the method that made it rejects the same way as when a per-request `signal` aborts it.

```ts
const serverClient = new ServerClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  httpTimeout: 10_000, // 10 seconds
  // ...stores and other options
});
```

How it works:
- It covers every request the SDK makes: discovery, the token endpoint (login, refresh, token exchange) and the other Auth0 APIs, the JWKS fetch used to verify logout tokens, and the Enterprise Connect domain lookup. Requests made through `customFetch` are covered too. It works the same in static-domain and resolver mode.
- It applies to each request on its own, not to a whole method call. A method that makes more than one request (for example discovery and then the token request, or a DPoP nonce retry) gives each request the full limit.
- It works alongside a per-request `signal`: the request is aborted when either one fires.
- It is not applied to a request made with a per-request `customFetch`, which replaces the SDK's fetch for that call.
- When it is not set, the SDK adds no limit. The underlying libraries keep their own limits: openid-client puts a default limit of 30 seconds on its requests (on all of them from openid-client 6.8.8, before that only on discovery), and jose puts 5 seconds on the JWKS fetch. The other requests have no limit. When it is set, it replaces those limits, so it can be shorter or longer than them.
- In Enterprise Connect, a domain lookup that takes longer than the limit counts as not federated, so `startEnterpriseLogin` returns `null`.
- It must be a positive integer; anything else throws an `InvalidConfigurationError` when the client is created.

For framework SDK authors: the rule and the wrapper are exported, so an SDK built on this one can validate its own `httpTimeout` setting the same way and put the same limit on requests it makes itself. Policy, such as a default or a minimum, stays in your SDK.

```ts
import { ServerClient, createTimeoutFetch, isValidHttpTimeout } from '@auth0/auth0-server-js';

// Validate your own setting with the same rule, and raise your own error type.
if (config.httpTimeout !== undefined && !isValidHttpTimeout(config.httpTimeout)) {
  throw new MyConfigError('httpTimeout must be a positive integer (milliseconds)');
}

const client = new ServerClient({ /* ... */ httpTimeout: config.httpTimeout });

// For requests your SDK makes itself:
const limitedFetch = config.httpTimeout === undefined ? fetch : createTimeoutFetch(fetch, config.httpTimeout);
```

`createTimeoutFetch` throws a `TypeError` if the limit is not valid.

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

// With a hint, Auth0 ends the session without asking the user. In a production app, only let the user trigger this route.
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

### Requiring a recent login with `max_age`

Set `max_age`, in seconds, in `authorizationParams` to make Auth0 ask the user to log in again when their last login is older:

```ts
await serverClient.startInteractiveLogin({ authorizationParams: { max_age: 300 } });
```

The SDK keeps the value with the login and checks it in `completeInteractiveLogin()`: the ID token must have an `auth_time` claim that is no older than `max_age` seconds. Otherwise `completeInteractiveLogin()` throws a `TokenByCodeError` and no session is saved. A value passed to `startInteractiveLogin()` wins over the one in the `ServerClient` options.

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

To change the session before it is saved, pass a `beforeSessionSaved` hook as the fourth argument; see [Changing the session before it is saved](#changing-the-session-before-it-is-saved).

### Logging in again without logging out

A login is a new authentication, so the session reflects the login that just happened. When a user who already has a session logs in again without logging out:

- For the same user, `user`, the session ID (`sid`) and the session start time, which `absoluteDuration` counts from, come from the new login. Tokens for other audiences are kept.
- For another organization (`org_id`), or when the user leaves an organization, the session is replaced, so tokens issued in the previous organization are not carried over.
- For another user, the session is replaced, as before.

This applies to `completeInteractiveLogin()`, `completePasswordless()`, `completePasswordlessMagicLink()`, `completePasswordlessDbConnection()`, `loginBackchannel()`, `loginWithCustomTokenExchange()`, `passkey.complete()` and `passkey.getToken()`. A token refresh with `getAccessToken()` is not a login and does not change the session ID or the session start time.

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

A passkey login is a new login. When a session already exists for the same user, `user`, `sid` and the session start time come from this login, and the tokens for other audiences are kept. A login into another organization replaces the session.

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
    // Optional: an audited reason, readable by your Action as `event.request.body.reason`.
    // Include it in `setActor(...)` in your Action for it to appear as `act.reason`.
    reason: 'Investigating TCK-4821',
    // Optional: any other custom context for your Action.
    extra: { ticketSystem: 'zendesk' },
  },
  storeOptions
);

// Build the redirect to the TARGET app's login URL (a trusted, app-controlled value).
const url = serverClient.buildSessionTransferRedirect('https://app.example.com/auth/login', result);

// Hand the URL to your framework's redirect (e.g. Fastify: reply.redirect(url.toString())).
```

> [!IMPORTANT]
> An **actor is mandatory** for an STT — that is what makes this auditable impersonation ("X acting as Y") rather than a silent takeover. If no explicit `actor` is passed and no usable session ID token can be resolved (no logged-in agent, or an expired ID token with no refresh token), the SDK throws a `TokenExchangeError` with code `actor_unavailable` **before any network call**.

The SDK checks that Auth0 actually issued a Session Transfer Token: if the response's `issued_token_type` is missing or is not `urn:auth0:params:oauth:token-type:session_transfer_token`, it throws a `TokenExchangeError` with code `unexpected_issued_token_type` rather than return another kind of token for you to put in a URL.

By default the actor is the agent session's ID token, and the SDK refreshes it automatically when it has expired and a refresh token is available. That refresh works like the one in `getAccessToken`:

- It gets the same `requestOptions` as the exchange, so `signal` cancels it and `dpopKeyPair` sends the DPoP proof a DPoP-bound refresh token needs.
- When it fails, the `actor_unavailable` error carries the server's error as `cause`. If the refresh needs MFA, `isMfaRequiredError(error)` narrows it and `error.cause.mfa_token` lets you continue with `serverClient.mfa`.
- The refreshed session runs through `beforeSessionSaved`, when you pass one, before it is saved. As with `getAccessToken`, the refresh keeps the session's `user` as it is; set it from `idTokenClaims` in the hook if you want the new claims there.

```ts
const result = await serverClient.requestSessionTransferToken(
  {
    subjectToken,
    subjectTokenType: 'urn:acme:customer-subject',
    beforeSessionSaved: (stateData, { idTokenClaims }) =>
      idTokenClaims ? { ...stateData, user: idTokenClaims as StateData['user'] } : stateData,
  },
  storeOptions,
  { dpopKeyPair }
);
```

To supply the acting party explicitly, pass `actor`. An explicit `actor` takes precedence and **the session is not read at all** — the SDK never touches the state store, so this also works where there is no logged-in agent:

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

### Changing the session before it is saved

`completeInteractiveLogin()`, `completePasswordless()`, `completePasswordlessMagicLink()`, `completePasswordlessDbConnection()`, `passkey.getToken()` and `mfa.verify()` take a fourth argument with a `beforeSessionSaved` hook. It runs once the session is built, before it is saved, and receives the session and `{ idTokenClaims, authorizationDetails }`. For `completeInteractiveLogin()` the second argument also has the `appState` of the login; the other logins have none.

- The state it returns is saved exactly as returned.
- If it throws, the error reaches you unchanged and nothing is saved: no session is written and the anonymous session is kept. The code, OTP, passkey assertion or MFA token is already spent, so the user has to start a new login.
- It is not called when the login is rejected before the session is built, for example with `SessionExpiredError`.

```ts
await serverClient.completePasswordless(
  { connection: 'email', email: 'user@example.com', verificationCode: '123456' },
  storeOptions,
  undefined, // requestOptions
  {
    // Keep only the claims the app needs in the session.
    beforeSessionSaved: (stateData, { idTokenClaims }) => ({
      ...stateData,
      user: stateData.user && { sub: stateData.user.sub, name: idTokenClaims?.name as string | undefined },
    }),
  }
);
```

## Retrieving the logged-in User

The SDK's `getUser()` can be used to retrieve the current logged-in user:

```ts
await serverClient.getUser();
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

### Forcing a refresh

Pass `refresh: true` to skip the cache and get a new access token from Auth0, even when the cached one is still valid. Use it when an API rejects the token (revoked, permissions changed), or to pick up new claims:

```ts
const tokenSet = await serverClient.getAccessToken({
  audience: 'https://api.example.com',
  refresh: true,
});
```

A refresh token is required; without one, `getAccessToken` throws `TokenByRefreshTokenError`.

### Refreshing before expiry

By default, a cached access token is served until it expires, so a token with one second left can still be returned and then fail at the API. Set `tokenRefreshBuffer` to refresh it that many seconds early:

```ts
const serverClient = new ServerClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  // Treat a cached token as expired 60 seconds before its `expiresAt`.
  tokenRefreshBuffer: 60,
  transactionStore,
  stateStore,
});
```

The buffer applies to `getAccessToken`, `getAccessTokenForConnection` and `anonymous.getAccessToken`. It defaults to `0` and must be a finite number >= 0; any other value makes the constructor throw `InvalidConfigurationError`. Keep it well below your access token lifetime, otherwise every call refreshes.

### Choosing the authorization scheme

The token set carries the `tokenType` returned by Auth0, lowercased: `'bearer'` or `'dpop'`. Use it to build the `Authorization` header, instead of assuming `Bearer`. Even with DPoP enabled, the server can decline to bind a token and return a Bearer token:

```ts
const tokenSet = await serverClient.getAccessToken({ audience: 'https://api.example.com' });

const scheme = tokenSet.tokenType?.toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer';
const headers: Record<string, string> = { Authorization: `${scheme} ${tokenSet.accessToken}` };
// For DPoP, also send a `DPoP` proof header for this request.
```

`tokenType` is `undefined` for tokens stored before this field existed, until their next refresh.

### Updating the session after a refresh

`getAccessToken` accepts a fourth argument with a `beforeSessionSaved` hook. It runs only when the SDK called Auth0 for a new token: after the new tokens are merged into the session and before it is saved. The state it returns is saved exactly as returned. It is not called when a cached token is served.

A refresh keeps the session's `user` as it is. If the refresh returned a new ID token and you want its claims in `user`, set them in the hook:

```ts
import type { StateData } from '@auth0/auth0-server-js';

const tokenSet = await serverClient.getAccessToken({}, storeOptions, undefined, {
  beforeSessionSaved: (stateData, { idTokenClaims }) =>
    // `idTokenClaims` is `undefined` when the refresh returned no ID token.
    idTokenClaims ? { ...stateData, user: idTokenClaims as StateData['user'] } : stateData,
});
```

> [!WARNING]
> If the hook throws, the error reaches the caller and nothing is saved. With refresh token rotation, Auth0 has already issued a new refresh token at that point, and it is lost. The next refresh uses the old refresh token, which Auth0 can reject, so the user may have to log in again. Avoid throwing from this hook unless you also end the session.

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
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' });
// Redirect user to logoutUrl
```

### Passing the `returnTo` parameter

When redirecting to Auth0, the user may need to be redirected back to the application. To achieve that, you can specify the `returnTo` parameter when calling `logout()`.

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' });
// Redirect user to logoutUrl
```

### Skipping the logout confirmation prompt

When [RP-Initiated Logout is enabled](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0) for your tenant, Auth0 shows a page that asks the user to confirm the logout when the request carries neither an `id_token_hint` nor a `logout_hint`. The [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specification requires this, because a logout request that cannot be tied to the user's session could come from another site. If the user cancels the page, Auth0 keeps its session, even though `logout()` has already cleared the session in your app.

To skip the page, `logout()` reads the session before it clears it and adds a hint to the returned URL. By default, that is the session's ID token, sent as `id_token_hint`:

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' });
// The URL carries `id_token_hint`, so Auth0 doesn't ask the user to confirm
```

The specification says the server should accept an expired ID token here, so the SDK doesn't refresh it first. The SDK only sends the ID token when it has a `sid` claim, which names the Auth0 session it belongs to, and was issued to your application. Not every ID token has a `sid`. Otherwise, the SDK sends the session's `sid` as `logout_hint` when it knows it. With no session, or no known `sid`, it adds no hint.

Use the `hint` option to choose what the SDK sends:

| `hint`                      | What the SDK sends                                                                                              |
| --------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `'id_token_hint'` (default) | The session's ID token as `id_token_hint`, or the session's `sid` as `logout_hint` when it can't use the token. |
| `'logout_hint'`             | The session's `sid` as `logout_hint`.                                                                           |
| `'none'`                    | No hint. Auth0 asks the user to confirm the logout.                                                             |

The SDK sends one hint at most. Any other value of `hint` sends no hint, so Auth0 keeps asking.

The ID token carries the user's profile claims and becomes part of the URL, which can end up in server and proxy logs and in the browser history. Servers and proxies also limit URL length, often to between 4 KB and 8 KB. If either is a concern, send the `sid` instead. Auth0 skips the page for it too:

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000', hint: 'logout_hint' });
// The URL carries `logout_hint` instead of `id_token_hint`
```

> [!IMPORTANT]
> With a hint, Auth0 ends its session without asking the user, so the page no longer protects the user from other sites that trigger a logout. Make sure only the user can trigger the route in your app that calls `logout()`. The safest way is a `POST` request with CSRF protection. If you keep a `GET` route, only send the hint when the `Sec-Fetch-Site` request header is `same-origin` or `none`, and set `hint` to `'none'` for every other request, so that Auth0 keeps asking. That includes `same-site` requests, which can come from subdomains of your site that you don't fully trust, and requests from browsers that don't send the header. Users in these cases still see the confirmation page. A `POST` route with CSRF protection doesn't have this limit.

For a `GET` route, for example with Fastify:

```ts
fastify.get('/auth/logout', async (request, reply) => {
  const fetchSite = request.headers['sec-fetch-site'];
  const hint = fetchSite === 'same-origin' || fetchSite === 'none' ? 'id_token_hint' : 'none';
  const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000', hint }, { request, reply });

  reply.redirect(logoutUrl.href);
});
```

> [!NOTE]
>
> - Hints are only used by the RP-Initiated Logout endpoint. For `/v2/logout`, the SDK leaves them out. Enterprise Connect keeps no session in the SDK, so it sends no hint either.
> - The SDK doesn't add a hint when the session belongs to another Auth0 domain than the logout URL, so a token is never sent to a different tenant. In resolver mode (multiple custom domains), that is the domain the request resolves to. In single domain mode, a session that records no domain is taken to belong to the configured domain.
> - If the ID token belongs to a different session than the one in the user's browser, the specification requires the server to ask the user anyway.
> - In single domain mode, a session that can't be read doesn't block the logout: the user is logged out, and Auth0 asks them to confirm. In resolver mode, a store that fails to read the session makes `logout()` throw, as it did before.
> - Code that calls `logout()` without `hint`, like a logout route built into a framework, now sends the default hint. Pass `hint: 'none'` to keep the confirmation page.

### Passing `state`

`state` is an opaque value that Auth0 sends back to `returnTo` after logout, so your app can carry data across the logout round trip:

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000', state: '<opaque_value>' });
```

Only `returnTo` has to be registered as an **Allowed Logout URL**; `state` is not checked against it. `state` is part of the URL, so don't put secrets in it.

### Choosing the logout endpoint

`strategy` picks which Auth0 logout endpoint the URL points to:

- `'auto'` (default): the tenant's `end_session_endpoint` (RP-Initiated Logout, `/oidc/logout`) when the tenant offers one, and `/v2/logout` otherwise.
- `'oidc'`: always `end_session_endpoint`. `logout()` throws a `NotSupportedError` with code `rp_initiated_logout_not_supported_error` when the tenant doesn't offer it. `logout()` has already cleared the session by then.
- `'v2'`: always `/v2/logout`, for apps whose Allowed Logout URLs are set up for it.

```ts
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000', strategy: 'v2' });
```

`/v2/logout` doesn't take hints or `state`, so the SDK leaves them out of that URL.

### Passing `StoreOptions`

Just like most methods, `logout()` accept a second argument that is used to pass to the configured Transaction and State Store:

```ts
const storeOptions = {
  /* ... */
};
const logoutUrl = await serverClient.logout({ returnTo: 'http://localhost:3000' }, storeOptions);
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
- A login whose [`session_expiry`](#session-expiry-from-upstream-idp-ipsie-session_expiry) is already in the past makes `completeInteractiveLogin` throw `SessionExpiredError`, as outside EC mode.

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

> [!NOTE]
> `domain` can also be a [domain resolver function](#dynamic-domain-resolver) when one deployment serves several Auth0 custom domains. The domain is resolved per request for WebFinger discovery, `/authorize`, and logout; the callback exchanges the code against the domain saved in the transaction. The `authClient` getter is still only available with a static domain.

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

`completeInteractiveLogin` exchanges the authorization code for tokens and returns the ID token claims. In EC mode it does **not** write to any state store.

If the ID token's `session_expiry` is already in the past, `completeInteractiveLogin` throws `SessionExpiredError` (`error.code === 'session_expired'`), because the upstream IdP session is already over. Send the user to log in again.

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

Clear your own session cookie and redirect through Auth0's logout with `federated: true` to also terminate the enterprise IdP session. Enterprise Connect doesn't keep a session in the SDK, so `logout()` doesn't add an `id_token_hint` or `logout_hint` here:

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
| `requestSessionTransferToken` | The Session Transfer Token exchange, and the refresh of an expired agent ID token used as the actor |

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

`logout()` does three things: it reads the session for the logout hint, it revokes the session's refresh token (best-effort), then it builds the Auth0 logout URL. Only the revocation is a request to Auth0, so `requestOptions` is forwarded to the revocation and nothing else. Reading the session goes to your store, and building the logout URL is local string work that issues no request, so a `signal` cannot cancel them and per-request `headers` have nothing to attach to.

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
