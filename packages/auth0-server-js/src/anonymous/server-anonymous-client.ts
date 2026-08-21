import { decodeJwt } from 'jose';
import { AnonymousSessionExpiredError, MissingAnonymousSessionError } from '../errors.js';
import { compareScopes } from '../utils.js';
import type {
  CreateAnonymousSessionOptions,
  GetAnonymousAccessTokenOptions,
  ServerAnonymousClientOptions,
} from './types.js';
import type { AnonymousSessionData, AnonymousStateData, AnonymousTokenSet, TokenSet } from '../types.js';

/**
 * Synthetic cache key used when no audience is requested. Never sent to Auth0 — it only
 * keys the token set inside the store. Mirrors the user-session `getAccessToken()`.
 */
const DEFAULT_AUDIENCE_CACHE_KEY = 'default';

/**
 * Reads the anonymous identity (`anon@<uuid>`) off an anonymous access token.
 *
 * The anonymous identity is the join key for anything the application stores for a visitor
 * before they log in, so it is captured at creation instead of leaving every application to
 * hand-decode a token for it. Returns `undefined` rather than throwing when the token cannot
 * be read: a resource server with token encryption (`token_encryption`) enabled gets an
 * encrypted JWE whose claims only the API can read, and that must not fail `createSession()`.
 * The session itself never depends on this value.
 */
const readAnonymousSub = (accessToken: string): string | undefined => {
  try {
    const { sub } = decodeJwt(accessToken);
    return typeof sub === 'string' ? sub : undefined;
  } catch {
    return undefined;
  }
};

/**
 * The scope a cached token is keyed on: what was asked for, falling back to what was granted
 * when Auth0 granted exactly that.
 *
 * Keying on the request is what makes a trimmed grant cacheable. Auth0 answers a request for
 * a scope an anonymous caller is not entitled to with a success and a narrower `scope`, so
 * looking the token up by its granted scope would miss for ever and re-mint on every call.
 */
const cacheKeyScope = (tokenSet: AnonymousTokenSet): string | undefined =>
  tokenSet.requestedScope ?? tokenSet.scope;

/**
 * Inserts or replaces the token set for an audience/scope pair, leaving token sets for
 * other audiences untouched.
 */
const upsertTokenSet = (
  tokenSets: AnonymousTokenSet[],
  tokenSet: AnonymousTokenSet
): AnonymousTokenSet[] => {
  const matches = (candidate: AnonymousTokenSet) =>
    candidate.audience === tokenSet.audience && cacheKeyScope(candidate) === cacheKeyScope(tokenSet);

  return tokenSets.some(matches)
    ? tokenSets.map((candidate) => (matches(candidate) ? tokenSet : candidate))
    : [...tokenSets, tokenSet];
};

/**
 * Client for Auth0 Anonymous Sessions on the server.
 *
 * An anonymous session gives a visitor who has not logged in a stable identity
 * (`anon@<uuid>`) and an access token, so your API can serve them personalised data
 * before they authenticate. Reach it through `serverClient.anonymous`, which requires an
 * `anonymousStore` on the `ServerClient`.
 *
 * How it is stored
 * ----------------
 * The anonymous session token is a long-lived bearer credential for the anonymous
 * identity, so this client keeps it in the anonymous store and never returns it. The
 * application only ever receives access tokens, exactly as it does for a user session.
 *
 * The anonymous store is separate from the state store on purpose. An anonymous visitor
 * must not show up as a logged-in user, so `serverClient.getSession()` and
 * `serverClient.getUser()` keep returning `undefined` while an anonymous session is
 * active.
 *
 * Lifecycle
 * ---------
 * - {@link ServerAnonymousClient.createSession} is the only thing that creates a session.
 *   Nothing here creates one implicitly, so an expired session surfaces as an error
 *   instead of silently swapping the visitor onto a new anonymous identity (and silently
 *   dropping their metadata).
 * - {@link ServerAnonymousClient.getAccessToken} returns a cached token, or re-mints one
 *   from the stored session token.
 * - {@link ServerAnonymousClient.logout} discards the session locally.
 * - Logging in ends the anonymous session. Every method that establishes a user session
 *   drops it afterwards, as does `serverClient.logout()`. Read `getSession()` **before**
 *   completing the login when you need the anonymous identity to merge data, or set
 *   `clearAnonymousSessionOnLogin: false` on the `ServerClient` to keep it and call
 *   `logout()` yourself.
 *
 * Linking an anonymous session to the user created at login
 * ---------------------------------------------------------
 * **An anonymous session created by this SDK is never linked to the user at login.** For a
 * redirect login, Auth0 links an anonymous session only when the `auth0_anon` cookie is
 * present on the `/authorize` request. Auth0 sets that cookie on the Auth0 domain, so it
 * exists only if the **browser** called `POST /anonymous/token` itself. A session created
 * here is created by your server, over `fetch`, so the browser never sees the cookie and the
 * login is treated as having no anonymous session at all.
 *
 * There is one non-cookie way to link: the password and password-realm grants accept an
 * `anonymous_session_token` parameter on the token request. This SDK deliberately does not
 * implement either grant — collecting a password in your own application is not a flow Auth0
 * recommends — so that path is not available here.
 *
 * The rest of the logins this SDK offers cannot carry an anonymous session either, including
 * the ones that never touch `/authorize`: `passkey.getToken()`, `completePasswordless()`,
 * `completePasswordlessMagicLink()`, `loginBackchannel()` and
 * `loginWithCustomTokenExchange()`. There is no request parameter to pass the anonymous
 * session on those endpoints, and Auth0 ignores the anonymous session for them.
 *
 * The rest of the feature is unaffected. `/anonymous/token` is independent of user login, so
 * `createSession()`, `getAccessToken()` for any number of audiences, and `getSession()` all
 * work normally in a passkey or passwordless application. Only the link to the user at login
 * is unavailable.
 *
 * If you need that link, have the browser create the anonymous session (see
 * `@auth0/auth0-spa-js`, or `fetch` with `credentials: 'include'`) and log the user in
 * through `/authorize`: the login redirect your server builds then carries the cookie and
 * Auth0 links it. Use this client for the server-side case: giving a pre-login visitor an
 * identity and an access token for your own API.
 *
 * @example
 * ```typescript
 * // Give a visitor an anonymous identity on their first request.
 * let session = await serverClient.anonymous.getSession(storeOptions);
 * if (!session) {
 *   await serverClient.anonymous.createSession(
 *     { audience: 'https://api.example.com', metadata: { landing: 'pricing' } },
 *     storeOptions
 *   );
 * }
 *
 * // On any later request, get a valid token for your API.
 * try {
 *   const { accessToken } = await serverClient.anonymous.getAccessToken(
 *     { audience: 'https://api.example.com' },
 *     storeOptions
 *   );
 * } catch (error) {
 *   if (error instanceof AnonymousSessionExpiredError) {
 *     await serverClient.anonymous.createSession({ audience: 'https://api.example.com' }, storeOptions);
 *   }
 * }
 * ```
 */
export class ServerAnonymousClient<TStoreOptions = unknown> {
  readonly #options: ServerAnonymousClientOptions<TStoreOptions>;

  /**
   * @internal
   */
  constructor(options: ServerAnonymousClientOptions<TStoreOptions>) {
    this.#options = options;
  }

  /**
   * Creates an anonymous session and stores it, returning the first anonymous access token.
   *
   * Replaces any anonymous session already stored for this visitor. Metadata can only be
   * attached here, because Auth0 rejects a request that carries both metadata and an
   * existing session.
   *
   * The anonymous identity (`sub`) is read off the first access token and stored alongside
   * the metadata, so {@link ServerAnonymousClient.getSession} can hand both back without the
   * application decoding a token. It stays `undefined` for an audience with token encryption
   * (`token_encryption`) enabled, whose access token is an encrypted JWE only the API can
   * read.
   *
   * @param options Optional audience, scope and metadata for the new session.
   * @param storeOptions Optional options used to pass to the anonymous store (and to resolve the domain in resolver mode).
   *
   * @throws {AnonymousSessionError} If Auth0 rejected the request. Common codes are
   * `feature_not_enabled` (the tenant flag is off), `unauthorized_client` (the client is
   * not enabled for anonymous sessions), `invalid_target` (the resource server does not
   * allow anonymous access), `invalid_request` (metadata over 1024 bytes, or not all
   * strings) and `access_denied`. `code` is `server_error` when Auth0 answers with a body
   * that is not JSON.
   *
   * Only call this once you have established the visitor has no anonymous session (check
   * {@link ServerAnonymousClient.getSession} first), rather than on every request.
   *
   * @returns The anonymous access token for the requested audience.
   */
  async createSession(
    options?: CreateAnonymousSessionOptions,
    storeOptions?: TStoreOptions
  ): Promise<TokenSet> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const requestedAudience = options?.audience ?? this.#options.defaultAudience;
    const audience = requestedAudience ?? DEFAULT_AUDIENCE_CACHE_KEY;
    const scope = options?.scope;

    const session = await this.#options.getAuthClient(domain).anonymous.createSession({
      ...(requestedAudience && { audience: requestedAudience }),
      ...(scope && { scope }),
      ...(options?.metadata && { metadata: options.metadata }),
    });

    const tokenSet: AnonymousTokenSet = {
      audience,
      accessToken: session.accessToken,
      scope: session.scope,
      ...(scope && scope !== session.scope && { requestedScope: scope }),
      expiresAt: session.expiresAt,
    };

    const stateData: AnonymousStateData = {
      sessionToken: session.sessionToken,
      sub: readAnonymousSub(session.accessToken),
      ...(options?.metadata && { metadata: options.metadata }),
      createdAt: Math.floor(Date.now() / 1000),
      tokenSets: [tokenSet],
      domain,
    };

    await this.#options.anonymousStore.set(
      this.#options.anonymousStoreIdentifier,
      stateData,
      true,
      storeOptions
    );

    return tokenSet;
  }

  /**
   * Returns an anonymous access token for the stored anonymous session, re-minting it from
   * the session token when the cached one has expired.
   *
   * Tokens are cached per audience and requested scope, so requesting a second audience
   * mints a second token against the same anonymous identity instead of replacing the first.
   * A token is reused when it was minted for this exact request, or when the scope Auth0
   * granted covers what is being asked for now. Auth0 can grant less than was requested (a
   * scope an anonymous caller is not entitled to is dropped, with a successful response), and
   * that outcome is cached too: re-asking would only get the same answer, at the cost of
   * another call to Auth0. Read `tokenSet.scope` to see what the token actually carries.
   *
   * This never creates a session. If the anonymous session has expired, the stored session
   * is deleted and `AnonymousSessionExpiredError` is thrown, so a visitor is never moved
   * onto a fresh anonymous identity behind your back.
   *
   * @param options Optional audience and scope for the requested token.
   * @param storeOptions Optional options used to pass to the anonymous store (and to resolve the domain in resolver mode).
   *
   * @throws {MissingAnonymousSessionError} When there is no anonymous session stored, or the stored one belongs to another Auth0 domain (resolver mode).
   * @throws {AnonymousSessionExpiredError} When the anonymous session has expired or Auth0 rejected the session token. The stored session is deleted first.
   * @throws {AnonymousSessionError} For any other failure reported by Auth0 when minting a
   * new token.
   *
   * @returns The anonymous access token for the requested audience.
   */
  async getAccessToken(
    options?: GetAnonymousAccessTokenOptions,
    storeOptions?: TStoreOptions
  ): Promise<TokenSet> {
    const stateData = await this.#options.anonymousStore.get(
      this.#options.anonymousStoreIdentifier,
      storeOptions
    );

    if (!stateData?.sessionToken) {
      throw new MissingAnonymousSessionError();
    }

    const domain = await this.#options.resolveDomain(storeOptions);

    // In resolver mode a stored anonymous session is only usable against the tenant it was
    // created for; its session token is meaningless anywhere else.
    if (this.#options.isResolverMode() && stateData.domain !== domain) {
      throw new MissingAnonymousSessionError(
        'The stored anonymous session was created for a different Auth0 domain.'
      );
    }

    const requestedAudience = options?.audience ?? this.#options.defaultAudience;
    const audience = requestedAudience ?? DEFAULT_AUDIENCE_CACHE_KEY;
    const scope = options?.scope;

    // A cached token is usable when nothing specific was asked for, when it was minted for
    // exactly this request, or when what Auth0 granted covers the request anyway.
    const cachedTokenSet = stateData.tokenSets.find(
      (tokenSet) =>
        tokenSet.audience === audience &&
        (!scope || cacheKeyScope(tokenSet) === scope || compareScopes(tokenSet.scope, scope))
    );

    if (cachedTokenSet && cachedTokenSet.expiresAt > Date.now() / 1000) {
      return cachedTokenSet;
    }

    const renewed = await this.#options.getAuthClient(domain).anonymous.getTokenSilently({
      sessionToken: stateData.sessionToken,
      ...(requestedAudience && { audience: requestedAudience }),
      ...(scope && { scope }),
    });

    // `auth0-auth-js` swallows `session_expired` / `invalid_session_token` and silently
    // creates a brand new anonymous identity instead. A re-mint always echoes back the
    // session token it was given, so a changed token is that silent re-create. Drop it and
    // report the expiry rather than moving the visitor onto an identity they did not ask
    // for, carrying none of their metadata.
    if (renewed.sessionToken !== stateData.sessionToken) {
      await this.#options.anonymousStore.delete(this.#options.anonymousStoreIdentifier, storeOptions);
      throw new AnonymousSessionExpiredError();
    }

    const tokenSet: AnonymousTokenSet = {
      audience,
      accessToken: renewed.accessToken,
      scope: renewed.scope,
      ...(scope && scope !== renewed.scope && { requestedScope: scope }),
      expiresAt: renewed.expiresAt,
    };

    // Re-read the session, so a token another request cached for a different audience while
    // this one waited on Auth0 is not thrown away. When the session is gone, or has been
    // replaced by a new one, nothing is written back: the minted token is still valid and is
    // returned, but it does not belong to whatever is in the store now.
    const existingStateData = await this.#options.anonymousStore.get(
      this.#options.anonymousStoreIdentifier,
      storeOptions
    );

    if (existingStateData?.sessionToken === stateData.sessionToken) {
      // The session token is never reissued, so the stored handle and `createdAt` are kept
      // as they are. Re-anchoring `createdAt` here would push the anonymous session's own
      // expiry out on every renewal and it would never end.
      //
      // `sub` is only read when it is missing, which happens when the token minted at
      // creation was an encrypted JWE. The session token was echoed back unchanged above, so
      // this token belongs to the same anonymous identity.
      await this.#options.anonymousStore.set(
        this.#options.anonymousStoreIdentifier,
        {
          ...existingStateData,
          ...(existingStateData.sub === undefined && { sub: readAnonymousSub(renewed.accessToken) }),
          tokenSets: upsertTokenSet(existingStateData.tokenSets, tokenSet),
        },
        false,
        storeOptions
      );
    }

    return tokenSet;
  }

  /**
   * Returns the stored anonymous session, or `undefined` when there is none.
   *
   * Use it to decide whether a visitor still needs
   * {@link ServerAnonymousClient.createSession}, and to read the anonymous identity
   * (`sub`) and `metadata` for data you keep for the visitor yourself. The anonymous session
   * token is not included.
   *
   * This is a local read of the store. It makes no request to Auth0, so it cannot tell you
   * whether Auth0 still considers the anonymous session valid — only
   * {@link ServerAnonymousClient.getAccessToken} can.
   *
   * @param storeOptions Optional options used to pass to the anonymous store (and to resolve the domain in resolver mode).
   *
   * @returns The anonymous session, or `undefined` when there is none for this visitor (or it belongs to another Auth0 domain).
   */
  async getSession(storeOptions?: TStoreOptions): Promise<AnonymousSessionData | undefined> {
    const stateData = await this.#options.anonymousStore.get(
      this.#options.anonymousStoreIdentifier,
      storeOptions
    );

    if (!stateData) {
      return;
    }

    if (this.#options.isResolverMode()) {
      const domain = await this.#options.resolveDomain(storeOptions);
      if (stateData.domain !== domain) {
        return;
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { sessionToken, ...sessionData } = stateData;
    return sessionData;
  }

  /**
   * Discards the anonymous session held for this visitor.
   *
   * This is local cleanup: the stored session token and the anonymous cookie are dropped.
   * It does not call `POST /anonymous/logout`, which exists to clear the `auth0_anon`
   * cookie in a browser. Your server never holds that cookie, and the endpoint revokes
   * nothing server-side, so calling it would achieve nothing here.
   *
   * Anonymous access tokens already handed out stay valid until they expire (2 hours by
   * default). There is no anonymous session to revoke them against.
   *
   * You do not have to call this after a login: every method that establishes a user session
   * clears the anonymous session for you, unless you set
   * `clearAnonymousSessionOnLogin: false` on the `ServerClient`. `serverClient.logout()`
   * clears it too. Call this directly to reset a visitor's anonymous identity, or after your
   * own post-login work when you have opted out of the automatic clearing.
   *
   * @param storeOptions Optional options used to pass to the anonymous store.
   */
  async logout(storeOptions?: TStoreOptions): Promise<void> {
    await this.#options.anonymousStore.delete(this.#options.anonymousStoreIdentifier, storeOptions);
  }
}
