import type { VerifiedAccessTokenClaims } from './types.js';

/**
 * Splits a space-separated scope string into a deduplicated, alphabetically sorted list.
 *
 * Returns an empty array for `undefined` and for the empty string. An empty result is
 * meaningful: it says the scope set is empty, which is not the same as "no scope was
 * requested or granted".
 *
 * Exported so a wrapper package can derive exactly the same scope representation that
 * the cache key and the stored `grantedScopes` use.
 *
 * @param scope - A space-separated scope string, or `undefined`.
 *
 * @returns The normalized scope list.
 */
export function normalizeScopes(scope: string | undefined): string[] {
  if (!scope) {
    return [];
  }

  return [...new Set(scope.split(/\s+/).filter(Boolean))].sort();
}

/**
 * An access token together with the claims obtained when it was verified.
 *
 * Pass one of these back into {@link ApiClient.getTokenOnBehalfOf} when the token has
 * already been verified earlier in the request, so the exchange does not have to verify
 * it a second time.
 */
export interface VerifiedToken {
  /**
   * The raw access token, without a `Bearer ` or `DPoP ` prefix.
   */
  accessToken: string;

  /**
   * The claims returned by `verifyAccessToken` for this exact token.
   */
  claims: VerifiedAccessTokenClaims;
}

/**
 * An access token and its expiry.
 *
 * `expiresAt` is always epoch **seconds**, never milliseconds.
 */
export interface TokenSet {
  /**
   * The access token.
   */
  accessToken: string;

  /**
   * Expiration time as Unix epoch seconds.
   */
  expiresAt: number;

  /**
   * The scope string exactly as the authorization server returned it.
   *
   * Absent when the server returned no `scope` field, which per RFC 6749 section 5.1
   * means the granted scope matched the request.
   */
  scope?: string;

  /**
   * The token type the authorization server returned, for example `bearer`.
   */
  tokenType?: string;
}

/**
 * A cached On Behalf Of token.
 *
 * `grantedScopes` is the normalized form of the scopes the exchange actually granted,
 * which is not necessarily what the caller asked for. It is recorded separately from
 * `scope` so a lookup can compare scope sets without reparsing, while `scope` stays
 * byte-identical to what the server sent.
 */
export interface CachedToken extends TokenSet {
  /**
   * The granted scopes, deduplicated and alphabetically sorted.
   */
  grantedScopes: string[];

  /**
   * The RFC 8693 `issued_token_type` returned by the exchange.
   */
  issuedTokenType?: string;
}

/**
 * A pluggable asynchronous cache for On Behalf Of tokens.
 *
 * ## What each layer owns
 *
 * This package owns the key schema, the stored record shape, the scope-matching modes,
 * the non-strict covering lookup and the index writes, all inside
 * {@link ApiClient.getTokenOnBehalfOf}. It records the scopes an exchange granted,
 * caches the resulting token under them, and in non-strict mode records each token in
 * the scope index of an {@link IndexedTokenStore}.
 *
 * A wrapper package owns the concrete {@link TokenStore} or {@link IndexedTokenStore}
 * implementation, the lifetime of the cache instance, eviction, and deciding whether a
 * result that was granted fewer scopes than requested is acceptable. This package does
 * not reject a narrowed result; see {@link ApiClient.getTokenOnBehalfOf}.
 *
 * ## Contract
 *
 * Keys are opaque, namespaced, fixed-length strings. An implementation must store and
 * return them unchanged and must not parse or transform them. Values are stored exactly
 * as the implementation chooses to store them: this package applies no encryption, so an
 * implementation backed by shared or persistent storage is responsible for protecting
 * the token at rest.
 *
 * An entry is validated for shape when it is read, but it is not integrity-checked, so a
 * store shared with other software is trusted to return what was written. This package
 * never deletes or prunes entries or index members, which makes eviction the
 * implementation's responsibility.
 *
 * A returned entry must expose its fields as its own properties. Each field is read once
 * through `Object.hasOwn`, so a value whose fields live on a prototype as accessors reads
 * as an empty entry and is treated as a cache miss. Plain objects, including the result of
 * `JSON.parse`, satisfy this.
 *
 * A `get` or `set` that throws is tolerated. A failed read counts as a cache miss and a
 * failed write still returns the freshly exchanged token, so a store outage costs extra
 * exchanges but never fails a call.
 */
export interface TokenStore {
  /**
   * Returns the entry stored under `key`, or `undefined` when there is none.
   */
  get(key: string): Promise<CachedToken | undefined>;

  /**
   * Stores `value` under `key`.
   */
  set(key: string, value: CachedToken): Promise<void>;

  /**
   * Removes the entry stored under `key`.
   */
  delete(key: string): Promise<void>;
}

/**
 * One member of a scope index: a pointer to a cached token plus the scope set and expiry
 * needed to decide whether that token covers a given request without fetching it first.
 */
export interface TokenIndexMember {
  /**
   * The {@link TokenStore} key the token itself is stored under.
   */
  tokenKey: string;

  /**
   * The granted scopes of the token at `tokenKey`, deduplicated and sorted.
   */
  grantedScopes: string[];

  /**
   * Expiration time of the token at `tokenKey`, as Unix epoch seconds.
   */
  expiresAt: number;
}

/**
 * A {@link TokenStore} that also maintains scope indexes.
 *
 * Non-strict scope matching needs to find a cached token whose granted scopes are a
 * superset of what is being requested. That is a search, not a lookup, so it needs an
 * index of the entries that share a subject, downstream audience, organization and
 * session. This package both writes index members as it caches tokens and reads them to
 * choose the smallest cached token that covers a request. The index is treated as a hint
 * and not as an authority: every member is checked against the key it should have, so an
 * implementation only needs to store and return members faithfully.
 *
 * Required whenever `scopeMatching` is `'non_strict'`.
 */
export interface IndexedTokenStore extends TokenStore {
  /**
   * Adds `member` to the index stored under `indexKey`, replacing any existing member
   * with the same `tokenKey`.
   */
  addIndexMember(indexKey: string, member: TokenIndexMember): Promise<void>;

  /**
   * Returns every member of the index stored under `indexKey`, or an empty list when
   * there is none.
   */
  listIndexMembers(indexKey: string): Promise<TokenIndexMember[]>;
}

/**
 * Per-call collaborators for {@link ApiClient.getTokenOnBehalfOf}.
 *
 * Kept separate from the request options so that infrastructure the integrator supplies
 * cannot arrive by accident through a spread of caller-controlled request data.
 */
export interface OnBehalfOfTokenContext {
  /**
   * Cache to read from and write to. Omit it to exchange on every call.
   *
   * Must be an {@link IndexedTokenStore} when `scopeMatching` is `'non_strict'`.
   */
  store?: TokenStore;

  /**
   * The already-verified form of the token being exchanged.
   *
   * Supply this when the token was verified earlier in the same request, for example by
   * an HTTP adapter that had the authentication scheme, the DPoP proof and the request
   * headers to hand. Its `accessToken` must equal the `accessToken` argument.
   */
  verified?: VerifiedToken;
}

/**
 * @internal
 * Narrows a {@link TokenStore} to an {@link IndexedTokenStore}.
 */
export function isIndexedTokenStore(store: TokenStore): store is IndexedTokenStore {
  const candidate = store as Partial<IndexedTokenStore>;
  return typeof candidate.addIndexMember === 'function' && typeof candidate.listIndexMembers === 'function';
}

/**
 * Checks every index of the array, holes included. `Array.prototype.every` skips holes,
 * so a sparse array such as `[, ,]` would otherwise pass with `undefined` elements.
 */
function isStringArray(value: unknown[]): value is string[] {
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== 'string') {
      return false;
    }
  }
  return true;
}

/**
 * @internal
 * Validates the shape of a value read back from a {@link TokenStore}.
 *
 * A store is pluggable and may be shared with other software, so an entry can be
 * missing fields or carry the wrong types. Anything that fails this check is treated as
 * a cache miss rather than being used or raised.
 */
export function isUsableCachedToken(value: unknown): value is CachedToken {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<CachedToken>;

  return (
    typeof candidate.accessToken === 'string' &&
    candidate.accessToken !== '' &&
    typeof candidate.expiresAt === 'number' &&
    Number.isFinite(candidate.expiresAt) &&
    Array.isArray(candidate.grantedScopes) &&
    isStringArray(candidate.grantedScopes) &&
    (candidate.scope === undefined || typeof candidate.scope === 'string') &&
    (candidate.tokenType === undefined || typeof candidate.tokenType === 'string') &&
    (candidate.issuedTokenType === undefined || typeof candidate.issuedTokenType === 'string')
  );
}

/**
 * @internal
 * Validates the shape of a {@link TokenIndexMember} read back from an index.
 */
export function isUsableTokenIndexMember(value: unknown): value is TokenIndexMember {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<TokenIndexMember>;

  return (
    typeof candidate.tokenKey === 'string' &&
    candidate.tokenKey !== '' &&
    typeof candidate.expiresAt === 'number' &&
    Number.isFinite(candidate.expiresAt) &&
    Array.isArray(candidate.grantedScopes) &&
    isStringArray(candidate.grantedScopes)
  );
}
