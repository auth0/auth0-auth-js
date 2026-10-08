/**
 * @internal
 * Split scope string on whitespace, deduplicate, sort alphabetically.
 * Returns [] for undefined or empty string.
 */
export function normalizeScopes(scope: string | undefined): string[] {
  if (!scope) return [];
  return [...new Set(scope.split(/\s+/).filter(Boolean))].sort();
}

/**
 * @internal
 * Returns true iff every element of requestedScopes is present in grantedScopes.
 * Used as a scope-superset predicate in the OBO downscope guard.
 */
export function isScopeSuperset(grantedScopes: string[], requestedScopes: string[]): boolean {
  const granted = new Set(grantedScopes);
  return requestedScopes.every((s) => granted.has(s));
}

/**
 * Minimal token record carrying an access token and its expiry.
 * All `expiresAt` values are epoch seconds (not milliseconds).
 */
export interface TokenSet {
  accessToken: string;
  /** Expiration time as Unix epoch seconds. */
  expiresAt: number;
}

/**
 * A cached OBO token record.
 * `grantedScopes` holds the scopes the exchange granted, deduplicated and sorted
 * alphabetically. This is what the Auth0 server actually authorized, not what
 * the caller requested.
 */
export interface CachedToken extends TokenSet {
  grantedScopes: string[];
  /** Token type of the cached token (e.g. `Bearer` or a DPoP-bound type). */
  tokenType?: string;
  /** The `issued_token_type` returned by the exchange. */
  issuedTokenType?: string;
}

/**
 * Pluggable async cache for OBO tokens.
 *
 * Core/MCP seam:
 *   - Core owns: this interface, CachedToken record, and single-key cache-aside in
 *     getTokenOnBehalfOf (exact-match get/set).
 *   - MCP layer owns: the running store instance, per-principal multi-entry index,
 *     Opt3 strict/non-strict covering-lookup, and eviction policy.
 *
 * The key is a namespaced opaque string. Store implementations must not
 * interpret or transform it.
 */
export interface TokenStore {
  get(key: string): Promise<CachedToken | undefined>;
  set(key: string, value: CachedToken): Promise<void>;
  delete(key: string): Promise<void>;
}
