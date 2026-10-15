/**
 * Token types shared by every flow that obtains an access token through this
 * package. This module is the single home for them, so that a flow which caches
 * tokens and a flow which does not still describe their results with the same
 * shape.
 */

/**
 * An access token and the metadata the authorization server returned alongside
 * it.
 */
export interface TokenSet {
  /** The access token issued by the authorization server. */
  accessToken: string;
  /** Unix timestamp in seconds at which the access token expires. */
  expiresAt: number;
  /**
   * The scope the authorization server granted, exactly as it was returned: a
   * space-delimited string, in the server's own ordering.
   *
   * This field may be absent. An absent `scope` means the authorization server
   * did not report a scope; it is not confirmation that the full requested
   * scope was granted, and it must not be read that way. When the granted
   * scopes matter to an authorization decision, compare the value that is
   * present against what you asked for rather than assuming.
   */
  scope?: string;
  /**
   * The token type returned by the authorization server, normalized to lower
   * case by the underlying OAuth client. For a bearer token the value is
   * `"bearer"`, not `"Bearer"`. Compare case-insensitively if you branch on it.
   */
  tokenType?: string;
}
