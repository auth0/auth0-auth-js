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
   * means the granted scope matched the request. An empty string is different: it
   * means nothing was granted.
   */
  scope?: string;

  /**
   * The token type the authorization server returned, for example `bearer`.
   */
  tokenType?: string;
}
