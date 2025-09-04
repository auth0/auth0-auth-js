export enum SUBJECT_TOKEN_TYPES {
  /**
   * Constant representing the subject type for a refresh token.
   * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is a refresh token.
   *
   * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
   */
  SUBJECT_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token",

  /**
   * Constant representing the subject type for a access token.
   * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is an access token.
   *
   * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
   */
  SUBJECT_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token",
}

export enum GRANT_TYPES {
  /**
   * A constant representing the grant type for federated connection access token exchange.
   *
   * This grant type is used in OAuth token exchange scenarios where a federated connection
   * access token is required. It is specific to Auth0's implementation and follows the
   * "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" format.
   */
  GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
}
