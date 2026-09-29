import type { AnonymousStore } from '../types.js';
import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * @internal
 * Options for constructing a ServerAnonymousClient.
 */
export interface ServerAnonymousClientOptions<TStoreOptions = unknown> {
  resolveDomain: (storeOptions?: TStoreOptions) => Promise<string>;
  getAuthClient: (domain: string) => AuthClient;
  isResolverMode: () => boolean;
  anonymousStore: AnonymousStore<TStoreOptions>;
  anonymousStoreIdentifier: string;
  defaultAudience?: string;
}

/**
 * Options for creating an anonymous session.
 */
export interface CreateAnonymousSessionOptions {
  /**
   * The API audience the anonymous access token should be scoped to.
   * Defaults to `authorizationParams.audience` on the `ServerClient`.
   */
  audience?: string;
  /**
   * Space-separated scopes to request. Does not fall back to `authorizationParams.scope`
   * (that value targets logged-in users and doesn't apply to anonymous identities).
   */
  scope?: string;
  /**
   * Up to 1024 bytes of string key-value metadata to attach to the anonymous identity.
   * The limit applies to the JSON-serialized object, so keys, quotes, and punctuation all
   * count. Set once at creation — Auth0 rejects metadata on any subsequent call. If the
   * session expires and a new one is created, the old metadata is gone. Exceeding the limit
   * throws an `AnonymousSessionError` with code `invalid_request`.
   */
  metadata?: Record<string, string>;
}

/**
 * Options for retrieving an anonymous access token.
 */
export interface GetAnonymousAccessTokenOptions {
  /**
   * The API audience the anonymous access token should be scoped to.
   * Defaults to `authorizationParams.audience` on the `ServerClient`.
   */
  audience?: string;
  /**
   * Space-separated scopes to request. Does not fall back to `authorizationParams.scope`.
   */
  scope?: string;
}
