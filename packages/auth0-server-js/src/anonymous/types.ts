import type { AnonymousStore } from '../types.js';
import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * @internal
 * Options for constructing a ServerAnonymousClient.
 *
 * Like the passkey and database clients, this one resolves the domain per call so it keeps
 * working in resolver (multi-tenant) mode.
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
   *
   * Defaults to `authorizationParams.audience` on the `ServerClient`. The resource server
   * must have `allow_anonymous_access` enabled and a `subject_type_authorization` policy
   * set, otherwise Auth0 rejects the request.
   */
  audience?: string;
  /**
   * Space-separated list of scopes to request for the anonymous access token.
   *
   * Unlike the user-session methods, this does NOT fall back to
   * `authorizationParams.scope`. That value is written for a logged-in user (it normally
   * contains `openid profile email offline_access`) and none of it applies to an anonymous
   * identity, which has no user profile and no refresh token.
   */
  scope?: string;
  /**
   * Up to 1024 bytes of string key-value metadata to attach to the anonymous identity.
   *
   * Set once, at creation. Auth0 rejects any later attempt to change it, and the SDK
   * therefore only ever sends metadata on this call. If the anonymous session expires and
   * you create a new one, the metadata of the old identity is gone.
   *
   * Values must be strings; Auth0 rejects nested objects. Auth0 applies the 1024-byte limit
   * to the JSON-serialized object, so the keys, the quotes and the punctuation all count. Too
   * much and you get an `AnonymousSessionError` with code `invalid_request` and the message
   * `metadata exceeds the maximum allowed size`.
   */
  metadata?: Record<string, string>;
}

/**
 * Options for retrieving an anonymous access token.
 */
export interface GetAnonymousAccessTokenOptions {
  /**
   * The API audience the anonymous access token should be scoped to.
   *
   * Defaults to `authorizationParams.audience` on the `ServerClient`. Tokens are cached
   * per audience and scope, so asking for a second audience mints a second token against
   * the same anonymous identity rather than replacing the first.
   */
  audience?: string;
  /**
   * Space-separated list of scopes to request. Does not fall back to
   * `authorizationParams.scope`, for the reason described on
   * {@link CreateAnonymousSessionOptions.scope}.
   */
  scope?: string;
}
