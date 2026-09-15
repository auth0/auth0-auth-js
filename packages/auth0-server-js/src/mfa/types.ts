import type { StateStore } from '../types.js';
import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * Response from a successful MFA verification.
 */
export interface MfaVerifyResponse {
  /** The access token */
  accessToken: string;
  /** The ID token (if openid scope was requested) */
  idToken?: string;
  /** The refresh token (if offline_access scope was requested) */
  refreshToken?: string;
  /** The token type (typically "bearer") */
  tokenType: string;
  /** Unix timestamp (seconds) at which the access token expires */
  expiresAt: number;
  /** The granted scopes */
  scope?: string;
  /** A new recovery code (only returned when verifying with a recovery code) */
  recoveryCode?: string;
}

/**
 * @internal
 * Options for constructing a ServerMfaClient.
 *
 * The MFA client resolves the domain per call (like the passkey and database
 * clients), so it keeps working in resolver (multi-tenant) mode. It therefore
 * receives the parent client's `resolveDomain` and `getAuthClient` helpers
 * instead of a fixed domain/authClient.
 */
export interface ServerMfaClientOptions<TStoreOptions = unknown> {
  resolveDomain: (storeOptions?: TStoreOptions) => Promise<string>;
  getAuthClient: (domain: string) => AuthClient;
  stateStore: StateStore<TStoreOptions>;
  stateStoreIdentifier: string;
  defaultAudience: string;
}
