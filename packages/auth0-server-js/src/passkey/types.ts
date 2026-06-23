import type { StateStore } from '../types.js';
import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * @internal
 * Options for constructing a ServerPasskeyClient.
 *
 * Unlike the MFA client, the passkey client resolves the domain per call so it
 * keeps working in resolver (multi-tenant) mode. It therefore receives the
 * parent client's `resolveDomain` and `getAuthClient` helpers instead of a
 * fixed domain/authClient.
 */
export interface ServerPasskeyClientOptions<TStoreOptions = unknown> {
  resolveDomain: (storeOptions?: TStoreOptions) => Promise<string>;
  getAuthClient: (domain: string) => AuthClient;
  stateStore: StateStore<TStoreOptions>;
  stateStoreIdentifier: string;
  defaultScope?: string;
  defaultAudience?: string;
}
