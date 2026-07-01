import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * @internal
 * Options for constructing a ServerDatabaseClient.
 *
 * Like the passkey client, the database client resolves the domain per call so
 * it keeps working in resolver (multi-tenant) mode. It therefore receives the
 * parent client's `resolveDomain` and `getAuthClient` helpers instead of a
 * fixed domain/authClient. Unlike the MFA/passkey clients, it never touches the
 * state store — signup and change-password write no session.
 */
export interface ServerDatabaseClientOptions<TStoreOptions = unknown> {
  resolveDomain: (storeOptions?: TStoreOptions) => Promise<string>;
  getAuthClient: (domain: string) => AuthClient;
}
