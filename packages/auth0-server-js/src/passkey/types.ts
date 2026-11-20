import type { StateData, StateStore } from '../types.js';
import type { AuthClient, TokenResponse } from '@auth0/auth0-auth-js';
import type { TransactionSlot } from '../store/transaction-slot.js';
import type { PasskeyTransactionData } from './passkey-transaction.js';

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
  /**
   * Where `startSignup()` and `startLogin()` keep the auth session for `complete()`.
   */
  transaction: TransactionSlot<PasskeyTransactionData, TStoreOptions>;
  defaultScope?: string;
  defaultAudience?: string;
  /**
   * Called after a passkey exchange has written the user session, so the parent client can
   * clear the anonymous session. Must never throw: a login has already succeeded by the time
   * it runs.
   */
  onUserSessionEstablished?: (storeOptions?: TStoreOptions) => Promise<void>;
  /**
   * Gives the stored session that a passkey login builds on. The parent client gives `undefined` for a session that a
   * login must not build on (an agent session, with the `poppy` option), so the login starts a new session. When it is
   * not given, the stored session is used as it is.
   */
  existingForLogin?: (stored: StateData | undefined) => StateData | undefined;
  /**
   * The guard of the `poppy` option. It is called with the tokens of the exchange before anything is written. It throws
   * when the login is refused. It gives a value when the login was an agent's and has been saved, and the exchange then
   * writes no session of its own. It gives `undefined` for a person's login, and the exchange goes on as usual. When it is
   * not given, nothing is checked.
   */
  completePoppyLogin?: (
    response: TokenResponse,
    input: { audience: string; domain: string },
    storeOptions?: TStoreOptions
  ) => Promise<unknown>;
}
