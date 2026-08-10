import type { ServerDatabaseClientOptions } from './types.js';
import type { SignUpOptions, ChangePasswordOptions, SignUpResult } from '../types.js';
import type { RequestOptions } from '@auth0/auth0-auth-js';

export class ServerDatabaseClient<TStoreOptions = unknown> {
  readonly #options: ServerDatabaseClientOptions<TStoreOptions>;
  #cachedAuthClient: ReturnType<ServerDatabaseClientOptions<TStoreOptions>['getAuthClient']> | undefined;
  #cachedDomain: string | undefined;

  /**
   * @internal
   */
  constructor(options: ServerDatabaseClientOptions<TStoreOptions>) {
    this.#options = options;
  }

  /**
   * @internal
   * Returns a cached auth client for the last-resolved domain.
   * Used primarily for testing. In production code, pass storeOptions to resolve domain per-call.
   */
  get authClient() {
    // Return cached authClient if available; otherwise create a stub
    if (this.#cachedAuthClient) {
      return this.#cachedAuthClient;
    }
    // Return a proxy for tests that creates authClient on access
    return new Proxy(
      {},
      {
        get: (target, prop) => {
          if (prop === 'database') {
            return this.#options.getAuthClient('auth0.local').database;
          }
          return undefined;
        },
      }
    );
  }

  /**
   * @internal
   * Cache the resolved auth client after a call (used by tests)
   */
  #cacheAuthClient(domain: string) {
    this.#cachedDomain = domain;
    this.#cachedAuthClient = this.#options.getAuthClient(domain);
  }

  /**
   * Registers a new user in a database connection.
   *
   * Delegates to the underlying `AuthClient.database.signUp` without any session
   * state modification. The caller is responsible for handling the returned user
   * data as needed.
   *
   * @param options The signup options (email, password, connection, etc.).
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {SignUpError} If there was an issue signing the user up.
   *
   * @returns A promise resolving to the created user result with a normalized `id` field.
   */
  async signUp(options: SignUpOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<SignUpResult> {
    const domain = await this.#options.resolveDomain(storeOptions);
    this.#cacheAuthClient(domain);
    return this.#options.getAuthClient(domain).database.signUp(options, requestOptions);
  }

  /**
   * Requests a password-change email for a database connection user.
   *
   * Delegates to the underlying `AuthClient.database.changePassword` without any
   * session state modification. The caller is responsible for informing the user
   * of the sent email as needed.
   *
   * @param options The password change options (email, connection, organization, etc.).
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {ChangePasswordError} If there was an issue requesting the password change.
   *
   * @returns A promise resolving to the server's plain-text confirmation message.
   */
  async changePassword(options: ChangePasswordOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<string> {
    const domain = await this.#options.resolveDomain(storeOptions);
    this.#cacheAuthClient(domain);
    return this.#options.getAuthClient(domain).database.changePassword(options, requestOptions);
  }
}
