import type { ServerDatabaseClientOptions } from './types.js';
import type { SignUpOptions, ChangePasswordOptions, SignUpResult } from '../types.js';

export class ServerDatabaseClient<TStoreOptions = unknown> {
  readonly #options: ServerDatabaseClientOptions<TStoreOptions>;

  /**
   * @internal
   */
  constructor(options: ServerDatabaseClientOptions<TStoreOptions>) {
    this.#options = options;
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
  async signUp(options: SignUpOptions, storeOptions?: TStoreOptions): Promise<SignUpResult> {
    const domain = await this.#options.resolveDomain(storeOptions);
    return this.#options.getAuthClient(domain).database.signUp(options);
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
  async changePassword(options: ChangePasswordOptions, storeOptions?: TStoreOptions): Promise<string> {
    const domain = await this.#options.resolveDomain(storeOptions);
    return this.#options.getAuthClient(domain).database.changePassword(options);
  }
}
