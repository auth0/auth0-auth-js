import { AbstractStateStore, EncryptedStoreOptions, LogoutTokenClaims, StateData } from '@auth0/auth0-server-js';
import type { SessionConfiguration, StoreOptions } from '../types.js';

export abstract class AbstractSessionStore extends AbstractStateStore<StoreOptions> {
  readonly #rolling: boolean;
  readonly #absoluteDuration: number;
  readonly #inactivityDuration: number;

  constructor(options: SessionConfiguration & EncryptedStoreOptions) {
    super(options);

    this.#rolling = options.rolling ?? true;
    this.#absoluteDuration = options.absoluteDuration ?? 60 * 60 * 24 * 3;
    this.#inactivityDuration = options.inactivityDuration ?? 60 * 60 * 24 * 1;
  }

  abstract set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: StoreOptions | undefined
  ): Promise<void>;

  abstract get(identifier: string, options?: StoreOptions | undefined): Promise<StateData | undefined>;

  abstract delete(identifier: string, options?: StoreOptions | undefined): Promise<void>;

  abstract deleteByLogoutToken(claims: LogoutTokenClaims, options?: StoreOptions | undefined): Promise<void>;

  /**
   * calculateMaxAge calculates the max age of the session based on createdAt and the rolling and absolute durations.
   */
  protected calculateMaxAge(createdAt: number) {
    if (!this.#rolling) {
      return this.#absoluteDuration;
    }

    const now = (Date.now() / 1000) | 0;
    const expiresAt = Math.min(now + this.#inactivityDuration, createdAt + this.#absoluteDuration);
    const maxAge = expiresAt - now;

    return maxAge > 0 ? maxAge : 0;
  }
}
