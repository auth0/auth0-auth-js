import { AbstractStateStore } from './abstract-state-store.js';
import type { EncryptedStoreOptions, SessionConfiguration } from '../types.js';

export abstract class AbstractSessionStore<TStoreOptions> extends AbstractStateStore<TStoreOptions> {
  readonly #rolling: boolean;
  readonly #absoluteDuration: number;
  readonly #inactivityDuration: number;

  constructor(options: SessionConfiguration & EncryptedStoreOptions) {
    super(options);

    this.#rolling = options.rolling ?? true;
    this.#absoluteDuration = options.absoluteDuration ?? 60 * 60 * 24 * 3;
    this.#inactivityDuration = options.inactivityDuration ?? 60 * 60 * 24 * 1;
  }

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