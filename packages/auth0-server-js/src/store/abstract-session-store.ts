import { AbstractStateStore } from './abstract-state-store.js';
import type { EncryptedStoreOptions, SessionConfiguration } from '../types.js';

export abstract class AbstractSessionStore<TStoreOptions> extends AbstractStateStore<TStoreOptions> {
  readonly #rolling: boolean;
  readonly #absoluteDuration: number;
  readonly #inactivityDuration: number;

  constructor(options: SessionConfiguration & EncryptedStoreOptions) {
    super(options);

    // Not `??`: a `null` from a caller that isn't type-checked must not turn rolling on.
    this.#rolling = options.rolling === undefined ? true : Boolean(options.rolling);
    this.#absoluteDuration = options.absoluteDuration ?? 60 * 60 * 24 * 3;
    this.#inactivityDuration = options.inactivityDuration ?? 60 * 60 * 24 * 1;
  }

  /**
   * calculateMaxAge calculates the max age of the session based on createdAt and the rolling and absolute durations.
   * When sessionExpiresAt is provided, caps the maxAge to not exceed the time until that ceiling.
   */
  protected calculateMaxAge(createdAt: number, sessionExpiresAt?: number) {
    const now = (Date.now() / 1000) | 0;

    let maxAge = this.#rolling
      ? Math.min(now + this.#inactivityDuration, createdAt + this.#absoluteDuration) - now
      : this.#absoluteDuration;

    if (sessionExpiresAt !== undefined) {
      maxAge = Math.min(maxAge, sessionExpiresAt - now);
    }

    return maxAge > 0 ? maxAge : 0;
  }
}