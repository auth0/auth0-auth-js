export class LruCache<T> {
  #map: Map<string, { value: T; expiresAt?: number }>;
  #inflight: Map<string, Promise<T>>;
  readonly #ttlMs?: number;
  readonly #maxEntries?: number;

  constructor(ttlMs?: number, maxEntries?: number) {
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
    this.#map = new Map();
    this.#inflight = new Map();
  }

  get(key: string): T | undefined {
    const entry = this.#map.get(key);
    if (!entry) {
      return undefined;
    }

    if (this.#ttlMs !== undefined && entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.#map.delete(key);
      return undefined;
    }

    this.#map.delete(key);
    this.#map.set(key, entry);
    return entry.value;
  }

  set(key: string, value: T) {
    const expiresAt = this.#ttlMs !== undefined ? Date.now() + this.#ttlMs : undefined;
    this.#map.set(key, { value, expiresAt });
    this.#enforceLimit();
  }

  async getOrSet(key: string, loader: () => Promise<T> | T): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const inflight = this.#inflight.get(key);
    if (inflight) {
      return inflight;
    }

    const promise = (async () => {
      const value = await loader();
      this.set(key, value);
      return value;
    })();
    const inflightPromise = promise.finally(() => {
      this.#inflight.delete(key);
    });

    this.#inflight.set(key, inflightPromise);
    return inflightPromise;
  }

  #enforceLimit() {
    if (this.#maxEntries === undefined) {
      return;
    }
    while (this.#map.size > this.#maxEntries) {
      const oldestKey = this.#map.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.#map.delete(oldestKey);
    }
  }
}
