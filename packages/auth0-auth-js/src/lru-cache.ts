export class LruCache<K, V> {
  readonly #entries = new Map<K, { value: V; expiresAt: number }>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;

  constructor(maxEntries: number, ttlMs: number) {
    this.#maxEntries = Math.max(1, Math.floor(maxEntries));
    this.#ttlMs = Math.max(1, Math.floor(ttlMs));
  }

  get(key: K): V | undefined {
    const entry = this.#entries.get(key);
    if (!entry) {
      return;
    }

    if (Date.now() >= entry.expiresAt) {
      this.#entries.delete(key);
      return;
    }

    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    if (this.#entries.has(key)) {
      this.#entries.delete(key);
    }

    this.#entries.set(key, {
      value,
      expiresAt: Date.now() + this.#ttlMs,
    });

    while (this.#entries.size > this.#maxEntries) {
      const oldestKey = this.#entries.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.#entries.delete(oldestKey);
    }
  }
}
