import type { DiscoveryCache } from './types.js';

/**
 * LRU (Least Recently Used) Cache implementation.
 *
 * Provides in-memory caching with:
 * - TTL (Time-To-Live) support for automatic expiration
 * - LRU eviction when capacity is exceeded
 * - O(1) get/set operations
 *
 * The cache is generic over key and value types for type safety.
 *
 * @template K - Cache key type (typically string)
 * @template V - Cache value type
 *
 * @example
 * ```typescript
 * // Create a cache with 100 entries and 10 minute TTL
 * const cache = new LruCache<string, MyData>(100, 600_000);
 *
 * // Store data
 * cache.set('key1', data);
 *
 * // Retrieve data (returns undefined if expired)
 * const value = cache.get('key1');
 * ```
 */
export class LruCache<K, V> implements DiscoveryCache<K, V> {
  readonly #entries = new Map<K, { value: V; expiresAt: number }>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;

  /**
   * Create a new LRU cache.
   *
   * @param maxEntries - Maximum number of entries. Minimum 1.
   * @param ttlMs - Time-to-live in milliseconds for each entry. Minimum 1.
   */
  constructor(maxEntries: number, ttlMs: number) {
    this.#maxEntries = Math.max(1, Math.floor(maxEntries));
    this.#ttlMs = Math.max(1, Math.floor(ttlMs));
  }

  /**
   * Retrieves a value from the cache.
   *
   * Returns undefined if:
   * - Key doesn't exist
   * - Entry has expired
   *
   * Automatically deletes expired entries.
   * Updates LRU order by moving accessed entries to the end.
   *
   * @param key - Cache key
   * @returns Cached value or undefined
   */
  get(key: K): V | undefined {
    const entry = this.#entries.get(key);
    if (!entry) {
      return;
    }

    // Check if expired
    if (Date.now() >= entry.expiresAt) {
      this.#entries.delete(key);
      return;
    }

    // Update LRU order by moving to end
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry.value;
  }

  /**
   * Stores a value in the cache.
   *
   * If entry already exists, updates it and moves it to the end (most recently used).
   * If cache is full, evicts the least recently used entry.
   *
   * @param key - Cache key
   * @param value - Value to cache
   */
  set(key: K, value: V): void {
    if (this.#entries.has(key)) {
      this.#entries.delete(key);
    }

    this.#entries.set(key, {
      value,
      expiresAt: Date.now() + this.#ttlMs,
    });

    // Evict LRU when over capacity
    while (this.#entries.size > this.#maxEntries) {
      const oldestKey = this.#entries.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.#entries.delete(oldestKey);
    }
  }
}
