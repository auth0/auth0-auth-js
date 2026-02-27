/**
 * Cache provider factory and utilities.
 *
 * This module handles cache instantiation based on user configuration.
 * It abstracts away the complexity of choosing between built-in and custom implementations.
 *
 * @module cache-provider
 */

import type { DiscoveryCacheOptions } from './types.js';
import type { JWKSCacheInput } from 'jose';
import { LruCache } from './lru-cache.js';

/**
 * Interface for discovery cache implementations.
 *
 * Implementations should handle TTL/expiration internally.
 * The cache key format is: "domain|mtls:0|1"
 *
 * @template K - Cache key (string)
 * @template V - Cache value (discovery metadata)
 */
export interface DiscoveryCache<K = string, V = unknown> {
  /**
   * Retrieves a value from the cache.
   * Should return undefined if entry doesn't exist or is expired.
   */
  get(key: K): V | undefined;

  /**
   * Sets a value in the cache with optional TTL.
   *
   * @param key - Cache key
   * @param value - Value to cache
   * @param ttlMs - Optional TTL in milliseconds
   */
  set(key: K, value: V, ttlMs?: number): void;
}

/**
 * Global cache storage for shared caches across all AuthClient instances.
 * Key format: "${maxEntries}:${ttlMs}"
 */
const globalCaches = new Map<string, DiscoveryCache>();

function getGlobalCache<K, V>(key: string): DiscoveryCache<K, V> | undefined {
  return globalCaches.get(key) as DiscoveryCache<K, V> | undefined;
}

/**
 * Creates a cache key for global cache lookup.
 * @param maxEntries - Maximum cache entries
 * @param ttlMs - Time to live in milliseconds
 * @returns Cache key string
 */
function getGlobalCacheKey(maxEntries: number, ttlMs: number): string {
  return `${maxEntries}:${ttlMs}`;
}

/**
 * Resolved cache configuration combining TTL and provider strategy.
 */
export interface ResolvedCacheConfig {
  ttlMs: number;
  maxEntries: number;
}

/**
 * Resolves cache configuration to a consistent format.
 *
 * Handles:
 * - Default values for TTL and maxEntries
 * - Validation of cache options
 * - Provider strategy selection
 *
 * @param options - User-provided cache options
 * @returns Resolved cache configuration
 *
 * @throws {Error} If configuration is invalid
 */
export function resolveCacheConfig(options?: DiscoveryCacheOptions): ResolvedCacheConfig {
  const ttlSeconds = typeof options?.ttl === 'number' ? options.ttl : 600; // Default 10 minutes

  const maxEntries = typeof options?.maxEntries === 'number' && options.maxEntries > 0 ? options.maxEntries : 100;

  const ttlMs = ttlSeconds * 1000;

  return {
    ttlMs,
    maxEntries,
  };
}

/**
 * Coordinates discovery requests against a {@link DiscoveryCache} with in-flight
 * request deduplication.
 *
 * The in-flight map is per-instance, so two `DiscoveryProvider` instances wrapping the
 * same underlying cache will not deduplicate against each other (they will both get a
 * cache-hit after the first settles, but may issue concurrent fetches on a cold miss).
 * This matches the desired behaviour: a shared persistent cache across `AuthClient`
 * instances, but independent in-flight tracking per instance.
 */
export class DiscoveryProvider<K, V> {
  readonly #cache: DiscoveryCache<K, V>;
  readonly #inFlight = new Map<K, Promise<V>>();

  constructor(cache: DiscoveryCache<K, V>) {
    this.#cache = cache;
  }

  /**
   * Returns the cached value for `key` if present, deduplicates against any in-flight fetch
   * for the same key, or starts a new fetch via `fetcher`.
   *
   * On a successful fetch the value is written to the underlying cache automatically.
   * The in-flight entry is always removed once the fetch settles (success or failure).
   */
  async getOrFetch(key: K, fetcher: () => Promise<V>): Promise<V> {
    const cached = this.#cache.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const inFlight = this.#inFlight.get(key);
    if (inFlight) return inFlight;

    const promise = fetcher()
      .then((value) => {
        this.#cache.set(key, value);
        return value;
      })
      .finally(() => {
        this.#inFlight.delete(key);
      });

    // Prevent unhandled-rejection warnings for concurrent waiters that join before
    // the promise rejects.
    void promise.catch(() => undefined);
    this.#inFlight.set(key, promise);

    return promise;
  }
}

/**
 * Discovery cache factory.
 *
 * Creates appropriate cache implementation based on provider strategy.
 */
export class DiscoveryCacheFactory {
  /**
   * Create a {@link DiscoveryProvider} backed by a shared global LRU cache.
   *
   * Instances that share the same `config` values share the same underlying
   * {@link DiscoveryCache}, so a successful discovery by one `AuthClient` is
   * immediately visible to all others with equivalent configuration.
   *
   * @param config - Resolved cache configuration
   * @returns DiscoveryProvider instance backed by a shared global LRU cache
   */
  static createDiscoveryProvider<K = string, V = unknown>(config: ResolvedCacheConfig): DiscoveryProvider<K, V> {
    // Get or create global cache for this configuration
    const cacheKey = getGlobalCacheKey(config.maxEntries, config.ttlMs);
    let cache = getGlobalCache(cacheKey);

    if (!cache) {
      cache = new LruCache<K, V>(config.maxEntries, config.ttlMs);
      globalCaches.set(cacheKey, cache);
    }

    return new DiscoveryProvider<K, V>(cache as DiscoveryCache<K, V>);
  }

  /**
   * Create a JWKS cache instance.
   *
   * @param config - Resolved cache configuration
   * @returns JWKS cache instance
   */
  static createJwksCache(): JWKSCacheInput {
    return {};
  }
}

/**
 * Clears all global caches.
 * Useful for testing or when you need to reset cache state.
 *
 * @internal
 */
export function clearGlobalCaches(): void {
  globalCaches.clear();
}
