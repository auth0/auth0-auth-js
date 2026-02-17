/**
 * Cache provider factory and utilities.
 *
 * This module handles cache instantiation based on user configuration.
 * It abstracts away the complexity of choosing between built-in and custom implementations.
 *
 * @module cache-provider
 */

import type { DiscoveryCacheOptions, DiscoveryCache } from './types.js';
import type { JWKSCacheInput } from 'jose';
import { LruCache } from './lru-cache.js';

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
 * Discovery cache factory.
 *
 * Creates appropriate cache implementation based on provider strategy.
 */
export class DiscoveryCacheFactory {
  /**
   * Create a discovery cache instance.
   *
   * @param config - Resolved cache configuration
   * @returns Discovery cache instance, or null-like object if caching disabled
   */
  static createDiscoveryCache<K = string, V = unknown>(config: ResolvedCacheConfig): DiscoveryCache<K, V> {
    // Get or create global cache for this configuration
    const cacheKey = getGlobalCacheKey(config.maxEntries, config.ttlMs);
    let cache = getGlobalCache(cacheKey);

    if (!cache) {
      cache = new LruCache<K, V>(config.maxEntries, config.ttlMs);
      globalCaches.set(cacheKey, cache);
    }

    return cache as DiscoveryCache<K, V>;
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
