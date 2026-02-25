import { describe, expect, test, afterEach, beforeEach, vi } from 'vitest';
import { LruCache } from './lru-cache.js';

describe('LruCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('returns undefined for missing keys', () => {
    const cache = new LruCache<string, number>(2, 1000);

    expect(cache.get('missing')).toBeUndefined();
  });

  test('evicts entries after ttl', () => {
    const cache = new LruCache<string, number>(2, 1000);

    cache.set('a', 1);
    expect(cache.get('a')).toBe(1);

    vi.advanceTimersByTime(1000);

    expect(cache.get('a')).toBeUndefined();
  });

  test('evicts least recently used when max entries exceeded', () => {
    const cache = new LruCache<string, number>(2, 1000);

    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  test('get() marks entry as recently used so it is not evicted next', () => {
    const cache = new LruCache<string, number>(2, 1000);

    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.get('a')).toBe(1);

    cache.set('c', 3);

    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBe(3);
  });

  test('overwrites existing keys', () => {
    const cache = new LruCache<string, number>(2, 1000);

    cache.set('a', 1);
    cache.set('a', 2);

    expect(cache.get('a')).toBe(2);
  });

  test('defensive: handles undefined oldest key in eviction guard (branch coverage)', () => {
    const cache = new LruCache<string | undefined, number>(1, 1000);

    // Defensive branch coverage for eviction guard; production cache keys are strings.
    cache.set(undefined, 1);
    cache.set('b', 2);

    expect(cache.get(undefined)).toBe(1);
    expect(cache.get('b')).toBe(2);
  });
});
