import { describe, expect, test, vi } from 'vitest';
import { LruCache } from './lru-cache.js';

describe('LruCache', () => {
  test('returns undefined when key is missing', () => {
    const cache = new LruCache<number>(1000, 10);
    expect(cache.get('missing')).toBeUndefined();
  });

  test('evicts least recently used entry', () => {
    const cache = new LruCache<number>(1000, 2);
    cache.set('a', 1);
    cache.set('b', 2);
    // touch a so b becomes LRU
    expect(cache.get('a')).toBe(1);
    cache.set('c', 3);

    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBe(3);
  });

  test('expires entries after ttl', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));

    const cache = new LruCache<number>(1000, 10);
    cache.set('a', 1);
    vi.advanceTimersByTime(1001);

    expect(cache.get('a')).toBeUndefined();
    vi.useRealTimers();
  });

  test('does not expire entries when ttl is undefined', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));

    const cache = new LruCache<number>(undefined, 10);
    cache.set('a', 1);
    vi.advanceTimersByTime(10_000);

    expect(cache.get('a')).toBe(1);
    vi.useRealTimers();
  });

  test('does not enforce limit when maxEntries is undefined', () => {
    const cache = new LruCache<number>(1000);
    cache.set('a', 1);
    cache.set('b', 2);

    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBe(2);
  });

  test('handles negative maxEntries without infinite eviction', () => {
    const cache = new LruCache<number>(1000, -1);
    cache.set('a', 1);
    cache.set('b', 2);

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBeUndefined();
  });

  test('dedupes inflight loaders', async () => {
    const cache = new LruCache<number>(1000, 10);
    let resolve: (value: number) => void = () => undefined;
    const loader = vi.fn(
      () =>
        new Promise<number>((res) => {
          resolve = res;
        })
    );

    const promiseA = cache.getOrSet('a', loader);
    const promiseB = cache.getOrSet('a', loader);

    expect(loader).toHaveBeenCalledTimes(1);
    resolve(42);

    await expect(Promise.all([promiseA, promiseB])).resolves.toEqual([42, 42]);
  });

  test('clears inflight on failure and allows retry', async () => {
    const cache = new LruCache<number>(1000, 10);
    const loader = vi.fn(async () => {
      throw new Error('loader failed');
    });

    await expect(cache.getOrSet('a', loader)).rejects.toThrow('loader failed');
    await expect(cache.getOrSet('a', loader)).rejects.toThrow('loader failed');
    expect(loader).toHaveBeenCalledTimes(2);
  });
});
