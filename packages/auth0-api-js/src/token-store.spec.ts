import { expect, test, describe } from 'vitest';
import {
  normalizeScopes,
  isIndexedTokenStore,
  isUsableCachedToken,
  isUsableTokenIndexMember,
  type TokenStore,
} from './token-store.js';

function sparseArray(length: number): unknown[] {
  return new Array(length);
}

describe('normalizeScopes', () => {
  test('normalizeScopes - deduplicates and sorts alphabetically', () => {
    const result = normalizeScopes('b a b');
    expect(result).toEqual(['a', 'b']);
  });

  test('normalizeScopes - returns empty array for undefined', () => {
    const result = normalizeScopes(undefined);
    expect(result).toEqual([]);
  });

  test('normalizeScopes - returns empty array for empty string', () => {
    const result = normalizeScopes('');
    expect(result).toEqual([]);
  });

  test('normalizeScopes - returns empty array for whitespace-only string', () => {
    const result = normalizeScopes('   ');
    expect(result).toEqual([]);
  });

  test('normalizeScopes - returns single-element array for single scope', () => {
    const result = normalizeScopes('read');
    expect(result).toEqual(['read']);
  });

  test('normalizeScopes - handles multiple spaces between scopes', () => {
    const result = normalizeScopes('write  read');
    expect(result).toEqual(['read', 'write']);
  });

  test('normalizeScopes - splits on tabs and newlines', () => {
    expect(normalizeScopes('write\tread\nadmin\r\nread')).toEqual(['admin', 'read', 'write']);
  });

  test('normalizeScopes - ignores leading and trailing whitespace', () => {
    expect(normalizeScopes(' \t read write \n')).toEqual(['read', 'write']);
  });

  test('normalizeScopes - collapses duplicates written with different separators', () => {
    expect(normalizeScopes('read\twrite read\nwrite')).toEqual(['read', 'write']);
  });

  test('normalizeScopes - produces the same result regardless of input ordering', () => {
    expect(normalizeScopes('c a b')).toEqual(normalizeScopes('b c a'));
    expect(normalizeScopes('c a b')).toEqual(['a', 'b', 'c']);
  });

  test('normalizeScopes - sorts by code unit order', () => {
    expect(normalizeScopes('b:read a:write B:read')).toEqual(['B:read', 'a:write', 'b:read']);
  });
});

describe('isIndexedTokenStore', () => {
  const base: TokenStore = {
    get: async () => undefined,
    set: async () => undefined,
    delete: async () => undefined,
  };

  test('isIndexedTokenStore - rejects a plain store', () => {
    expect(isIndexedTokenStore(base)).toBe(false);
  });

  test('isIndexedTokenStore - accepts a store with both index methods', () => {
    const store = {
      ...base,
      addIndexMember: async () => undefined,
      listIndexMembers: async () => [],
    };
    expect(isIndexedTokenStore(store)).toBe(true);
  });

  test('isIndexedTokenStore - rejects a store with only addIndexMember', () => {
    const store = { ...base, addIndexMember: async () => undefined };
    expect(isIndexedTokenStore(store)).toBe(false);
  });

  test('isIndexedTokenStore - rejects a store with only listIndexMembers', () => {
    const store = { ...base, listIndexMembers: async () => [] };
    expect(isIndexedTokenStore(store)).toBe(false);
  });

  test('isIndexedTokenStore - rejects a store whose index members are not functions', () => {
    const store = { ...base, addIndexMember: 'nope', listIndexMembers: 1 } as unknown as TokenStore;
    expect(isIndexedTokenStore(store)).toBe(false);
  });
});

describe('isUsableCachedToken', () => {
  const valid = {
    accessToken: 'token',
    expiresAt: 1_700_000_000,
    grantedScopes: ['a', 'b'],
  };

  test('isUsableCachedToken - accepts a minimal valid entry', () => {
    expect(isUsableCachedToken(valid)).toBe(true);
  });

  test('isUsableCachedToken - accepts a valid entry with every optional field', () => {
    expect(
      isUsableCachedToken({
        ...valid,
        scope: 'a b',
        tokenType: 'bearer',
        issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      })
    ).toBe(true);
  });

  test('isUsableCachedToken - accepts an empty grantedScopes array', () => {
    expect(isUsableCachedToken({ ...valid, grantedScopes: [] })).toBe(true);
  });

  test('isUsableCachedToken - rejects a sparse grantedScopes array', () => {
    expect(isUsableCachedToken({ ...valid, grantedScopes: sparseArray(2) })).toBe(false);
  });

  test('isUsableCachedToken - rejects a partially sparse grantedScopes array', () => {
    const partial = sparseArray(3);
    partial[1] = 'a';
    expect(isUsableCachedToken({ ...valid, grantedScopes: partial })).toBe(false);
  });

  test('isUsableCachedToken - rejects a grantedScopes array with a non-string element', () => {
    expect(isUsableCachedToken({ ...valid, grantedScopes: ['a', 1] })).toBe(false);
  });

  test.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'token'],
    ['a number', 1],
  ])('isUsableCachedToken - rejects %s', (_name, value) => {
    expect(isUsableCachedToken(value)).toBe(false);
  });

  test('isUsableCachedToken - rejects an empty accessToken', () => {
    expect(isUsableCachedToken({ ...valid, accessToken: '' })).toBe(false);
  });

  test('isUsableCachedToken - rejects a non-finite expiresAt', () => {
    expect(isUsableCachedToken({ ...valid, expiresAt: NaN })).toBe(false);
    expect(isUsableCachedToken({ ...valid, expiresAt: Infinity })).toBe(false);
  });
});

describe('isUsableTokenIndexMember', () => {
  const valid = {
    tokenKey: 'key',
    expiresAt: 1_700_000_000,
    grantedScopes: ['a'],
  };

  test('isUsableTokenIndexMember - accepts a valid member', () => {
    expect(isUsableTokenIndexMember(valid)).toBe(true);
  });

  test('isUsableTokenIndexMember - rejects a sparse grantedScopes array', () => {
    expect(isUsableTokenIndexMember({ ...valid, grantedScopes: sparseArray(2) })).toBe(false);
  });

  test('isUsableTokenIndexMember - rejects a grantedScopes array with a non-string element', () => {
    expect(isUsableTokenIndexMember({ ...valid, grantedScopes: ['a', null] })).toBe(false);
  });

  test('isUsableTokenIndexMember - rejects null and non-objects', () => {
    expect(isUsableTokenIndexMember(null)).toBe(false);
    expect(isUsableTokenIndexMember('member')).toBe(false);
  });

  test('isUsableTokenIndexMember - rejects an empty tokenKey', () => {
    expect(isUsableTokenIndexMember({ ...valid, tokenKey: '' })).toBe(false);
  });
});
