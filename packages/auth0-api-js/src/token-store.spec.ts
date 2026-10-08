import { expect, test, describe } from 'vitest';
import { normalizeScopes, isScopeSuperset } from './token-store.js';

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
});

describe('isScopeSuperset', () => {
  test('isScopeSuperset - returns true when granted contains all requested', () => {
    const result = isScopeSuperset(['a', 'b', 'c'], ['a', 'b']);
    expect(result).toBe(true);
  });

  test('isScopeSuperset - returns false when granted does not cover all requested', () => {
    const result = isScopeSuperset(['a', 'b'], ['a', 'b', 'c']);
    expect(result).toBe(false);
  });

  test('isScopeSuperset - returns true when requested is empty', () => {
    const result = isScopeSuperset(['a', 'b'], []);
    expect(result).toBe(true);
  });

  test('isScopeSuperset - returns true when both arrays are empty', () => {
    const result = isScopeSuperset([], []);
    expect(result).toBe(true);
  });

  test('isScopeSuperset - returns false when granted is empty and requested is not', () => {
    const result = isScopeSuperset([], ['a']);
    expect(result).toBe(false);
  });
});
