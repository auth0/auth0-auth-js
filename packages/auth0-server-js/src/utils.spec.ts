import { expect, test } from 'vitest';
import type { AuthorizationParameters } from './types.js';
import { compareScopes, normalizeNullParams, resolveAudience } from './utils.js';

test('should match scopes when more scopes are available', () => {
  const scopes = 'a b';
  const requiredScopes = 'a';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when leading whitespaces in scopes', () => {
  const scopes = '   a b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when trailing whitespaces in scopes', () => {
  const scopes = 'a b   ';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when additional whitespaces in scopes', () => {
  const scopes = 'a    b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when leading whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = '   a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when trailing whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b  ';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when additional whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a    b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});


test('should match exact scopes in reverse order', () => {
  const scopes = 'a b';
  const requiredScopes = 'b a';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match when both empty', () => {
  const scopes = '';
  const requiredScopes = '';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should not match when scopes empty', () => {
  const scopes = '';
  const requiredScopes = 'a b c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('should not match when requiredScopes empty', () => {
  const scopes = 'a b';
  const requiredScopes = '';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('should not match when no scope included', () => {
  const scopes = 'a b';
  const requiredScopes = 'c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('should not match when some scopes not included', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('should not match when scopes is undefined and requiredScopes empty string', () => {
  expect(compareScopes(undefined,'')).toBe(false);
});

test('normalizeNullParams - returns undefined for no params', () => {
  expect(normalizeNullParams(undefined)).toBeUndefined();
});

test('normalizeNullParams - turns null into undefined and keeps the key', () => {
  const params = { audience: null, scope: '<scope>' } as unknown as AuthorizationParameters;

  const normalized = normalizeNullParams(params);

  expect(normalized).toStrictEqual({ audience: undefined, scope: '<scope>' });
  expect(normalized).toHaveProperty('audience');
});

test('normalizeNullParams - keeps other values as they are', () => {
  const params = { audience: '<audience>', max_age: 0, prompt: '', foo: false } as AuthorizationParameters;

  expect(normalizeNullParams(params)).toStrictEqual(params);
});

test('normalizeNullParams - keeps only the own keys, which are the keys the request carries', () => {
  const params = Object.create({ audience: undefined }) as AuthorizationParameters;
  params.scope = '<scope>';

  const normalized = normalizeNullParams(params);

  expect(normalized).toStrictEqual({ scope: '<scope>' });
  expect(normalized && 'audience' in normalized).toBe(false);
});

test.each([
  ['no call params', undefined, '<client_audience>'],
  ['call params without an audience', { scope: '<scope>' }, '<client_audience>'],
  ['an audience in the call', { audience: '<call_audience>' }, '<call_audience>'],
  ['audience: undefined in the call', { audience: undefined }, undefined],
  ['audience: null in the call', { audience: null }, undefined],
])('resolveAudience - %s', (_, callParams, expected) => {
  expect(resolveAudience({ audience: '<client_audience>' }, callParams as AuthorizationParameters | undefined)).toBe(
    expected
  );
});

test('resolveAudience - returns undefined when neither the client nor the call has an audience', () => {
  expect(resolveAudience(undefined, undefined)).toBeUndefined();
  expect(resolveAudience({ scope: '<scope>' }, { scope: '<scope>' })).toBeUndefined();
});

test('resolveAudience - an inherited audience key, dropped by normalizeNullParams, falls back to the client', () => {
  const params = Object.create({ audience: undefined }) as AuthorizationParameters;

  expect(resolveAudience({ audience: '<client_audience>' }, normalizeNullParams(params))).toBe('<client_audience>');
});
