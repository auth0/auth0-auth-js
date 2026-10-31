import { expect, test } from 'vitest';
import { compareScopes, digestAnonymousSessionToken } from './utils.js';

test('digestAnonymousSessionToken returns the hex-encoded SHA-256 digest', async () => {
  expect(await digestAnonymousSessionToken('abc')).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

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
