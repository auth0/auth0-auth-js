import { expect, test } from 'vitest';
import { compareScopes } from './utils.js';

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

test('should match exact scopes when leading whitespaces is scopes', () => {
  const scopes = '   a b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when trailing whitespaces is scopes', () => {
  const scopes = 'a b   ';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when additional whitespaces is scopes', () => {
  const scopes = 'a    b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when leading whitespaces is requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = '   a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when trailing whitespaces is requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b  ';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('should match exact scopes when additional whitespaces is requiredScopes', () => {
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
