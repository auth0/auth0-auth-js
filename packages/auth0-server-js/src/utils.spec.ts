import { expect, test } from 'vitest';
import { compareScopes, mergeScopes, getScopeForAudience, ensureDefaultScopes, resolveScopes } from './utils.js';
import { DEFAULT_SCOPES } from './constants.js';

test('compareScopes - should match scopes when more scopes are available', () => {
  const scopes = 'a b';
  const requiredScopes = 'a';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when leading whitespaces in scopes', () => {
  const scopes = '   a b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when trailing whitespaces in scopes', () => {
  const scopes = 'a b   ';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when additional whitespaces in scopes', () => {
  const scopes = 'a    b';
  const requiredScopes = 'a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when leading whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = '   a b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when trailing whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b  ';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match exact scopes when additional whitespaces in requiredScopes', () => {
  const scopes = 'a b';
  const requiredScopes = 'a    b';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});


test('compareScopes - should match exact scopes in reverse order', () => {
  const scopes = 'a b';
  const requiredScopes = 'b a';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should match when both empty', () => {
  const scopes = '';
  const requiredScopes = '';

  expect(compareScopes(scopes, requiredScopes)).toBe(true);
});

test('compareScopes - should not match when scopes empty', () => {
  const scopes = '';
  const requiredScopes = 'a b c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('compareScopes - should not match when requiredScopes empty', () => {
  const scopes = 'a b';
  const requiredScopes = '';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('compareScopes - should not match when no scope included', () => {
  const scopes = 'a b';
  const requiredScopes = 'c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('compareScopes - should not match when some scopes not included', () => {
  const scopes = 'a b';
  const requiredScopes = 'a b c d';

  expect(compareScopes(scopes, requiredScopes)).toBe(false);
});

test('compareScopes - should not match when scopes is undefined and requiredScopes empty string', () => {
  expect(compareScopes(undefined,'')).toBe(false);
});

test('mergeScopes - should return undefined when both inputs are undefined', () => {
  expect(mergeScopes(undefined, undefined)).toBeUndefined();
});

test('mergeScopes - should return base scope when requested scope is undefined', () => {
  expect(mergeScopes('read write', undefined)).toBe('read write');
});

test('mergeScopes - should return requested scope when base scope is undefined', () => {
  expect(mergeScopes(undefined, 'read write')).toBe('read write');
});

test('mergeScopes - should merge scopes with no overlap', () => {
  expect(mergeScopes('read', 'write')).toBe('read write');
});

test('mergeScopes - should merge scopes with overlap and deduplicate', () => {
  expect(mergeScopes('read write', 'read delete')).toBe('delete read write');
});

test('mergeScopes - should return deduplicated scope when identical', () => {
  expect(mergeScopes('read write', 'read write')).toBe('read write');
});

test('mergeScopes - should handle empty base scope string', () => {
  expect(mergeScopes('', 'read')).toBe('read');
});

test('mergeScopes - should handle empty requested scope string', () => {
  expect(mergeScopes('read', '')).toBe('read');
});

test('mergeScopes - should return undefined when both are empty strings', () => {
  expect(mergeScopes('', '')).toBeUndefined();
});

test('mergeScopes - should trim leading whitespace in base scope', () => {
  expect(mergeScopes('  read', 'write')).toBe('read write');
});

test('mergeScopes - should trim trailing whitespace in base scope', () => {
  expect(mergeScopes('read  ', 'write')).toBe('read write');
});

test('mergeScopes - should trim leading whitespace in requested scope', () => {
  expect(mergeScopes('read', '  write')).toBe('read write');
});

test('mergeScopes - should trim trailing whitespace in requested scope', () => {
  expect(mergeScopes('read', 'write  ')).toBe('read write');
});

test('mergeScopes - should handle multiple spaces between scopes', () => {
  expect(mergeScopes('read   write', 'delete')).toBe('delete read write');
});

test('mergeScopes - should sort scopes alphabetically', () => {
  expect(mergeScopes('z a', 'm b')).toBe('a b m z');
});

test('mergeScopes - should handle single scope in each input', () => {
  expect(mergeScopes('read', 'write')).toBe('read write');
});

test('mergeScopes - should handle many scopes', () => {
  expect(mergeScopes('scope1 scope2 scope3', 'scope4 scope5')).toBe('scope1 scope2 scope3 scope4 scope5');
});

test('mergeScopes - should handle mixed whitespace', () => {
  expect(mergeScopes('  read   write  ', '  delete   modify  ')).toBe('delete modify read write');
});

test('getScopeForAudience - should return undefined when scope is undefined', () => {
  expect(getScopeForAudience(undefined, 'api://v1')).toBeUndefined();
});

test('getScopeForAudience - should return undefined when scope is empty string', () => {
  expect(getScopeForAudience('', 'api://v1')).toBeUndefined();
});

test('getScopeForAudience - should return string scope for any audience', () => {
  expect(getScopeForAudience('read write', 'api://v1')).toBe('read write');
  expect(getScopeForAudience('read write', 'api://v2')).toBe('read write');
});

test('getScopeForAudience - should return audience-specific scope from Record', () => {
  const scope = {
    'api://v1': 'read',
    'api://v2': 'write'
  };
  expect(getScopeForAudience(scope, 'api://v1')).toBe('read');
});

test('getScopeForAudience - should fallback to default key when audience not found', () => {
  const scope = {
    'default': 'read',
    'api://v1': 'write'
  };
  expect(getScopeForAudience(scope, 'api://v2')).toBe('read');
});

test('getScopeForAudience - should return undefined when audience not in Record and no default', () => {
  const scope = {
    'api://v1': 'read'
  };
  expect(getScopeForAudience(scope, 'api://v2')).toBeUndefined();
});

test('getScopeForAudience - should be case-sensitive for audience lookup', () => {
  const scope = {
    'API://V1': 'read'
  };
  expect(getScopeForAudience(scope, 'api://v1')).toBeUndefined();
});

test('getScopeForAudience - should handle empty string audience', () => {
  const scope = {
    'api://v1': 'read',
    '': 'empty-scope'
  };
  expect(getScopeForAudience(scope, '')).toBe('empty-scope');
});

test('getScopeForAudience - should prefer exact match over default', () => {
  const scope = {
    'default': 'read',
    'api://v1': 'write'
  };
  expect(getScopeForAudience(scope, 'api://v1')).toBe('write');
});

test('getScopeForAudience - should handle multiple audiences in Record', () => {
  const scope = {
    'api://v1': 'read',
    'api://v2': 'write',
    'api://v3': 'delete'
  };
  expect(getScopeForAudience(scope, 'api://v3')).toBe('delete');
});

test('ensureDefaultScopes - should return DEFAULT_SCOPES when scope is undefined', () => {
  expect(ensureDefaultScopes(undefined, undefined)).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should return string scope as-is without merging defaults', () => {
  const result = ensureDefaultScopes('read', undefined);
  expect(result).toBe('read');
});

test('ensureDefaultScopes - should return string scope exactly as provided', () => {
  const result = ensureDefaultScopes('openid read', undefined);
  expect(result).toBe('openid read');
});

test('ensureDefaultScopes - should return Record scope as-is and add defaults only for default audience', () => {
  const result = ensureDefaultScopes({ 'api://v1': 'read' }, undefined) as Record<string, string>;
  expect(result['api://v1']).toBe('read');
  expect(result['default']).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should ensure default audience has DEFAULT_SCOPES in Record', () => {
  const result = ensureDefaultScopes({ 'api://v1': 'read' }, undefined) as Record<string, string>;
  expect(result['default']).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should return Record scope as-is when configured audience is already present', () => {
  const result = ensureDefaultScopes({ 'api://v1': 'read' }, 'api://v1') as Record<string, string>;
  expect(result['api://v1']).toBe('read');
});

test('ensureDefaultScopes - should add defaults to configured audience when not in Record', () => {
  const result = ensureDefaultScopes({ 'api://v1': 'read' }, 'api://v2') as Record<string, string>;
  expect(result['api://v2']).toBe(DEFAULT_SCOPES);
  expect(result['api://v1']).toBe('read');
});

test('ensureDefaultScopes - should return multiple audiences as-is and add defaults for default audience', () => {
  const result = ensureDefaultScopes({
    'api://v1': 'read',
    'api://v2': 'write'
  }, undefined) as Record<string, string>;
  expect(result['api://v1']).toBe('read');
  expect(result['api://v2']).toBe('write');
  expect(result['default']).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should handle empty Record', () => {
  const result = ensureDefaultScopes({}, undefined) as Record<string, string>;
  expect(result['default']).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should handle empty Record with explicit audience', () => {
  const result = ensureDefaultScopes({}, 'api://v1') as Record<string, string>;
  expect(result['api://v1']).toBe(DEFAULT_SCOPES);
});

test('ensureDefaultScopes - should return string scope as-is including whitespace', () => {
  const result = ensureDefaultScopes('  read  write  ', undefined);
  expect(result).toBe('  read  write  ');
});

test('ensureDefaultScopes - should return Record audience scope exactly as provided', () => {
  const result = ensureDefaultScopes({
    'api://v1': 'openid profile email offline_access'
  }, undefined) as Record<string, string>;
  expect(result['api://v1']).toBe('openid profile email offline_access');
  expect(result['default']).toBe(DEFAULT_SCOPES);
});

test('resolveScopes - should return undefined when no configuration and no request', () => {
  expect(resolveScopes(undefined, undefined, undefined, undefined)).toBeUndefined();
});

test('resolveScopes - should return configured string scope when no request', () => {
  expect(resolveScopes('read write', undefined, undefined, undefined)).toBe('read write');
});

test('resolveScopes - should merge string scope with requested scope', () => {
  const result = resolveScopes('read', undefined, undefined, 'write');
  expect(result).toBe('read write');
});

test('resolveScopes - should apply string scope to any requested audience', () => {
  expect(resolveScopes('read', undefined, 'api://v1', undefined)).toBe('read');
  expect(resolveScopes('read', undefined, 'api://v2', undefined)).toBe('read');
});

test('resolveScopes - should return audience-specific scope from Record', () => {
  const result = resolveScopes({
    'api://v1': 'read',
    'api://v2': 'write'
  }, undefined, 'api://v1', undefined);
  expect(result).toBe('read');
});

test('resolveScopes - should fallback to default key when audience not in Record', () => {
  const result = resolveScopes({
    'default': 'read',
    'api://v1': 'write'
  }, undefined, 'api://v2', undefined);
  expect(result).toBe('read');
});

test('resolveScopes - should return undefined when audience not in Record and no default', () => {
  const result = resolveScopes({
    'api://v1': 'read'
  }, undefined, 'api://v2', undefined);
  expect(result).toBeUndefined();
});

test('resolveScopes - should merge Record scope with requested scope', () => {
  const result = resolveScopes({
    'api://v1': 'read'
  }, undefined, 'api://v1', 'write');
  expect(result).toBe('read write');
});

test('resolveScopes - should use requested audience over configured audience', () => {
  const result = resolveScopes('read', 'api://v1', 'api://v2', undefined);
  expect(result).toBe('read');
});

test('resolveScopes - should deduplicate scopes when merging', () => {
  const result = resolveScopes('read write', undefined, undefined, 'read delete');
  expect(result).toBe('delete read write');
});

test('resolveScopes - should sort merged scopes alphabetically', () => {
  const result = resolveScopes('z', undefined, undefined, 'a');
  expect(result).toBe('a z');
});

test('resolveScopes - should handle empty string as configured scope', () => {
  const result = resolveScopes('', undefined, undefined, 'read');
  expect(result).toBe('read');
});

test('resolveScopes - should merge multiple scopes from both base and requested', () => {
  const result = resolveScopes('read write', undefined, undefined, 'delete modify');
  expect(result).toBe('delete modify read write');
});

test('resolveScopes - should handle whitespace in Record values', () => {
  const result = resolveScopes({
    'api://v1': '  read  write  '
  }, undefined, 'api://v1', 'execute');
  expect(result).toContain('read');
  expect(result).toContain('write');
  expect(result).toContain('execute');
});

test('resolveScopes - should use DEFAULT_AUDIENCE when no audience specified', () => {
  const result = resolveScopes({
    'default': 'read',
    'api://v1': 'write'
  }, undefined, undefined, undefined);
  expect(result).toBe('read');
});

test('resolveScopes - should use configuredAudience when no requestedAudience', () => {
  const result = resolveScopes({
    'default': 'read',
    'api://v1': 'write'
  }, 'api://v1', undefined, undefined);
  expect(result).toBe('write');
});
