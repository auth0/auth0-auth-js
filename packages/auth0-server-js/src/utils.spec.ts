import { describe, it, expect, test } from 'vitest';
import { mergeScopes, compareScopes } from './utils.js';

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

describe('mergeScopes', () => {
  it('should return undefined when both scopes are undefined', () => {
    expect(mergeScopes()).toBeUndefined();
    expect(mergeScopes(undefined, undefined)).toBeUndefined();
  });

  it('should return undefined when both scopes are empty strings', () => {
    expect(mergeScopes('', '')).toBeUndefined();
    expect(mergeScopes('   ', '   ')).toBeUndefined();
  });

  it('should return the first scope when second is undefined', () => {
    expect(mergeScopes('read:user', undefined)).toBe('read:user');
    expect(mergeScopes('read:user write:user', undefined)).toBe('read:user write:user');
  });

  it('should return the second scope when first is undefined', () => {
    expect(mergeScopes(undefined, 'read:user')).toBe('read:user');
    expect(mergeScopes(undefined, 'read:user write:user')).toBe('read:user write:user');
  });

  it('should return the first scope when second is empty', () => {
    expect(mergeScopes('read:user', '')).toBe('read:user');
    expect(mergeScopes('read:user', '   ')).toBe('read:user');
  });

  it('should return the second scope when first is empty', () => {
    expect(mergeScopes('', 'read:user')).toBe('read:user');
    expect(mergeScopes('   ', 'read:user')).toBe('read:user');
  });

  it('should merge two different scopes', () => {
    expect(mergeScopes('read:user', 'write:user')).toBe('read:user write:user');
    expect(mergeScopes('openid profile', 'email offline_access')).toBe('openid profile email offline_access');
  });

  it('should remove duplicate scopes', () => {
    expect(mergeScopes('read:user', 'read:user')).toBe('read:user');
    expect(mergeScopes('read:user write:user', 'read:user')).toBe('read:user write:user');
    expect(mergeScopes('openid profile', 'profile email')).toBe('openid profile email');
  });

  it('should handle multiple spaces and trim whitespace', () => {
    expect(mergeScopes('  read:user   write:user  ', '  admin:user  ')).toBe('read:user write:user admin:user');
    expect(mergeScopes('read:user\t\twrite:user', 'admin:user')).toBe('read:user write:user admin:user');
    expect(mergeScopes(' read:user ', ' write:user ')).toBe('read:user write:user');
    expect(mergeScopes('read:user  ', '  write:user')).toBe('read:user write:user');
    expect(mergeScopes('read:user\nwrite:user', 'admin:user')).toBe('read:user write:user admin:user');
    expect(mergeScopes('read:user\t \n write:user', 'admin:user')).toBe('read:user write:user admin:user');
  });

  it('should preserve order and remove duplicates', () => {
    expect(mergeScopes('openid profile email', 'profile offline_access')).toBe('openid profile email offline_access');
    expect(mergeScopes('a b c', 'b c d')).toBe('a b c d');
  });

  it('should handle complex real-world scenarios', () => {
    // Common OAuth2/OpenID Connect scopes
    expect(mergeScopes('openid profile', 'email offline_access')).toBe('openid profile email offline_access');
    
    // Auth0 Management API scopes
    expect(mergeScopes('read:users write:users', 'read:users read:roles')).toBe('read:users write:users read:roles');
    
    // Custom API scopes
    expect(mergeScopes('api:read api:write', 'api:read admin:all')).toBe('api:read api:write admin:all');
  });

  it('should handle edge cases with empty scopes in the middle', () => {
    expect(mergeScopes('read:user  write:user', 'admin:user')).toBe('read:user write:user admin:user');
    expect(mergeScopes('read:user   ', '   admin:user')).toBe('read:user admin:user');
  });

  it('should return undefined when all scopes are empty after filtering', () => {
    expect(mergeScopes('   ', '   ')).toBeUndefined();
    expect(mergeScopes('', '')).toBeUndefined();
  });
});

describe('compareScopes', () => {
  it('should return true when both scopes are exactly the same', () => {
    expect(compareScopes('read:user write:user', 'read:user write:user')).toBe(true);
    expect(compareScopes('openid profile email', 'openid profile email')).toBe(true);
    expect(compareScopes('', '')).toBe(true);
    expect(compareScopes(undefined, undefined)).toBe(true);
  });

  it('should return false when one scope is undefined and the other is not', () => {
    expect(compareScopes(undefined, 'read:user')).toBe(false);
    expect(compareScopes('read:user', undefined)).toBe(false);
    expect(compareScopes('', 'read:user')).toBe(false);
    expect(compareScopes('read:user', '')).toBe(false);
  });

  it('should return true when all required scopes are present', () => {
    expect(compareScopes('read:user write:user admin:user', 'read:user write:user')).toBe(true);
    expect(compareScopes('openid profile email offline_access', 'openid profile')).toBe(true);
    expect(compareScopes('a b c d e', 'a c e')).toBe(true);
  });

  it('should return false when not all required scopes are present', () => {
    expect(compareScopes('read:user', 'read:user write:user')).toBe(false);
    expect(compareScopes('openid profile', 'openid profile email')).toBe(false);
    expect(compareScopes('a b c', 'a c d')).toBe(false);
  });

  it('should return true when required scopes is a subset regardless of order', () => {
    expect(compareScopes('write:user read:user admin:user', 'read:user write:user')).toBe(true);
    expect(compareScopes('email profile openid offline_access', 'profile openid')).toBe(true);
    expect(compareScopes('c a e b d', 'a c e')).toBe(true);
  });

  it('should handle whitespace correctly', () => {
    expect(compareScopes('  read:user   write:user  ', 'read:user write:user')).toBe(true);
    expect(compareScopes('read:user write:user', '  read:user   write:user  ')).toBe(true);
    expect(compareScopes('  read:user   write:user  admin:user  ', '  read:user   write:user  ')).toBe(true);
  });

  it('should handle empty scopes after trimming', () => {
    expect(compareScopes('read:user  write:user', 'read:user write:user')).toBe(true);
    expect(compareScopes('read:user   ', 'read:user')).toBe(true);
    expect(compareScopes('   read:user', 'read:user')).toBe(true);
  });

  it('should return false for completely different scopes', () => {
    expect(compareScopes('read:user write:user', 'admin:user delete:user')).toBe(false);
    expect(compareScopes('openid profile', 'email offline_access')).toBe(false);
    expect(compareScopes('a b c', 'd e f')).toBe(false);
  });

  it('should handle single scope comparisons', () => {
    expect(compareScopes('read:user', 'read:user')).toBe(true);
    expect(compareScopes('read:user write:user', 'read:user')).toBe(true);
    expect(compareScopes('read:user', 'write:user')).toBe(false);
  });

  it('should handle real-world OAuth2/OpenID Connect scenarios', () => {
    // Basic OpenID Connect flow
    expect(compareScopes('openid profile email', 'openid')).toBe(true);
    expect(compareScopes('openid profile email offline_access', 'openid profile')).toBe(true);
    
    // Auth0 Management API scopes
    expect(compareScopes('read:users write:users read:roles', 'read:users')).toBe(true);
    expect(compareScopes('read:users write:users', 'read:users write:users delete:users')).toBe(false);
    
    // Custom API scopes
    expect(compareScopes('api:read api:write admin:all', 'api:read api:write')).toBe(true);
    expect(compareScopes('api:read', 'api:read api:write')).toBe(false);
  });

  it('should handle duplicate scopes correctly', () => {
    expect(compareScopes('read:user read:user write:user', 'read:user')).toBe(true);
    expect(compareScopes('read:user write:user', 'read:user read:user')).toBe(true);
    expect(compareScopes('a a b b c', 'a b')).toBe(true);
  });

  it('should be case sensitive', () => {
    expect(compareScopes('Read:User', 'read:user')).toBe(false);
    expect(compareScopes('OPENID PROFILE', 'openid profile')).toBe(false);
    expect(compareScopes('read:user', 'Read:User')).toBe(false);
  });
});
