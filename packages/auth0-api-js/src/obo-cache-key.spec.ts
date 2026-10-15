import { describe, expect, test } from 'vitest';
import {
  buildOboIndexKey,
  buildOboTokenKey,
  deriveSessionKey,
  hasUnkeyableClaims,
  type OboCacheKeyInput,
} from './obo-cache-key.js';
import type { VerifiedAccessTokenClaims } from './types.js';
import type { VerifiedToken } from './token-store.js';

const TOKEN_KEY_FORMAT = /^a0\.obo\.v1\.(strict|index)\.[A-Za-z0-9_-]{43}$/;
const INDEX_KEY_FORMAT = /^a0\.obo\.index\.v1\.[A-Za-z0-9_-]{43}$/;

type Claims = Record<string, unknown>;

const baseClaims: Claims = {
  iss: 'https://issuer.example.com/',
  client_id: 'subject-client',
  sub: 'user|123',
  org_id: 'org_abc',
  sid: 'session-1',
};

function makeVerified(claims: Claims, accessToken = 'access-token-1'): VerifiedToken {
  return { accessToken, claims: claims as VerifiedToken['claims'] };
}

function makeInput(overrides: Partial<OboCacheKeyInput> = {}, claims: Claims = baseClaims): OboCacheKeyInput {
  return {
    exchangeTenant: 'https://tenant.example.com',
    exchangeClientId: 'exchange-client',
    exchangeAudience: 'https://mcp.example.com',
    verified: makeVerified(claims),
    requestedAudience: 'https://downstream.example.com',
    layout: 'strict',
    scope: 'read:a write:a',
    ...overrides,
  };
}

/**
 * Builds a token key from the baseline input with the given claim overrides applied.
 * A value of `MISSING` removes the claim entirely.
 */
const MISSING = Symbol('missing');

function keyWithClaims(patch: Record<string, unknown | typeof MISSING>, accessToken?: string): string {
  const claims: Claims = { ...baseClaims };
  for (const [name, value] of Object.entries(patch)) {
    if (value === MISSING) {
      delete claims[name];
    } else {
      claims[name] = value;
    }
  }
  return buildOboTokenKey({ ...makeInput({}, claims), verified: makeVerified(claims, accessToken) });
}

describe('buildOboTokenKey', () => {
  describe('format', () => {
    test('strict token keys use the versioned strict namespace with a 43 character digest', () => {
      const key = buildOboTokenKey(makeInput({ layout: 'strict' }));
      expect(key).toMatch(TOKEN_KEY_FORMAT);
      expect(key.startsWith('a0.obo.v1.strict.')).toBe(true);
    });

    test('index layout token keys use the versioned index namespace with a 43 character digest', () => {
      const key = buildOboTokenKey(makeInput({ layout: 'index' }));
      expect(key).toMatch(TOKEN_KEY_FORMAT);
      expect(key.startsWith('a0.obo.v1.index.')).toBe(true);
    });

    test('keys contain no padding or characters outside the base64url alphabet', () => {
      const keys = [
        buildOboTokenKey(makeInput()),
        buildOboTokenKey(makeInput({ layout: 'index', scope: undefined })),
        buildOboTokenKey(makeInput({ exchangeTenant: undefined })),
        buildOboIndexKey(makeInput()),
      ];
      for (const key of keys) {
        expect(key).not.toContain('=');
        expect(key).not.toContain('+');
        expect(key).not.toContain('/');
      }
    });

    test('index keys use the versioned index key namespace with a 43 character digest', () => {
      const key = buildOboIndexKey(makeInput());
      expect(key).toMatch(INDEX_KEY_FORMAT);
    });

    test('keys carry no claim value in the clear', () => {
      const key = buildOboTokenKey(makeInput());
      expect(key).not.toContain('user|123');
      expect(key).not.toContain('org_abc');
      expect(key).not.toContain('session-1');
      expect(key).not.toContain('example.com');
    });
  });

  describe('determinism', () => {
    test('the same input gives the same token key', () => {
      expect(buildOboTokenKey(makeInput())).toBe(buildOboTokenKey(makeInput()));
    });

    test('the same input gives the same index key', () => {
      expect(buildOboIndexKey(makeInput())).toBe(buildOboIndexKey(makeInput()));
    });
  });

  describe('slot independence', () => {
    const baseline = () => buildOboTokenKey(makeInput());

    test('exchangeTenant is part of the key', () => {
      expect(buildOboTokenKey(makeInput({ exchangeTenant: 'https://other-tenant.example.com' }))).not.toBe(baseline());
    });

    test('exchangeClientId is part of the key', () => {
      expect(buildOboTokenKey(makeInput({ exchangeClientId: 'other-exchange-client' }))).not.toBe(baseline());
    });

    test('exchangeAudience is part of the key', () => {
      expect(buildOboTokenKey(makeInput({ exchangeAudience: 'https://other-mcp.example.com' }))).not.toBe(baseline());
    });

    test('iss claim is part of the key', () => {
      expect(keyWithClaims({ iss: 'https://other-issuer.example.com/' })).not.toBe(baseline());
    });

    test('client_id claim is part of the key', () => {
      expect(keyWithClaims({ client_id: 'other-subject-client' })).not.toBe(baseline());
    });

    test('sub claim is part of the key', () => {
      expect(keyWithClaims({ sub: 'user|456' })).not.toBe(baseline());
    });

    test('org_id claim is part of the key', () => {
      expect(keyWithClaims({ org_id: 'org_other' })).not.toBe(baseline());
    });

    test('session key is part of the key', () => {
      expect(keyWithClaims({ sid: 'session-2' })).not.toBe(baseline());
    });

    test('requestedAudience is part of the key', () => {
      expect(buildOboTokenKey(makeInput({ requestedAudience: 'https://other-downstream.example.com' }))).not.toBe(
        baseline()
      );
    });

    test('normalized scope set is part of the key', () => {
      expect(buildOboTokenKey(makeInput({ scope: 'read:a write:b' }))).not.toBe(baseline());
    });

    test('changing each slot in turn yields ten keys distinct from each other and from the baseline', () => {
      const keys = [
        buildOboTokenKey(makeInput({ exchangeTenant: 'https://other-tenant.example.com' })),
        buildOboTokenKey(makeInput({ exchangeClientId: 'other-exchange-client' })),
        buildOboTokenKey(makeInput({ exchangeAudience: 'https://other-mcp.example.com' })),
        keyWithClaims({ iss: 'https://other-issuer.example.com/' }),
        keyWithClaims({ client_id: 'other-subject-client' }),
        keyWithClaims({ sub: 'user|456' }),
        keyWithClaims({ org_id: 'org_other' }),
        keyWithClaims({ sid: 'session-2' }),
        buildOboTokenKey(makeInput({ requestedAudience: 'https://other-downstream.example.com' })),
        buildOboTokenKey(makeInput({ scope: 'read:a write:b' })),
      ];

      expect(keys).toHaveLength(10);
      expect(new Set([...keys, baseline()]).size).toBe(11);
    });
  });

  describe('absent versus empty', () => {
    test('exchangeTenant undefined, empty and populated all give different keys', () => {
      const absent = buildOboTokenKey(makeInput({ exchangeTenant: undefined }));
      const empty = buildOboTokenKey(makeInput({ exchangeTenant: '' }));
      const populated = buildOboTokenKey(makeInput());
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('exchangeClientId undefined, empty and populated all give different keys', () => {
      const absent = buildOboTokenKey(makeInput({ exchangeClientId: undefined }));
      const empty = buildOboTokenKey(makeInput({ exchangeClientId: '' }));
      const populated = buildOboTokenKey(makeInput());
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('exchangeAudience undefined, empty and populated all give different keys', () => {
      const absent = buildOboTokenKey(makeInput({ exchangeAudience: undefined }));
      const empty = buildOboTokenKey(makeInput({ exchangeAudience: '' }));
      const populated = buildOboTokenKey(makeInput());
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('iss claim missing, empty and populated all give different keys', () => {
      const absent = keyWithClaims({ iss: MISSING });
      const empty = keyWithClaims({ iss: '' });
      const populated = keyWithClaims({});
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('client_id claim missing, empty and populated all give different keys', () => {
      const absent = keyWithClaims({ client_id: MISSING });
      const empty = keyWithClaims({ client_id: '' });
      const populated = keyWithClaims({});
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('sub claim missing, empty and populated all give different keys', () => {
      const absent = keyWithClaims({ sub: MISSING });
      const empty = keyWithClaims({ sub: '' });
      const populated = keyWithClaims({});
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('org_id claim missing, empty and populated all give different keys', () => {
      const absent = keyWithClaims({ org_id: MISSING });
      const empty = keyWithClaims({ org_id: '' });
      const populated = keyWithClaims({});
      expect(new Set([absent, empty, populated]).size).toBe(3);
    });

    test('a value of the absent marker character is not confused with an absent field', () => {
      const absent = keyWithClaims({ org_id: MISSING });
      const dash = keyWithClaims({ org_id: '-' });
      expect(dash).not.toBe(absent);
    });
  });

  describe('non-string claims', () => {
    test('a numeric sub is treated as absent', () => {
      expect(keyWithClaims({ sub: 42 })).toBe(keyWithClaims({ sub: MISSING }));
    });

    test('a numeric zero sub is treated as absent', () => {
      expect(keyWithClaims({ sub: 0 })).toBe(keyWithClaims({ sub: MISSING }));
    });

    test('a boolean false org_id is treated as absent', () => {
      expect(keyWithClaims({ org_id: false })).toBe(keyWithClaims({ org_id: MISSING }));
    });

    test('a boolean true org_id is treated as absent', () => {
      expect(keyWithClaims({ org_id: true })).toBe(keyWithClaims({ org_id: MISSING }));
    });

    test('a null org_id is treated as absent', () => {
      expect(keyWithClaims({ org_id: null })).toBe(keyWithClaims({ org_id: MISSING }));
    });

    test('an object iss is treated as absent', () => {
      expect(keyWithClaims({ iss: { nested: true } })).toBe(keyWithClaims({ iss: MISSING }));
    });

    test('an array client_id is treated as absent', () => {
      expect(keyWithClaims({ client_id: ['a'] })).toBe(keyWithClaims({ client_id: MISSING }));
    });

    test('a non-string value is not the same as an empty string', () => {
      expect(keyWithClaims({ sub: 0 })).not.toBe(keyWithClaims({ sub: '' }));
      expect(keyWithClaims({ org_id: false })).not.toBe(keyWithClaims({ org_id: '' }));
    });

    test('a non-string client_id falls through to azp', () => {
      expect(keyWithClaims({ client_id: 0, azp: 'azp-client' })).toBe(
        keyWithClaims({ client_id: MISSING, azp: 'azp-client' })
      );
    });
  });

  describe('field boundary injectivity', () => {
    test('a separator character inside sub does not shift into org_id', () => {
      const a = keyWithClaims({ sub: 'a\u001fb', org_id: 'c' });
      const b = keyWithClaims({ sub: 'a', org_id: 'b\u001fc' });
      expect(a).not.toBe(b);
    });

    test('moving characters between adjacent fields changes the key', () => {
      const a = keyWithClaims({ iss: 'ab', client_id: 'c' });
      const b = keyWithClaims({ iss: 'a', client_id: 'bc' });
      expect(a).not.toBe(b);
    });

    test('a literal colon inside a value does not collide with a different value', () => {
      const a = keyWithClaims({ sub: 'user:1' });
      const b = keyWithClaims({ sub: 'user1' });
      const c = keyWithClaims({ sub: 'user' });
      expect(new Set([a, b, c]).size).toBe(3);
    });

    test('a value that looks like a length prefix does not collide with the bare value', () => {
      const prefixed = keyWithClaims({ sub: '3:abc' });
      const bare = keyWithClaims({ sub: 'abc' });
      expect(prefixed).not.toBe(bare);
    });

    test('a value that embeds a length prefix and a separator does not impersonate two fields', () => {
      const embedded = keyWithClaims({ sub: 'x\u001f6:org_ab', org_id: MISSING });
      const split = keyWithClaims({ sub: 'x', org_id: 'org_ab' });
      expect(embedded).not.toBe(split);
    });

    test('an empty field next to a populated one differs from the swapped arrangement', () => {
      const a = keyWithClaims({ sub: '', org_id: 'x' });
      const b = keyWithClaims({ sub: 'x', org_id: '' });
      expect(a).not.toBe(b);
    });
  });

  describe('client_id to azp fallback', () => {
    test('client_id wins over azp when both are present', () => {
      expect(keyWithClaims({ client_id: 'c1', azp: 'a1' })).toBe(keyWithClaims({ client_id: 'c1', azp: 'other' }));
      expect(keyWithClaims({ client_id: 'c1', azp: 'a1' })).toBe(keyWithClaims({ client_id: 'c1', azp: MISSING }));
    });

    test('a missing client_id falls back to azp', () => {
      expect(keyWithClaims({ client_id: MISSING, azp: 'a1' })).toBe(keyWithClaims({ client_id: 'a1', azp: MISSING }));
    });

    test('an empty client_id does not fall back to azp', () => {
      const emptyWithAzp = keyWithClaims({ client_id: '', azp: 'x' });
      expect(emptyWithAzp).toBe(keyWithClaims({ client_id: '', azp: MISSING }));
      expect(emptyWithAzp).not.toBe(keyWithClaims({ client_id: 'x', azp: MISSING }));
    });

    test('neither client_id nor azp behaves as absent', () => {
      const neither = keyWithClaims({ client_id: MISSING, azp: MISSING });
      expect(neither).not.toBe(keyWithClaims({ client_id: '', azp: MISSING }));
      expect(neither).not.toBe(keyWithClaims({}));
    });
  });

  describe('session key', () => {
    const noSession = { sid: MISSING, jti: MISSING };

    test('sid wins over jti', () => {
      expect(keyWithClaims({ sid: 's1', jti: 'j1' })).toBe(keyWithClaims({ sid: 's1', jti: 'j2' }));
      expect(keyWithClaims({ sid: 's1', jti: 'j1' })).toBe(keyWithClaims({ sid: 's1', jti: MISSING }));
    });

    test('an empty sid falls through to jti', () => {
      expect(keyWithClaims({ sid: '', jti: 'j1' })).toBe(keyWithClaims({ sid: MISSING, jti: 'j1' }));
    });

    test('an empty sid and an empty jti fall through to the access token hash', () => {
      expect(keyWithClaims({ sid: '', jti: '' }, 'tok-a')).toBe(keyWithClaims(noSession, 'tok-a'));
      expect(keyWithClaims({ sid: '', jti: '' }, 'tok-a')).not.toBe(keyWithClaims({ sid: '', jti: '' }, 'tok-b'));
    });

    test('a non-string sid falls through to jti', () => {
      expect(keyWithClaims({ sid: 42, jti: 'j1' })).toBe(keyWithClaims({ sid: MISSING, jti: 'j1' }));
    });

    test('a non-string sid and jti fall through to the access token hash', () => {
      expect(keyWithClaims({ sid: 42, jti: false }, 'tok-a')).toBe(keyWithClaims(noSession, 'tok-a'));
    });

    test('the same value as sid and as jti gives different keys', () => {
      expect(keyWithClaims({ sid: 'v', jti: MISSING })).not.toBe(keyWithClaims({ sid: MISSING, jti: 'v' }));
    });

    test('without sid or jti, different access tokens give different keys', () => {
      expect(keyWithClaims(noSession, 'tok-a')).not.toBe(keyWithClaims(noSession, 'tok-b'));
    });

    test('without sid or jti, the same access token gives the same key', () => {
      expect(keyWithClaims(noSession, 'tok-a')).toBe(keyWithClaims(noSession, 'tok-a'));
    });

    test('the access token is ignored when sid is present', () => {
      expect(keyWithClaims({ sid: 's1' }, 'tok-a')).toBe(keyWithClaims({ sid: 's1' }, 'tok-b'));
    });

    test('the access token is ignored when jti is present and sid is absent', () => {
      expect(keyWithClaims({ sid: MISSING, jti: 'j1' }, 'tok-a')).toBe(
        keyWithClaims({ sid: MISSING, jti: 'j1' }, 'tok-b')
      );
    });
  });

  describe('layout prefix', () => {
    test('the same input under strict and index layouts gives different keys', () => {
      const strict = buildOboTokenKey(makeInput({ layout: 'strict' }));
      const index = buildOboTokenKey(makeInput({ layout: 'index' }));
      expect(strict).not.toBe(index);
    });

    test('the layout prefixes differ while the namespace version is shared', () => {
      const strict = buildOboTokenKey(makeInput({ layout: 'strict' }));
      const index = buildOboTokenKey(makeInput({ layout: 'index' }));
      expect(strict.split('.').slice(0, 4)).toEqual(['a0', 'obo', 'v1', 'strict']);
      expect(index.split('.').slice(0, 4)).toEqual(['a0', 'obo', 'v1', 'index']);
    });
  });

  describe('scope normalization', () => {
    test('reordered scopes give the same key', () => {
      expect(buildOboTokenKey(makeInput({ scope: 'b a c' }))).toBe(buildOboTokenKey(makeInput({ scope: 'c b a' })));
    });

    test('duplicated scopes give the same key', () => {
      expect(buildOboTokenKey(makeInput({ scope: 'a b' }))).toBe(buildOboTokenKey(makeInput({ scope: 'a a b b a' })));
    });

    test('tabs, newlines and runs of spaces separate scopes the same as a single space', () => {
      const expected = buildOboTokenKey(makeInput({ scope: 'a b c' }));
      expect(buildOboTokenKey(makeInput({ scope: 'a\tb\tc' }))).toBe(expected);
      expect(buildOboTokenKey(makeInput({ scope: 'a\nb\nc' }))).toBe(expected);
      expect(buildOboTokenKey(makeInput({ scope: 'a    b     c' }))).toBe(expected);
      expect(buildOboTokenKey(makeInput({ scope: '  a \t\n b   c  ' }))).toBe(expected);
    });

    test('an undefined scope and an empty scope give the same key', () => {
      expect(buildOboTokenKey(makeInput({ scope: undefined }))).toBe(buildOboTokenKey(makeInput({ scope: '' })));
    });

    test('a whitespace only scope gives the same key as an empty scope', () => {
      expect(buildOboTokenKey(makeInput({ scope: '  \t ' }))).toBe(buildOboTokenKey(makeInput({ scope: '' })));
    });

    test('an empty scope set differs from any non-empty scope set', () => {
      expect(buildOboTokenKey(makeInput({ scope: '' }))).not.toBe(buildOboTokenKey(makeInput({ scope: 'a' })));
    });

    test('a strict superset of scopes gives a different key', () => {
      expect(buildOboTokenKey(makeInput({ scope: 'a b' }))).not.toBe(buildOboTokenKey(makeInput({ scope: 'a b c' })));
    });

    test('a strict subset of scopes gives a different key', () => {
      expect(buildOboTokenKey(makeInput({ scope: 'a b c' }))).not.toBe(buildOboTokenKey(makeInput({ scope: 'a b' })));
    });
  });

  describe('bounded length', () => {
    test('a very long sub still gives a key of the baseline length', () => {
      const baseline = buildOboTokenKey(makeInput());
      const long = keyWithClaims({ sub: 'x'.repeat(100000) });
      expect(long.length).toBe(baseline.length);
      expect(long).toMatch(TOKEN_KEY_FORMAT);
    });

    test('a very long scope string still gives a key of the baseline length', () => {
      const baseline = buildOboTokenKey(makeInput());
      const scope = Array.from({ length: 10000 }, (_, i) => `s${i}`)
        .join(' ')
        .padEnd(100000, ' ');
      expect(scope.length).toBe(100000);
      const long = buildOboTokenKey(makeInput({ scope }));
      expect(long.length).toBe(baseline.length);
      expect(long).toMatch(TOKEN_KEY_FORMAT);
    });

    test('a very long single scope token still gives a key of the baseline length', () => {
      const baseline = buildOboTokenKey(makeInput());
      const long = buildOboTokenKey(makeInput({ scope: 's'.repeat(100000) }));
      expect(long.length).toBe(baseline.length);
    });
  });
});

describe('buildOboIndexKey', () => {
  const baseline = () => buildOboIndexKey(makeInput());

  test('ignores the scope set entirely', () => {
    expect(buildOboIndexKey(makeInput({ scope: 'a' }))).toBe(buildOboIndexKey(makeInput({ scope: 'a b c' })));
    expect(buildOboIndexKey(makeInput({ scope: undefined }))).toBe(buildOboIndexKey(makeInput({ scope: 'a' })));
    expect(buildOboIndexKey(makeInput({ scope: '' }))).toBe(buildOboIndexKey(makeInput({ scope: 'a' })));
  });

  test('ignores the layout', () => {
    expect(buildOboIndexKey(makeInput({ layout: 'strict' }))).toBe(buildOboIndexKey(makeInput({ layout: 'index' })));
  });

  test('changes when exchangeTenant changes', () => {
    expect(buildOboIndexKey(makeInput({ exchangeTenant: 'https://other-tenant.example.com' }))).not.toBe(baseline());
  });

  test('changes when exchangeClientId changes', () => {
    expect(buildOboIndexKey(makeInput({ exchangeClientId: 'other-exchange-client' }))).not.toBe(baseline());
  });

  test('changes when exchangeAudience changes', () => {
    expect(buildOboIndexKey(makeInput({ exchangeAudience: 'https://other-mcp.example.com' }))).not.toBe(baseline());
  });

  test('changes when the iss claim changes', () => {
    const claims = { ...baseClaims, iss: 'https://other-issuer.example.com/' };
    expect(buildOboIndexKey(makeInput({}, claims))).not.toBe(baseline());
  });

  test('changes when the client_id claim changes', () => {
    const claims = { ...baseClaims, client_id: 'other-subject-client' };
    expect(buildOboIndexKey(makeInput({}, claims))).not.toBe(baseline());
  });

  test('changes when the sub claim changes', () => {
    const claims = { ...baseClaims, sub: 'user|456' };
    expect(buildOboIndexKey(makeInput({}, claims))).not.toBe(baseline());
  });

  test('changes when the org_id claim changes', () => {
    const claims = { ...baseClaims, org_id: 'org_other' };
    expect(buildOboIndexKey(makeInput({}, claims))).not.toBe(baseline());
  });

  test('changes when the session changes', () => {
    const claims = { ...baseClaims, sid: 'session-2' };
    expect(buildOboIndexKey(makeInput({}, claims))).not.toBe(baseline());
  });

  test('changes when requestedAudience changes', () => {
    expect(buildOboIndexKey(makeInput({ requestedAudience: 'https://other-downstream.example.com' }))).not.toBe(
      baseline()
    );
  });

  test('distinguishes absent from empty for optional identity fields', () => {
    const absent = buildOboIndexKey(makeInput({ exchangeTenant: undefined }));
    const empty = buildOboIndexKey(makeInput({ exchangeTenant: '' }));
    expect(new Set([absent, empty, baseline()]).size).toBe(3);
  });

  test('never equals a token key built from the same input under either layout', () => {
    const input = makeInput();
    const indexKey = buildOboIndexKey(input);
    expect(indexKey).not.toBe(buildOboTokenKey({ ...input, layout: 'strict' }));
    expect(indexKey).not.toBe(buildOboTokenKey({ ...input, layout: 'index' }));
    expect(indexKey).not.toBe(buildOboTokenKey({ ...input, layout: 'strict', scope: undefined }));
    expect(indexKey).not.toBe(buildOboTokenKey({ ...input, layout: 'index', scope: undefined }));
  });

  test('never shares a digest with a token key, because the scope field is not hashed', () => {
    const input = makeInput({ scope: undefined });
    const indexDigest = buildOboIndexKey(input).split('.')[4];
    expect(indexDigest).not.toBe(buildOboTokenKey({ ...input, layout: 'strict' }).split('.')[4]);
  });
});

describe('deriveSessionKey', () => {
  test('returns a sid prefixed value when sid is a non-empty string', () => {
    expect(deriveSessionKey(makeVerified({ sid: 's1', jti: 'j1' }))).toBe('sid:s1');
  });

  test('returns a jti prefixed value when sid is missing', () => {
    expect(deriveSessionKey(makeVerified({ jti: 'j1' }))).toBe('jti:j1');
  });

  test('returns a jti prefixed value when sid is empty', () => {
    expect(deriveSessionKey(makeVerified({ sid: '', jti: 'j1' }))).toBe('jti:j1');
  });

  test('returns a jti prefixed value when sid is not a string', () => {
    expect(deriveSessionKey(makeVerified({ sid: 42, jti: 'j1' }))).toBe('jti:j1');
  });

  test('returns an access token hash when sid and jti are both missing', () => {
    expect(deriveSessionKey(makeVerified({}, 'tok-a'))).toMatch(/^at:[A-Za-z0-9_-]{43}$/);
  });

  test('returns an access token hash when sid and jti are both empty', () => {
    expect(deriveSessionKey(makeVerified({ sid: '', jti: '' }, 'tok-a'))).toMatch(/^at:[A-Za-z0-9_-]{43}$/);
  });

  test('returns an access token hash when sid and jti are both non-strings', () => {
    expect(deriveSessionKey(makeVerified({ sid: 1, jti: {} }, 'tok-a'))).toMatch(/^at:[A-Za-z0-9_-]{43}$/);
  });

  test('the access token hash is stable for one token and differs between tokens', () => {
    const a1 = deriveSessionKey(makeVerified({}, 'tok-a'));
    const a2 = deriveSessionKey(makeVerified({}, 'tok-a'));
    const b = deriveSessionKey(makeVerified({}, 'tok-b'));
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
  });

  test('the access token hash does not contain the token', () => {
    expect(deriveSessionKey(makeVerified({}, 'secret-access-token'))).not.toContain('secret-access-token');
  });

  test('the same value as sid and as jti gives different session keys', () => {
    expect(deriveSessionKey(makeVerified({ sid: 'v' }))).not.toBe(deriveSessionKey(makeVerified({ jti: 'v' })));
  });
});

describe('hasUnkeyableClaims', () => {
  const claimsOf = (claims: Claims) => claims as unknown as VerifiedAccessTokenClaims;
  const keyedClaimNames = ['iss', 'client_id', 'azp', 'sub', 'org_id', 'sid', 'jti'] as const;

  test('claims that are all strings are keyable', () => {
    const allStrings = Object.fromEntries(keyedClaimNames.map((name) => [name, `${name}-value`]));

    expect(hasUnkeyableClaims(claimsOf(allStrings))).toBe(false);
  });

  test('claims with none of the keyed claims present are keyable', () => {
    expect(hasUnkeyableClaims(claimsOf({ aud: 'x', exp: 1, scope: 'read' }))).toBe(false);
  });

  test('an empty claims object is keyable', () => {
    expect(hasUnkeyableClaims(claimsOf({}))).toBe(false);
  });

  test('an empty string is a string and stays keyable', () => {
    expect(hasUnkeyableClaims(claimsOf({ sub: '', sid: '' }))).toBe(false);
  });

  test.each(keyedClaimNames)('%s absent is keyable', (name) => {
    const claims: Claims = Object.fromEntries(keyedClaimNames.map((other) => [other, `${other}-value`]));
    delete claims[name];

    expect(hasUnkeyableClaims(claimsOf(claims))).toBe(false);
  });

  test.each(keyedClaimNames)('%s present as a number is unkeyable', (name) => {
    expect(hasUnkeyableClaims(claimsOf({ ...baseClaims, [name]: 123 }))).toBe(true);
  });

  test.each(keyedClaimNames)('%s present as an object is unkeyable', (name) => {
    expect(hasUnkeyableClaims(claimsOf({ ...baseClaims, [name]: { nested: 'value' } }))).toBe(true);
  });

  test.each(keyedClaimNames)('%s present as null is unkeyable', (name) => {
    expect(hasUnkeyableClaims(claimsOf({ ...baseClaims, [name]: null }))).toBe(true);
  });

  test.each(keyedClaimNames)('%s present as an array is unkeyable', (name) => {
    expect(hasUnkeyableClaims(claimsOf({ ...baseClaims, [name]: ['a'] }))).toBe(true);
  });

  test('a claim the key does not use may hold any type', () => {
    expect(hasUnkeyableClaims(claimsOf({ ...baseClaims, exp: 1, aud: ['x', 'y'], cnf: { jkt: 'x' } }))).toBe(false);
  });
});
