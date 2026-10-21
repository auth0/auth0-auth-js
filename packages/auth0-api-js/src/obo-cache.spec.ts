import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS,
  oboCacheLayout,
  readOboCachedToken,
  writeOboCachedToken,
  type OboCacheAccess,
} from './obo-cache.js';
import { buildOboIndexKey, buildOboTokenKey, type OboCacheKeyIdentity } from './obo-cache-key.js';
import type { CachedToken, IndexedTokenStore, TokenIndexMember, TokenStore } from './token-store.js';
import type { ScopeMatching, VerifiedAccessTokenClaims } from './types.js';

const NOW = 1_700_000_000;
const LEEWAY = OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS;

const identity: OboCacheKeyIdentity = {
  exchangeTenant: 'https://tenant.example.com',
  exchangeClientId: 'client-1',
  exchangeAudience: 'https://mcp.example.com',
  verified: {
    accessToken: 'subject-token',
    claims: { iss: 'https://tenant.example.com/', sub: 'user-1', sid: 'session-1' } as VerifiedAccessTokenClaims,
  },
  requestedAudience: 'https://downstream.example.com',
};

/**
 * In-memory store with call counters and switches that make individual operations throw.
 */
class FakeStore implements TokenStore {
  entries = new Map<string, unknown>();
  calls = { get: 0, set: 0, delete: 0 };
  failGet = false;
  failSet = false;

  async get(key: string): Promise<CachedToken | undefined> {
    this.calls.get++;
    if (this.failGet) {
      throw new Error('get failed');
    }
    return this.entries.get(key) as CachedToken | undefined;
  }

  async set(key: string, value: CachedToken): Promise<void> {
    this.calls.set++;
    if (this.failSet) {
      throw new Error('set failed');
    }
    this.entries.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.calls.delete++;
    this.entries.delete(key);
  }
}

class FakeIndexedStore extends FakeStore implements IndexedTokenStore {
  indexes = new Map<string, unknown[]>();
  indexCalls = { add: 0, list: 0 };
  failList = false;
  failAdd = false;
  listResultOverride: unknown;

  async addIndexMember(indexKey: string, member: TokenIndexMember): Promise<void> {
    this.indexCalls.add++;
    if (this.failAdd) {
      throw new Error('add failed');
    }
    const existing = (this.indexes.get(indexKey) ?? []).filter(
      (candidate) => (candidate as TokenIndexMember).tokenKey !== member.tokenKey
    );
    this.indexes.set(indexKey, [...existing, member]);
  }

  async listIndexMembers(indexKey: string): Promise<TokenIndexMember[]> {
    this.indexCalls.list++;
    if (this.failList) {
      throw new Error('list failed');
    }
    if (this.listResultOverride !== undefined) {
      return this.listResultOverride as TokenIndexMember[];
    }
    return (this.indexes.get(indexKey) ?? []) as TokenIndexMember[];
  }
}

function entry(scopes: string[], overrides: Partial<CachedToken> = {}): CachedToken {
  return {
    accessToken: `token-${scopes.join('+') || 'none'}`,
    expiresAt: NOW + 3600,
    grantedScopes: scopes,
    scope: scopes.join(' '),
    tokenType: 'bearer',
    ...overrides,
  };
}

function access(store: TokenStore, scopeMatching: ScopeMatching): OboCacheAccess {
  return { store, scopeMatching, identity };
}

function keyFor(scopeMatching: ScopeMatching, scopes: string[]): Promise<string> {
  return buildOboTokenKey({ ...identity, layout: oboCacheLayout(scopeMatching), scope: scopes.join(' ') });
}

const indexKey = await buildOboIndexKey(identity);

// Keys are hashed asynchronously, so the ones that describe blocks need while collecting are
// computed once here, where top-level await is available.
const goodKeyAbc = await keyFor('non_strict', ['a', 'b', 'c']);
const goodKeyAb = await keyFor('non_strict', ['a', 'b']);
const placeKeys = {
  strict: await keyFor('strict', ['a']),
  non_strict: await keyFor('non_strict', ['a']),
};

/**
 * Seeds the entry under the key for its granted scopes and, optionally, an index member.
 * The index member can diverge from the entry so tests can model drift between the two.
 */
async function seed(
  store: FakeStore,
  scopeMatching: ScopeMatching,
  value: CachedToken,
  member?: Partial<TokenIndexMember> | false
): Promise<string> {
  const tokenKey = await keyFor(scopeMatching, value.grantedScopes);
  store.entries.set(tokenKey, value);

  if (member !== false && store instanceof FakeIndexedStore) {
    const existing = store.indexes.get(indexKey) ?? [];
    store.indexes.set(indexKey, [
      ...existing,
      { tokenKey, grantedScopes: value.grantedScopes, expiresAt: value.expiresAt, ...member },
    ]);
  }

  return tokenKey;
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW * 1000);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('strict mode read', () => {
  test('returns the stored entry when granted scopes equal the requested set', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a', 'b']);
    await seed(store, 'strict', stored, false);

    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toEqual(stored);
  });

  test('misses when the cached entry granted a strict superset of the request', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'strict', entry(['a', 'b', 'c']), false);

    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toBeUndefined();
  });

  test('misses when the cached entry granted a strict subset of the request', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'strict', entry(['a']), false);

    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toBeUndefined();
  });

  test('misses when the value at the requested key was granted different scopes than the key says', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(await keyFor('strict', ['a', 'b']), entry(['a', 'b', 'c']));

    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(1);
  });

  test('misses when the value at the requested key was granted a subset of what the key says', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(await keyFor('strict', ['a', 'b']), entry(['a']));

    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toBeUndefined();
  });

  test('a request for no scopes hits an entry with no granted scopes', async () => {
    const store = new FakeIndexedStore();
    const stored = entry([]);
    await seed(store, 'strict', stored, false);

    await expect(readOboCachedToken(access(store, 'strict'), [])).resolves.toEqual(stored);
  });

  test('a request for no scopes misses an entry that was granted scopes', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'strict', entry(['a']), false);

    await expect(readOboCachedToken(access(store, 'strict'), [])).resolves.toBeUndefined();
  });

  test('never reads the index', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'strict', entry(['a', 'b', 'c']));

    await readOboCachedToken(access(store, 'strict'), ['a']);
    await readOboCachedToken(access(store, 'strict'), ['a', 'b', 'c']);

    expect(store.indexCalls.list).toBe(0);
  });

  test('does not read entries written under the non-strict key layout', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a']));

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toBeUndefined();
  });
});

describe('non-strict mode read', () => {
  test('hits a covering superset and returns the stored entry', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a', 'b', 'c']);
    await seed(store, 'non_strict', stored);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b'])).resolves.toEqual(stored);
  });

  test('hits an exact match', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a', 'b']);
    await seed(store, 'non_strict', stored);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b'])).resolves.toEqual(stored);
  });

  test('prefers the candidate with the fewest granted scopes', async () => {
    const store = new FakeIndexedStore();
    const widest = entry(['a', 'b', 'c', 'd']);
    const narrowest = entry(['a', 'b']);
    const middle = entry(['a', 'b', 'c']);
    await seed(store, 'non_strict', widest);
    await seed(store, 'non_strict', middle);
    await seed(store, 'non_strict', narrowest);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(narrowest);
  });

  test('resolves candidates with equal scope counts by plain key comparison, regardless of insertion order', async () => {
    // The token key for {a, c} starts with an uppercase letter and the one for {a, e} with a
    // lowercase letter. Code unit order puts uppercase first, so {a, c} must win. A
    // locale-aware comparison orders these two the other way round, so this also pins the
    // comparison as locale independent.
    const first = entry(['a', 'c']);
    const second = entry(['a', 'e']);
    expect((await keyFor('non_strict', ['a', 'c'])).startsWith('a0.obo.v1.index.M')).toBe(true);
    expect((await keyFor('non_strict', ['a', 'e'])).startsWith('a0.obo.v1.index.h')).toBe(true);

    const forward = new FakeIndexedStore();
    await seed(forward, 'non_strict', first);
    await seed(forward, 'non_strict', second);

    const reverse = new FakeIndexedStore();
    await seed(reverse, 'non_strict', second);
    await seed(reverse, 'non_strict', first);

    await expect(readOboCachedToken(access(forward, 'non_strict'), ['a'])).resolves.toEqual(first);
    await expect(readOboCachedToken(access(reverse, 'non_strict'), ['a'])).resolves.toEqual(first);
  });

  test('skips a member that does not cover the request', async () => {
    const store = new FakeIndexedStore();
    const unrelated = entry(['x']);
    const covering = entry(['a', 'b', 'c']);
    await seed(store, 'non_strict', unrelated);
    await seed(store, 'non_strict', covering);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b'])).resolves.toEqual(covering);
  });

  test('misses when no member covers the request', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['x']));
    await seed(store, 'non_strict', entry(['a']));

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b'])).resolves.toBeUndefined();
  });

  test('misses when the index is empty', async () => {
    const store = new FakeIndexedStore();

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('a request for no scopes never reuses a cached token, even when covering entries exist', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a', 'b']));
    await seed(store, 'non_strict', entry([]));

    await expect(readOboCachedToken(access(store, 'non_strict'), [])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
    expect(store.indexCalls.list).toBe(0);
  });

  test('skips a member that is fresh in the index when its stored entry is stale, and tries the next candidate', async () => {
    const store = new FakeIndexedStore();
    const stale = entry(['a', 'b'], { expiresAt: NOW - 10 });
    const fallback = entry(['a', 'b', 'c']);
    await seed(store, 'non_strict', stale, { expiresAt: NOW + 3600 });
    await seed(store, 'non_strict', fallback);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(fallback);
    expect(store.calls.get).toBe(2);
  });

  test('skips a member whose stored entry is missing and tries the next candidate', async () => {
    const store = new FakeIndexedStore();
    const missing = entry(['a', 'b']);
    const fallback = entry(['a', 'b', 'c']);
    const missingKey = await seed(store, 'non_strict', missing);
    store.entries.delete(missingKey);
    await seed(store, 'non_strict', fallback);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(fallback);
  });

  test('skips a member whose stored entry no longer covers the request, trusting the value over the index', async () => {
    const store = new FakeIndexedStore();
    const fallback = entry(['a', 'b', 'c']);
    // The member is honest about its key and scopes, but the value stored at that key was
    // granted something else.
    const driftedKey = await keyFor('non_strict', ['a', 'b']);
    store.entries.set(driftedKey, entry(['x', 'y']));
    store.indexes.set(indexKey, [
      { tokenKey: driftedKey, grantedScopes: ['a', 'b'], expiresAt: NOW + 3600 },
    ]);
    await seed(store, 'non_strict', fallback);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(fallback);
    expect(store.calls.get).toBe(2);
  });

  test('misses when the only member points at an entry that was granted different scopes', async () => {
    const store = new FakeIndexedStore();
    const key = await keyFor('non_strict', ['a']);
    store.entries.set(key, entry(['x']));
    store.indexes.set(indexKey, [{ tokenKey: key, grantedScopes: ['a'], expiresAt: NOW + 3600 }]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(1);
  });

  test('skips a member whose tokenKey is not the key for the scopes it claims, and never reads that key', async () => {
    // A planted member claims to cover the request but points at an entry that belongs to a
    // different identity. The key an identity would write for the claimed scopes does not
    // match, so the member is ignored and the foreign entry is never read.
    const store = new FakeIndexedStore();
    const foreignIdentity: OboCacheKeyIdentity = {
      ...identity,
      verified: {
        accessToken: 'other-subject-token',
        claims: { iss: 'https://tenant.example.com/', sub: 'user-2', sid: 'session-2' } as VerifiedAccessTokenClaims,
      },
    };
    const foreignKey = await buildOboTokenKey({ ...foreignIdentity, layout: 'index', scope: 'a' });
    const foreignEntry = entry(['a'], { accessToken: 'token-belonging-to-user-2' });
    store.entries.set(foreignKey, foreignEntry);
    store.indexes.set(indexKey, [{ tokenKey: foreignKey, grantedScopes: ['a'], expiresAt: NOW + 3600 }]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
  });

  test('a planted member is skipped while an honest sibling in the same index is still served', async () => {
    const store = new FakeIndexedStore();
    const honest = entry(['a', 'b']);
    await seed(store, 'non_strict', honest);
    store.entries.set(await keyFor('strict', ['a']), entry(['a'], { accessToken: 'strict-layout-entry' }));
    store.indexes.set(indexKey, [
      { tokenKey: await keyFor('strict', ['a']), grantedScopes: ['a'], expiresAt: NOW + 3600 },
      ...(store.indexes.get(indexKey) ?? []),
    ] as TokenIndexMember[]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(honest);
    expect(store.calls.get).toBe(1);
  });

  test('skips a member whose claimed scopes do not match its tokenKey, even when the entry there is valid', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['x']), { grantedScopes: ['a'] });

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
  });

  test('misses when the store is not an indexed store', async () => {
    const store = new FakeStore();
    await seed(store, 'non_strict', entry(['a']));

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('does not read entries written under the strict key layout', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(await keyFor('strict', ['a']), entry(['a']));

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });
});

describe('expiry and leeway', () => {
  test.each(['strict', 'non_strict'] as const)('%s: an entry expiring beyond now plus the leeway is a hit', async (mode) => {
    const store = new FakeIndexedStore();
    const stored = entry(['a'], { expiresAt: NOW + LEEWAY + 1 });
    await seed(store, mode, stored);

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toEqual(stored);
  });

  test.each(['strict', 'non_strict'] as const)(
    '%s: an entry expiring at exactly now plus the leeway is a miss',
    async (mode) => {
      const store = new FakeIndexedStore();
      await seed(store, mode, entry(['a'], { expiresAt: NOW + LEEWAY }));

      await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
    }
  );

  test.each(['strict', 'non_strict'] as const)('%s: an entry inside the leeway window is a miss', async (mode) => {
    const store = new FakeIndexedStore();
    await seed(store, mode, entry(['a'], { expiresAt: NOW + LEEWAY - 1 }));

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test.each(['strict', 'non_strict'] as const)('%s: an already expired entry is a miss', async (mode) => {
    const store = new FakeIndexedStore();
    await seed(store, mode, entry(['a'], { expiresAt: NOW - 1 }));

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test('non-strict: a fresh index member with a stored entry inside the leeway window is a miss', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a'], { expiresAt: NOW + LEEWAY }), { expiresAt: NOW + 3600 });

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(1);
  });

  test('non-strict: an index member inside the leeway window with a fresh stored entry is a miss', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a'], { expiresAt: NOW + 3600 }), { expiresAt: NOW + LEEWAY });

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
  });

  test('non-strict: the index member and the stored entry both just past the leeway window are a hit', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a'], { expiresAt: NOW + LEEWAY + 1 });
    await seed(store, 'non_strict', stored, { expiresAt: NOW + LEEWAY + 1 });

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(stored);
  });

  test('the leeway is five seconds', () => {
    expect(OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS).toBe(5);
  });

  test('time advancing past the leeway window turns a hit into a miss', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'strict', entry(['a'], { expiresAt: NOW + 60 }), false);

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toBeDefined();

    vi.setSystemTime((NOW + 56) * 1000);

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toBeUndefined();
  });
});

describe('failing open on read', () => {
  test.each(['strict', 'non_strict'] as const)('%s: store.get throwing is a miss', async (mode) => {
    const store = new FakeIndexedStore();
    await seed(store, mode, entry(['a']));
    store.failGet = true;

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test('non-strict: listIndexMembers throwing is a miss', async () => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a']));
    store.failList = true;

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
  });

  test.each([
    ['a string', 'members'],
    ['an object', {}],
    ['null', null],
    ['a number', 7],
  ])('non-strict: listIndexMembers returning %s is a miss', async (_name, result) => {
    const store = new FakeIndexedStore();
    await seed(store, 'non_strict', entry(['a']));
    store.listResultOverride = result;

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('non-strict: a get that throws for one candidate does not hide the next one', async () => {
    const store = new FakeIndexedStore();
    const first = entry(['a', 'b']);
    const second = entry(['a', 'b', 'c']);
    const firstKey = await seed(store, 'non_strict', first);
    await seed(store, 'non_strict', second);

    const originalGet = store.get.bind(store);
    store.get = async (key: string) => {
      if (key === firstKey) {
        throw new Error('get failed');
      }
      return originalGet(key);
    };

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(second);
  });
});

describe('entry shape validation on read', () => {
  const valid = (): Record<string, unknown> => ({ ...entry(['a']) });
  const without = (value: Record<string, unknown>, field: string): Record<string, unknown> => {
    const copy = { ...value };
    delete copy[field];
    return copy;
  };

  const cases: Array<[string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['a string', 'token'],
    ['a number', 42],
    ['a boolean', true],
    ['a missing accessToken', without(valid(), 'accessToken')],
    ['a non-string accessToken', { ...valid(), accessToken: 123 }],
    ['an empty accessToken', { ...valid(), accessToken: '' }],
    ['a missing expiresAt', without(valid(), 'expiresAt')],
    ['a string expiresAt', { ...valid(), expiresAt: String(NOW + 3600) }],
    ['a NaN expiresAt', { ...valid(), expiresAt: NaN }],
    ['an Infinity expiresAt', { ...valid(), expiresAt: Infinity }],
    ['a missing grantedScopes', without(valid(), 'grantedScopes')],
    ['a string grantedScopes', { ...valid(), grantedScopes: 'a' }],
    ['an object grantedScopes', { ...valid(), grantedScopes: { 0: 'a', length: 1 } }],
    ['a grantedScopes array with a non-string element', { ...valid(), grantedScopes: ['a', 2] }],
    ['a grantedScopes array with a null element', { ...valid(), grantedScopes: ['a', null] }],
    ['a sparse grantedScopes array built with new Array', { ...valid(), grantedScopes: new Array(2) }],
    ['a sparse grantedScopes array with one hole', { ...valid(), grantedScopes: Object.assign(new Array(2), { 0: 'a' }) }],
    ['a non-string scope', { ...valid(), scope: 5 }],
    ['a non-string tokenType', { ...valid(), tokenType: 5 }],
    ['a non-string issuedTokenType', { ...valid(), issuedTokenType: 5 }],
  ];

  test.each(cases)('strict: %s is a miss and does not throw', async (_name, value) => {
    const store = new FakeIndexedStore();
    store.entries.set(await keyFor('strict', ['a']), value);

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toBeUndefined();
  });

  test.each(cases)('non-strict: %s is a miss and does not throw', async (_name, value) => {
    const store = new FakeIndexedStore();
    const tokenKey = await keyFor('non_strict', ['a']);
    store.entries.set(tokenKey, value);
    store.indexes.set(indexKey, [{ tokenKey, grantedScopes: ['a'], expiresAt: NOW + 3600 }]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('a valid entry with only the required fields is a hit', async () => {
    const store = new FakeIndexedStore();
    const minimal: CachedToken = { accessToken: 't', expiresAt: NOW + 3600, grantedScopes: ['a'] };
    store.entries.set(await keyFor('strict', ['a']), minimal);

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toEqual(minimal);
  });
});

describe('index member shape validation on read', () => {
  const goodEntry = entry(['a', 'b', 'c']);
  const goodKey = goodKeyAbc;
  const goodMember = { tokenKey: goodKey, grantedScopes: goodEntry.grantedScopes, expiresAt: goodEntry.expiresAt };

  const malformed: Array<[string, unknown]> = [
    ['null', null],
    ['a string', 'member'],
    ['a number', 1],
    ['a missing tokenKey', { grantedScopes: ['a'], expiresAt: NOW + 3600 }],
    ['a non-string tokenKey', { tokenKey: 5, grantedScopes: ['a'], expiresAt: NOW + 3600 }],
    ['an empty tokenKey', { tokenKey: '', grantedScopes: ['a'], expiresAt: NOW + 3600 }],
    ['a NaN expiresAt', { tokenKey: 'k', grantedScopes: ['a'], expiresAt: NaN }],
    ['an Infinity expiresAt', { tokenKey: 'k', grantedScopes: ['a'], expiresAt: Infinity }],
    ['a string expiresAt', { tokenKey: 'k', grantedScopes: ['a'], expiresAt: '99999999999' }],
    ['a missing expiresAt', { tokenKey: 'k', grantedScopes: ['a'] }],
    ['a non-array grantedScopes', { tokenKey: 'k', grantedScopes: 'a', expiresAt: NOW + 3600 }],
    ['a sparse grantedScopes array', { tokenKey: 'k', grantedScopes: new Array(2), expiresAt: NOW + 3600 }],
    ['a grantedScopes array with a non-string element', { tokenKey: 'k', grantedScopes: ['a', 3], expiresAt: NOW + 3600 }],
  ];

  test.each(malformed)('%s is skipped and a well-formed sibling is still used', async (_name, bad) => {
    const store = new FakeIndexedStore();
    store.entries.set(goodKey, goodEntry);
    store.indexes.set(indexKey, [bad, goodMember]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(goodEntry);
  });

  test.each(malformed)('%s alone is a miss and does not throw', async (_name, bad) => {
    const store = new FakeIndexedStore();
    store.indexes.set(indexKey, [bad]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });
});

describe('write', () => {
  test('strict: stores the entry under the key for its granted scopes', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a', 'b']);

    await writeOboCachedToken(access(store, 'strict'), stored);

    expect([...store.entries.keys()]).toEqual([await keyFor('strict', ['a', 'b'])]);
    expect(store.entries.get(await keyFor('strict', ['a', 'b']))).toBe(stored);
  });

  test('strict: does not write an index member even when the store supports it', async () => {
    const store = new FakeIndexedStore();

    await writeOboCachedToken(access(store, 'strict'), entry(['a']));

    expect(store.indexCalls.add).toBe(0);
    expect(store.indexes.size).toBe(0);
  });

  test('keys the entry by the scopes it was granted rather than the scopes that were requested', async () => {
    const store = new FakeIndexedStore();
    const narrowed = entry(['a']);

    await writeOboCachedToken(access(store, 'strict'), narrowed);

    await expect(readOboCachedToken(access(store, 'strict'), ['a'])).resolves.toEqual(narrowed);
    await expect(readOboCachedToken(access(store, 'strict'), ['a', 'b'])).resolves.toBeUndefined();
  });

  test('non-strict: stores the entry and records an index member that matches it', async () => {
    const store = new FakeIndexedStore();
    const stored = entry(['a', 'b'], { expiresAt: NOW + 1234 });

    await writeOboCachedToken(access(store, 'non_strict'), stored);

    const tokenKey = await keyFor('non_strict', ['a', 'b']);
    expect(store.entries.get(tokenKey)).toBe(stored);
    expect(store.indexes.get(indexKey)).toEqual([
      { tokenKey, grantedScopes: ['a', 'b'], expiresAt: NOW + 1234 },
    ]);
  });

  test('non-strict: a grant narrower than the request is indexed under what was granted and serves a later narrower request', async () => {
    const store = new FakeIndexedStore();
    // Imagine the request was for a, b, c, d and the server granted only a, b, c.
    const narrowed = entry(['a', 'b', 'c']);

    await writeOboCachedToken(access(store, 'non_strict'), narrowed);

    expect(store.indexes.get(indexKey)).toEqual([
      { tokenKey: await keyFor('non_strict', ['a', 'b', 'c']), grantedScopes: ['a', 'b', 'c'], expiresAt: narrowed.expiresAt },
    ]);
    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b'])).resolves.toEqual(narrowed);
    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b', 'c'])).resolves.toEqual(narrowed);
    await expect(readOboCachedToken(access(store, 'non_strict'), ['a', 'b', 'c', 'd'])).resolves.toBeUndefined();
  });

  test('non-strict: writing the same scopes twice leaves one index member', async () => {
    const store = new FakeIndexedStore();

    await writeOboCachedToken(access(store, 'non_strict'), entry(['a'], { accessToken: 'first' }));
    await writeOboCachedToken(access(store, 'non_strict'), entry(['a'], { accessToken: 'second' }));

    expect(store.indexes.get(indexKey)).toHaveLength(1);
    expect(store.entries.get(await keyFor('non_strict', ['a']))).toMatchObject({ accessToken: 'second' });
  });

  test('non-strict: a plain store receives the entry and no index write', async () => {
    const store = new FakeStore();

    await writeOboCachedToken(access(store, 'non_strict'), entry(['a']));

    expect(store.calls.set).toBe(1);
  });
});

describe('failing open on write', () => {
  test.each(['strict', 'non_strict'] as const)('%s: store.set throwing does not propagate', async (mode) => {
    const store = new FakeIndexedStore();
    store.failSet = true;

    await expect(writeOboCachedToken(access(store, mode), entry(['a']))).resolves.toBeUndefined();
    expect(store.entries.size).toBe(0);
  });

  test.each(['strict', 'non_strict'] as const)(
    '%s: a failure to compute the cache key does not propagate and writes nothing',
    async (mode) => {
      const store = new FakeIndexedStore();
      vi.stubGlobal('crypto', {});

      try {
        await expect(writeOboCachedToken(access(store, mode), entry(['a']))).resolves.toBeUndefined();
      } finally {
        vi.unstubAllGlobals();
      }

      expect(store.calls.set).toBe(0);
      expect(store.indexCalls.add).toBe(0);
    }
  );

  test('non-strict: store.set throwing skips the index write', async () => {
    const store = new FakeIndexedStore();
    store.failSet = true;

    await writeOboCachedToken(access(store, 'non_strict'), entry(['a']));

    expect(store.indexCalls.add).toBe(0);
  });

  test('non-strict: addIndexMember throwing does not propagate and keeps the entry that was written', async () => {
    const store = new FakeIndexedStore();
    store.failAdd = true;
    const stored = entry(['a']);

    await expect(writeOboCachedToken(access(store, 'non_strict'), stored)).resolves.toBeUndefined();

    expect(store.indexCalls.add).toBe(1);
    expect(store.entries.get(await keyFor('non_strict', ['a']))).toBe(stored);
  });
});

describe('hostile store entries', () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).accessToken;
  });

  const modes = ['strict', 'non_strict'] as const;

  function place(store: FakeIndexedStore, mode: ScopeMatching, value: unknown): void {
    const tokenKey = placeKeys[mode];
    store.entries.set(tokenKey, value);
    if (mode === 'non_strict') {
      store.indexes.set(indexKey, [{ tokenKey, grantedScopes: ['a'], expiresAt: NOW + 3600 }]);
    }
  }

  test.each(modes)('%s: an entry whose getter throws is a miss and nothing propagates', async (mode) => {
    const store = new FakeIndexedStore();
    const hostile = { expiresAt: NOW + 3600, grantedScopes: ['a'] };
    Object.defineProperty(hostile, 'accessToken', {
      enumerable: true,
      get() {
        throw new Error('getter exploded');
      },
    });
    place(store, mode, hostile);

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test.each(modes)('%s: a getter on an optional field that throws is a miss', async (mode) => {
    const store = new FakeIndexedStore();
    const hostile = { accessToken: 't', expiresAt: NOW + 3600, grantedScopes: ['a'] };
    Object.defineProperty(hostile, 'scope', {
      enumerable: true,
      get() {
        throw new Error('getter exploded');
      },
    });
    place(store, mode, hostile);

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test.each(modes)('%s: a getter that returns a string once and an object afterwards yields only a plain string', async (mode) => {
    const store = new FakeIndexedStore();
    let reads = 0;
    const hostile = { expiresAt: NOW + 3600, grantedScopes: ['a'] };
    Object.defineProperty(hostile, 'accessToken', {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? 'first-read-token' : { smuggled: true };
      },
    });
    place(store, mode, hostile);

    const result = await readOboCachedToken(access(store, mode), ['a']);

    expect(result).toEqual({ accessToken: 'first-read-token', expiresAt: NOW + 3600, grantedScopes: ['a'] });
    expect(typeof result?.accessToken).toBe('string');
    expect(reads).toBe(1);
  });

  test.each(modes)('%s: the returned entry is a copy, not the object the store held', async (mode) => {
    const store = new FakeIndexedStore();
    const stored = entry(['a']);
    place(store, mode, stored);

    const result = await readOboCachedToken(access(store, mode), ['a']);

    expect(result).toEqual(stored);
    expect(result).not.toBe(stored);
    expect(result?.grantedScopes).not.toBe(stored.grantedScopes);
  });

  test.each(modes)('%s: mutating the store object after the read does not change the returned entry', async (mode) => {
    const store = new FakeIndexedStore();
    const stored = entry(['a']);
    place(store, mode, stored);

    const result = await readOboCachedToken(access(store, mode), ['a']);
    stored.accessToken = 'changed-after-read';
    stored.grantedScopes.push('z');

    expect(result?.accessToken).toBe('token-a');
    expect(result?.grantedScopes).toEqual(['a']);
  });

  test.each(modes)('%s: an entry whose fields live only on its prototype is a miss', async (mode) => {
    const store = new FakeIndexedStore();
    place(store, mode, Object.create({ ...entry(['a']) }));

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test.each(modes)('%s: a polluted Object.prototype cannot supply a missing accessToken', async (mode) => {
    Object.defineProperty(Object.prototype, 'accessToken', {
      value: 'inherited-token',
      configurable: true,
      enumerable: false,
      writable: true,
    });
    const store = new FakeIndexedStore();
    place(store, mode, { expiresAt: NOW + 3600, grantedScopes: ['a'] });

    await expect(readOboCachedToken(access(store, mode), ['a'])).resolves.toBeUndefined();
  });

  test('strict: a record carrying more than 1000 scopes is a miss even when its key matches the request exactly', async () => {
    const store = new FakeIndexedStore();
    const scopes = Array.from({ length: 1001 }, (_, i) => `s${String(i).padStart(4, '0')}`);
    store.entries.set(await keyFor('strict', scopes), entry(scopes));

    await expect(readOboCachedToken(access(store, 'strict'), scopes)).resolves.toBeUndefined();
  });

  test('non-strict: a record carrying more than 1000 scopes is a miss even though it covers the request', async () => {
    const store = new FakeIndexedStore();
    const scopes = ['a', ...Array.from({ length: 1000 }, (_, i) => `s${String(i).padStart(4, '0')}`)];
    // The member is honest and small. Only the stored record is oversized.
    const tokenKey = await keyFor('non_strict', ['a']);
    store.entries.set(tokenKey, entry(scopes));
    store.indexes.set(indexKey, [{ tokenKey, grantedScopes: ['a'], expiresAt: NOW + 3600 }]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(1);
  });

  test('a record carrying exactly 1000 scopes is still served', async () => {
    const store = new FakeIndexedStore();
    const scopes = Array.from({ length: 1000 }, (_, i) => `s${String(i).padStart(4, '0')}`);
    const stored = entry(scopes);
    store.entries.set(await keyFor('strict', scopes), stored);

    await expect(readOboCachedToken(access(store, 'strict'), scopes)).resolves.toEqual(stored);
  });
});

describe('hostile index members', () => {
  const goodEntry = entry(['a', 'b']);
  const goodKey = goodKeyAb;
  const goodMember: TokenIndexMember = {
    tokenKey: goodKey,
    grantedScopes: goodEntry.grantedScopes,
    expiresAt: goodEntry.expiresAt,
  };

  test.each(['tokenKey', 'grantedScopes', 'expiresAt'] as const)(
    'a member whose %s getter throws is dropped and a well-formed sibling is still used',
    async (field) => {
      const store = new FakeIndexedStore();
      store.entries.set(goodKey, goodEntry);
      const hostile = { ...goodMember };
      Object.defineProperty(hostile, field, {
        enumerable: true,
        get() {
          throw new Error('getter exploded');
        },
      });
      store.indexes.set(indexKey, [hostile, goodMember]);

      await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(goodEntry);
    }
  );

  test('a member whose getter throws, alone in the index, is a miss', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(goodKey, goodEntry);
    const hostile = { ...goodMember };
    Object.defineProperty(hostile, 'tokenKey', {
      enumerable: true,
      get() {
        throw new Error('getter exploded');
      },
    });
    store.indexes.set(indexKey, [hostile]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('a member whose tokenKey getter returns the real key once and something else afterwards uses only the first read', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(goodKey, goodEntry);
    let reads = 0;
    const hostile = { grantedScopes: goodMember.grantedScopes, expiresAt: goodMember.expiresAt };
    Object.defineProperty(hostile, 'tokenKey', {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? goodKey : 'some-other-key';
      },
    });
    store.indexes.set(indexKey, [hostile]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(goodEntry);
    expect(reads).toBe(1);
  });

  test('an index member inherited from the prototype is dropped', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(goodKey, goodEntry);
    store.indexes.set(indexKey, [Object.create({ ...goodMember })]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
  });

  test('a member carrying more than 1000 scopes is dropped and a sibling is still used', async () => {
    const store = new FakeIndexedStore();
    store.entries.set(goodKey, goodEntry);
    const scopes = ['a', ...Array.from({ length: 1000 }, (_, i) => `s${i}`)];
    const oversizedKey = await keyFor('non_strict', scopes);
    store.entries.set(oversizedKey, entry(scopes));
    store.indexes.set(indexKey, [
      { tokenKey: oversizedKey, grantedScopes: scopes, expiresAt: NOW + 3600 },
      goodMember,
    ]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(goodEntry);
    expect(store.calls.get).toBe(1);
  });

  test('a member carrying more than 1000 scopes alone is a miss', async () => {
    const store = new FakeIndexedStore();
    const scopes = ['a', ...Array.from({ length: 1000 }, (_, i) => `s${i}`)];
    const oversizedKey = await keyFor('non_strict', scopes);
    store.entries.set(oversizedKey, entry(scopes));
    store.indexes.set(indexKey, [{ tokenKey: oversizedKey, grantedScopes: scopes, expiresAt: NOW + 3600 }]);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(0);
  });
});

describe('candidate read cap', () => {
  const CAP = 20;
  const COUNT = 25;

  /** Candidate i grants `a` plus i extra scopes, so candidate 1 is the smallest superset of `a`. */
  async function seedCandidates(
    store: FakeIndexedStore,
    hasEntry: (rank: number) => boolean
  ): Promise<CachedToken[]> {
    const entries: CachedToken[] = [];
    for (let rank = 1; rank <= COUNT; rank++) {
      const scopes = ['a', ...Array.from({ length: rank }, (_, i) => `s${String(i).padStart(2, '0')}`)];
      const candidate = entry(scopes);
      entries.push(candidate);
      const tokenKey = await seed(store, 'non_strict', candidate);
      if (!hasEntry(rank)) {
        store.entries.delete(tokenKey);
      }
    }
    return entries;
  }

  test('with more candidates than the cap, the smallest superset still wins on the first read', async () => {
    const store = new FakeIndexedStore();
    const entries = await seedCandidates(store, () => true);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(entries[0]);
    expect(store.calls.get).toBe(1);
  });

  test('with more candidates than the cap, a hit inside the cap is still found', async () => {
    const store = new FakeIndexedStore();
    const entries = await seedCandidates(store, (rank) => rank === 4);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(entries[3]);
    expect(store.calls.get).toBe(4);
  });

  test('when every candidate entry is missing, exactly the cap is read and the lookup misses', async () => {
    const store = new FakeIndexedStore();
    await seedCandidates(store, () => false);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(CAP);
  });

  test('a candidate ranked beyond the cap is never read, so it cannot be served', async () => {
    const store = new FakeIndexedStore();
    await seedCandidates(store, (rank) => rank === CAP + 1);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toBeUndefined();
    expect(store.calls.get).toBe(CAP);
  });

  test('the candidate ranked exactly at the cap is still read', async () => {
    const store = new FakeIndexedStore();
    const entries = await seedCandidates(store, (rank) => rank === CAP);

    await expect(readOboCachedToken(access(store, 'non_strict'), ['a'])).resolves.toEqual(entries[CAP - 1]);
    expect(store.calls.get).toBe(CAP);
  });
});

describe('oboCacheLayout', () => {
  test('maps strict to the strict layout', () => {
    expect(oboCacheLayout('strict')).toBe('strict');
  });

  test('maps non_strict to the index layout', () => {
    expect(oboCacheLayout('non_strict')).toBe('index');
  });
});
