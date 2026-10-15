import {
  buildOboIndexKey,
  buildOboTokenKey,
  type OboCacheKeyIdentity,
  type OboCacheKeyLayout,
} from './obo-cache-key.js';
import {
  isIndexedTokenStore,
  isUsableCachedToken,
  isUsableTokenIndexMember,
  type CachedToken,
  type TokenIndexMember,
  type TokenStore,
} from './token-store.js';
import type { ScopeMatching } from './types.js';

/**
 * Leeway, in seconds, applied to every cache expiry comparison.
 *
 * An entry is only reused while it stays valid at least this far past now, so a token
 * about to expire is re-exchanged instead of being handed out and then rejected
 * downstream. Applied identically to index members and to stored entries, so a
 * candidate cannot pass one check and fail the other.
 */
export const OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS = 5;

/**
 * @internal
 * Everything the cache needs to locate entries for one exchange.
 */
export interface OboCacheAccess {
  store: TokenStore;
  scopeMatching: ScopeMatching;
  identity: OboCacheKeyIdentity;
}

/**
 * @internal
 * Maps a scope-matching mode to its key layout. Keys are namespaced by layout so
 * switching modes can never read entries written under the other one.
 */
export function oboCacheLayout(scopeMatching: ScopeMatching): OboCacheKeyLayout {
  return scopeMatching === 'non_strict' ? 'index' : 'strict';
}

/**
 * Most candidate entries a single non-strict lookup will read from the store. Candidates
 * are tried smallest superset first, so the cap only drops the loosest matches. It exists
 * so a corrupted or oversized index cannot turn one call into an unbounded number of
 * store reads.
 */
const MAX_CANDIDATE_READS = 20;

function isFresh(expiresAt: number, nowSeconds: number): boolean {
  return expiresAt > nowSeconds + OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS;
}

/**
 * True when `granted` contains every scope in `requested`.
 */
function covers(granted: readonly string[], requested: readonly string[]): boolean {
  const grantedSet = new Set(granted);
  return requested.every((scope) => grantedSet.has(scope));
}

/**
 * True when two normalized scope lists hold the same scopes.
 */
function sameScopes(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((scope, index) => scope === right[index]);
}

function tokenKeyFor(access: OboCacheAccess, scopes: readonly string[]): string {
  return buildOboTokenKey({
    ...access.identity,
    layout: oboCacheLayout(access.scopeMatching),
    scope: scopes.join(' '),
  });
}

/**
 * Upper bound on the number of scopes accepted in one stored record. A real token carries
 * a handful. The bound stops a hostile or corrupted record with an enormous (possibly
 * sparse) array from stalling the copy below.
 */
const MAX_STORED_SCOPES = 1000;

/**
 * Reads an own property exactly once. Inherited properties are ignored, so a polluted
 * `Object.prototype` cannot supply a field the record does not actually carry.
 */
function ownValue(source: object, name: string): unknown {
  return Object.hasOwn(source, name) ? (source as Record<string, unknown>)[name] : undefined;
}

/**
 * Copies a scope array element by element, reading each element once. Holes and
 * non-string elements are kept as they are so the shape check that follows rejects them.
 */
function copyScopes(value: unknown): unknown {
  if (!Array.isArray(value)) {
    return value;
  }

  const length = value.length;
  if (length > MAX_STORED_SCOPES) {
    return undefined;
  }

  const copy: unknown[] = [];
  for (let i = 0; i < length; i++) {
    copy.push(value[i]);
  }
  return copy;
}

/**
 * Copies the fields of a stored entry into a fresh plain object, reading each field
 * exactly once. Everything after this point works on the copy, never on the object the
 * store returned, so a getter or proxy cannot change its answer between the check and the
 * use. Must run inside the same `try` as the store read, because reading a field can throw.
 */
function snapshotEntry(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return undefined;
  }

  const snapshot: Record<string, unknown> = {
    accessToken: ownValue(value, 'accessToken'),
    expiresAt: ownValue(value, 'expiresAt'),
    grantedScopes: copyScopes(ownValue(value, 'grantedScopes')),
  };

  for (const name of ['scope', 'tokenType', 'issuedTokenType']) {
    const field = ownValue(value, name);
    if (field !== undefined) {
      snapshot[name] = field;
    }
  }

  return snapshot;
}

/**
 * Same as {@link snapshotEntry}, for a scope index member.
 */
function snapshotMember(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return undefined;
  }

  return {
    tokenKey: ownValue(value, 'tokenKey'),
    grantedScopes: copyScopes(ownValue(value, 'grantedScopes')),
    expiresAt: ownValue(value, 'expiresAt'),
  };
}

/**
 * Reads an entry, treating a store failure and a malformed value alike as a miss. A
 * cache must never become an availability dependency of the operation it accelerates.
 *
 * The value is copied and validated inside the `try`, so a hostile entry that throws
 * while it is being read is a miss like any other store failure. The copy is returned, so
 * the caller never touches the object the store handed back.
 */
async function readEntry(store: TokenStore, key: string, nowSeconds: number): Promise<CachedToken | undefined> {
  try {
    const snapshot = snapshotEntry(await store.get(key));

    if (!isUsableCachedToken(snapshot) || !isFresh(snapshot.expiresAt, nowSeconds)) {
      return undefined;
    }

    return snapshot;
  } catch {
    return undefined;
  }
}

async function readIndexMembers(store: TokenStore, indexKey: string): Promise<TokenIndexMember[]> {
  if (!isIndexedTokenStore(store)) {
    return [];
  }

  try {
    const members = await store.listIndexMembers(indexKey);

    if (!Array.isArray(members)) {
      return [];
    }

    const usable: TokenIndexMember[] = [];
    const length = members.length;

    for (let i = 0; i < length; i++) {
      try {
        const snapshot = snapshotMember(members[i]);

        if (isUsableTokenIndexMember(snapshot)) {
          usable.push(snapshot);
        }
      } catch {
        // A member that throws while being read is dropped; the others stay usable.
      }
    }

    return usable;
  } catch {
    return [];
  }
}

/**
 * Exact-match lookup. The key already embeds the scope set an entry was written under,
 * and entries are written under the scopes they were granted, so a hit here is an entry
 * whose granted scopes equal what is being requested. The explicit comparison keeps that
 * guarantee independent of whatever else may have written to a shared store.
 */
async function readStrict(
  access: OboCacheAccess,
  requestedScopes: string[],
  nowSeconds: number
): Promise<CachedToken | undefined> {
  const entry = await readEntry(access.store, tokenKeyFor(access, requestedScopes), nowSeconds);

  if (entry === undefined || !sameScopes(entry.grantedScopes, requestedScopes)) {
    return undefined;
  }

  return entry;
}

/**
 * Covering lookup.
 *
 * Reads the scope index for this subject, downstream audience, organization and session,
 * keeps the members whose granted scopes cover the request, and tries them smallest
 * superset first so a broadly scoped token is not handed out when a tighter one exists.
 * The winning member's stored entry is re-checked against the request, because an index
 * member is a hint maintained alongside the entry rather than part of it.
 *
 * A request for no scopes never reuses anything: every cached token would cover it, so a
 * hit would mean handing out arbitrary scopes for a request that asked for none.
 */
async function readNonStrict(
  access: OboCacheAccess,
  requestedScopes: string[],
  nowSeconds: number
): Promise<CachedToken | undefined> {
  if (requestedScopes.length === 0) {
    return undefined;
  }

  const members = await readIndexMembers(access.store, buildOboIndexKey(access.identity));

  const candidates = members
    .filter(
      (member) =>
        isFresh(member.expiresAt, nowSeconds) &&
        covers(member.grantedScopes, requestedScopes) &&
        // The index is a hint kept next to the data, not an authority. A member is only
        // considered when the key it points at is exactly the key this identity would
        // have written for the scopes the member claims. A poisoned or corrupted member
        // can therefore never redirect a lookup to an entry outside this identity.
        tokenKeyFor(access, member.grantedScopes) === member.tokenKey
    )
    .sort((left, right) => {
      const byExtraScopes = left.grantedScopes.length - right.grantedScopes.length;

      if (byExtraScopes !== 0) {
        return byExtraScopes;
      }

      // Plain code unit comparison, so the order does not depend on locale or ICU.
      if (left.tokenKey < right.tokenKey) {
        return -1;
      }
      return left.tokenKey > right.tokenKey ? 1 : 0;
    })
    .slice(0, MAX_CANDIDATE_READS);

  for (const candidate of candidates) {
    const entry = await readEntry(access.store, candidate.tokenKey, nowSeconds);

    if (entry !== undefined && covers(entry.grantedScopes, requestedScopes)) {
      return entry;
    }
  }

  return undefined;
}

/**
 * @internal
 * Looks up a cached On Behalf Of token for `requestedScopes` under the configured
 * scope-matching mode. Returns `undefined` for a miss, a store failure, a malformed
 * entry, or an entry too close to expiry.
 */
export async function readOboCachedToken(
  access: OboCacheAccess,
  requestedScopes: string[]
): Promise<CachedToken | undefined> {
  const nowSeconds = Math.floor(Date.now() / 1000);

  return access.scopeMatching === 'non_strict'
    ? readNonStrict(access, requestedScopes, nowSeconds)
    : readStrict(access, requestedScopes, nowSeconds);
}

/**
 * @internal
 * Caches `entry` under the scopes it was actually granted, and records it in the scope
 * index when non-strict matching is in use.
 *
 * Writing under the granted scopes rather than the requested ones is what lets a later,
 * narrower request be served from cache, and it is why a narrowed result is still worth
 * caching. A write failure is swallowed: the token has already been issued and paid for,
 * so it is returned to the caller regardless.
 */
export async function writeOboCachedToken(access: OboCacheAccess, entry: CachedToken): Promise<void> {
  const tokenKey = tokenKeyFor(access, entry.grantedScopes);

  try {
    await access.store.set(tokenKey, entry);

    if (access.scopeMatching === 'non_strict' && isIndexedTokenStore(access.store)) {
      await access.store.addIndexMember(buildOboIndexKey(access.identity), {
        tokenKey,
        grantedScopes: entry.grantedScopes,
        expiresAt: entry.expiresAt,
      });
    }
  } catch {
    // Intentionally ignored. See the note above.
  }
}
