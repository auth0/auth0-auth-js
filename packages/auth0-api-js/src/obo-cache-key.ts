import { base64url } from 'jose';
import { InvalidConfigurationError } from './errors.js';
import { normalizeScopes, type VerifiedToken } from './token-store.js';
import type { VerifiedAccessTokenClaims } from './types.js';

/**
 * Key layout for the On Behalf Of cache.
 *
 * `'strict'` keys serve exact scope-set matching. `'index'` keys serve non-strict
 * matching, where several entries coexist for one subject and a scope index picks
 * between them. The layout is part of the key, so switching `scopeMatching` can never
 * read entries written under the other policy.
 */
export type OboCacheKeyLayout = 'strict' | 'index';

/**
 * Everything that identifies a cached On Behalf Of token apart from its scopes.
 */
export interface OboCacheKeyIdentity {
  /**
   * The Auth0 domain of the client performing the exchange, normalized to an origin.
   */
  exchangeTenant: string | undefined;

  /**
   * The client ID performing the exchange.
   */
  exchangeClientId: string | undefined;

  /**
   * The audience the exchanging client validates its own incoming tokens against.
   */
  exchangeAudience: string | undefined;

  /**
   * The verified subject token being exchanged.
   */
  verified: VerifiedToken;

  /**
   * The downstream audience the exchanged token is being requested for.
   */
  requestedAudience: string;
}

/**
 * Input to {@link buildOboTokenKey}.
 */
export interface OboCacheKeyInput extends OboCacheKeyIdentity {
  /**
   * The key layout, which becomes part of the key namespace.
   */
  layout: OboCacheKeyLayout;

  /**
   * The scope set this key stands for, space separated. Normalized before hashing, so
   * ordering and duplicates do not matter.
   */
  scope: string | undefined;
}

const TOKEN_KEY_PREFIX = 'a0.obo.v1';
const INDEX_KEY_PREFIX = 'a0.obo.index.v1';

/**
 * ASCII unit separator. Not valid in a JWT claim value in practice, and the
 * length prefix on each field makes the encoding unambiguous even if it were.
 */
const FIELD_SEPARATOR = '\u001f';

/**
 * Marks a field whose claim or option was absent, which has to stay distinct from a
 * field that was present and empty.
 */
const ABSENT_FIELD = '-';

/**
 * Encodes one field so the concatenation of all fields is injective: an absent field
 * becomes a sentinel that no present field can produce, and a present field is prefixed
 * with its length so no value can impersonate a field boundary.
 */
function encodeField(value: string | undefined): string {
  return value === undefined ? ABSENT_FIELD : `${value.length}:${value}`;
}

/**
 * SHA-256 through WebCrypto, which jose already requires, so the key builder carries no
 * Node-only dependency and runs on any runtime this package targets.
 */
async function sha256Base64Url(input: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;

  if (!subtle) {
    throw new InvalidConfigurationError('Web Crypto (crypto.subtle) is required to build OBO cache keys.');
  }

  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * Reads a claim that must be a string, preserving the empty string. A claim of the wrong
 * type is treated as absent, because a non-string value cannot safely be folded into a
 * key alongside real string values.
 */
function claimString(claims: VerifiedAccessTokenClaims, name: string): string | undefined {
  const value = (claims as Record<string, unknown>)[name];
  return typeof value === 'string' ? value : undefined;
}

/**
 * Reads a claim that must be a non-empty string. Used where an empty value carries no
 * information and should fall through to the next candidate.
 */
function nonEmptyClaimString(claims: VerifiedAccessTokenClaims, name: string): string | undefined {
  const value = claimString(claims, name);
  return value !== undefined && value !== '' ? value : undefined;
}

const KEYED_CLAIM_NAMES = ['iss', 'client_id', 'azp', 'sub', 'org_id', 'sid', 'jti'] as const;

/**
 * True when a claim the cache key depends on is present with a non-string value.
 *
 * The key encoding treats a non-string claim as absent, so a `sub` of `123` would key the
 * same as a token with no `sub` at all. A caller that sees `true` here should skip the
 * cache for that token instead of risking two different identities sharing one key.
 * An absent claim is fine and returns `false`.
 *
 * @param claims - The verified claims of the subject token.
 *
 * @returns `true` when at least one keyed claim is present but not a string.
 */
export function hasUnkeyableClaims(claims: VerifiedAccessTokenClaims): boolean {
  const record = claims as Record<string, unknown>;

  return KEYED_CLAIM_NAMES.some((name) => {
    const value = record[name];
    return value !== undefined && typeof value !== 'string';
  });
}

/**
 * Derives the session component of the cache key.
 *
 * A delegated token is tied to the session that produced the subject token, so two
 * concurrent sessions of the same user must not share one. `sid` identifies the session
 * directly. Failing that, `jti` identifies the subject token, which is narrower than a
 * session but never broader. Failing both, a hash of the token itself is used, which
 * still allows reuse across the many tool calls that one incoming token drives.
 *
 * Because the session component outlives any single access token, a delegated token
 * minted earlier in a session is reused for later tokens from the same session. A session
 * revoked at the authorization server therefore does not invalidate an already cached
 * delegated token before its own expiry. This window is inherent to caching, and callers
 * need to know it exists.
 *
 * Derived from verified claims only. The hash fallback never exposes the token: only its
 * digest reaches the key, and the key itself is hashed again.
 *
 * @param verified - The verified subject token.
 *
 * @returns An opaque, prefixed session identifier.
 */
export async function deriveSessionKey(verified: VerifiedToken): Promise<string> {
  const sid = nonEmptyClaimString(verified.claims, 'sid');
  if (sid !== undefined) {
    return `sid:${sid}`;
  }

  const jti = nonEmptyClaimString(verified.claims, 'jti');
  if (jti !== undefined) {
    return `jti:${jti}`;
  }

  return `at:${await sha256Base64Url(verified.accessToken)}`;
}

/**
 * Builds the hashed field list. `scope` is the last field, so omitting it yields the
 * index identity: the same token under any scope set hashes into the same index.
 */
async function encodeFields(
  identity: OboCacheKeyIdentity,
  scope: string | undefined,
  includeScope: boolean
): Promise<string> {
  const { claims } = identity.verified;

  const fields: Array<string | undefined> = [
    identity.exchangeTenant,
    identity.exchangeClientId,
    identity.exchangeAudience,
    claimString(claims, 'iss'),
    claimString(claims, 'client_id') ?? claimString(claims, 'azp'),
    claimString(claims, 'sub'),
    claimString(claims, 'org_id'),
    await deriveSessionKey(identity.verified),
    identity.requestedAudience,
  ];

  if (includeScope) {
    fields.push(normalizeScopes(scope).join(' '));
  }

  return fields.map(encodeField).join(FIELD_SEPARATOR);
}

/**
 * Builds the {@link TokenStore} key a single On Behalf Of token is cached under.
 *
 * The key is `a0.obo.v1.<layout>.<base64url(sha256(fields))>`, so it is versioned,
 * namespaced by layout, fixed length whatever the claims contain, and carries no claim
 * value in the clear. The hashed fields, in order, are the exchanging tenant, client ID
 * and audience, then the subject token's issuer, client ID, subject, organization and
 * session, then the downstream audience, then the normalized scope set.
 *
 * This package uses the key for both its reads and its writes, including the covering
 * lookup that non-strict matching performs over {@link IndexedTokenStore}. It is exported
 * so a wrapper package that needs to inspect or evict entries can derive the same keys.
 *
 * @param input - The identity, layout and scope set to key on.
 *
 * @returns The cache key. Asynchronous because it hashes with WebCrypto.
 */
export async function buildOboTokenKey(input: OboCacheKeyInput): Promise<string> {
  return `${TOKEN_KEY_PREFIX}.${input.layout}.${await sha256Base64Url(await encodeFields(input, input.scope, true))}`;
}

/**
 * Builds the index key that groups every cached On Behalf Of token sharing one subject,
 * downstream audience, organization and session, across scope sets.
 *
 * Same fields and same order as {@link buildOboTokenKey} minus the scope set, under a
 * separate namespace so an index key can never collide with a token key.
 *
 * @param identity - The identity to key on.
 *
 * @returns The index key. Asynchronous because it hashes with WebCrypto.
 */
export async function buildOboIndexKey(identity: OboCacheKeyIdentity): Promise<string> {
  return `${INDEX_KEY_PREFIX}.${await sha256Base64Url(await encodeFields(identity, undefined, false))}`;
}
