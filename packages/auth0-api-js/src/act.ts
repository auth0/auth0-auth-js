import { InvalidRequestError } from './errors.js';
import type { VerifiedAccessTokenClaims } from './types.js';

type ClaimsWithAct = Pick<VerifiedAccessTokenClaims, 'act'>;
const INVALID_ACT_CLAIM_MESSAGE = 'Invalid "act" claim';

/**
 * Returns the current actor from a verified token's `act` claim.
 *
 * The current actor is always the outermost `act.sub`.
 *
 * @param claims - Verified access token claims returned from `verifyAccessToken()`
 * @returns The current actor identifier or `undefined` when the token is not delegated
 * @throws {InvalidRequestError} When the `act` claim is present but malformed
 */
export function getCurrentActor(claims: ClaimsWithAct): string | undefined {
  if (!claims || typeof claims !== 'object') {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  if (claims.act === undefined) {
    return undefined;
  }

  if (!claims.act || typeof claims.act !== 'object' || Array.isArray(claims.act)) {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  const sub = (claims.act as unknown as { sub?: unknown }).sub;
  if (typeof sub !== 'string' || sub.trim().length === 0) {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  return sub;
}

/**
 * Returns the delegation chain from newest actor to oldest actor.
 *
 * For a token with:
 * `act.sub = service-b`
 * `act.act.sub = service-a`
 *
 * this function returns `['service-b', 'service-a']`.
 *
 * @param claims - Verified access token claims returned from `verifyAccessToken()`
 * @returns Delegation chain from newest actor to oldest actor
 * @throws {InvalidRequestError} When the `act` claim is present but malformed
 */
export function getDelegationChain(claims: ClaimsWithAct): string[] {
  if (!claims || typeof claims !== 'object') {
    throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
  }

  if (claims.act === undefined) {
    return [];
  }

  const chain: string[] = [];
  let current: unknown = claims.act;

  while (current) {
    if (typeof current !== 'object' || Array.isArray(current)) {
      throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
    }

    const record = current as Record<string, unknown>;
    if (typeof record.sub !== 'string' || record.sub.trim().length === 0) {
      throw new InvalidRequestError(INVALID_ACT_CLAIM_MESSAGE);
    }

    chain.push(record.sub);
    current = record.act;
  }

  return chain;
}
