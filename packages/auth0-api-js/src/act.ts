import { InvalidRequestError } from './errors.js';
import type { ActClaim, VerifiedAccessTokenClaims } from './types.js';

type ClaimsWithAct = Pick<VerifiedAccessTokenClaims, 'act'>;

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
  return getValidatedActClaim(claims)?.sub;
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
  const act = getValidatedActClaim(claims);
  if (!act) {
    return [];
  }

  const chain: string[] = [];
  let current: ActClaim | undefined = act;
  while (current) {
    chain.push(current.sub);
    current = current.act;
  }

  return chain;
}

function getValidatedActClaim(claims: ClaimsWithAct): ActClaim | undefined {
  if (!claims || typeof claims !== 'object') {
    throw new InvalidRequestError('Verified claims must be an object');
  }

  if (claims.act === undefined) {
    return undefined;
  }

  return parseActClaim(claims.act, 'act', new WeakSet<object>());
}

function parseActClaim(value: unknown, path: string, seen: WeakSet<object>): ActClaim {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new InvalidRequestError(`Invalid "act" claim: "${path}" must be an object`);
  }

  if (seen.has(value)) {
    throw new InvalidRequestError('Invalid "act" claim: circular structures are not supported');
  }
  seen.add(value);

  const record = value as Record<string, unknown>;
  if (typeof record.sub !== 'string' || record.sub.trim().length === 0) {
    throw new InvalidRequestError(`Invalid "act" claim: "${path}.sub" must be a non-empty string`);
  }

  if (record.act === undefined) {
    return { sub: record.sub };
  }

  return {
    sub: record.sub,
    act: parseActClaim(record.act, `${path}.act`, seen),
  };
}
