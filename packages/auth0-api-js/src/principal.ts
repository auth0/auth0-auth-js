import type { VerifiedAccessTokenClaims } from './types.js';
import { VerifyAccessTokenError } from './errors.js';

/**
 * A resolved identity derived from a verified access token.
 */
export interface Principal {
  sub: string;
  clientId: string | null;
  orgId: string | null;
  expiresAt: number;
  scopes: string[];
  permissions: string[] | null;
}

/**
 * Builds a Principal from already-verified JWT claims.
 *
 * Mirrors the Python `build_principal` function minus the token fingerprint
 * field (omitted intentionally). Does not re-verify the token — callers must
 * verify before passing claims here.
 */
export function buildPrincipal(claims: VerifiedAccessTokenClaims): Principal {
  const rawSub = claims.sub;
  if (!rawSub || rawSub.trim() === '') {
    throw new VerifyAccessTokenError('Missing or blank "sub" claim in access token.');
  }

  const clientId: string | null =
    (claims['client_id'] as string | undefined) ?? (claims['azp'] as string | undefined) ?? null;

  const orgId: string | null = (claims['org_id'] as string | undefined) ?? null;

  const rawScope = claims['scope'] as string | undefined;
  const scopes: string[] =
    rawScope != null
      ? rawScope
          .trim()
          .split(' ')
          .filter((s) => s.length > 0)
      : [];

  const rawPermissions = claims['permissions'] as string[] | undefined;
  const permissions: string[] | null = rawPermissions !== undefined ? rawPermissions : null;

  return {
    sub: rawSub,
    clientId,
    orgId,
    expiresAt: claims.exp as number,
    scopes,
    permissions,
  };
}
