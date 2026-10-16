import type { VerifiedAccessTokenClaims } from './types.js';
import { VerifyAccessTokenError } from './errors.js';

/**
 * A resolved identity derived from a verified access token.
 */
export interface Principal {
  /** The `sub` claim: the user or client the token was issued for. Always non-blank. */
  sub: string;
  /**
   * The OAuth client the token was issued to. Sourced from the `client_id` claim,
   * falling back to `azp`. `null` when neither claim is present.
   */
  clientId: string | null;
  /** The `org_id` claim. `null` when the token was not issued in an organization context. */
  orgId: string | null;
  /**
   * Token expiry as an epoch timestamp in SECONDS (from the `exp` claim).
   * Guaranteed present because callers pass claims from a verified token, and
   * `verifyAccessToken` validates `exp`.
   */
  expiresAt: number;
  /** Scopes parsed from the space-delimited `scope` claim. `[]` when the claim is absent or malformed. */
  scopes: string[];
  /**
   * RBAC permissions from the `permissions` claim.
   * `null` means the claim is absent (for example, RBAC is not enabled for the API or
   * "Add Permissions in the Access Token" is off), so permissions are unknown.
   * `[]` means the claim is present but empty or malformed, so the principal has no permissions.
   */
  permissions: string[] | null;
}

/**
 * Builds a {@link Principal} from already-verified access token claims.
 *
 * This function does not verify the token. Pass only the claims returned by
 * `verifyAccessToken()`.
 *
 * @param claims - Verified access token claims returned from `verifyAccessToken()`
 * @returns The resolved principal. `permissions` is a copy, so mutating it does not affect `claims`.
 * @throws {VerifyAccessTokenError} When the `sub` claim is missing, blank, or not a string.
 * This error does not carry `WWW-Authenticate` headers (unlike errors thrown by
 * `verifyAccessToken()`), so a caller that handles both in one block must add the challenge itself.
 *
 * @example
 * ```ts
 * const claims = await apiClient.verifyAccessToken({ accessToken });
 * const principal = buildPrincipal(claims);
 * if (principal.permissions?.includes('read:data')) {
 *   // authorized
 * }
 * ```
 */
export function buildPrincipal(claims: VerifiedAccessTokenClaims): Principal {
  const rawSub: unknown = claims.sub;
  if (typeof rawSub !== 'string' || rawSub.trim() === '') {
    throw new VerifyAccessTokenError('Missing or blank "sub" claim in access token.');
  }

  const clientId: string | null =
    (claims['client_id'] as string | undefined) ?? (claims['azp'] as string | undefined) ?? null;

  const orgId: string | null = (claims['org_id'] as string | undefined) ?? null;

  const rawScope: unknown = claims['scope'];
  const scopes: string[] =
    typeof rawScope === 'string' ? rawScope.split(/\s+/).filter(Boolean) : [];

  const rawPermissions: unknown = claims['permissions'];
  let permissions: string[] | null = null;
  if (rawPermissions !== undefined) {
    permissions = Array.isArray(rawPermissions) ? [...(rawPermissions as string[])] : [];
  }

  return {
    sub: rawSub,
    clientId,
    orgId,
    expiresAt: claims.exp as number,
    scopes,
    permissions,
  };
}
