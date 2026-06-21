import type { IDToken } from 'openid-client';
import { OrganizationValidationError } from './errors.js';

/**
 * Helper function that removes properties from an object when the value is undefined.
 * @returns The object, without the properties whose values are undefined.
 */
export function stripUndefinedProperties<T extends object>(value: T): Partial<T> {
  return Object.entries(value)
    .filter(([, value]) => typeof value !== 'undefined')
    .reduce((acc, curr) => ({ ...acc, [curr[0]]: curr[1] }), {});
}

/**
 * Asserts that a requested organization is a usable (non-blank) value.
 *
 * This is an input-shape check, intended to run before the token request so that
 * malformed input fails fast — consistent with the other up-front option checks
 * (e.g. subject-token validation) rather than only after a network round-trip.
 *
 * @throws {OrganizationValidationError} when `organization` is blank or whitespace-only.
 */
export function assertValidOrganization(organization: string): void {
  if (!organization.trim()) {
    throw new OrganizationValidationError('organization must not be blank');
  }
}

/**
 * Validates the organization claim in an ID token against the requested organization.
 * - an `org_`-prefixed value is matched exactly (case-sensitive) against `org_id`;
 * - any other value is matched case-insensitively against `org_name`.
 *
 * Validation only applies when an ID token was returned. If no ID token is present
 * (`claims` is undefined) there is nothing to validate and the function is a no-op —
 * for example, token-exchange flows that return only an access token. When an ID token
 * is present, a missing or mismatched organization claim throws.
 *
 * Assumes `organization` has already passed {@link assertValidOrganization}.
 *
 * @throws {OrganizationValidationError} when an ID token is present and its
 * organization claim is missing or does not match.
 */
export function validateOrganizationClaim(claims: IDToken | undefined, organization: string): void {
  if (!claims) {
    return;
  }

  const org = organization.trim();

  if (org.startsWith('org_')) {
    const actual = claims.org_id;
    if (typeof actual !== 'string') {
      throw new OrganizationValidationError('Organization Id (org_id) claim must be a string present in the ID token');
    }
    if (actual !== org) {
      throw new OrganizationValidationError(
        `Organization Id (org_id) claim value mismatch in the ID token; expected "${org}", found "${actual}"`
      );
    }
  } else {
    const actual = claims.org_name;
    if (typeof actual !== 'string') {
      throw new OrganizationValidationError(
        'Organization Name (org_name) claim must be a string present in the ID token'
      );
    }
    if (actual.toLowerCase() !== org.toLowerCase()) {
      throw new OrganizationValidationError(
        `Organization Name (org_name) claim value mismatch in the ID token; expected "${org}", found "${actual}"`
      );
    }
  }
}
