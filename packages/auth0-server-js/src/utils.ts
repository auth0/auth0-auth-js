export const DEFAULT_SCOPES = 'openid profile email offline_access';

/**
 * Ensures that the "openid" scope is always included in the scope string.
 *
 * @param scope - The scope provided by the user (optional)
 * @returns A scope string that includes "openid" if it was not already present.
 */
export const ensureOpenIdScope = (scope?: string) => {
  const normalizedScope = scope?.trim();
  if (!normalizedScope) {
    return DEFAULT_SCOPES;
  }

  const scopes = normalizedScope.split(/\s+/);
  if (!scopes.includes('openid')) {
    scopes.unshift('openid');
  }

  return scopes.join(' ');
};

/**
 * Compares two sets of scopes to determine if all required scopes are present in the provided scopes.
 * @param scopes Scopes to compare
 * @param requiredScopes Scopes required to be present in the scopes
 * @returns True if all required scopes are present in the scopes, false otherwise
 */
export const compareScopes = (scopes: string | undefined, requiredScopes: string | undefined) => {
  // When the scopes and requiredScopes are exactly the same, return true
  // This handles cases where both are empty or undefined or both are the same string
  if (scopes === requiredScopes) {
    return true;
  }

  if (!scopes || !requiredScopes) {
    return false;
  }

  const scopesSet = new Set(scopes.trim().split(' ').filter(Boolean));
  const requiredScopesArray = requiredScopes.trim().split(' ').filter(Boolean);

  return requiredScopesArray.every((scope) => scopesSet.has(scope));
};
