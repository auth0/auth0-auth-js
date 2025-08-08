/**
 * Compares two sets of scopes to determine if all required scopes are present in the provided scopes.
 * @param scopes Scopes to compare
 * @param requiredScopes Scopes required to be present in the scopes
 * @returns True if all required scopes are present in the scopes, false otherwise
 */
export const compareScopes = (scopes: string | undefined, requiredScopes: string | undefined) => {
  if (!scopes && !requiredScopes) {
    return true;
  }

  if (!scopes || !requiredScopes) {
    return false;
  }

  const scopesArray = scopes.split(' ');
  const requiredScopesArray = requiredScopes.split(' ');

  return requiredScopesArray.every((scope) => scopesArray.includes(scope));
};
