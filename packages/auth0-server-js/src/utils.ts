/**
 * Merges two scope strings, removing duplicates and filtering out empty values.
 * @param scope1 First scope string (space-separated scopes)
 * @param scope2 Second scope string (space-separated scopes)
 * @returns Merged scope string with unique values, or undefined if no scopes provided
 */
export function mergeScopes(scope1?: string, scope2?: string): string | undefined {
  if (!scope1 && !scope2) {
    return undefined;
  }

  const allScopes = [
    ...(scope1 ? scope1.split(/\s+/).map(s => s.trim()).filter(s => s) : []),
    ...(scope2 ? scope2.split(/\s+/).map(s => s.trim()).filter(s => s) : [])
  ];
  
  const uniqueScopes = [...new Set(allScopes)];
  return uniqueScopes.length > 0 ? uniqueScopes.join(' ') : undefined;
}


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