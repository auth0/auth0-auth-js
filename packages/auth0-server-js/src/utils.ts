import { DEFAULT_AUDIENCE, DEFAULT_SCOPES, REQUIRED_LOGIN_SCOPES } from "./constants.js";

/**
 * Parses a scope string into an array of individual scopes, filtering out empty strings.
 * 
 * @param scopes Space-separated scope string
 * @returns Array of scope strings
 */
function parseScopesToArray(scopes: string | undefined): string[] {
  if (!scopes) return [];
  return scopes.trim().split(" ").filter(Boolean);
}

/**
 * Ensures default scopes are present in the scope configuration only when no explicit scope is provided.
 *
 * Rules:
 * - If no scope configured: return DEFAULT_SCOPES
 * - If scope is a string: return it as-is (respects explicit configuration)
 * - If scope is a Record: return it as-is, but add DEFAULT_SCOPES for configured audience if missing
 *
 * @param scope - The configured scope (string, Record, or undefined)
 * @param audience - The configured audience
 * @returns Scope with defaults only added when nothing is explicitly configured
 */
export function ensureDefaultScopes(
  scope: string | Record<string, string> | undefined,
  audience: string | undefined
): string | Record<string, string> {
  // No scope configured: use defaults
  if (!scope) {
    return DEFAULT_SCOPES;
  }

  // String scope: return as-is (respect explicit configuration)
  if (typeof scope === 'string') {
    return scope;
  }

  const targetAudience = audience || DEFAULT_AUDIENCE;

  // Only add defaults for the configured audience if it's not already present
  if (!scope[targetAudience]) {
    return { ...scope, [targetAudience]: DEFAULT_SCOPES };
  }

  return scope;
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

  const scopesSet = new Set(parseScopesToArray(scopes));
  const requiredScopesArray = parseScopesToArray(requiredScopes);

  return requiredScopesArray.every((scope) => scopesSet.has(scope));
};

/**
 * Merges two scope strings, removing duplicates and sorting alphabetically.
 *
 * @param baseScope - The base scope string (space-separated)
 * @param requestedScope - The requested scope string (space-separated)
 * @returns Merged scope string (space-separated, sorted, deduplicated) or undefined if both are empty
 */
export function mergeScopes(
  baseScope: string | undefined,
  requestedScope: string | undefined
): string | undefined {
  if (!baseScope && !requestedScope) {
    return undefined;
  }

  const baseScopeArray = parseScopesToArray(baseScope);
  const requestedScopeArray = parseScopesToArray(requestedScope);

  const uniqueScopes = new Set([...baseScopeArray, ...requestedScopeArray]);

  return Array.from(uniqueScopes).sort().join(' ');
}

/**
 * Resolves the target audience with fallback logic.
 *
 * Rules:
 * - If requestedAudience is provided: Use it
 * - Else if configuredAudience is provided: Use it
 * - Else: Use DEFAULT_AUDIENCE
 *
 * @param configuredAudience - The audience from authorizationParams
 * @param requestedAudience - The audience from method options
 * @returns Resolved audience string
 */
export function resolveAudience(
  configuredAudience: string | undefined,
  requestedAudience: string | undefined
): string {
  return requestedAudience || configuredAudience || DEFAULT_AUDIENCE;
}

/**
 * Gets the appropriate base scope for a given audience from configuration.
 *
 * Rules:
 * - If scope is a string: Returns it for ALL audiences
 * - If scope is a Record: Looks up by audience with fallback to 'default' key
 * - If scope is undefined: Returns undefined
 *
 * @param scope - The scope from authorizationParams (string or Record)
 * @param audience - The target audience for this request
 * @returns Base scope string for the audience, or undefined
 */
export function getScopeForAudience(
  scope: string | Record<string, string> | undefined,
  audience: string
): string | undefined {
  if (!scope) {
    return undefined;
  }

  if (typeof scope === 'string') {
    // String scope: apply to ALL audiences
    return scope;
  }

  // Record scope: look up by audience with fallback to 'default'
  return scope[audience] || scope[DEFAULT_AUDIENCE];
}

/**
 * Resolves the final scope for login operations (interactive login or backchannel login).
 *
 * @param configuredScope - The scope from authorizationParams (string or Record)
 * @param configuredAudience - The audience from authorizationParams
 * @param requestedAudience - The audience from method options
 * @param requestedScope - The scope from method options
 * @returns Final resolved scope string with openid guaranteed
 */
export function resolveLoginScopes(
  configuredScope: string | Record<string, string> | undefined,
  configuredAudience: string | undefined,
  requestedAudience: string | undefined,
  requestedScope: string | undefined
): string | undefined {
  const resolvedScope = resolveTokenScopes(configuredScope, configuredAudience, requestedAudience, requestedScope);

  // Ensure scopes like 'openid' are always included for login operations
  return mergeScopes(resolvedScope, REQUIRED_LOGIN_SCOPES);
}

/**
 * Resolves the final scope for token requests (access token retrieval).
 *
 * @param configuredScope - The scope from authorizationParams (string or Record)
 * @param configuredAudience - The audience from authorizationParams
 * @param requestedAudience - The audience from method options
 * @param requestedScope - The scope from method options
 * @returns Final resolved scope string (space-separated, sorted, deduplicated) or undefined
 */
export function resolveTokenScopes(
  configuredScope: string | Record<string, string> | undefined,
  configuredAudience: string | undefined,
  requestedAudience: string | undefined,
  requestedScope: string | undefined
): string | undefined {
  const targetAudience = requestedAudience || configuredAudience || DEFAULT_AUDIENCE;

  // Get base scope for the target audience
  const baseScope = getScopeForAudience(configuredScope, targetAudience);

  // Merge base scope with requested scope
  return mergeScopes(baseScope, requestedScope);
}
