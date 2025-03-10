/**
 * Ensures the value has a trailing slash.
 * If it does not, it will append one.
 * @param value The value to ensure has a trailing slash.
 * @returns The value with a trailing slash.
 */
function ensureTrailingSlash(value: string) {
  return value && !value.endsWith('/') ? `${value}/` : value;
}

/**
 * Ensures the value does not have a leading slash.
 * If it does, it will trim it.
 * @param value The value to ensure has no leading slash.
 * @returns The value without a leading slash.
 */
function ensureNoLeadingSlash(value: string) {
  return value && value.startsWith('/') ? value.substring(1, value.length) : value;
}

/**
 * Utility function to ensure Route URLs are created correctly when using both the root and subpath as base URL.
 * @param url The URL to use.
 * @param base The base URL to use.
 * @returns A URL object, combining the base and url.
 */
export function createRouteUrl(url: string, base: string) {
  return new URL(ensureNoLeadingSlash(url), ensureTrailingSlash(base));
}
