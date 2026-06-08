/**
 * Reads an environment variable in a way that is safe across runtimes.
 *
 * Some runtimes (e.g. Cloudflare Workers without `nodejs_compat`) do not expose a
 * `process` global, so a bare `process.env` reference would throw. This guards the
 * access and returns `undefined` when no environment is available.
 */
export function readEnv(name: string): string | undefined {
  return typeof process !== 'undefined' && process.env ? process.env[name] : undefined;
}

/**
 * Helper function that removes properties from an object when the value is undefined.
 * @returns The object, without the properties whose values are undefined.
 */
export function stripUndefinedProperties<T extends object>(value: T): Partial<T> {
  return Object.entries(value)
    .filter(([, value]) => typeof value !== 'undefined')
    .reduce((acc, curr) => ({ ...acc, [curr[0]]: curr[1] }), {});
}
