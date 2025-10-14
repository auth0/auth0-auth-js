/**
 * Helper function that removes properties from an object when the value is undefined.
 * @returns The object, without the properties whose values are undefined.
 */
export function stripUndefinedProperties<T extends object>(
  value: T
): Partial<T> {
  return Object.entries(value)
    .filter(([, value]) => typeof value !== 'undefined')
    .reduce((acc, curr) => ({ ...acc, [curr[0]]: curr[1] }), {});
}
