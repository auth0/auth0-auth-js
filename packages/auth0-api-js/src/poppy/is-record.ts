/**
 * Whether a value is an object that is neither `null` nor an array, read as a record of members by name. It does not
 * look at the prototype, so a `Map` or an instance of a class passes as well. Use it for data that came from JSON or
 * from the options of a caller, where the members are all that count.
 *
 * @param value - The value to check.
 * @returns Whether `value` is a non-null object that is not an array.
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
