/**
 * Returns the chunk index of a cookie named `<identifier>.<index>`, which is how the stateless stores
 * split a value across cookies, or `undefined` for any other name.
 *
 * The stores use this to find the cookies they own, so they never read or remove a cookie that merely
 * starts with the identifier (`<identifier>_theme`, `<identifier>__0`, `<identifier>.x`).
 */
export function getChunkIndex(identifier: string, name: string): number | undefined {
  const prefix = `${identifier}.`;
  if (!name.startsWith(prefix)) {
    return undefined;
  }

  const index = name.slice(prefix.length);
  return /^(0|[1-9]\d*)$/.test(index) ? Number(index) : undefined;
}
