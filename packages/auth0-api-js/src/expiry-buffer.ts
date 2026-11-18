/**
 * @internal
 * Seconds a cached or pre-verified token must outlive "now" to be reused. Matches auth0-api-python.
 */
export const EXPIRY_BUFFER_SECONDS = 5;

/**
 * @internal
 * True when `expiresAt` (epoch seconds) is strictly more than the buffer past `nowSeconds`.
 */
export function hasExpiryBuffer(expiresAt: number, nowSeconds: number): boolean {
  return Number.isFinite(expiresAt) && expiresAt > nowSeconds + EXPIRY_BUFFER_SECONDS;
}
