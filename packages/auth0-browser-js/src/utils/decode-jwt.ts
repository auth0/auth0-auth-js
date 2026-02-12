import { IdToken } from '../types.js';

/**
 * Decodes a JWT token and returns the claims.
 * Does not verify the signature - assumes token is already validated.
 *
 * @param token - The JWT token to decode
 * @returns The decoded claims or undefined if invalid
 */
export function decodeJWT(token: string): IdToken | undefined {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return undefined;
    }

    // Decode the payload (second part)
    const payload = parts[1];
    if (!payload) {
      return undefined;
    }

    const decodedPayload = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(decodedPayload);

    // Add the raw token
    return {
      ...claims,
      __raw: token,
    };
  } catch {
    return undefined;
  }
}
