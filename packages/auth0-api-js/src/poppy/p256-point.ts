// The check of the public key that a delegation vouches for (see `delegation.ts`), done in the SDK and not by the
// runtime. Not every runtime refuses a bad key when it imports one: Deno imports an EC key whose coordinates are too
// short, or that is not a point of the curve (denoland/deno issue 37031). So the SDK looks at the point before it
// imports the key. It uses BigInt only, so it runs on Node, Workers, Deno and Bun.

// The prime of the field of NIST P-256 (secp256r1): 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

// The constant `b` in the equation of the curve, y^2 = x^3 - 3x + b (mod p).
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

// 32 bytes are 256 bits, which is 43 base64url characters of 6 bits each (258 bits) with no padding.
const COORDINATE_LENGTH = 43;
const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** `value` modulo p, as a number from 0 to p - 1 (the `%` of JavaScript keeps the sign of `value`). */
function mod(value: bigint): bigint {
  const remainder = value % P;
  return remainder < 0n ? remainder + P : remainder;
}

/**
 * The number that a coordinate stands for, or `undefined` when `text` is not the base64url text of exactly 32 bytes.
 * The 43 characters hold 258 bits, and the last 2 are not part of the 32 bytes. They must be zero, so that the same
 * 32 bytes have one spelling only.
 */
function readCoordinate(text: unknown): bigint | undefined {
  if (typeof text !== 'string' || text.length !== COORDINATE_LENGTH) {
    return undefined;
  }
  let bits = 0n;
  for (let index = 0; index < COORDINATE_LENGTH; index += 1) {
    const value = BASE64URL_ALPHABET.indexOf(text.charAt(index));
    if (value < 0) {
      return undefined;
    }
    bits = (bits << 6n) | BigInt(value);
  }
  return (bits & 3n) === 0n ? bits >> 2n : undefined;
}

/**
 * Whether `x` and `y`, the members of an EC key in a JWK, are a public key on NIST P-256 (secp256r1).
 *
 * Each coordinate must be the base64url text of exactly 32 bytes, because RFC 7518 (sections 6.2.1.2 and 6.2.1.3)
 * asks for the full size of a coordinate: 43 characters out of `A-Z`, `a-z`, `0-9`, `-` and `_`, with no padding, and
 * with the 2 bits after the last byte set to zero. A number written without its leading zero bytes is refused. Each
 * coordinate must also be below the prime p of the field, and the point must satisfy `y^2 = x^3 - 3x + b (mod p)`.
 *
 * The curve has the cofactor 1, so every point that satisfies the equation is in the group of prime order, and nothing
 * else needs to be checked. The point at infinity has no coordinates, so a JWK cannot be it.
 *
 * The coordinates of a public key are public, so the comparison does not run in constant time. A value that is not a
 * string is not a point, and nothing throws.
 *
 * @param x - The `x` member of the JWK.
 * @param y - The `y` member of the JWK.
 * @returns `true` for a point of the curve, `false` for anything else.
 */
export function isP256Point(x: unknown, y: unknown): boolean {
  const px = readCoordinate(x);
  const py = readCoordinate(y);
  if (px === undefined || py === undefined || px >= P || py >= P) {
    return false;
  }
  return mod(py * py) === mod(px * px * px - 3n * px + B);
}
