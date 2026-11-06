import { base64url, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, test } from 'vitest';

import { isP256Point } from './p256-point.js';

// The prime of the field of NIST P-256, written here as a sum, and not as the hex number of the code under test.
const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// The generator G of the curve, which is the public key of the private key 1.
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

// More points of the curve, found by taking a square root (x small) or by solving the cubic (y small), and each one
// checked with OpenSSL. There is a point for x = 0, x = 5, x = 60 and x = p - 3, and for y = 5. The y at x = 60 starts
// with a zero byte.
const Y_AT_X_0 = 0x66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4n;
const Y_AT_X_5 = 0x459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbccn;
const Y_AT_X_60 = 0x00732d1e92b60907d7efab40def9181cd32f7348a1840c161a286911b17c3edbn;
const Y_AT_X_P_MINUS_3 = 0x19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121n;
const X_AT_Y_5 = 0xd7325d7646cd60d80a92738ceb345f844cffaf35841022cab176f692de8de1d7n;

// The public key of RFC 7515, appendix A.3, and the delegated key in the example of section 5.2 of the Poppy
// specification (https://personalagentprotocol.org/docs/0.3/spec).
const RFC_7515_KEY = {
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};
const POPPY_EXAMPLE_KEY = {
  x: 'B484TQp7695xQfzTcW5Rf8HUNC3a-Bt9zYTlgxtJUeU',
  y: '5ji2Z0dKOVQLXZJ2yzHiryVoopigNfpEVr_D36MPgwM',
};

/** The bytes of `value`, big endian, in `length` bytes. */
function bytesOf(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let rest = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return bytes;
}

/** A coordinate as a JWK writes it: 32 bytes, big endian, in base64url without padding. */
function encode(value: bigint): string {
  return base64url.encode(bytesOf(value, 32));
}

/** `text` with the character at `index` replaced. */
function replaceAt(text: string, index: number, replacement: string): string {
  return `${text.slice(0, index)}${replacement}${text.slice(index + 1)}`;
}

/** The same 32 bytes written another way: the last character has bits set that come after the last byte. */
function nonCanonical(coordinate: string, extraBits: 1 | 2 | 3): string {
  const last = ALPHABET.indexOf(coordinate.slice(-1));
  return replaceAt(coordinate, coordinate.length - 1, ALPHABET.charAt(last + extraBits));
}

const GX_TEXT = encode(GX);
const GY_TEXT = encode(GY);

describe('isP256Point', () => {
  test('writes the generator G in the base64url that its coordinates have, which pins encode() for the tests', () => {
    expect(GX_TEXT).toBe('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY');
    expect(GY_TEXT).toBe('T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU');
  });

  describe('a point of the curve', () => {
    test('is accepted for the generator G', () => {
      expect(isP256Point(GX_TEXT, GY_TEXT)).toBe(true);
    });

    test('is accepted for the mirror of G, (Gx, p - Gy)', () => {
      expect(isP256Point(GX_TEXT, encode(P - GY))).toBe(true);
    });

    test.each([
      { name: 'x = 0, whose 32 bytes are all zero', x: 0n, y: Y_AT_X_0 },
      { name: 'x = 0, mirrored', x: 0n, y: P - Y_AT_X_0 },
      { name: 'x = 5, which has 31 zero bytes in front', x: 5n, y: Y_AT_X_5 },
      { name: 'x = 60, with a y that starts with a zero byte', x: 60n, y: Y_AT_X_60 },
      { name: 'x = 60, mirrored', x: 60n, y: P - Y_AT_X_60 },
      { name: 'y = 5, which has 31 zero bytes in front', x: X_AT_Y_5, y: 5n },
      { name: 'x = p - 3, the last x below p that has a point', x: P - 3n, y: Y_AT_X_P_MINUS_3 },
      { name: 'x = p - 3, mirrored', x: P - 3n, y: P - Y_AT_X_P_MINUS_3 },
      { name: 'y = p - 5, mirrored from y = 5', x: X_AT_Y_5, y: P - 5n },
    ])('is accepted with $name, because a coordinate is written in all of its 32 bytes', ({ x, y }) => {
      expect(isP256Point(encode(x), encode(y))).toBe(true);
    });

    test.each([
      { name: 'RFC 7515', key: RFC_7515_KEY },
      { name: 'the Poppy specification', key: POPPY_EXAMPLE_KEY },
    ])('is accepted for the example key of $name', ({ key }) => {
      expect(isP256Point(key.x, key.y)).toBe(true);
    });

    test('is accepted for 50 public keys that Web Crypto makes', async () => {
      for (let count = 0; count < 50; count += 1) {
        const { publicKey } = await generateKeyPair('ES256');
        const { x, y } = await exportJWK(publicKey);

        // The key is public, so the coordinates go into the message if it fails.
        expect(isP256Point(x, y), `x ${x} y ${y}`).toBe(true);
      }
    });
  });

  describe('a point that is not on the curve', () => {
    test.each([
      { name: 'G with 1 added to y', x: GX_TEXT, y: encode(GY + 1n) },
      { name: 'G with 1 added to x', x: encode(GX + 1n), y: GY_TEXT },
      { name: 'G with its x and y swapped', x: GY_TEXT, y: GX_TEXT },
      { name: 'the x of G and the y of another point', x: GX_TEXT, y: encode(Y_AT_X_5) },
      {
        name: 'zero for x and for y, as the point at infinity would be if a key could write it',
        x: encode(0n),
        y: encode(0n),
      },
      { name: 'one for x and for y', x: encode(1n), y: encode(1n) },
      { name: 'p - 1 for x and for y', x: encode(P - 1n), y: encode(P - 1n) },
    ])('is refused for $name', ({ x, y }) => {
      expect(isP256Point(x, y)).toBe(false);
    });
  });

  describe('a coordinate that does not have the full size', () => {
    test.each([
      { name: 'an x of 31 bytes', x: base64url.encode(bytesOf(GX, 32).subarray(1)), y: GY_TEXT },
      {
        name: 'an x of 33 bytes, the same number with a zero byte in front',
        x: base64url.encode(bytesOf(GX, 33)),
        y: GY_TEXT,
      },
      { name: 'a y of 31 bytes', x: GX_TEXT, y: base64url.encode(bytesOf(GY, 32).subarray(1)) },
      {
        name: 'a y of 33 bytes, the same number with a zero byte in front',
        x: GX_TEXT,
        y: base64url.encode(bytesOf(GY, 33)),
      },
      {
        name: 'an x of 1 byte, the number 5 without its zero bytes',
        x: base64url.encode(Uint8Array.of(5)),
        y: encode(Y_AT_X_5),
      },
      {
        name: 'a y of 31 bytes, the number at x = 60 without its zero byte',
        x: encode(60n),
        y: base64url.encode(bytesOf(Y_AT_X_60, 31)),
      },
      { name: 'an x of 64 bytes', x: base64url.encode(new Uint8Array(64)), y: GY_TEXT },
      { name: 'an empty x', x: '', y: GY_TEXT },
      { name: 'an empty y', x: GX_TEXT, y: '' },
    ])('is refused for $name', ({ x, y }) => {
      expect(isP256Point(x, y)).toBe(false);
    });
  });

  describe('a coordinate that is not below the prime p', () => {
    // The first three are points of the curve once p is taken away, so only the range stops them.
    test.each([
      { name: 'x = p, where x - p = 0 is the x of a point', x: P, y: Y_AT_X_0 },
      { name: 'x = p + 5, where x - p = 5 is the x of a point', x: P + 5n, y: Y_AT_X_5 },
      { name: 'y = p + 5, where y - p = 5 is the y of a point', x: X_AT_Y_5, y: P + 5n },
      { name: 'x = p + 1', x: P + 1n, y: GY },
      { name: 'x = 2^256 - 1', x: 2n ** 256n - 1n, y: GY },
      { name: 'y = p', x: GX, y: P },
      { name: 'y = p + 1', x: GX, y: P + 1n },
      { name: 'y = 2^256 - 1', x: GX, y: 2n ** 256n - 1n },
    ])('is refused for $name', ({ x, y }) => {
      expect(isP256Point(encode(x), encode(y))).toBe(false);
    });
  });

  describe('an encoding that is not canonical base64url', () => {
    test.each([1, 2, 3] as const)(
      'is refused for an x whose last character has %i of its 2 unused bits set',
      (bits) => {
        expect(isP256Point(nonCanonical(GX_TEXT, bits), GY_TEXT)).toBe(false);
      }
    );

    test.each([1, 2, 3] as const)('is refused for a y whose last character has %i of its 2 unused bits set', (bits) => {
      expect(isP256Point(GX_TEXT, nonCanonical(GY_TEXT, bits))).toBe(false);
    });

    test('is accepted when the unused bits are zero, which is the one way to write the 32 bytes', () => {
      // The last character of an encoding of 32 bytes is a multiple of 4 in the alphabet.
      expect(ALPHABET.indexOf(GX_TEXT.slice(-1)) % 4).toBe(0);
      expect(ALPHABET.indexOf(GY_TEXT.slice(-1)) % 4).toBe(0);
      expect(isP256Point(GX_TEXT, GY_TEXT)).toBe(true);
    });

    test.each([
      { name: 'the + of standard base64', character: '+' },
      { name: 'the / of standard base64', character: '/' },
      { name: 'padding with =', character: '=' },
      { name: 'a space', character: ' ' },
      { name: 'a new line', character: '\n' },
      { name: 'a NUL character', character: '\0' },
      { name: 'a letter that is not ASCII', character: 'é' },
      { name: 'a digit that is not ASCII', character: '５' },
      { name: 'a lone surrogate', character: '\ud800' },
    ])('is refused for an x and for a y with $name in the middle', ({ character }) => {
      expect(isP256Point(replaceAt(GX_TEXT, 20, character), GY_TEXT)).toBe(false);
      expect(isP256Point(GX_TEXT, replaceAt(GY_TEXT, 20, character))).toBe(false);
    });

    test.each([
      { name: 'the padding of the usual base64 text of 32 bytes, which makes 44 characters', suffix: '=' },
      { name: 'two padding characters', suffix: '==' },
      { name: 'a new line at the end', suffix: '\n' },
      { name: 'a space at the end', suffix: ' ' },
    ])('is refused for an x and for a y with $name', ({ suffix }) => {
      expect(isP256Point(`${GX_TEXT}${suffix}`, GY_TEXT)).toBe(false);
      expect(isP256Point(GX_TEXT, `${GY_TEXT}${suffix}`)).toBe(false);
    });

    test('is refused for the standard base64 spelling of a point, with + and / where base64url has - and _', () => {
      const standard = GY_TEXT.replaceAll('-', '+').replaceAll('_', '/');

      expect(standard).not.toBe(GY_TEXT);
      expect(isP256Point(GX_TEXT, standard)).toBe(false);
    });

    test('is refused for a character outside the alphabet that a careless decoder would count as a digit', () => {
      // A decoder that looks up each character in a table, and does not check for "not found" (-1), reads the last two
      // characters of this text as the number -12. That makes x = -3, which is p - 3 modulo p, and there is a point at
      // that x. The text is not base64url, so it must be refused all the same.
      const crafted = `${'A'.repeat(41)}!0`;

      expect(crafted).toHaveLength(43);
      expect(isP256Point(crafted, encode(Y_AT_X_P_MINUS_3))).toBe(false);
    });

    test('is refused for a space or a new line in front', () => {
      expect(isP256Point(` ${GX_TEXT}`, GY_TEXT)).toBe(false);
      expect(isP256Point(`\n${GX_TEXT}`, GY_TEXT)).toBe(false);
      expect(isP256Point(GX_TEXT, ` ${GY_TEXT}`)).toBe(false);
    });

    test('is refused when padding takes the place of the last character', () => {
      expect(isP256Point(replaceAt(GX_TEXT, 42, '='), GY_TEXT)).toBe(false);
      expect(isP256Point(GX_TEXT, replaceAt(GY_TEXT, 42, '='))).toBe(false);
    });

    test('is accepted for the - and the _ of base64url', () => {
      // The y of G has both of them.
      expect(GY_TEXT).toContain('-');
      expect(GY_TEXT).toContain('_');
      expect(isP256Point(GX_TEXT, GY_TEXT)).toBe(true);
    });
  });

  describe('input that is not a string', () => {
    class Hostile {
      toString(): string {
        throw new Error('The coordinate must not be turned into text.');
      }

      valueOf(): string {
        throw new Error('The coordinate must not be turned into a value.');
      }
    }

    test.each([
      { name: 'undefined', value: undefined },
      { name: 'null', value: null },
      { name: 'a number', value: 5 },
      { name: 'NaN', value: NaN },
      { name: 'a boolean', value: true },
      { name: 'a bigint', value: GX },
      { name: 'a symbol', value: Symbol('x') },
      { name: 'a function', value: () => GX_TEXT },
      { name: 'an object', value: {} },
      { name: 'a list with the coordinate in it', value: [GX_TEXT] },
      { name: 'the bytes of the coordinate', value: bytesOf(GX, 32) },
      { name: 'a String object that holds the coordinate', value: new String(GX_TEXT) },
      { name: 'an object that throws when it is turned into text', value: new Hostile() },
    ])('is refused for $name as x and as y, and does not throw', ({ value }) => {
      expect(isP256Point(value, GY_TEXT)).toBe(false);
      expect(isP256Point(GX_TEXT, value)).toBe(false);
      expect(isP256Point(value, value)).toBe(false);
    });

    test('is refused when the arguments are missing', () => {
      const unchecked = isP256Point as (...args: unknown[]) => boolean;

      expect(unchecked()).toBe(false);
      expect(unchecked(GX_TEXT)).toBe(false);
    });
  });
});
