import { describe, expect, test } from 'vitest';
import { EXPIRY_BUFFER_SECONDS, hasExpiryBuffer } from './expiry-buffer.js';

const NOW = 1_700_000_000;

describe('expiry buffer', () => {
  test('requires strictly more than the buffer', () => {
    expect(hasExpiryBuffer(NOW + EXPIRY_BUFFER_SECONDS - 1, NOW)).toBe(false);
    expect(hasExpiryBuffer(NOW + EXPIRY_BUFFER_SECONDS, NOW)).toBe(false);
    expect(hasExpiryBuffer(NOW + EXPIRY_BUFFER_SECONDS + 1, NOW)).toBe(true);
  });

  test('rejects non-finite values', () => {
    expect(hasExpiryBuffer(Number.NaN, NOW)).toBe(false);
    expect(hasExpiryBuffer(Number.POSITIVE_INFINITY, NOW)).toBe(false);
  });
});
