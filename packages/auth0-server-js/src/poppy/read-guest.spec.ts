import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { TokenSet } from '../types.js';
import { guestTokenIsUsable } from './read-guest.js';

const NOW = Date.parse('2026-11-10T10:00:00.400Z');
const at = Math.floor(NOW / 1000);

const tokenSet = (expiresAt: unknown): TokenSet =>
  ({ audience: 'default', accessToken: 'at', scope: 'openid', expiresAt }) as TokenSet;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('guestTokenIsUsable', () => {
  // The same test for `getGuestAccessToken()` and for the renewal of a guest, so a token that the app cannot read is the
  // one that any login may replace. A silent login may replace a token that is still good too.
  test('is true while the token has not ended, down to the last second', () => {
    expect(guestTokenIsUsable(tokenSet(at + 600))).toBe(true);
    expect(guestTokenIsUsable(tokenSet(at + 1))).toBe(true);
  });

  test('is false from the second the token ends, with no extra time', () => {
    // The time is `at` seconds and 400 ms, so a token that ends at `at` ended 0.4 s ago.
    expect(guestTokenIsUsable(tokenSet(at))).toBe(false);
    expect(guestTokenIsUsable(tokenSet(at - 1))).toBe(false);

    vi.setSystemTime((at + 1) * 1000);
    expect(guestTokenIsUsable(tokenSet(at + 1))).toBe(false);
  });

  test.each([undefined, null])('is false for %s: there is no token to read', (missing) => {
    expect(guestTokenIsUsable(missing as unknown as TokenSet | undefined)).toBe(false);
  });

  test.each([
    { name: 'a missing expiry', expiresAt: undefined },
    { name: 'an expiry that is NaN', expiresAt: Number.NaN },
    { name: 'an expiry that is null', expiresAt: null },
  ])('is false for $name, so the guest may renew', ({ expiresAt }) => {
    // `getGuestAccessToken()` gives nothing for such a token, so the app cannot use it and a login may replace it.
    expect(guestTokenIsUsable(tokenSet(expiresAt))).toBe(false);
  });
});
