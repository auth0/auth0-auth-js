import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { CIMD_URL, OTHER_SESSION_ID, SESSION_ID, SESSION_KEY, USER_ID } from '../test-utils/poppy.js';
import { computePoppySessionKey } from './session-key.js';

describe('computePoppySessionKey', () => {
  test('is the base64url SHA-256 hash of the agent, the Session id and the User ID, each after a newline', async () => {
    const expected = createHash('sha256').update(`${CIMD_URL}\n${SESSION_ID}\n${USER_ID}`, 'utf8').digest('base64url');

    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID)).resolves.toBe(expected);
  });

  test('gives the key that auth0-api-js gives for the same agent, Session and User', async () => {
    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID)).resolves.toBe(SESSION_KEY);
  });

  // The vector of `session-verifier.spec.ts` in `@auth0/auth0-api-js`, with its default User ID. If either SDK changes
  // the formula, one of the two vectors stops matching.
  test('gives the vector of the tests of auth0-api-js', async () => {
    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID, 'usr_test')).resolves.toBe(
      '_BKvENretPSXFQ_ptaGM04IZBecCszGWrARX9rOQwP8'
    );
  });

  test('gives 43 characters of the base64url alphabet, with no padding', async () => {
    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID)).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test('gives the same key each time for the same agent, Session and User', async () => {
    const [first, second] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID),
      computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID),
    ]);

    expect(first).toBe(second);
  });

  // The keys come from the function under test, so a change that drops an input from the key is caught here and not
  // only by the vector.
  test('gives another key when the agent changes', async () => {
    const [key, other] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID),
      computePoppySessionKey('https://other.example/agent.json', SESSION_ID, USER_ID),
    ]);

    expect(other).not.toBe(key);
  });

  test('gives another key when the Session id changes', async () => {
    const [key, other] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID),
      computePoppySessionKey(CIMD_URL, OTHER_SESSION_ID, USER_ID),
    ]);

    expect(other).not.toBe(key);
  });

  test('gives another key when the User ID changes, so two Users with the same Session id have two Sessions', async () => {
    const [key, other] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID, USER_ID),
      computePoppySessionKey(CIMD_URL, SESSION_ID, 'usr_other'),
    ]);

    expect(other).not.toBe(key);
  });

  test('keeps the three parts apart, so two combinations never give one text', async () => {
    // Without the newlines, both would be hashed as `https://a.example/xyz`.
    const keys = await Promise.all([
      computePoppySessionKey('https://a.example/x', 'y', 'z'),
      computePoppySessionKey('https://a.example/', 'xy', 'z'),
      computePoppySessionKey('https://a.example/', 'x', 'yz'),
    ]);

    expect(new Set(keys).size).toBe(3);
  });
});
