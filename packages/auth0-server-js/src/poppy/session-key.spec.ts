import { describe, expect, test } from 'vitest';
import { CIMD_URL, OTHER_SESSION_ID, SESSION_ID, SESSION_KEY } from '../test-utils/poppy.js';
import { computePoppySessionKey } from './session-key.js';

describe('computePoppySessionKey', () => {
  // The vector is the one that the tests of `@auth0/auth0-api-js` use for the same agent URL and Session id.
  test('gives the key that auth0-api-js gives for the same agent and Session', async () => {
    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID)).resolves.toBe(SESSION_KEY);
  });

  test('gives 43 characters of the base64url alphabet, with no padding', async () => {
    await expect(computePoppySessionKey(CIMD_URL, SESSION_ID)).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test('gives the same key each time for the same agent and Session', async () => {
    const [first, second] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID),
      computePoppySessionKey(CIMD_URL, SESSION_ID),
    ]);

    expect(first).toBe(second);
  });

  // Both keys come from the function under test, so a change that drops an input from the key is caught here and not
  // only by the vector.
  test('gives another key when the agent changes', async () => {
    const [key, keyForOtherAgent] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID),
      computePoppySessionKey('https://other.example/agent.json', SESSION_ID),
    ]);

    expect(keyForOtherAgent).not.toBe(key);
  });

  test('gives another key when the Session id changes', async () => {
    const [key, keyForOtherSession] = await Promise.all([
      computePoppySessionKey(CIMD_URL, SESSION_ID),
      computePoppySessionKey(CIMD_URL, OTHER_SESSION_ID),
    ]);

    expect(keyForOtherSession).not.toBe(key);
  });
});
