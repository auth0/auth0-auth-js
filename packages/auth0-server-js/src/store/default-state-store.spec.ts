import { expect, test } from 'vitest';
import type { StateData } from '../types.js';
import { DefaultStateStore } from './default-state-store.js';

test('should get, set and delete', async () => {
  const store = new DefaultStateStore({ secret: '<secret>' });

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: 0 },
  };

  await store.set('<identifier>', stateData);

  const cachedData = await store.get('<identifier>');
  expect(cachedData).toBeDefined();
  expect(cachedData?.idToken).toBe('<id_token>');
  expect(cachedData?.refreshToken).toBe('<refresh_token>');
  expect(cachedData?.internal.sid).toBe('<sid>');
  expect(cachedData?.user!.sub).toBe('<sub>');

  await store.delete('<identifier>');
  await expect(store.get('<identifier>')).resolves.toBeUndefined();
});
