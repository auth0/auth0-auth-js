import { expect, test } from 'vitest';
import type { TransactionData } from '../types.js';
import { DefaultTransactionStore } from './default-transaction-store.js';

test('should get, set and delete', async () => {
  const store = new DefaultTransactionStore({ secret: '<secret>' });

  const transactionData: TransactionData = {
    codeVerifier: '<code_verifier>',
  };

  await store.set('<identifier>', transactionData);

  const cachedData = await store.get('<identifier>');
  expect(cachedData).toBeDefined();
  expect(cachedData?.codeVerifier).toBe('<code_verifier>');

  await store.delete('<identifier>');
  await expect(store.get('<identifier>')).resolves.toBeUndefined();
});
