import { expect, test } from 'vitest';
import type { TransactionData } from '../types.js';
import { DefaultTransactionStore } from './default-transaction-store.js';

test('should get, set and delete', async () => {
  const store = new DefaultTransactionStore();

  const transactionData: TransactionData = {
    state: '<state>',
    code_verifier: '<code_verifier>',
  };

  await store.set('<identifier>', transactionData);

  const cachedData = await store.get('<identifier>');
  expect(cachedData).toBeDefined();
  expect(cachedData?.state).toBe('<state>');
  expect(cachedData?.code_verifier).toBe('<code_verifier>');

  await store.delete('<identifier>');
  await expect(store.get('<identifier>')).resolves.toBeUndefined();
});
