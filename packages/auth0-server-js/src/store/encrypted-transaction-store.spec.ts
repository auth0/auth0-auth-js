import { expect, Mock, test, vi } from 'vitest';
import type { EncryptedStoreOptions, TransactionData } from '../types.js';
import { decrypt, encrypt } from '../encryption/index.js';
import { AbstractEncryptedTransactionStore } from './encrypted-transaction-store.js';

class TestStateStore extends AbstractEncryptedTransactionStore {
  onSet: (identifier: string, encryptedTransactionData: string, options?: unknown) => Promise<void>;
  onGet: (identifier: string, options?: unknown) => Promise<string | undefined>;
  onDelete: (identifier: string, options?: unknown) => Promise<void>;
  constructor(
    {
      onSetMock,
      onGetMock,
      onDeleteMock,
    }: {
      onSetMock: Mock<(identifier: string, encryptedTransactionData: string, options?: unknown) => Promise<void>>;
      onGetMock: Mock<(identifier: string, options?: unknown) => Promise<string | undefined>>;
      onDeleteMock: Mock<(identifier: string, options?: unknown) => Promise<void>>;
    },
    options: EncryptedStoreOptions
  ) {
    super(options);

    this.onSet = onSetMock;
    this.onGet = onGetMock;
    this.onDelete = onDeleteMock;
  }
}

test('get - should return encrypted data', async () => {
  const onGetMock = vi.fn();
  const onSetMock = vi.fn();
  const onDeleteMock = vi.fn();

  const store = new TestStateStore(
    {
      onGetMock,
      onSetMock,
      onDeleteMock,
    },
    { secret: '<secret>' }
  );

  const expected = { foo: 'bar' };
  onGetMock.mockReturnValue(encrypt(expected, '<secret>', '<identifier>'));

  const result = await store.get('<identifier>');

  expect(result).toStrictEqual(expected);
});

test('set - should encrypt and set data', async () => {
  const onGetMock = vi.fn();
  const onSetMock = vi.fn();
  const onDeleteMock = vi.fn();

  const store = new TestStateStore(
    {
      onGetMock,
      onSetMock,
      onDeleteMock,
    },
    { secret: '<secret>' }
  );

  const transactionData: TransactionData = {
    state: '<state>',
    code_verifier: '<code_verfifier>',
  };
  onGetMock.mockReturnValue(encrypt(transactionData, '<secret>', '<identifier>'));

  await store.set('<identifier>', transactionData);

  const args = onSetMock.mock.calls[0];
  const encryptedCookieValue = args![1];
  const decryptedCookieValue = await decrypt(encryptedCookieValue, '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>');
  expect(decryptedCookieValue).toStrictEqual(transactionData);
});

test('delete - should call onDelete', async () => {
  const onGetMock = vi.fn();
  const onSetMock = vi.fn();
  const onDeleteMock = vi.fn();

  const store = new TestStateStore(
    {
      onGetMock,
      onSetMock,
      onDeleteMock,
    },
    { secret: '<secret>' }
  );

  const storeOptions = { foo: 'bar' };
  await store.delete('<identifier>', storeOptions);

  expect(onDeleteMock).toHaveBeenCalledWith('<identifier>', storeOptions);
});
