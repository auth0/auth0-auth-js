import { expect, Mock, test, vi } from 'vitest';
import type { EncryptedStoreOptions, StateData } from '../types.js';
import { decrypt, encrypt } from '../encryption/index.js';
import { AbstractEncryptedStateStore } from './encrypted-state-store.js';

class TestStateStore extends AbstractEncryptedStateStore {
  onSet: (identifier: string, encryptedStateData: string, options?: unknown) => Promise<void>;
  onGet: (identifier: string, options?: unknown) => Promise<string | undefined>;
  onDelete: (identifier: string, options?: unknown) => Promise<void>;
  constructor(
    {
      onSetMock,
      onGetMock,
      onDeleteMock,
    }: {
      onSetMock: Mock<(identifier: string, encryptedStateData: string, options?: unknown) => Promise<void>>;
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: 0 },
  };
  onGetMock.mockReturnValue(encrypt(stateData, '<secret>', '<identifier>'));

  await store.set('<identifier>', stateData);

  const args = onSetMock.mock.calls[0];
  const encryptedCookieValue = args![1];
  const decryptedCookieValue = await decrypt(encryptedCookieValue, '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>');
  expect(decryptedCookieValue).toStrictEqual(stateData);
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
