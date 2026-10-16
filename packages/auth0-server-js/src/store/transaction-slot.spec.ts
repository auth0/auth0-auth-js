import { describe, expect, test, vi } from 'vitest';
import { errors } from 'jose';
import { TransactionSlot } from './transaction-slot.js';
import type { TransactionSlotEntry } from './transaction-slot.js';
import { InvalidConfigurationError } from '../errors.js';
import type { TransactionData, TransactionStore } from '../types.js';

interface TestEntry extends TransactionSlotEntry {
  kind: 'test';
  value: string;
}

const isTestEntry = (data: TransactionData): data is TestEntry =>
  data.kind === 'test' && typeof data.value === 'string' && typeof data.expiresAt === 'number';

const storeOptions = { request: 'r1' };

const makeSlot = (stored?: TransactionData | Error, otherIdentifiers = [{ option: 'transactionIdentifier', identifier: '__a0_tx' }]) => {
  const store = {
    get: vi.fn(async () => {
      if (stored instanceof Error) {
        throw stored;
      }
      return stored;
    }),
    set: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
  } satisfies TransactionStore<typeof storeOptions>;

  const slot = new TransactionSlot<TestEntry, typeof storeOptions>({
    store,
    identifier: { option: 'testIdentifier', identifier: '__a0_test_tx' },
    otherIdentifiers,
    kind: 'test',
    isEntry: isTestEntry,
  });

  return { slot, store };
};

const inAMinute = () => Date.now() / 1000 + 60;

describe('read', () => {
  test('returns a stored entry of its kind', async () => {
    const entry = { kind: 'test', value: 'v', expiresAt: inAMinute() };
    const { slot, store } = makeSlot(entry);

    await expect(slot.read(storeOptions)).resolves.toEqual(entry);
    expect(store.get).toHaveBeenCalledWith('__a0_test_tx', storeOptions);
    expect(store.delete).not.toHaveBeenCalled();
  });

  test('returns undefined when nothing is stored', async () => {
    const { slot, store } = makeSlot(undefined);

    await expect(slot.read(storeOptions)).resolves.toBeUndefined();
    expect(store.delete).not.toHaveBeenCalled();
  });

  test.each([
    { label: 'without a kind', data: { codeVerifier: 'verifier', expiresAt: inAMinute() } },
    { label: 'of another kind', data: { kind: 'other', value: 'v', expiresAt: inAMinute() } },
  ])('leaves an entry $label alone', async ({ data }) => {
    const { slot, store } = makeSlot(data);

    await expect(slot.read(storeOptions)).resolves.toBeUndefined();
    expect(store.delete).not.toHaveBeenCalled();
  });

  test.each([
    { label: 'malformed', data: { kind: 'test', expiresAt: inAMinute() } },
    { label: 'expired', data: { kind: 'test', value: 'v', expiresAt: Date.now() / 1000 - 1 } },
    { label: 'expiring now', data: { kind: 'test', value: 'v', expiresAt: Date.now() / 1000 } },
  ])('deletes an entry of its kind that is $label', async ({ data }) => {
    const { slot, store } = makeSlot(data);

    await expect(slot.read(storeOptions)).resolves.toBeUndefined();
    expect(store.delete).toHaveBeenCalledWith('__a0_test_tx', storeOptions);
  });

  test('deletes an entry whose encrypted value has expired', async () => {
    const { slot, store } = makeSlot(new errors.JWTExpired('"exp" claim timestamp check failed', {}, 'exp', 'check_failed'));

    await expect(slot.read(storeOptions)).resolves.toBeUndefined();
    expect(store.delete).toHaveBeenCalledWith('__a0_test_tx', storeOptions);
  });

  test('rethrows any other store error', async () => {
    const { slot, store } = makeSlot(new Error('store unavailable'));

    await expect(slot.read(storeOptions)).rejects.toThrowError('store unavailable');
    expect(store.delete).not.toHaveBeenCalled();
  });
});

describe('write and clear', () => {
  test('write stores the entry under the identifier', async () => {
    const entry: TestEntry = { kind: 'test', value: 'v', expiresAt: inAMinute() };
    const { slot, store } = makeSlot();

    await slot.write(entry, storeOptions);

    expect(store.set).toHaveBeenCalledWith('__a0_test_tx', entry, false, storeOptions);
  });

  test('clear deletes the identifier', async () => {
    const { slot, store } = makeSlot();

    await slot.clear(storeOptions);

    expect(store.delete).toHaveBeenCalledWith('__a0_test_tx', storeOptions);
  });
});

describe('assertPrefixFree', () => {
  test('accepts identifiers that are not prefixes of one another', () => {
    const { slot } = makeSlot(undefined, [
      { option: 'transactionIdentifier', identifier: '__a0_tx' },
      { option: 'stateIdentifier', identifier: '__a0_session' },
      { option: 'anonymousSessionIdentifier', identifier: '__a0_anon' },
    ]);

    expect(() => slot.assertPrefixFree()).not.toThrow();
  });

  test.each(['__a0_test', '__a0_test_tx', '__a0_test_tx.0', '__a0_test_tx_other', '_'])(
    'rejects %s, which shares a prefix with the slot identifier',
    (identifier) => {
      const { slot } = makeSlot(undefined, [{ option: 'stateIdentifier', identifier }]);

      expect(() => slot.assertPrefixFree()).toThrowError(InvalidConfigurationError);
      expect(() => slot.assertPrefixFree()).toThrowError(
        `\`testIdentifier\` ('__a0_test_tx') and \`stateIdentifier\` ('${identifier}') must not be a prefix of one another.`
      );
    }
  );

  test.each([
    { label: 'read', call: (slot: TransactionSlot<TestEntry, typeof storeOptions>) => slot.read(storeOptions) },
    {
      label: 'write',
      call: (slot: TransactionSlot<TestEntry, typeof storeOptions>) =>
        slot.write({ kind: 'test', value: 'v', expiresAt: inAMinute() }, storeOptions),
    },
    { label: 'clear', call: (slot: TransactionSlot<TestEntry, typeof storeOptions>) => slot.clear(storeOptions) },
  ])('$label checks the identifiers before using the store', async ({ call }) => {
    const { slot, store } = makeSlot({ kind: 'test', value: 'v', expiresAt: inAMinute() }, [
      { option: 'transactionIdentifier', identifier: '__a0_test' },
    ]);

    await expect(call(slot)).rejects.toThrowError(InvalidConfigurationError);
    expect(store.get).not.toHaveBeenCalled();
    expect(store.set).not.toHaveBeenCalled();
    expect(store.delete).not.toHaveBeenCalled();
  });
});
