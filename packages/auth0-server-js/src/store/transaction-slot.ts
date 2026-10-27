import { errors } from 'jose';
import { InvalidConfigurationError } from '../errors.js';
import type { TransactionData, TransactionStore } from '../types.js';

/**
 * @internal
 * The fields every entry kept in a {@link TransactionSlot} has.
 */
export interface TransactionSlotEntry extends TransactionData {
  /**
   * Unix timestamp (seconds) after which the entry can no longer be used.
   */
  expiresAt: number;
}

/**
 * @internal
 * A store identifier, together with the `ServerClient` option that sets it (used in error messages).
 */
export interface StoreIdentifier {
  option: string;
  identifier: string;
}

/**
 * @internal
 */
export interface TransactionSlotOptions<TEntry extends TransactionSlotEntry, TStoreOptions> {
  store: TransactionStore<TStoreOptions>;
  identifier: StoreIdentifier;
  /**
   * The identifiers of the SDK's other stores. The cookie-backed session and anonymous stores find
   * their cookies with `startsWith`, so none of these may be a prefix of the slot's identifier, and
   * the slot's identifier may not be a prefix of any of them.
   */
  otherIdentifiers: StoreIdentifier[];
  /**
   * Checks that a stored value has the expected shape.
   */
  isEntry: (data: TransactionData) => data is TEntry;
}

/**
 * @internal
 * A named slot in the transaction store. It keeps the server-side state of a short-lived flow (the
 * passkey `authSession` today) from the request that starts the flow until the request that
 * completes it.
 *
 * Every read and write uses exactly one identifier, and a read only returns a well-formed entry that
 * has not expired.
 */
export class TransactionSlot<TEntry extends TransactionSlotEntry, TStoreOptions = unknown> {
  readonly #options: TransactionSlotOptions<TEntry, TStoreOptions>;

  constructor(options: TransactionSlotOptions<TEntry, TStoreOptions>) {
    this.#options = options;
  }

  /**
   * Throws when the slot's identifier and the identifier of another store are a prefix of one another.
   *
   * Checked when the slot is used rather than when the `ServerClient` is created, so an application
   * that never uses the slot is not affected by its identifier.
   *
   * @throws {InvalidConfigurationError}
   */
  assertPrefixFree(): void {
    const own = this.#options.identifier;

    for (const other of this.#options.otherIdentifiers) {
      if (own.identifier.startsWith(other.identifier) || other.identifier.startsWith(own.identifier)) {
        throw new InvalidConfigurationError(
          `\`${own.option}\` ('${own.identifier}') and \`${other.option}\` ('${other.identifier}') must not be a ` +
            "prefix of one another. The cookie-backed session and anonymous stores find their cookies by prefix, so one store could read or delete the other's data."
        );
      }
    }
  }

  /**
   * Reads the slot's entry.
   *
   * Returns `undefined` when there is none, and when the entry has expired or is malformed (deleted).
   */
  async read(storeOptions?: TStoreOptions): Promise<TEntry | undefined> {
    this.assertPrefixFree();

    const { store, identifier, isEntry } = this.#options;
    let data: TransactionData | undefined;

    try {
      data = await store.get(identifier.identifier, storeOptions);
    } catch (e: unknown) {
      // The encrypted value outlived its expiry. The identifier is part of the encryption key, so it
      // was written under this slot's identifier: it is this slot's entry, and it can't be used.
      if (e instanceof errors.JWTExpired) {
        await store.delete(identifier.identifier, storeOptions);
        return;
      }

      throw e;
    }

    if (!data) {
      return;
    }

    if (!isEntry(data) || data.expiresAt <= Date.now() / 1000) {
      await store.delete(identifier.identifier, storeOptions);
      return;
    }

    return data;
  }

  /**
   * Stores the entry, replacing any entry already in the slot.
   */
  async write(entry: TEntry, storeOptions?: TStoreOptions): Promise<void> {
    this.assertPrefixFree();

    await this.#options.store.set(this.#options.identifier.identifier, entry, false, storeOptions);
  }

  /**
   * Deletes the slot's entry.
   */
  async clear(storeOptions?: TStoreOptions): Promise<void> {
    this.assertPrefixFree();

    await this.#options.store.delete(this.#options.identifier.identifier, storeOptions);
  }
}
