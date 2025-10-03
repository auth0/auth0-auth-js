import { type KeyPair } from './utils.js';
import type { StorageAdapter } from './adapters/storage-adapter.js';

const TABLES = {
  NONCE: 'nonce',
  KEYPAIR: 'keypair',
} as const;

const AUTH0_NONCE_ID = 'auth0';

type Table = (typeof TABLES)[keyof typeof TABLES];

export class DpopStorage {
  protected readonly clientId: string;
  protected readonly adapter: StorageAdapter;

  constructor(clientId: string, adapter: StorageAdapter) {
    this.clientId = clientId;
    this.adapter = adapter;
  }

  protected buildKey(id?: string): string {
    const finalId = id
      ? `_${id}` // prefix to avoid collisions
      : AUTH0_NONCE_ID;

    return `${this.clientId}::${finalId}`;
  }

  public setNonce(nonce: string, id?: string): Promise<void> {
    return this.save(TABLES.NONCE, this.buildKey(id), nonce);
  }

  public setKeyPair(keyPair: KeyPair): Promise<void> {
    return this.save(TABLES.KEYPAIR, this.buildKey(), keyPair);
  }

  protected async save(table: Table, key: string, obj: unknown): Promise<void> {
    await this.adapter.set(table, key, obj);
  }

  public findNonce(id?: string): Promise<string | undefined> {
    return this.find(TABLES.NONCE, this.buildKey(id));
  }

  public findKeyPair(): Promise<KeyPair | undefined> {
    return this.find(TABLES.KEYPAIR, this.buildKey());
  }

  protected find<T = unknown>(
    table: Table,
    key: string
  ): Promise<T | undefined> {
    return this.adapter.get<T>(table, key);
  }

  protected async deleteBy(
    table: Table,
    predicate: (key: string) => boolean
  ): Promise<void> {
    const allKeys = await this.adapter.getAllKeys(table);

    const deletions = allKeys
      .filter(predicate)
      .map((k) => this.adapter.delete(table, k));

    await Promise.all(deletions);
  }

  protected deleteByClientId(table: Table, clientId: string): Promise<void> {
    return this.deleteBy(table, (k) => k.startsWith(`${clientId}::`));
  }

  public clearNonces(): Promise<void> {
    return this.deleteByClientId(TABLES.NONCE, this.clientId);
  }

  public clearKeyPairs(): Promise<void> {
    return this.deleteByClientId(TABLES.KEYPAIR, this.clientId);
  }
}
