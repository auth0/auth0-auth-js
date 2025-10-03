import { DpopStorage } from './storage.js';
import { IndexedDBAdapter } from './adapters/indexeddb-adapter.js';
import { MemoryAdapter } from './adapters/memory-adapter.js';
import type { StorageAdapter } from './adapters/storage-adapter.js';
import { calculateThumbprint, generateKeyPair, generateProof } from './utils.js';
import type { KeyPair } from './utils.js';

/**
 * Detects the appropriate storage adapter for the current environment.
 * @returns An IndexedDBAdapter for browsers, or MemoryAdapter for Node.js.
 */
function createDefaultAdapter(): StorageAdapter {
  // Check if we're in a browser environment with IndexedDB support
  if (typeof window !== 'undefined' && window.indexedDB) {
    return new IndexedDBAdapter();
  }

  // Fall back to in-memory storage for Node.js and other environments
  return new MemoryAdapter();
}

export class Dpop {
  protected readonly storage: DpopStorage;

  /**
   * Creates a new Dpop instance.
   * @param clientId The client ID to use for storage namespacing.
   * @param adapter Optional storage adapter. If not provided, automatically detects the environment.
   */
  public constructor(clientId: string, adapter?: StorageAdapter) {
    this.storage = new DpopStorage(clientId, adapter || createDefaultAdapter());
  }

  public getNonce(id?: string): Promise<string | undefined> {
    return this.storage.findNonce(id);
  }

  public setNonce(nonce: string, id?: string): Promise<void> {
    return this.storage.setNonce(nonce, id);
  }

  protected async getOrGenerateKeyPair(): Promise<KeyPair> {
    let keyPair = await this.storage.findKeyPair();

    if (!keyPair) {
      keyPair = await generateKeyPair();
      await this.storage.setKeyPair(keyPair);
    }

    return keyPair;
  }

  public async generateProof(params: {
    url: string;
    method: string;
    nonce?: string;
    accessToken?: string;
  }): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return generateProof({
      keyPair,
      ...params
    });
  }

  public async calculateThumbprint(): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return calculateThumbprint(keyPair);
  }

  public async clear(): Promise<void> {
    await Promise.all([
      this.storage.clearNonces(),
      this.storage.clearKeyPairs()
    ]);
  }
}
