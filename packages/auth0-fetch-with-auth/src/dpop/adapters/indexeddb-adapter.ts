import type { StorageAdapter } from './storage-adapter.js';

const VERSION = 1;
const NAME = 'auth0-fetch-with-auth';

/**
 * IndexedDB storage adapter for browser environments.
 */
export class IndexedDBAdapter implements StorageAdapter {
  private dbHandle: IDBDatabase | undefined;
  private tables: Set<string> = new Set();

  /**
   * Creates or opens the IndexedDB database.
   */
  private async getDbHandle(): Promise<IDBDatabase> {
    if (this.dbHandle) {
      return this.dbHandle;
    }

    return new Promise((resolve, reject) => {
      const req = window.indexedDB.open(NAME, VERSION);

      req.onupgradeneeded = () => {
        const db = req.result;
        // Create object stores for known tables
        this.tables.forEach(table => {
          if (!db.objectStoreNames.contains(table)) {
            db.createObjectStore(table);
          }
        });
      };

      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        this.dbHandle = req.result;
        resolve(req.result);
      };
    });
  }

  /**
   * Ensures that a table (object store) exists.
   */
  private ensureTable(table: string): void {
    if (!this.tables.has(table)) {
      this.tables.add(table);
      // If database is already open, we need to close and reopen with new version
      if (this.dbHandle) {
        this.dbHandle.close();
        this.dbHandle = undefined;
      }
    }
  }

  /**
   * Executes a request on the IndexedDB.
   */
  private async executeDbRequest<T = unknown>(
    table: string,
    mode: IDBTransactionMode,
    requestFactory: (store: IDBObjectStore) => IDBRequest<T>
  ): Promise<T> {
    this.ensureTable(table);
    const db = await this.getDbHandle();

    const txn = db.transaction(table, mode);
    const store = txn.objectStore(table);
    const request = requestFactory(store);

    return new Promise((resolve, reject) => {
      txn.onerror = () => reject(txn.error);
      txn.onabort = () => reject(new Error('Transaction aborted'));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async get<T = unknown>(table: string, key: string): Promise<T | undefined> {
    try {
      return await this.executeDbRequest(table, 'readonly', store =>
        store.get(key)
      );
    } catch (error) {
      // If the object store doesn't exist, return undefined
      if (error instanceof DOMException && error.name === 'NotFoundError') {
        return undefined;
      }
      throw error;
    }
  }

  async set(table: string, key: string, value: unknown): Promise<void> {
    await this.executeDbRequest(table, 'readwrite', store =>
      store.put(value, key)
    );
  }

  async delete(table: string, key: string): Promise<void> {
    await this.executeDbRequest(table, 'readwrite', store =>
      store.delete(key)
    );
  }

  async getAllKeys(table: string): Promise<string[]> {
    try {
      const keys = await this.executeDbRequest(table, 'readonly', store =>
        store.getAllKeys()
      );
      return keys.filter((k): k is string => typeof k === 'string');
    } catch (error) {
      // If the object store doesn't exist, return empty array
      if (error instanceof DOMException && error.name === 'NotFoundError') {
        return [];
      }
      throw error;
    }
  }
}
