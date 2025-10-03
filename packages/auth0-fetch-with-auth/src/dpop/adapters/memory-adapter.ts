import type { StorageAdapter } from './storage-adapter.js';

/**
 * In-memory storage adapter for Node.js and other non-browser environments.
 * Note: This storage is ephemeral and will be lost when the process restarts.
 */
export class MemoryAdapter implements StorageAdapter {
  private storage: Map<string, Map<string, unknown>> = new Map();

  /**
   * Gets or creates a table (namespace) in memory.
   */
  private getTable(table: string): Map<string, unknown> {
    let tableMap = this.storage.get(table);
    if (!tableMap) {
      tableMap = new Map();
      this.storage.set(table, tableMap);
    }
    return tableMap;
  }

  async get<T = unknown>(table: string, key: string): Promise<T | undefined> {
    const tableMap = this.getTable(table);
    return tableMap.get(key) as T | undefined;
  }

  async set(table: string, key: string, value: unknown): Promise<void> {
    const tableMap = this.getTable(table);
    tableMap.set(key, value);
  }

  async delete(table: string, key: string): Promise<void> {
    const tableMap = this.getTable(table);
    tableMap.delete(key);
  }

  async getAllKeys(table: string): Promise<string[]> {
    const tableMap = this.getTable(table);
    return Array.from(tableMap.keys());
  }
}
