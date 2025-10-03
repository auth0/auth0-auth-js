/**
 * Abstract storage adapter interface for cross-platform storage support.
 * Different platforms (browser, Node.js) can provide their own implementations.
 */
export interface StorageAdapter {
  /**
   * Retrieves a value from storage by key.
   * @param table The table/namespace to read from.
   * @param key The key to retrieve.
   * @returns The stored value, or undefined if not found.
   */
  get<T = unknown>(table: string, key: string): Promise<T | undefined>;

  /**
   * Stores a value in storage.
   * @param table The table/namespace to write to.
   * @param key The key to store under.
   * @param value The value to store.
   */
  set(table: string, key: string, value: unknown): Promise<void>;

  /**
   * Deletes a value from storage by key.
   * @param table The table/namespace to delete from.
   * @param key The key to delete.
   */
  delete(table: string, key: string): Promise<void>;

  /**
   * Retrieves all keys from a table.
   * @param table The table/namespace to list keys from.
   * @returns An array of all keys in the table.
   */
  getAllKeys(table: string): Promise<string[]>;
}
