/**
 * Installs an in-memory `localStorage` for the test environment.
 *
 * MSW's core module eagerly constructs a `CookieStore` singleton on import that
 * reads from `globalThis.localStorage`. In Deno, `localStorage` is backed by
 * SQLite, so running tests across multiple worker threads makes each store open
 * the same database and fail with "database is locked". Swapping in a plain
 * in-memory store removes that contention (and keeps MSW's `localStorage`
 * invariant satisfied) without giving up test parallelism.
 */
const store = new Map<string, string>();

const memoryLocalStorage: Storage = {
  get length() {
    return store.size;
  },
  clear() {
    store.clear();
  },
  getItem(key: string) {
    return store.has(key) ? store.get(key)! : null;
  },
  key(index: number) {
    return Array.from(store.keys())[index] ?? null;
  },
  removeItem(key: string) {
    store.delete(key);
  },
  setItem(key: string, value: string) {
    store.set(key, String(value));
  },
};

Object.defineProperty(globalThis, 'localStorage', {
  value: memoryLocalStorage,
  configurable: true,
  writable: true,
});
