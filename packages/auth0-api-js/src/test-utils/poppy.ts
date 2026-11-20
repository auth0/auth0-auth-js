import { PoppySessionStore } from '../poppy/session-store.js';
import type { PoppySessionRecord } from '../types.js';

/**
 * An in-memory `PoppySessionStore` for tests that follows the contract of the base class: `get` gives `undefined` for a
 * key it does not know, and `set` never overwrites, so it resolves to the record that is stored, which is the one given
 * or the one that was already there. The race tests of the Session record check depend on that. It records its calls.
 */
export class MemoryStore extends PoppySessionStore {
  readonly records = new Map<string, PoppySessionRecord>();
  readonly getCalls: string[] = [];
  readonly setCalls: Array<{ key: string; record: PoppySessionRecord }> = [];

  async get(key: string): Promise<PoppySessionRecord | undefined> {
    this.getCalls.push(key);
    return this.records.get(key);
  }

  async set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
    this.setCalls.push({ key, record });
    const existing = this.records.get(key);
    if (existing !== undefined) {
      return existing;
    }
    this.records.set(key, record);
    return record;
  }
}

/** The error that `promise` rejects with. It fails the test when `promise` resolves. */
export async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected the promise to reject.');
}
